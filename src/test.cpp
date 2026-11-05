// Parser self-check. `make test` builds it with ASan/UBSan and runs it.
#include "parse.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>

using namespace wg;
using B = std::vector<uint8_t>;

static B cat(B a, const B& b) { a.insert(a.end(), b.begin(), b.end()); return a; }
static B u16(unsigned v) { return {uint8_t(v >> 8), uint8_t(v)}; }

static B ipv4(uint8_t proto, B src, B dst, const B& payload) {
    B h = {0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, proto, 0, 0};
    h = cat(cat(h, src), dst);
    unsigned len = 20 + payload.size();
    h[2] = len >> 8, h[3] = len;
    return cat(h, payload);
}
static B udp(unsigned sp, unsigned dp, const B& pl) { return cat(cat(cat(cat(u16(sp), u16(dp)), u16(8 + pl.size())), u16(0)), pl); }
static B tcp(unsigned sp, unsigned dp, uint8_t flags, const B& pl) {
    B h = cat(u16(sp), u16(dp));
    h = cat(h, {0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xfa, 0xf0, 0, 0, 0, 0});
    return cat(h, pl);
}
static B qname(const char* s) {  // "bad.example" -> 3bad7example0
    B out;
    const char* p = s;
    while (*p) {
        const char* e = p;
        while (*e && *e != '.') e++;
        out.push_back(uint8_t(e - p));
        out.insert(out.end(), p, e);
        p = *e ? e + 1 : e;
    }
    out.push_back(0);
    return out;
}

static std::string text(const Line& l) { std::string s; for (auto& g : l) s += g.s; return s; }

// Feed every truncated prefix through the parsers: must never read out of bounds.
static void fuzz_prefixes(const B& pkt) {
    for (size_t i = 0; i <= pkt.size(); i++) {
        summarize(pkt.data(), i);
        detail(pkt.data(), i);
        hexdump(pkt.data(), i, 100);
    }
}

int main() {
    B phone = {10, 8, 0, 2}, cf = {1, 1, 1, 3}, web = {93, 184, 216, 34};

    // DNS: blocked answer from a family filter resolver.
    B dns = cat(cat(B{0x3f, 0x2a, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, qname("bad.example")), {0, 1, 0, 1});
    dns = cat(dns, {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 0, 0, 0, 0});
    B blocked = ipv4(17, cf, phone, udp(53, 53211, dns));
    Summary s = summarize(blocked.data(), blocked.size());
    assert(s.proto == "dns" && s.blocked && text(s.info) == "blocked  bad.example");
    assert(s.src == "1.1.1.3" && s.dport == 53211);
    auto d = detail(blocked.data(), blocked.size());
    assert(d.size() == 5 && text(d[4]).find("blocked by resolver") != std::string::npos);

    // DNS: normal answer teaches us ip -> name.
    B ok = dns;
    ok[ok.size() - 4] = 93, ok[ok.size() - 3] = 184, ok[ok.size() - 2] = 216, ok[ok.size() - 1] = 34;
    B okpkt = ipv4(17, cf, phone, udp(53, 53211, ok));
    s = summarize(okpkt.data(), okpkt.size());
    assert(!s.blocked && s.learned.size() == 1 && s.learned[0].first == "93.184.216.34" && s.learned[0].second == "bad.example");

    // DNS: compression pointer loop is rejected, not followed forever.
    B loop = {0xc0, 0x00};
    size_t off = 0;
    std::string name;
    assert(!dns_name(loop.data(), loop.size(), off, name));

    // TLS ClientHello with SNI + ALPN.
    B sni = cat(cat(u16(0), u16(16)), cat(cat(u16(14), B{0}), cat(u16(11), B{'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'})));
    B alpn = cat(cat(u16(16), u16(5)), cat(u16(3), B{2, 'h', '2'}));
    B ext = cat(sni, alpn);
    B body = cat(B{3, 3}, B(32, 0));
    body = cat(body, {0, 0, 2, 0x13, 1, 1, 0});
    body = cat(cat(body, u16(ext.size())), ext);
    B hs = cat(B{1, 0, uint8_t(body.size() >> 8), uint8_t(body.size())}, body);
    B rec = cat(cat(B{22, 3, 1}, u16(hs.size())), hs);
    B tls = ipv4(6, phone, web, tcp(51544, 443, 0x18, rec));
    s = summarize(tls.data(), tls.size());
    assert(s.proto == "tls" && text(s.info) == "client hello  sni example.com");
    assert(s.learned.size() == 1 && s.learned[0].first == "93.184.216.34");
    d = detail(tls.data(), tls.size());
    assert(d.size() == 3 && text(d[2]).find("alpn h2") != std::string::npos);

    // TCP SYN, plain HTTP.
    B syn = ipv4(6, phone, web, tcp(51544, 443, 0x02, {}));
    assert(text(summarize(syn.data(), syn.size()).info) == "syn");
    const char* req = "GET /index.html HTTP/1.1\r\nHost: neverssl.com\r\n\r\n";
    B http = ipv4(6, phone, web, tcp(40000, 80, 0x18, B(req, req + strlen(req))));
    s = summarize(http.data(), http.size());
    assert(s.proto == "http" && text(s.info) == "GET /index.html HTTP/1.1" && s.learned[0].second == "neverssl.com");

    for (auto* p : {&blocked, &okpkt, &tls, &syn, &http}) fuzz_prefixes(*p);
    puts("ok");
}
