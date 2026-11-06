// Packet decoding: IPv4/IPv6 -> TCP/UDP/ICMP -> DNS / TLS / HTTP.
// Every byte here comes off the wire: all reads are bounds-checked.
#pragma once
#include <algorithm>
#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace wg {

inline uint16_t be16(const uint8_t* p) { return uint16_t(p[0] << 8 | p[1]); }
inline uint32_t be32(const uint8_t* p) { return uint32_t(p[0]) << 24 | p[1] << 16 | p[2] << 8 | p[3]; }

// Colour roles; the UI maps them to terminal colours.
enum Role { R_TEXT, R_DIM, R_FAINT, R_LABEL, R_BAD, R_WARN, R_PEER0, R_PEER1, R_PEER2, R_PEER3 };
struct Seg { std::string s; Role r = R_TEXT; };
using Line = std::vector<Seg>;

inline std::string ip4(const uint8_t* p) {
    char b[16];
    snprintf(b, sizeof b, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return b;
}
inline std::string ip6(const uint8_t* p) {
    char b[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, p, b, sizeof b);
    return b;
}
inline std::string hex16(uint16_t v) { char b[16]; snprintf(b, sizeof b, "0x%04x", v); return b; }
inline std::string hex32(uint32_t v) { char b[16]; snprintf(b, sizeof b, "0x%08x", v); return b; }
// Wire text -> safe printable ASCII.
inline std::string clean(const uint8_t* p, size_t n, size_t max = 200) {
    std::string s;
    for (size_t i = 0; i < n && i < max; i++) s += (p[i] >= 32 && p[i] < 127) ? char(p[i]) : '.';
    return s;
}
inline std::string str(uint64_t v) { return std::to_string(v); }

// ---------- IP ----------
struct Ip {
    bool ok = false, v6 = false, df = false, mf = false;
    std::string src, dst;
    uint8_t proto = 0, ttl = 0;
    uint16_t id = 0, len = 0, fragoff = 0;
    uint32_t flow = 0;
    const uint8_t* l4 = nullptr;
    size_t l4n = 0;
};

inline Ip decode_ip(const uint8_t* p, size_t n) {
    Ip ip;
    if (n < 1) return ip;
    if (p[0] >> 4 == 4) {
        if (n < 20) return ip;
        size_t ihl = (p[0] & 15) * 4;
        if (ihl < 20 || ihl > n) return ip;
        ip.len = be16(p + 2);
        ip.id = be16(p + 4);
        uint16_t f = be16(p + 6);
        ip.df = f & 0x4000;
        ip.mf = f & 0x2000;
        ip.fragoff = (f & 0x1fff) * 8;
        ip.ttl = p[8];
        ip.proto = p[9];
        ip.src = ip4(p + 12);
        ip.dst = ip4(p + 16);
        size_t tot = ip.len ? std::min<size_t>(n, ip.len) : n;  // len 0 = offloaded super-packet
        ip.l4 = p + ihl;
        ip.l4n = tot > ihl ? tot - ihl : 0;
        ip.ok = true;
    } else if (p[0] >> 4 == 6) {
        if (n < 40) return ip;
        ip.v6 = true;
        ip.flow = be32(p) & 0xfffff;
        ip.len = be16(p + 4);
        ip.proto = p[6];
        ip.ttl = p[7];
        ip.src = ip6(p + 8);
        ip.dst = ip6(p + 24);
        const uint8_t* q = p + 40;
        size_t m = ip.len ? std::min<size_t>(n - 40, ip.len) : n - 40;
        // Walk extension headers: hop-by-hop, routing, fragment, destination options.
        for (int i = 0; i < 8; i++) {
            if (ip.proto == 0 || ip.proto == 43 || ip.proto == 60) {
                if (m < 8) break;
                size_t l = (q[1] + 1) * 8;
                if (l > m) break;
                ip.proto = q[0], q += l, m -= l;
            } else if (ip.proto == 44) {
                if (m < 8) break;
                ip.fragoff = be16(q + 2) & 0xfff8;
                ip.mf = q[3] & 1;
                ip.proto = q[0], q += 8, m -= 8;
            } else break;
        }
        ip.l4 = q;
        ip.l4n = m;
        ip.ok = true;
    }
    return ip;
}

inline std::string proto_name(uint8_t p, bool v6) {
    switch (p) {
    case 1: return "icmp";
    case 6: return "tcp";
    case 17: return "udp";
    case 47: return "gre";
    case 50: return "esp";
    case 58: return "icmp6";
    }
    return (v6 ? "ip6/" : "ip/") + str(p);
}

// ---------- TCP / UDP / ICMP ----------
struct L4 {
    bool ok = false;
    uint16_t sport = 0, dport = 0, win = 0, ulen = 0, iid = 0, iseq = 0;
    uint32_t seq = 0, ack = 0;
    uint8_t flags = 0, itype = 0, icode = 0;
    const uint8_t* pl = nullptr;
    size_t pln = 0;
};

inline L4 decode_l4(const Ip& ip) {
    L4 l;
    const uint8_t* p = ip.l4;
    size_t n = ip.l4n;
    if (!ip.ok || ip.fragoff) return l;
    if (ip.proto == 6) {
        if (n < 20) return l;
        size_t off = (p[12] >> 4) * 4;
        if (off < 20 || off > n) return l;
        l.sport = be16(p), l.dport = be16(p + 2), l.seq = be32(p + 4), l.ack = be32(p + 8);
        l.flags = p[13], l.win = be16(p + 14), l.pl = p + off, l.pln = n - off;
    } else if (ip.proto == 17) {
        if (n < 8) return l;
        l.sport = be16(p), l.dport = be16(p + 2), l.ulen = be16(p + 4), l.pl = p + 8, l.pln = n - 8;
    } else if (ip.proto == 1 || ip.proto == 58) {
        if (n < 4) return l;
        l.itype = p[0], l.icode = p[1];
        if (n >= 8) l.iid = be16(p + 4), l.iseq = be16(p + 6);
    } else return l;
    l.ok = true;
    return l;
}

inline std::string tcp_flags(uint8_t f) {
    static const std::pair<uint8_t, const char*> names[] = {
        {0x02, "syn"}, {0x01, "fin"}, {0x04, "rst"}, {0x08, "psh"},
        {0x10, "ack"}, {0x20, "urg"}, {0x40, "ece"}, {0x80, "cwr"}};
    std::string s;
    for (auto& [bit, name] : names)
        if (f & bit) s += (s.empty() ? "" : " ") + std::string(name);
    return s.empty() ? "none" : s;
}

inline std::string icmp_name(const L4& l, bool v6) {
    if (!v6) switch (l.itype) {
        case 0: return "echo reply";
        case 3: return l.icode == 3 ? "port unreachable" : l.icode == 1 ? "host unreachable"
                     : l.icode == 4 ? "fragmentation needed" : "unreachable";
        case 5: return "redirect";
        case 8: return "echo request";
        case 11: return "time exceeded";
        }
    else switch (l.itype) {
        case 1: return "unreachable";
        case 2: return "packet too big";
        case 3: return "time exceeded";
        case 128: return "echo request";
        case 129: return "echo reply";
        case 133: return "router solicit";
        case 134: return "router advert";
        case 135: return "neighbor solicit";
        case 136: return "neighbor advert";
        }
    return "type " + str(l.itype) + " code " + str(l.icode);
}

// ---------- DNS ----------
struct DnsRR { std::string name, data; uint16_t type = 0; uint32_t ttl = 0; };
struct Dns { bool ok = false, qr = false; uint16_t id = 0, nq = 0, na = 0; int rcode = 0; std::vector<DnsRR> qs, ans; };

// Reads a (possibly compressed) name at off. Advances off past it.
inline bool dns_name(const uint8_t* m, size_t n, size_t& off, std::string& out) {
    out.clear();
    size_t p = off;
    bool jumped = false;
    for (int hops = 0;;) {
        if (p >= n) return false;
        uint8_t l = m[p];
        if ((l & 0xC0) == 0xC0) {
            if (p + 1 >= n || ++hops > 16) return false;  // pointer loops
            if (!jumped) off = p + 2;
            jumped = true;
            p = size_t(l & 0x3F) << 8 | m[p + 1];
            continue;
        }
        if (l & 0xC0) return false;
        p++;
        if (l == 0) break;
        if (p + l > n || out.size() > 255) return false;
        if (!out.empty()) out += '.';
        out += clean(m + p, l);
        p += l;
    }
    if (!jumped) off = p;
    if (out.empty()) out = ".";
    return true;
}

inline std::string rr_type(uint16_t t) {
    switch (t) {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    case 64: return "SVCB";
    case 65: return "HTTPS";
    }
    return "TYPE" + str(t);
}

inline std::string rcode_name(int r) {
    static const char* n[] = {"noerror", "formerr", "servfail", "nxdomain", "notimp", "refused"};
    return r < 6 ? n[r] : "rcode " + str(r);
}

inline Dns parse_dns(const uint8_t* m, size_t n) {
    Dns d;
    if (n < 12) return d;
    d.id = be16(m);
    d.qr = m[2] >> 7;
    d.rcode = m[3] & 15;
    d.nq = be16(m + 4);
    d.na = be16(m + 6);
    size_t off = 12;
    for (int i = 0; i < d.nq && i < 4; i++) {
        DnsRR r;
        if (!dns_name(m, n, off, r.name) || off + 4 > n) return d;
        r.type = be16(m + off);
        off += 4;
        d.qs.push_back(r);
    }
    for (int i = 0; i < d.na && i < 32; i++) {
        DnsRR r;
        if (!dns_name(m, n, off, r.name) || off + 10 > n) break;
        r.type = be16(m + off);
        r.ttl = be32(m + off + 4);
        uint16_t rl = be16(m + off + 8);
        off += 10;
        if (off + rl > n) break;
        if (r.type == 1 && rl == 4) r.data = ip4(m + off);
        else if (r.type == 28 && rl == 16) r.data = ip6(m + off);
        else if (r.type == 2 || r.type == 5 || r.type == 12) { size_t o = off; dns_name(m, n, o, r.data); }
        else r.data = str(rl) + " bytes";
        off += rl;
        d.ans.push_back(r);
    }
    d.ok = true;
    return d;
}

// Filtering resolvers (1.1.1.2 / 1.1.1.3) answer blocked names with 0.0.0.0 / ::.
inline bool dns_blocked(const Dns& d) {
    for (auto& a : d.ans)
        if (a.data == "0.0.0.0" || a.data == "::") return true;
    return false;
}

// ---------- TLS ----------
enum TlsKind { TLS_NONE, TLS_CLIENT_HELLO, TLS_SERVER_HELLO, TLS_APPDATA, TLS_ALERT, TLS_OTHER };
struct Tls { TlsKind kind = TLS_NONE; std::string sni, alpn; bool v13 = false; };

// Only recognises a TLS record that starts at the beginning of this segment.
inline Tls parse_tls(const uint8_t* p, size_t n) {
    Tls t;
    if (n < 5 || p[1] != 3 || p[2] > 4 || p[0] < 20 || p[0] > 23) return t;
    if (p[0] == 23) return t.kind = TLS_APPDATA, t;
    if (p[0] == 21) return t.kind = TLS_ALERT, t;
    if (p[0] == 20 || n < 6 || p[5] > 2) return t.kind = TLS_OTHER, t;
    if (p[5] == 2) return t.kind = TLS_SERVER_HELLO, t;
    if (p[5] != 1) return t.kind = TLS_OTHER, t;
    t.kind = TLS_CLIENT_HELLO;
    size_t o = 5 + 4 + 2 + 32;  // record hdr, handshake hdr, version, random
    if (o + 1 > n) return t;
    o += 1 + p[o];  // session id
    if (o + 2 > n) return t;
    o += 2 + be16(p + o);  // cipher suites
    if (o + 1 > n) return t;
    o += 1 + p[o];  // compression
    if (o + 2 > n) return t;
    size_t end = std::min(n, o + 2 + be16(p + o));
    o += 2;
    while (o + 4 <= end) {
        uint16_t et = be16(p + o), el = be16(p + o + 2);
        o += 4;
        if (o + el > end) break;
        const uint8_t* e = p + o;
        if (et == 0 && el >= 5) {  // server_name: list len, type, name len, name
            uint16_t nl = be16(e + 3);
            if (5u + nl <= el) t.sni = clean(e + 5, nl);
        } else if (et == 16 && el >= 2) {  // ALPN
            for (size_t q = 2; q < el;) {
                uint8_t l = e[q++];
                if (q + l > el) break;
                t.alpn += (t.alpn.empty() ? "" : ", ") + clean(e + q, l);
                q += l;
            }
        } else if (et == 43) {  // supported_versions
            for (size_t q = 1; q + 1 < el; q += 2)
                if (be16(e + q) == 0x0304) t.v13 = true;
        }
        o += el;
    }
    return t;
}

// ---------- HTTP (plain text, port 80) ----------
inline std::string http_line(const uint8_t* p, size_t n) {
    static const char* starts[] = {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "HTTP/1."};
    for (auto s : starts) {
        size_t k = std::char_traits<char>::length(s);
        if (n >= k && std::equal(s, s + k, p)) {
            size_t e = 0;
            while (e < n && p[e] != '\r' && p[e] != '\n') e++;
            return clean(p, e, 120);
        }
    }
    return "";
}
inline std::string http_host(const uint8_t* p, size_t n) {
    std::string s = clean(p, n, 2048);
    size_t i = s.find("..Host: ");  // CRLF became ".."
    if (i == std::string::npos) return "";
    size_t e = s.find("..", i + 8);
    return s.substr(i + 8, e == std::string::npos ? std::string::npos : e - i - 8);
}

// ---------- WireGuard (the outer UDP, seen when watching eth0) ----------
inline uint16_t wg_port = 51820;  // main() sets the device's real listen port when it can read it
inline uint32_t le32(const uint8_t* p) { return uint32_t(p[0] | p[1] << 8 | p[2] << 16) | uint32_t(p[3]) << 24; }
struct Wg { int type = 0; uint32_t sender = 0, receiver = 0; uint64_t counter = 0; size_t inner = 0; };

// Message types from the WireGuard paper; each has a fixed size except data (padded to 16).
inline Wg parse_wg(const L4& l) {
    Wg w;
    const uint8_t* p = l.pl;
    size_t n = l.pln;
    if ((l.sport != wg_port && l.dport != wg_port) || n < 4 || (p[1] | p[2] | p[3])) return w;
    if (p[0] == 1 && n == 148) w.type = 1, w.sender = le32(p + 4);
    else if (p[0] == 2 && n == 92) w.type = 2, w.sender = le32(p + 4), w.receiver = le32(p + 8);
    else if (p[0] == 3 && n == 64) w.type = 3, w.receiver = le32(p + 4);
    else if (p[0] == 4 && n >= 32 && n % 16 == 0)
        w.type = 4, w.receiver = le32(p + 4), w.counter = le32(p + 8) | uint64_t(le32(p + 12)) << 32, w.inner = n - 32;
    return w;
}
inline const char* wg_kind(const Wg& w) {
    static const char* k[] = {"", "handshake init", "handshake response", "cookie reply", "data"};
    return w.type == 4 && !w.inner ? "keepalive" : k[w.type];
}

// ---------- one-line summary ----------
struct Summary {
    bool ok = false, ports = false, blocked = false;
    std::string src, dst, proto, qname;
    uint8_t ipproto = 0, tcpflags = 0;
    int dns = 0;  // 1 query, 2 response
    uint16_t sport = 0, dport = 0, dns_id = 0;
    Line info;
    std::vector<std::pair<std::string, std::string>> learned;  // ip -> hostname
};

inline Summary summarize(const uint8_t* p, size_t n) {
    Summary s;
    Ip ip = decode_ip(p, n);
    if (!ip.ok) return s.proto = "?", s.info = {{"not ip", R_DIM}}, s;
    s.ok = true, s.src = ip.src, s.dst = ip.dst;
    s.proto = proto_name(ip.proto, ip.v6);
    s.ipproto = ip.proto;
    if (ip.fragoff) return s.info = {{"fragment +" + str(ip.fragoff), R_DIM}}, s;
    L4 l = decode_l4(ip);
    if (!l.ok) return s.info = {{ip.l4n ? "" : "truncated", R_DIM}}, s;

    if (ip.proto == 1 || ip.proto == 58) {
        s.info = {{icmp_name(l, ip.v6), R_DIM}};
        return s;
    }
    s.ports = true, s.sport = l.sport, s.dport = l.dport;

    if (ip.proto == 6) {
        s.tcpflags = l.flags;
        Tls t = l.pln ? parse_tls(l.pl, l.pln) : Tls{};
        std::string http = (l.sport == 80 || l.dport == 80) ? http_line(l.pl, l.pln) : "";
        if (t.kind == TLS_CLIENT_HELLO) {
            s.proto = "tls";
            s.info = {{"client hello  "}, {"sni ", R_DIM}, {t.sni.empty() ? "-" : t.sni}};
            if (!t.sni.empty()) s.learned.push_back({ip.dst, t.sni});
        } else if (t.kind != TLS_NONE) {
            s.proto = "tls";
            if (t.kind == TLS_SERVER_HELLO) s.info = {{"server hello"}};
            else if (t.kind == TLS_APPDATA) s.info = {{"encrypted", R_DIM}};
            else if (t.kind == TLS_ALERT) s.info = {{"alert", R_WARN}};
            else s.info = {{"handshake", R_DIM}};
        } else if (!http.empty()) {
            s.proto = "http";
            s.info = {{http}};
            std::string host = http_host(l.pl, l.pln);
            if (!host.empty() && l.dport == 80) s.learned.push_back({ip.dst, host});
        } else {
            s.info = {{tcp_flags(l.flags), R_DIM}};
            if (l.pln) s.info.push_back({"  " + str(l.pln) + " B", R_FAINT});
        }
        return s;
    }

    // UDP
    if (Wg w = parse_wg(l); w.type) {
        s.proto = "wg";
        if (w.type == 4) s.info = {{wg_kind(w), R_DIM}, {"  #" + str(w.counter) + (w.inner ? "  " + str(w.inner) + " B inside" : ""), R_FAINT}};
        else s.info = {{wg_kind(w)}, {"  " + hex32(w.type == 3 ? w.receiver : w.sender), R_FAINT}};
        return s;
    }
    if (l.sport == 53 || l.dport == 53) {
        Dns d = parse_dns(l.pl, l.pln);
        if (d.ok && !d.qs.empty()) {
            s.proto = "dns";
            const std::string& q = d.qs[0].name;
            s.dns = d.qr ? 2 : 1, s.dns_id = d.id, s.qname = q;
            if (!d.qr) {
                s.info = {{rr_type(d.qs[0].type) + " " + q}};
            } else if (dns_blocked(d)) {
                s.blocked = true;
                s.info = {{"blocked", R_BAD}, {"  " + q}};
            } else if (d.rcode) {
                s.info = {{rcode_name(d.rcode), R_WARN}, {"  " + q}};
            } else {
                const DnsRR* first = nullptr;
                for (auto& a : d.ans)
                    if (a.type == 1 || a.type == 28) {
                        s.learned.push_back({a.data, q});
                        if (!first) first = &a;
                    }
                if (first) s.info = {{q}, {" → ", R_DIM}, {first->data}};
                else s.info = {{q}, {"  " + str(d.ans.size()) + " answers", R_DIM}};
            }
            return s;
        }
    }
    if (l.sport == 443 || l.dport == 443) {
        bool initial = l.pln && (l.pl[0] & 0xF0) == 0xC0;  // long header, type Initial
        s.info = {{initial ? "quic initial" : "quic", R_DIM}};
    } else if (l.sport == 123 || l.dport == 123) {
        s.info = {{"ntp", R_DIM}};
    } else {
        s.info = {{str(l.pln) + " B", R_FAINT}};
    }
    return s;
}

// ---------- layered detail ----------
struct LB {
    Line l;
    explicit LB(const std::string& label) { l.push_back({label, R_LABEL}); l.push_back({std::string(label.size() < 7 ? 7 - label.size() : 1, ' ')}); }
    LB& t(const std::string& s, Role r = R_TEXT) { l.push_back({s, r}); return *this; }
    LB& kv(const std::string& k, const std::string& v) { return t("   ").t(k, R_DIM).t(" ").t(v); }
    LB& arrow(const std::string& a, const std::string& b) { return t(a).t(" → ", R_DIM).t(b); }
};

inline std::vector<Line> detail(const uint8_t* p, size_t n) {
    std::vector<Line> out;
    Ip ip = decode_ip(p, n);
    if (!ip.ok) {
        out.push_back(LB("?").t("not an ip packet", R_DIM).l);
        return out;
    }
    LB a(ip.v6 ? "ip6" : "ip");
    a.arrow(ip.src, ip.dst).kv(ip.v6 ? "hop" : "ttl", str(ip.ttl)).kv("len", str(ip.len ? ip.len : n));
    if (ip.v6) { if (ip.flow) a.kv("flow", hex16(ip.flow)); }
    else a.kv("id", hex16(ip.id));
    if (ip.df) a.t("   ").t("df", R_DIM);
    if (ip.mf || ip.fragoff) a.kv("frag", "+" + str(ip.fragoff) + (ip.mf ? " more" : ""));
    out.push_back(a.l);

    L4 l = decode_l4(ip);
    if (!l.ok) {
        out.push_back(LB(proto_name(ip.proto, ip.v6)).t(str(ip.l4n) + " bytes not decoded", R_DIM).l);
        return out;
    }
    if (ip.proto == 1 || ip.proto == 58) {
        LB b(ip.v6 ? "icmp6" : "icmp");
        b.t(icmp_name(l, ip.v6)).kv("type", str(l.itype)).kv("code", str(l.icode));
        bool echo = ip.v6 ? (l.itype == 128 || l.itype == 129) : (l.itype == 0 || l.itype == 8);
        if (echo) b.kv("id", str(l.iid)).kv("seq", str(l.iseq));
        out.push_back(b.l);
        return out;
    }
    if (ip.proto == 6) {
        LB b("tcp");
        b.arrow(str(l.sport), str(l.dport)).kv("seq", str(l.seq));
        if (l.flags & 0x10) b.kv("ack", str(l.ack));
        b.kv("flags", tcp_flags(l.flags)).kv("win", str(l.win));
        if (l.pln) b.kv("data", str(l.pln));
        out.push_back(b.l);
        if (!l.pln) return out;
        Tls t = parse_tls(l.pl, l.pln);
        if (t.kind == TLS_CLIENT_HELLO) {
            LB c("tls");
            c.t("client hello").kv("sni", t.sni.empty() ? "-" : t.sni);
            if (!t.alpn.empty()) c.kv("alpn", t.alpn);
            if (t.v13) c.kv("ver", "1.3");
            out.push_back(c.l);
        } else if (t.kind != TLS_NONE) {
            const char* k[] = {"", "", "server hello", "application data (encrypted)", "alert", "handshake"};
            out.push_back(LB("tls").t(k[t.kind]).kv("record", str(be16(l.pl + 3))).l);
        } else if (std::string h = http_line(l.pl, l.pln); !h.empty()) {
            LB c("http");
            c.t(h);
            if (std::string host = http_host(l.pl, l.pln); !host.empty()) c.kv("host", host);
            out.push_back(c.l);
        }
        return out;
    }
    // UDP
    out.push_back(LB("udp").arrow(str(l.sport), str(l.dport)).kv("len", str(l.ulen)).l);
    if (Wg w = parse_wg(l); w.type) {
        LB c("wg");
        c.t(wg_kind(w));
        if (w.sender) c.kv("sender", hex32(w.sender));
        if (w.receiver) c.kv("receiver", hex32(w.receiver));
        if (w.type == 4) c.kv("counter", str(w.counter)).kv("inside", str(w.inner) + " B padded");
        else c.kv("size", str(l.pln));
        out.push_back(c.l);
        return out;
    }
    if (l.sport == 53 || l.dport == 53) {
        Dns d = parse_dns(l.pl, l.pln);
        if (!d.ok) return out;
        LB c("dns");
        c.t(d.qr ? "response" : "query").kv("id", hex16(d.id));
        if (d.qr) c.kv("rcode", rcode_name(d.rcode));
        c.kv("qd", str(d.nq)).kv("an", str(d.na));
        out.push_back(c.l);
        auto pad = [](std::string s) { s.resize(std::max<size_t>(s.size() + 1, 6), ' '); return s; };
        for (auto& q : d.qs) out.push_back(LB("").t("q", R_DIM).t("  " + pad(rr_type(q.type))).t(q.name).l);
        bool blocked = dns_blocked(d);
        for (size_t i = 0; i < d.ans.size() && i < 8; i++) {
            auto& r = d.ans[i];
            LB x("");
            x.t("a", R_DIM).t("  " + pad(rr_type(r.type))).t(r.data).kv("ttl", str(r.ttl));
            if (!d.qs.empty() && r.name != d.qs.front().name) x.kv("for", r.name);
            if (blocked && (r.data == "0.0.0.0" || r.data == "::")) x.t("   ").t("blocked by resolver", R_BAD);
            out.push_back(x.l);
        }
        if (d.ans.size() > 8) out.push_back(LB("").t("+" + str(d.ans.size() - 8) + " more answers", R_DIM).l);
    } else if (l.sport == 443 || l.dport == 443) {
        out.push_back(LB("quic").t(l.pln && (l.pl[0] & 0x80) ? "long header (handshake)" : "short header (encrypted)", R_DIM).l);
    }
    return out;
}

// ---------- plain-English notes for the detail pane (`?`) ----------
inline std::string service(uint16_t p) {
    switch (p) {
    case 22: return "ssh";
    case 53: return "dns";
    case 80: return "http, unencrypted web";
    case 123: return "ntp, clock sync";
    case 443: return "https (tcp) or http/3 (udp)";
    case 853: return "dns over tls";
    case 993: return "imap over tls, mail";
    case 5223: return "apple push notifications";
    case 5228: return "google push notifications";
    }
    return p == wg_port ? "wireguard" : "";
}
inline std::string resolver(const std::string& ip) {
    if (ip == "1.1.1.1" || ip == "1.0.0.1" || ip == "2606:4700:4700::1111") return "cloudflare, no filtering";
    if (ip == "1.1.1.2" || ip == "1.0.0.2" || ip == "2606:4700:4700::1112") return "cloudflare, blocks malware";
    if (ip == "1.1.1.3" || ip == "1.0.0.3" || ip == "2606:4700:4700::1113") return "cloudflare for families, blocks malware and adult sites";
    if (ip == "8.8.8.8" || ip == "8.8.4.4") return "google public dns";
    if (ip == "9.9.9.9") return "quad9, blocks malware";
    return "";
}

inline std::vector<Line> explain(const uint8_t* p, size_t n) {
    std::vector<Line> out;
    auto say = [&](const std::string& k, const std::string& v, Role r = R_DIM) { out.push_back(LB(k).t(v, r).l); };
    Ip ip = decode_ip(p, n);
    if (!ip.ok) return say("?", "not ip: wgmon decodes ipv4 and ipv6 only"), out;
    int start = ip.ttl > 128 ? 255 : ip.ttl > 64 ? 128 : 64;
    const char* who = start == 255 ? "network gear" : start == 128 ? "windows" : "linux, android or apple";
    say(ip.v6 ? "ip6" : "ip", std::string(ip.v6 ? "hop limit " : "ttl ") + str(ip.ttl) + " = routers it may still cross; started at " +
        str(start) + " (" + who + "), so about " + str(start - ip.ttl) + (start - ip.ttl == 1 ? " hop" : " hops") + " so far");
    if (ip.fragoff || ip.mf) say("frag", "one piece of a packet too big for a link; the receiver glues the pieces back together");
    L4 l = decode_l4(ip);
    if (!l.ok) return out;

    if (ip.proto == 1 || ip.proto == 58) {
        std::string nm = icmp_name(l, ip.v6);
        say(ip.v6 ? "icmp6" : "icmp",
            nm.rfind("echo", 0) == 0 ? "ping: checks a host is reachable and how long a round trip takes"
            : nm == "time exceeded" ? "a router dropped a packet whose ttl hit 0; traceroute maps paths with this"
            : nm == "packet too big" || nm == "fragmentation needed" ? "too big for a link on the path; the sender should shrink its packets (path mtu)"
            : nm.find("unreachable") != std::string::npos ? "can't be delivered; port unreachable = nothing is listening there"
            : "a control message from the network stack, not user data");
        return out;
    }
    uint16_t sp = !service(l.dport).empty() ? l.dport : l.sport;
    std::string svc = service(sp);

    if (ip.proto == 6) {
        uint8_t f = l.flags;
        say("tcp", (f & 0x04) ? "rst: connection aborted on the spot (nothing listening, or one side gave up)"
                   : (f & 0x12) == 0x02 ? "syn: step 1 of the handshake, asking to open a connection"
                   : (f & 0x12) == 0x12 ? "syn ack: step 2, the server agrees; the client's ack completes it"
                   : (f & 0x01) ? "fin: this side is done sending; the connection closes politely"
                   : l.pln ? "carries " + str(l.pln) + " bytes of a stream; seq counts bytes sent, ack = next byte expected back"
                   : "bare ack: \"got everything up to byte " + str(l.ack) + "\"; unacked data gets resent");
        if (!svc.empty()) say("port", str(sp) + " = " + svc);
        if (!l.pln) return out;
        Tls t = parse_tls(l.pl, l.pln);
        if (t.kind == TLS_CLIENT_HELLO) {
            say("tls", "client hello: the site name (sni) travels in plaintext so the server can pick its certificate");
            if (!t.alpn.empty()) say("alpn", "protocols offered: h2 = http/2, http/1.1 = classic; the server picks one");
        } else if (t.kind == TLS_SERVER_HELLO) say("tls", "server hello: cipher chosen; with tls 1.3 everything after this is encrypted");
        else if (t.kind == TLS_APPDATA) say("tls", "encrypted: you (and this vps) see size and timing, never the content");
        else if (t.kind == TLS_ALERT) say("tls", "alert: usually a polite close, sometimes an error");
        else if (t.kind == TLS_OTHER) say("tls", "handshake: key exchange and certificates");
        else if (!http_line(l.pl, l.pln).empty()) say("http", "plain http: unencrypted, readable by this vps and anyone on the path", R_WARN);
        return out;
    }

    if (Wg w = parse_wg(l); w.type) {
        say("wg", w.type == 1 ? "handshake init: the peer proves who it is and starts fresh keys (every ~2 min while active)"
                  : w.type == 2 ? "handshake response: both sides now share new session keys"
                  : w.type == 3 ? "cookie reply: the server is busy and asks the peer to prove its address first (dos protection)"
                  : w.inner ? "one encrypted inner packet (wg0 shows it decrypted); receiver picks the session, counter blocks replays"
                  : "keepalive: an empty encrypted packet that keeps nat mappings open (persistent-keepalive)");
        return out;
    }
    if (l.sport == 53 || l.dport == 53) {
        Dns d = parse_dns(l.pl, l.pln);
        if (!d.ok || d.qs.empty()) return out;
        auto& q = d.qs[0];
        std::string what = q.type == 1 ? "ipv4 address" : q.type == 28 ? "ipv6 address"
                         : q.type == 65 ? "https settings (http/3, ech keys)" : rr_type(q.type) + " record";
        if (!d.qr) say("dns", "query: asking for the " + what + " of " + q.name + "; plain dns is unencrypted");
        else if (dns_blocked(d)) say("dns", "blocked: the resolver answered 0.0.0.0, a dead address, so the app can't connect", R_BAD);
        else if (d.rcode == 3) say("dns", "nxdomain: that name doesn't exist");
        else if (d.rcode) say("dns", rcode_name(d.rcode) + ": the resolver couldn't answer");
        else say("dns", "answer: wgmon now labels these addresses " + q.name + "; ttl = seconds it may be cached");
        std::string srv = d.qr ? ip.src : ip.dst;
        if (std::string r = resolver(srv); !r.empty()) say("server", srv + " = " + r);
        return out;
    }
    say("udp", sp == 443 ? "quic (http/3): encrypted from the first packet except a little setup in the initial ones"
                         : "single datagrams, no handshake, no resend; the app copes with loss");
    if (!svc.empty()) say("port", str(sp) + " = " + svc);
    return out;
}

inline std::vector<Line> hexdump(const uint8_t* p, size_t n, size_t max_lines) {
    std::vector<Line> out;
    for (size_t off = 0; off < n && out.size() < max_lines; off += 16) {
        char b[24];
        snprintf(b, sizeof b, "%04zx  ", off);
        std::string hex, asc;
        for (size_t i = 0; i < 16; i++) {
            if (i == 8) hex += ' ';
            if (off + i < n) {
                char h[4];
                snprintf(h, sizeof h, "%02x ", p[off + i]);
                hex += h;
                asc += (p[off + i] >= 32 && p[off + i] < 127) ? char(p[off + i]) : '.';
            } else hex += "   ";
        }
        out.push_back({{b, R_FAINT}, {hex + "  ", R_DIM}, {asc, R_DIM}});
    }
    return out;
}

}  // namespace wg
