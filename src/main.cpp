// wgmon: watch the decrypted packets crossing a WireGuard interface.
#include "parse.hpp"

#include <cerrno>
#include <climits>
#include <clocale>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <ifaddrs.h>
#include <linux/genetlink.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/wireguard.h>
#include <ncurses.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>

#ifndef WGMON_VERSION
#define WGMON_VERSION "dev"
#endif

using namespace wg;

constexpr size_t RING = 10000;  // ponytail: fixed history, add --keep N if 10k packets is too short
constexpr size_t SNAP = 4096;   // bytes stored per packet; the full length is still shown
constexpr size_t FLOWS = 5000;  // ponytail: oldest 10% evicted past this, no LRU list needed at this size

struct Peer {
    Peer(std::string i, std::string n) : ip(std::move(i)), name(std::move(n)) {}
    std::string ip, name;
    uint64_t up = 0, down = 0;        // bytes wgmon saw
    bool wg = false;                  // the fields below come from the kernel (netlink), when allowed
    std::string endpoint;
    int64_t handshake = 0;            // unix seconds, 0 = never
    uint64_t dns_ms = 0, dns_n = 0;   // how fast this peer's resolver answers
};

struct Pkt {
    uint64_t seq;
    timespec ts;
    uint32_t len;
    std::vector<uint8_t> raw;
    int peer;  // index into App::peers, -1 = unknown
    bool up;   // peer -> internet
    Summary s;
    std::string remote, hay;
    int dns_ms = -1;
};

// A connection: same protocol and the same two address:port ends.
struct Flow {
    int peer = -1;
    std::string proto, remote, hay, state;
    timespec first{}, last{}, syn{};
    uint64_t pkts = 0, up = 0, down = 0;
    int rtt = -1;  // ms from syn to syn-ack, i.e. this VPS <-> the server
};
struct Blocked { int peer = -1; std::string domain, resolver, hay; uint64_t n = 0; timespec last{}; };

enum View { V_PKTS, V_FLOWS, V_BLOCKED };

struct App {
    std::string iface = "wg0";
    std::vector<Peer> peers;
    std::unordered_map<std::string, int> peer_of;
    uint32_t net = 0, mask = 0, self = 0;               // interface IPv4 subnet, to auto-detect peers
    std::unordered_map<std::string, std::string> names;  // ip -> hostname, from DNS answers / SNI / Host
    std::deque<Pkt> buf;
    uint64_t next_seq = 1, total = 0, drops = 0;
    std::unordered_map<std::string, Flow> flows;
    std::unordered_map<std::string, Blocked> blocked;
    std::unordered_map<std::string, timespec> dns_pending;  // client|port|id -> query time
    // kernel WireGuard status
    int nl = -1, nl_err = 0;
    uint16_t wg_family = 0;
    uint32_t nl_seq = 0;
    std::string wgdev, note;
    std::unordered_map<std::string, int> peer_by_key;
    // view state
    View view = V_PKTS;
    View back = V_PKTS;   // list to return to on esc after enter jumped to its packets
    std::string back_sel;
    std::string agg_sel;  // selected flow / blocked key; empty = follow the newest
    std::string msg;      // footer message, shown for a few seconds
    timespec msg_at{};
    std::string agg_top;  // first visible flow / blocked row, so clicks don't scroll the list
    int sort[3] = {};     // per view, index into kSorts
    bool live = true, hex = true, explain = false, typing = false, quit = false, help = false;
    int tab_x[4] = {};                          // header tab boundaries, for clicks
    int rows_y = 0, rows_n = 0; size_t rows_ti = 0;  // visible list rows, for clicks
    int click_y = -1; timespec click_at{};           // last row click, for double-click
    uint64_t sel = 0, top = 0, fresh = 0;  // fresh = packets arrived while paused
    int page = 10, peer_filter = -1;
    std::string filter;
};

static volatile sig_atomic_t g_stop = 0;

[[noreturn]] static void die(const std::string& msg) {
    fprintf(stderr, "wgmon: %s\n", msg.c_str());
    exit(1);
}

// ---------- text helpers ----------
static size_t width(const std::string& s) {
    size_t w = 0;
    for (unsigned char c : s) w += (c & 0xC0) != 0x80;
    return w;
}
static size_t width(const Line& l) { size_t w = 0; for (auto& g : l) w += width(g.s); return w; }
static std::string text(const Line& l) { std::string s; for (auto& g : l) s += g.s; return s; }

// Pad or cut to exactly w columns (all glyphs we print are one column wide).
static std::string fit(const std::string& s, size_t w, bool right = false) {
    size_t cw = width(s);
    if (cw <= w) return right ? std::string(w - cw, ' ') + s : s + std::string(w - cw, ' ');
    if (w == 0) return "";
    std::string o;
    size_t k = 0;
    for (size_t i = 0; i < s.size() && k + 1 < w; k++) {
        unsigned char c = s[i];
        size_t l = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : 4;
        o.append(s, i, l);
        i += l;
    }
    return o + "…";
}

static std::string human(uint64_t b) {
    const char* u = "BKMGT";
    double v = double(b);
    int i = 0;
    while (v >= 1024 && i < 4) v /= 1024, i++;
    char s[16];
    snprintf(s, sizeof s, i < 2 ? "%.0f%c" : "%.1f%c", v, u[i]);
    return s;
}
static std::string commas(uint64_t v) {
    std::string s = std::to_string(v);
    for (int i = int(s.size()) - 3; i > 0; i -= 3) s.insert(size_t(i), ",");
    return s;
}
static std::string ago(int64_t s) {
    if (s < 60) return str(s) + "s";
    if (s < 3600) return str(s / 60) + "m";
    if (s < 86400) return str(s / 3600) + "h";
    return str(s / 86400) + "d";
}
static long ms_between(const timespec& a, const timespec& b) {
    return long(b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
}
static bool older(const timespec& a, const timespec& b) { return a.tv_sec != b.tv_sec ? a.tv_sec < b.tv_sec : a.tv_nsec < b.tv_nsec; }
static std::string hms(const timespec& ts) {
    tm t;
    localtime_r(&ts.tv_sec, &t);
    char b[16];
    snprintf(b, sizeof b, "%02d:%02d:%02d", t.tm_hour, t.tm_min, t.tm_sec);
    return b;
}
static std::string lower(std::string s) { for (auto& c : s) c = char(tolower((unsigned char)c)); return s; }

// ---------- capture ----------
static int open_capture(const std::string& ifname) {
    int fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) die(errno == EPERM ? "need root or CAP_NET_RAW (sudo setcap cap_net_raw,cap_net_admin+ep $(command -v wgmon))" : strerror(errno));
    unsigned idx = if_nametoindex(ifname.c_str());
    if (!idx) die("no interface " + ifname);
    sockaddr_ll sa{};
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = int(idx);
    if (bind(fd, (sockaddr*)&sa, sizeof sa) < 0) die("bind " + ifname + ": " + strerror(errno));
    int rcv = 4 << 20;  // absorb bursts while the UI draws; the kernel caps it at net.core.rmem_max
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof rcv);
    return fd;
}

static void load_subnet(App& a) {
    ifaddrs* ifs;
    if (getifaddrs(&ifs) != 0) return;
    // Only on a point-to-point link (WireGuard): on eth0 the "subnet" is the provider's LAN, not peers.
    for (ifaddrs* i = ifs; i; i = i->ifa_next)
        if (i->ifa_addr && i->ifa_netmask && i->ifa_addr->sa_family == AF_INET && a.iface == i->ifa_name &&
            (i->ifa_flags & IFF_POINTOPOINT)) {
            a.self = ntohl(((sockaddr_in*)i->ifa_addr)->sin_addr.s_addr);
            a.mask = ntohl(((sockaddr_in*)i->ifa_netmask)->sin_addr.s_addr);
            a.net = a.self & a.mask;
        }
    freeifaddrs(ifs);
}

// Known peer, or an address inside the tunnel subnet (auto-added, named by its IP).
// ponytail: IPv4 subnet only; IPv6 peers need --peer
static int peer_index(App& a, const std::string& ip) {
    if (auto it = a.peer_of.find(ip); it != a.peer_of.end()) return it->second;
    in_addr x;
    if (a.mask && a.mask != 0xffffffff && inet_pton(AF_INET, ip.c_str(), &x) == 1) {
        uint32_t v = ntohl(x.s_addr);
        if ((v & a.mask) == a.net && v != a.self) {
            a.peers.push_back({ip, ip});
            return a.peer_of[ip] = int(a.peers.size() - 1);
        }
    }
    return -1;
}

// ---------- peer status from the kernel: generic netlink, the same thing `wg show` asks ----------
// Needs CAP_NET_ADMIN. Without it wgmon still works; the status line just says how to enable it.
using Bytes = std::vector<uint8_t>;

static void add_attr(Bytes& m, uint16_t type, const void* d, size_t n) {
    size_t o = m.size();
    m.resize(o + NLA_ALIGN(NLA_HDRLEN + n));
    nlattr h{uint16_t(NLA_HDRLEN + n), type};
    memcpy(&m[o], &h, sizeof h);
    memcpy(&m[o + NLA_HDRLEN], d, n);
}
template <class F> static void each_attr(const uint8_t* p, size_t n, F f) {
    while (n >= NLA_HDRLEN) {
        nlattr h;
        memcpy(&h, p, sizeof h);
        if (h.nla_len < NLA_HDRLEN || h.nla_len > n) return;
        f(uint16_t(h.nla_type & NLA_TYPE_MASK), p + NLA_HDRLEN, size_t(h.nla_len - NLA_HDRLEN));
        size_t step = NLA_ALIGN(h.nla_len);
        if (step >= n) return;
        p += step, n -= step;
    }
}

// One request -> the attribute block of every reply message. false on error (a.nl_err = errno).
static bool genl(App& a, uint16_t family, uint8_t cmd, uint16_t flags, const Bytes& attrs, std::vector<Bytes>& out) {
    Bytes m(NLMSG_HDRLEN + GENL_HDRLEN + attrs.size());
    if (!attrs.empty()) memcpy(m.data() + NLMSG_HDRLEN + GENL_HDRLEN, attrs.data(), attrs.size());
    nlmsghdr h{};
    h.nlmsg_len = uint32_t(m.size());
    h.nlmsg_type = family;
    h.nlmsg_flags = uint16_t(NLM_F_REQUEST | flags);
    h.nlmsg_seq = ++a.nl_seq;
    genlmsghdr g{cmd, 1, 0};
    memcpy(m.data(), &h, sizeof h);
    memcpy(m.data() + NLMSG_HDRLEN, &g, sizeof g);
    if (send(a.nl, m.data(), m.size(), 0) < 0) return a.nl_err = errno, false;
    alignas(nlmsghdr) static uint8_t buf[1 << 16];
    for (;;) {
        ssize_t r = recv(a.nl, buf, sizeof buf, 0);
        if (r <= 0) return a.nl_err = errno, false;
        for (size_t o = 0; o + sizeof(nlmsghdr) <= size_t(r);) {
            auto* nh = (nlmsghdr*)(buf + o);
            if (nh->nlmsg_len < sizeof *nh || o + nh->nlmsg_len > size_t(r)) break;
            o += NLMSG_ALIGN(nh->nlmsg_len);
            if (nh->nlmsg_seq != a.nl_seq) continue;
            if (nh->nlmsg_type == NLMSG_DONE) return true;
            if (nh->nlmsg_type == NLMSG_ERROR) {
                int e = ((nlmsgerr*)NLMSG_DATA(nh))->error;
                return a.nl_err = -e, e == 0;
            }
            if (nh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN) return false;
            out.emplace_back((uint8_t*)NLMSG_DATA(nh) + GENL_HDRLEN, (uint8_t*)nh + nh->nlmsg_len);
            if (!(nh->nlmsg_flags & NLM_F_MULTI)) return true;
        }
    }
}

static void wg_open(App& a) {
    a.nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (a.nl < 0) return;
    timeval tv{1, 0};
    setsockopt(a.nl, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    Bytes at;
    add_attr(at, CTRL_ATTR_FAMILY_NAME, WG_GENL_NAME, sizeof WG_GENL_NAME);
    std::vector<Bytes> out;
    if (genl(a, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0, at, out))
        for (auto& m : out)
            each_attr(m.data(), m.size(), [&](uint16_t t, const uint8_t* d, size_t n) {
                if (t == CTRL_ATTR_FAMILY_ID && n >= 2) memcpy(&a.wg_family, d, 2);
            });
}

static std::string key8(const uint8_t* k) {  // the first 8 base64 chars, as `wg show` prints keys
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string s;
    for (int i = 0; i < 6; i += 3) {
        uint32_t v = uint32_t(k[i] << 16 | k[i + 1] << 8 | k[i + 2]);
        for (int j = 18; j >= 0; j -= 6) s += t[v >> j & 63];
    }
    return s;
}

struct WgPeer { std::string key, endpoint, endpoint_ip; int64_t handshake = 0; std::vector<std::string> ips; };

static bool wg_dump(App& a, const std::string& dev, std::vector<WgPeer>& peers, uint16_t& port) {
    if (a.nl < 0 || !a.wg_family) return false;
    Bytes at;
    add_attr(at, WGDEVICE_A_IFNAME, dev.c_str(), dev.size() + 1);
    std::vector<Bytes> out;
    if (!genl(a, a.wg_family, WG_CMD_GET_DEVICE, NLM_F_DUMP, at, out)) return false;
    std::unordered_map<std::string, size_t> seen;  // big devices split one peer across messages
    for (auto& m : out)
        each_attr(m.data(), m.size(), [&](uint16_t t, const uint8_t* d, size_t n) {
            if (t == WGDEVICE_A_LISTEN_PORT && n >= 2) memcpy(&port, d, 2);
            if (t != WGDEVICE_A_PEERS) return;
            each_attr(d, n, [&](uint16_t, const uint8_t* pd, size_t pn) {
                WgPeer w;
                each_attr(pd, pn, [&](uint16_t k, const uint8_t* v, size_t vn) {
                    if (k == WGPEER_A_PUBLIC_KEY && vn == 32) w.key = key8(v);
                    else if (k == WGPEER_A_LAST_HANDSHAKE_TIME && vn >= 8) memcpy(&w.handshake, v, 8);
                    else if (k == WGPEER_A_ENDPOINT && vn >= sizeof(sockaddr_in)) {
                        sockaddr_in6 sa{};
                        memcpy(&sa, v, std::min(vn, sizeof sa));
                        if (sa.sin6_family == AF_INET) {
                            auto* s4 = (sockaddr_in*)&sa;
                            w.endpoint_ip = ip4((uint8_t*)&s4->sin_addr);
                            w.endpoint = w.endpoint_ip + ":" + str(ntohs(s4->sin_port));
                        } else if (sa.sin6_family == AF_INET6 && vn >= sizeof sa) {
                            w.endpoint_ip = ip6((uint8_t*)&sa.sin6_addr);
                            w.endpoint = "[" + w.endpoint_ip + "]:" + str(ntohs(sa.sin6_port));
                        }
                    } else if (k == WGPEER_A_ALLOWEDIPS)
                        each_attr(v, vn, [&](uint16_t, const uint8_t* ad, size_t an) {
                            std::string ip;
                            int cidr = -1;
                            each_attr(ad, an, [&](uint16_t x, const uint8_t* xd, size_t xn) {
                                if (x == WGALLOWEDIP_A_IPADDR) ip = xn == 4 ? ip4(xd) : xn == 16 ? ip6(xd) : "";
                                else if (x == WGALLOWEDIP_A_CIDR_MASK && xn >= 1) cidr = xd[0];
                            });
                            // ponytail: only single-address routes name a peer; a peer routing a whole subnet shows by key
                            if (!ip.empty() && cidr == (ip.find(':') == std::string::npos ? 32 : 128)) w.ips.push_back(ip);
                        });
                });
                if (w.key.empty()) return;
                if (auto [it, fresh] = seen.try_emplace(w.key, peers.size()); fresh) peers.push_back(w);
                else peers[it->second].ips.insert(peers[it->second].ips.end(), w.ips.begin(), w.ips.end());
            });
        });
    return true;
}

// Called once a second: endpoints roam and handshakes renew.
static void wg_refresh(App& a) {
    std::vector<WgPeer> ws;
    uint16_t port = 0;
    if (a.wgdev.empty() || !wg_dump(a, a.wgdev, ws, port)) return;
    if (port) wg::wg_port = port;
    bool outer = a.wgdev != a.iface;  // watching eth0: peers appear by their public endpoint
    for (auto& w : ws) {
        int idx = -1;
        if (auto k = a.peer_by_key.find(w.key); k != a.peer_by_key.end()) idx = k->second;
        for (auto& ip : w.ips)
            if (auto it = a.peer_of.find(ip); idx < 0 && it != a.peer_of.end()) idx = it->second;
        if (idx < 0) {
            std::string ip = w.ips.empty() ? "" : w.ips[0];
            a.peers.push_back({ip, ip.empty() ? w.key : ip});
            idx = int(a.peers.size() - 1);
        }
        a.peer_by_key[w.key] = idx;
        for (auto& ip : w.ips) a.peer_of[ip] = idx;
        if (outer && !w.endpoint_ip.empty()) a.peer_of[w.endpoint_ip] = idx;
        Peer& p = a.peers[size_t(idx)];
        p.wg = true, p.endpoint = w.endpoint, p.handshake = w.handshake;
    }
}

static void wg_init(App& a) {
    wg_open(a);
    std::vector<WgPeer> t;
    uint16_t port;
    for (const std::string& dev : {a.iface, std::string("wg0")})
        if (wg_dump(a, dev, t, port)) { a.wgdev = dev; break; }
    if (a.wgdev.empty() && a.nl_err == EPERM)
        a.note = "peer status needs CAP_NET_ADMIN:  sudo setcap cap_net_raw,cap_net_admin+ep $(command -v wgmon)";
    wg_refresh(a);
}

static Role peer_role(int i) { return i < 0 ? R_DIM : Role(R_PEER0 + i % 4); }

// Drop the oldest 10% once a table passes its cap.
template <class M> static void trim(M& m, size_t cap) {
    if (m.size() <= cap) return;
    std::vector<timespec> t;
    for (auto& kv : m) t.push_back(kv.second.last);
    auto nth = t.begin() + long(t.size() / 10);
    std::nth_element(t.begin(), nth, t.end(), older);
    for (auto it = m.begin(); it != m.end();) it = older(it->second.last, *nth) ? m.erase(it) : std::next(it);
}

static void track_flow(App& a, const Pkt& p, const std::string& pname) {
    const std::string &lip = p.up ? p.s.src : p.s.dst, &rip = p.up ? p.s.dst : p.s.src;
    uint16_t lp = p.up ? p.s.sport : p.s.dport, rp = p.up ? p.s.dport : p.s.sport;
    Flow& f = a.flows[str(p.s.ipproto) + "|" + lip + "|" + str(lp) + "|" + rip + "|" + str(rp)];
    bool changed = !f.pkts;
    if (!f.pkts) f.first = p.ts, f.peer = p.peer, f.proto = p.s.proto;
    if ((f.proto == "tcp" || f.proto == "udp") && p.s.proto != f.proto) f.proto = p.s.proto, changed = true;  // learn tls/dns/http
    if (p.remote != f.remote) f.remote = p.remote, changed = true;  // the name may arrive later than the first packet
    if (changed) f.hay = lower(pname + " " + f.proto + " " + f.remote);
    f.last = p.ts, f.pkts++;
    (p.up ? f.up : f.down) += p.len;
    if (p.s.ipproto == 6) {
        uint8_t fl = p.s.tcpflags;
        if ((fl & 0x12) == 0x02) f.syn = p.ts, f.state = "open";
        else if ((fl & 0x12) == 0x12 && f.rtt < 0 && f.syn.tv_sec) f.rtt = int(ms_between(f.syn, p.ts));
        if (fl & 0x04) f.state = "reset";
        else if ((fl & 0x01) && f.state != "reset") f.state = "closed";
    }
    trim(a.flows, FLOWS);
}

static void ingest(App& a, const uint8_t* d, size_t got, size_t len, timespec ts, bool outgoing) {
    Pkt p;
    p.seq = a.next_seq++;
    p.ts = ts;
    p.len = uint32_t(len);
    p.raw.assign(d, d + std::min(got, SNAP));
    p.s = summarize(d, got);
    for (auto& [ip, name] : p.s.learned) a.names[ip] = name;  // ponytail: unbounded map, fine for 2 peers

    int ps = peer_index(a, p.s.src), pd = peer_index(a, p.s.dst);
    p.up = ps >= 0 ? true : pd >= 0 ? false : !outgoing;
    p.peer = ps >= 0 ? ps : pd;
    if (p.peer >= 0) (p.up ? a.peers[p.peer].up : a.peers[p.peer].down) += len;

    const std::string& rip = p.up ? p.s.dst : p.s.src;
    auto n = a.names.find(rip);
    p.remote = n != a.names.end() ? n->second : rip.find(':') != std::string::npos && p.s.ports ? "[" + rip + "]" : rip;
    if (p.s.ports) p.remote += ":" + std::to_string(p.up ? p.s.dport : p.s.sport);
    if (!p.s.ok) p.remote = "";

    std::string pname = p.peer >= 0 ? a.peers[p.peer].name : "";

    // DNS answer time: match the response to its query by client address, port and id.
    if (p.s.dns) {
        bool q = p.s.dns == 1;
        std::string k = (q ? p.s.src + "|" + str(p.s.sport) : p.s.dst + "|" + str(p.s.dport)) + "|" + str(p.s.dns_id);
        if (q) {
            if (a.dns_pending.size() > 4096) a.dns_pending.clear();  // lost answers never pile up
            a.dns_pending[k] = ts;
        } else if (auto it = a.dns_pending.find(k); it != a.dns_pending.end()) {
            p.dns_ms = int(ms_between(it->second, ts));
            a.dns_pending.erase(it);
            p.s.info.push_back({"  " + str(p.dns_ms) + " ms", R_FAINT});
            if (p.peer >= 0) a.peers[p.peer].dns_ms += uint64_t(p.dns_ms), a.peers[p.peer].dns_n++;
        }
    }
    if (p.s.blocked) {
        Blocked& b = a.blocked[str(p.peer) + "|" + p.s.qname];
        if (!b.n) b.peer = p.peer, b.domain = p.s.qname, b.resolver = p.s.src, b.hay = lower(pname + " " + b.domain + " " + b.resolver);
        b.n++, b.last = ts;
    }
    if (p.s.ok) track_flow(a, p, pname);

    p.hay = lower(pname + " " + p.s.proto + " " + p.remote + " " + text(p.s.info) + " " + p.s.src + " " + p.s.dst);

    a.buf.push_back(std::move(p));
    if (a.buf.size() > RING) a.buf.pop_front();
    a.total++;
    if (!a.live) a.fresh++;
    trim(a.blocked, 2000);
}

// Read whatever is queued, bounded so the UI stays responsive under load.
static void drain(App& a, int fd, int budget, void (*each)(App&) = nullptr) {
    static uint8_t buf[65536];
    for (int i = 0; i < budget; i++) {
        sockaddr_ll sll{};
        socklen_t sl = sizeof sll;
        ssize_t n = recvfrom(fd, buf, sizeof buf, MSG_TRUNC, (sockaddr*)&sll, &sl);
        if (n < 0) break;  // EAGAIN: queue empty; other errors (iface down) are reported once and cleared
        timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ingest(a, buf, std::min<size_t>(size_t(n), sizeof buf), size_t(n), ts, sll.sll_pkttype == PACKET_OUTGOING);
        if (each) each(a);
    }
}

// ---------- rows ----------
static Line row(const App& a, const Pkt& p) {
    char t[64];
    tm tmv;
    localtime_r(&p.ts.tv_sec, &tmv);
    snprintf(t, sizeof t, "%02d:%02d:%02d.%03ld  ", tmv.tm_hour, tmv.tm_min, tmv.tm_sec, p.ts.tv_nsec / 1000000);
    Line l = {{t, R_DIM},
              {fit(p.peer >= 0 ? a.peers[p.peer].name : "?", 8) + "  ", peer_role(p.peer)},
              {std::string(p.up ? "↑" : "↓") + "  ", R_DIM},
              {fit(p.s.proto, 5) + "  "},
              {fit(p.remote, 28) + "  "},
              {fit(std::to_string(p.len), 5, true) + "  "}};
    l.insert(l.end(), p.s.info.begin(), p.s.info.end());
    return l;
}
static const Line kTitles = {{fit("time", 14) + fit("peer", 10) + "   " + fit("proto", 7) + fit("remote", 30) + fit("len", 5, true) + "  info", R_FAINT}};

static bool match(const App& a, int peer, const std::string& hay) {
    if (a.peer_filter >= 0 && peer != a.peer_filter) return false;
    for (size_t i = 0; i < a.filter.size();) {
        while (i < a.filter.size() && a.filter[i] == ' ') i++;
        size_t e = a.filter.find(' ', i);
        if (e == std::string::npos) e = a.filter.size();
        if (e > i && hay.find(a.filter.substr(i, e - i)) == std::string::npos) return false;
        i = e;
    }
    return true;
}

static std::vector<const Pkt*> visible(const App& a) {
    std::vector<const Pkt*> v;
    v.reserve(a.buf.size());
    for (auto& p : a.buf)
        if (match(a, p.peer, p.hay)) v.push_back(&p);
    return v;
}
static size_t index_of(const std::vector<const Pkt*>& v, uint64_t seq) {
    auto it = std::lower_bound(v.begin(), v.end(), seq, [](const Pkt* p, uint64_t s) { return p->seq < s; });
    return it == v.end() ? v.size() - 1 : size_t(it - v.begin());
}

// ---------- flows / blocked views ----------
struct Row { std::string key, jump; int peer; Line line; };

struct Col { const char* name; int w; bool right; int sort; };  // sort = index into kSorts, -1 = not sortable
static const std::vector<Col> kFlowCols = {{"last", 10, false, 0}, {"peer", 10, false, -1}, {"proto", 7, false, -1},
                                           {"remote", 28, false, -1}, {"pkts", 7, true, 2}, {"up", 9, true, 1},
                                           {"down", 9, true, 1}, {"dur", 7, true, 3}, {"rtt", 8, true, 4}, {"  state", 0, false, -1}};
static const std::vector<Col> kBlockCols = {{"last", 10, false, 0}, {"peer", 10, false, -1}, {"domain", 42, false, -1},
                                            {"times", 7, true, 1}, {"  resolver", 0, false, -1}};
static const std::vector<std::string> kSorts[3] = {{}, {"newest", "bytes", "packets", "duration", "rtt"}, {"newest", "times"}};

static const std::vector<Col>& cols(const App& a) { return a.view == V_FLOWS ? kFlowCols : kBlockCols; }
static Line col_titles(const App& a) {  // the sorted column is highlighted
    Line l;
    for (auto& c : cols(a))
        l.push_back({c.w ? fit(c.name, size_t(c.w), c.right) : c.name, c.sort == a.sort[a.view] ? R_LABEL : R_FAINT});
    return l;
}
static int col_at(const App& a, int x) {  // sort index of the column under screen x, or -1
    x -= 2;
    for (auto& c : cols(a)) {
        if (!c.w || x < c.w) return c.sort;
        x -= c.w;
    }
    return -1;
}

static std::vector<Row> agg_rows(const App& a) {
    std::vector<Row> rows;
    auto pname = [&](int i) { return i >= 0 ? a.peers[size_t(i)].name : "?"; };
    // Ascending, so the newest / biggest row sits at the bottom where the selection starts.
    auto sorted = [&](auto& m, auto rank) {
        std::vector<const std::pair<const std::string, std::decay_t<decltype(m.begin()->second)>>*> v;
        for (auto& kv : m)
            if (match(a, kv.second.peer, kv.second.hay)) v.push_back(&kv);
        std::sort(v.begin(), v.end(), [&](auto* x, auto* y) {
            int64_t rx = rank(x->second), ry = rank(y->second);
            return rx != ry ? rx < ry : older(x->second.last, y->second.last);
        });
        return v;
    };
    const int so = a.sort[a.view];
    auto flow_rank = [so](const Flow& f) -> int64_t {
        switch (so) {
        case 1: return int64_t(f.up + f.down);
        case 2: return int64_t(f.pkts);
        case 3: return ms_between(f.first, f.last);
        case 4: return f.rtt;
        }
        return 0;
    };
    auto block_rank = [so](const Blocked& b) -> int64_t { return so == 1 ? int64_t(b.n) : 0; };
    if (a.view == V_FLOWS)
        for (auto* kv : sorted(a.flows, flow_rank)) {
            const Flow& f = kv->second;
            rows.push_back({kv->first, f.remote, f.peer,
                            {{hms(f.last) + "  ", R_DIM},
                             {fit(pname(f.peer), 8) + "  ", peer_role(f.peer)},
                             {fit(f.proto, 5) + "  "},
                             {fit(f.remote, 26) + "  "},
                             {fit(commas(f.pkts), 7, true), R_DIM},
                             {fit("↑ " + human(f.up), 9, true)},
                             {fit("↓ " + human(f.down), 9, true)},
                             {fit(ago(ms_between(f.first, f.last) / 1000), 7, true), R_DIM},
                             {fit(f.rtt >= 0 ? str(f.rtt) + " ms" : "", 8, true) + "  ", R_DIM},
                             {f.state, f.state == "reset" ? R_WARN : R_DIM}}});
        }
    else
        for (auto* kv : sorted(a.blocked, block_rank)) {
            const Blocked& b = kv->second;
            rows.push_back({kv->first, b.domain, b.peer,
                            {{hms(b.last) + "  ", R_DIM},
                             {fit(pname(b.peer), 8) + "  ", peer_role(b.peer)},
                             {fit(b.domain, 40) + "  ", R_BAD},
                             {fit("×" + commas(b.n), 7, true) + "  "},
                             {b.resolver + (resolver(b.resolver).empty() ? "" : "  " + resolver(b.resolver)), R_DIM}}});
        }
    return rows;
}
static size_t agg_index(const App& a, const std::vector<Row>& rows) {
    for (size_t i = 0; !a.agg_sel.empty() && i < rows.size(); i++)
        if (rows[i].key == a.agg_sel) return i;
    return rows.size() - 1;  // follow the newest
}

// ---------- save ----------
// Classic pcap, nanosecond timestamps, raw IP link type: opens in Wireshark / tcpdump -r.
static std::string save_pcap(const App& a) {
    auto v = visible(a);
    if (v.empty()) return "nothing to save";
    char name[64];
    time_t now = time(nullptr);
    tm t;
    localtime_r(&now, &t);
    strftime(name, sizeof name, "wgmon-%Y%m%d-%H%M%S.pcap", &t);
    char cwd[4096];
    std::string dir = getcwd(cwd, sizeof cwd) ? cwd : ".";
    std::string path = dir + (dir.back() == '/' ? "" : "/") + name;
    FILE* f = fopen(path.c_str(), "wbx");
    if (!f) path = std::string("/tmp/") + name, f = fopen(path.c_str(), "wbx");
    if (!f) return std::string("save failed: ") + strerror(errno);
    struct { uint32_t magic = 0xa1b23c4d; uint16_t major = 2, minor = 4; int32_t zone = 0; uint32_t sigfigs = 0, snap = SNAP, link = 101; } hdr;
    fwrite(&hdr, sizeof hdr, 1, f);
    for (auto* p : v) {
        uint32_t r[4] = {uint32_t(p->ts.tv_sec), uint32_t(p->ts.tv_nsec), uint32_t(p->raw.size()), p->len};
        fwrite(r, sizeof r, 1, f);
        fwrite(p->raw.data(), 1, p->raw.size(), f);
    }
    bool ok = !ferror(f);
    if (fclose(f) != 0) ok = false;
    return ok ? "saved " + commas(v.size()) + " packets → " + path : "save failed: disk full?";
}

// ---------- terminal ----------
static bool g_color = false, g_256 = false;

static void init_colors() {
    if (!has_colors()) return;
    start_color();
    use_default_colors();
    g_color = true;
    g_256 = COLORS >= 256;
    //                 text dim  faint label bad  warn peer0 peer1 peer2 peer3
    short c256[] = {-1, 246, 243, 78, 203, 221, 75, 215, 141, 114};
    short c8[] = {-1, COLOR_WHITE, COLOR_WHITE, COLOR_GREEN, COLOR_RED, COLOR_YELLOW,
                  COLOR_BLUE, COLOR_MAGENTA, COLOR_CYAN, COLOR_GREEN};
    for (short i = 0; i < 10; i++) {
        init_pair(i + 1, g_256 ? c256[i] : c8[i], -1);
        init_pair(i + 17, g_256 ? c256[i] : c8[i], g_256 ? 236 : -1);  // selected row
    }
}

static attr_t attr(Role r, bool sel = false) {
    attr_t a = g_color ? COLOR_PAIR(r + 1 + (sel && g_256 ? 16 : 0)) : A_NORMAL;
    if (!g_256 && (r == R_DIM || r == R_FAINT)) a |= A_DIM;
    if (sel && !g_256) a |= A_REVERSE;
    return a;
}

static void put(int y, int x, const Line& l, int maxw, bool sel = false, attr_t extra = 0) {
    move(y, x);
    int used = 0;
    for (auto& g : l) {
        if (used >= maxw) break;
        int w = int(width(g.s));
        std::string s = used + w > maxw ? fit(g.s, size_t(maxw - used)) : g.s;
        attrset(attr(g.r, sel) | extra);
        addstr(s.c_str());
        used += std::min(w, maxw - used);
    }
    if (sel && used < maxw) {
        attrset(attr(R_TEXT, true));
        addstr(std::string(size_t(maxw - used), ' ').c_str());
    }
    attrset(A_NORMAL);
}

static void center(int y, int W, const std::string& msg) {
    put(y, std::max(2, (W - int(width(msg))) / 2), {{msg, R_DIM}}, W - 4);
}

// Bottom-aligned like a chat log: the newest row is always the last line, even when the list is short.
template <class F> static void draw_rows(App& a, int y0, int h, size_t n, size_t si, size_t ti, int W, F line) {
    const int shown = int(std::min(n - ti, size_t(h)));
    a.rows_y = y0 + h - shown, a.rows_n = shown, a.rows_ti = ti;
    for (int r = 0; r < shown; r++) {
        int y = y0 + h - shown + r;
        size_t i = ti + size_t(r);
        if (i == si) put(y, 0, {{"▎", R_LABEL}, {" "}}, 2, true);
        put(y, 2, line(i), W - 4, i == si);
    }
}

static void draw_packets(App& a, int list_y, int list_h, int D, int W) {
    auto vis = visible(a);
    put(2, 2, kTitles, W - 4);
    a.rows_n = 0;
    if (vis.empty()) {
        center(list_y + list_h / 2, W, a.buf.empty() ? "waiting for packets on " + a.iface + "…" : "no packets match");
        return;
    }
    size_t si = a.live ? vis.size() - 1 : index_of(vis, a.sel);
    size_t ti = a.live ? 0 : index_of(vis, a.top);
    if (a.live || si >= ti + size_t(list_h)) ti = si + 1 > size_t(list_h) ? si + 1 - size_t(list_h) : 0;
    if (si < ti) ti = si;
    ti = std::min(ti, vis.size() > size_t(list_h) ? vis.size() - size_t(list_h) : 0);  // no empty tail
    a.sel = vis[si]->seq;
    a.top = vis[ti]->seq;
    const Pkt* cur = vis[si];
    draw_rows(a, list_y, list_h, vis.size(), si, ti, W, [&](size_t i) { return row(a, *vis[i]); });

    if (!D) return;
    std::string rule;
    for (int i = 0; i < W - 4; i++) rule += "─";
    put(list_y + list_h, 2, {{rule, R_FAINT}}, W - 4);
    auto lines = detail(cur->raw.data(), cur->raw.size());
    if (cur->dns_ms >= 0) lines.push_back({{"       "}, {"answered in " + str(cur->dns_ms) + " ms (this VPS ↔ resolver)", R_DIM}});
    if (cur->len > cur->raw.size())
        lines.push_back({{"       "}, {"stored first " + commas(cur->raw.size()) + " of " + commas(cur->len) + " bytes", R_DIM}});
    if (a.explain) {
        lines.push_back({});
        auto ex = explain(cur->raw.data(), cur->raw.size());
        lines.insert(lines.end(), ex.begin(), ex.end());
    } else if (a.hex && int(lines.size()) + 2 < D) {
        lines.push_back({});
        auto hx = hexdump(cur->raw.data(), cur->raw.size(), size_t(D - 1) - lines.size());
        lines.insert(lines.end(), hx.begin(), hx.end());
    }
    for (int i = 0; i < D - 1 && size_t(i) < lines.size(); i++) put(list_y + list_h + 2 + i, 2, lines[size_t(i)], W - 4);
}

static void draw_agg(App& a, int list_y, int list_h, int W) {
    auto rows = agg_rows(a);
    put(2, 2, col_titles(a), W - 4);
    a.rows_n = 0;
    if (rows.empty()) {
        bool none = a.view == V_FLOWS ? a.flows.empty() : a.blocked.empty();
        center(list_y + list_h / 2, W, !none ? "nothing matches" : a.view == V_FLOWS ? "no connections yet…"
                                            : "nothing blocked yet (only a filtering resolver like 1.1.1.3 blocks)");
        return;
    }
    size_t si = agg_index(a, rows), h = size_t(list_h), ti = SIZE_MAX;
    for (size_t i = 0; !a.agg_sel.empty() && i < rows.size(); i++)
        if (rows[i].key == a.agg_top) ti = i;
    if (ti == SIZE_MAX || si >= ti + h) ti = si + 1 > h ? si + 1 - h : 0;
    if (si < ti) ti = si;
    ti = std::min(ti, rows.size() > h ? rows.size() - h : 0);
    a.agg_top = rows[ti].key;
    draw_rows(a, list_y, list_h, rows.size(), si, ti, W, [&](size_t i) { return rows[i].line; });
}

static void draw_help(int W, int H) {
    static const std::vector<std::pair<std::string, std::string>> kHelp = {
        {"← →  1 2 3", "switch view: packets · flows · blocked"},
        {"j k  ↑ ↓", "move"},
        {"d u  pgdn pgup", "page down / up"},
        {"g  n", "oldest / newest"},
        {"space", "pause / live (packets)"},
        {"/", "filter by text: domain, ip, port"},
        {"tab  shift-tab", "cycle peer"},
        {"esc", "clear filters, or back to the list"},
        {"", ""},
        {"enter", "show the row's packets (flows, blocked)"},
        {"s", "change sort (flows, blocked)"},
        {"e  x", "explain the packet · toggle hex"},
        {"w", "save the packets on screen to .pcap"},
        {"", ""},
        {"mouse", "wheel scrolls, click selects"},
        {"", "click a tab or a column title"},
        {"", "click the selected row to open it"},
        {"shift-drag", "select text while the mouse is on"},
        {"q", "quit"},
    };
    const int bw = std::min(W - 4, 62), bh = std::min(H - 2, int(kHelp.size()) + 4);
    const int x = (W - bw) / 2, y = (H - bh) / 2;
    std::string bar;
    for (int i = 0; i < bw - 2; i++) bar += "─";
    std::string blank(size_t(bw - 2), ' ');
    put(y, x, {{"╭" + bar + "╮", R_FAINT}}, bw);
    for (int i = 1; i < bh - 1; i++) put(y + i, x, {{"│", R_FAINT}, {blank}, {"│", R_FAINT}}, bw);
    put(y + bh - 1, x, {{"╰" + bar + "╯", R_FAINT}}, bw);
    put(y, x + 2, {{" keys ", R_TEXT}}, 6);
    for (int i = 0; i < bh - 4; i++)
        put(y + 2 + i, x + 3, {{fit(kHelp[size_t(i)].first, 16), R_LABEL}, {kHelp[size_t(i)].second, R_DIM}}, bw - 6);
    std::string close = " any key closes ";
    put(y + bh - 1, x + bw - 2 - int(width(close)), {{close, R_FAINT}}, int(width(close)));
}

static void draw(App& a) {
    erase();
    const int W = COLS, H = LINES;
    if (W < 60 || H < 8) {
        put(0, 0, {{"wgmon needs at least 60×8", R_DIM}}, W);
        refresh();
        return;
    }
    timespec now;
    clock_gettime(CLOCK_REALTIME, &now);

    // header
    Line left = {{"wgmon", R_TEXT}, {"  " WGMON_VERSION "  " + a.iface + "  ", R_DIM}};
    static const char* kTabs[] = {"packets", "flows", "blocked"};
    a.tab_x[0] = 7 + int(width(left[1].s));
    for (int v = 0; v < 3; v++) {
        left.push_back({std::string(kTabs[v]) + "  ", v != a.view ? R_FAINT : v == V_BLOCKED ? R_BAD : R_LABEL});
        a.tab_x[v + 1] = a.tab_x[v] + int(width(left.back().s));
    }
    if (a.view != V_PKTS) {}
    else if (a.live) left.push_back({"● live", R_LABEL});
    else {
        left.push_back({"‖ paused", R_WARN});
        if (a.fresh) left.push_back({"  +" + commas(a.fresh) + " newer ↓", R_DIM});
    }
    if (a.peer_filter >= 0) left.push_back({"  · " + a.peers[size_t(a.peer_filter)].name, peer_role(a.peer_filter)});
    if (a.drops) left.push_back({"  " + commas(a.drops) + " dropped", R_BAD});
    Line right;
    for (size_t i = 0; i < a.peers.size() && i < 4; i++) {
        right.push_back({a.peers[i].name, peer_role(int(i))});
        right.push_back({"  ↑ " + human(a.peers[i].up) + "  ↓ " + human(a.peers[i].down) + "   ", R_DIM});
    }
    bool filtered = a.peer_filter >= 0 || !a.filter.empty();
    std::string cnt = a.view == V_FLOWS ? commas(a.flows.size()) + " flows"
                    : a.view == V_BLOCKED ? commas(a.blocked.size()) + " domains"
                    : filtered ? commas(visible(a).size()) + " of " + commas(a.total) : commas(a.total) + " pkts";
    Line count = {{cnt, R_DIM}};
    if (width(left) + width(right) + width(count) + 7 > size_t(W)) right.clear();
    right.insert(right.end(), count.begin(), count.end());
    put(0, 2, {left[0]}, 5, false, A_BOLD);
    put(0, 7, Line(left.begin() + 1, left.end()), W - 9);
    put(0, W - 2 - int(width(right)), right, int(width(right)));

    // peer status: endpoint, handshake age, resolver speed
    Line st;
    for (size_t i = 0; i < a.peers.size() && i < 4; i++) {
        const Peer& p = a.peers[i];
        if (!p.wg && !p.dns_n) continue;
        st.push_back({p.name, peer_role(int(i))});
        if (p.wg) {
            st.push_back({"  " + (p.endpoint.empty() ? "no endpoint" : p.endpoint), R_DIM});
            int64_t age = now.tv_sec - p.handshake;
            if (!p.handshake) st.push_back({"  never connected", R_WARN});
            else if (age > 180) st.push_back({"  idle · handshake " + ago(age) + " ago", R_WARN});  // keys expire after 3 min
            else st.push_back({"  handshake " + ago(age) + " ago", R_DIM});
        }
        if (p.dns_n) st.push_back({"  dns " + str(p.dns_ms / p.dns_n) + " ms", R_DIM});
        st.push_back({"      "});
    }
    if (!a.note.empty()) st.push_back({a.note, R_FAINT});
    put(1, 2, st, W - 4);

    // layout: header, status, titles, list, rule, detail, footer
    const int list_y = 3, footer_y = H - 1;
    const int D = a.view == V_PKTS && H >= 18 ? std::clamp(H / 3, 7, 18) : 0;
    const int list_h = footer_y - list_y - (D ? D + 1 : 0);
    a.page = std::max(1, list_h);
    if (a.view == V_PKTS) draw_packets(a, list_y, list_h, D, W);
    else draw_agg(a, list_y, list_h, W);

    // footer
    auto hint = [](Line& l, const char* k, const std::string& d) {
        l.push_back({k, R_TEXT});
        l.push_back({" " + d + "   ", R_DIM});
    };
    Line h;
    if (a.typing) {
        hint(h, "enter", "apply");
        hint(h, "esc", "clear");
    } else if (a.view != V_PKTS) {
        hint(h, "j k", "move");
        if (!a.agg_sel.empty()) hint(h, "n", "newest");
        hint(h, "enter", "show packets");
        hint(h, "s", "sort: " + kSorts[a.view][size_t(a.sort[a.view])]);
        hint(h, "/", "filter");
        hint(h, "tab", "peer");
        hint(h, "← →", "view");
        hint(h, "?", "help");
        hint(h, "q", "quit");
    } else {
        hint(h, "j k", "move");
        if (a.live) hint(h, "space", "pause");
        else hint(h, "n", "newest");
        hint(h, "/", "filter");
        hint(h, "tab", "peer");
        hint(h, "← →", "view");
        if (a.back != V_PKTS) hint(h, "esc", a.back == V_FLOWS ? "flows" : "blocked");
        hint(h, "e", a.explain ? "hex" : "explain");
        hint(h, "w", "save");
        hint(h, "?", "help");
        hint(h, "q", "quit");
    }
    if (!a.msg.empty() && ms_between(a.msg_at, now) < 4000) put(footer_y, 2, {{a.msg, R_LABEL}}, W - 4);
    else if (a.typing || !a.filter.empty()) {
        Line f = {{"/ ", R_DIM}, {a.filter}};
        if (a.typing) f.push_back({"▏", R_LABEL});
        int hw = std::min(int(width(h)) - 3, W * 2 / 3);
        put(footer_y, 2, f, W - 6 - hw);
        put(footer_y, W - 2 - hw, h, hw);
    } else put(footer_y, 2, h, W - 4);
    if (a.help) draw_help(W, H);
    refresh();
}

static void move_sel(App& a, long d) {
    if (a.view != V_PKTS) {
        auto rows = agg_rows(a);
        if (rows.empty()) return;
        long i = std::clamp(long(agg_index(a, rows)) + d, 0L, long(rows.size()) - 1);
        a.agg_sel = size_t(i) + 1 == rows.size() ? "" : rows[size_t(i)].key;  // landing on the newest = follow again
        return;
    }
    auto v = visible(a);
    if (v.empty()) return;
    long si = long(a.live ? v.size() - 1 : index_of(v, a.sel));
    if (a.live) a.live = false, a.fresh = 0;
    a.sel = v[size_t(std::clamp(si + d, 0L, long(v.size()) - 1))]->seq;
}

static void set_view(App& a, View v) {
    a.view = v;
    a.agg_sel.clear();
    a.back = V_PKTS;
}

static void key(App& a, int ch);

static void mouse(App& a) {
    MEVENT e;
    if (getmouse(&e) != OK) return;
    if (e.bstate & BUTTON4_PRESSED) return move_sel(a, -3);
    if (e.bstate & BUTTON5_PRESSED) return move_sel(a, 3);
    if (!(e.bstate & (BUTTON1_PRESSED | BUTTON1_CLICKED))) return;
    if (e.y == 0) {
        for (int v = 0; v < 3; v++)
            if (e.x >= a.tab_x[v] && e.x < a.tab_x[v + 1]) set_view(a, View(v));
        return;
    }
    if (e.y == 2 && a.view != V_PKTS) {
        int so = col_at(a, e.x);
        if (so >= 0) a.sort[a.view] = so, a.agg_sel.clear();
        return;
    }
    if (e.y < a.rows_y || e.y >= a.rows_y + a.rows_n) return;
    size_t i = a.rows_ti + size_t(e.y - a.rows_y);
    if (a.view == V_PKTS) {
        auto v = visible(a);
        if (i < v.size()) a.sel = v[i]->seq, a.live = false, a.fresh = 0;
        return;
    }
    // Open on a click on the selected row, or a quick second click on the same line
    // (a live list can reorder between the two clicks).
    timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    bool dbl = e.y == a.click_y && ms_between(a.click_at, now) < 500;
    a.click_y = e.y, a.click_at = now;
    auto rows = agg_rows(a);
    if (i >= rows.size()) return;
    if (dbl || i == agg_index(a, rows)) { a.click_y = -1; return key(a, '\n'); }
    a.agg_sel = i + 1 == rows.size() ? "" : rows[i].key;
}

static void key(App& a, int ch) {
    if (ch == KEY_RESIZE) return;
    if (a.help) {  // any key or click closes help
        MEVENT e;
        if (ch == KEY_MOUSE && getmouse(&e) == OK && !(e.bstate & (BUTTON1_PRESSED | BUTTON1_CLICKED))) return;
        a.help = false;
        return;
    }
    if (ch == KEY_MOUSE) {
        if (!a.typing) mouse(a);
        else { MEVENT e; getmouse(&e); }
        return;
    }
    if (a.typing) {
        if (ch == 27) a.filter.clear(), a.typing = false;
        else if (ch == '\n' || ch == KEY_ENTER) a.typing = false;
        else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) { if (!a.filter.empty()) a.filter.pop_back(); }
        else if (ch == KEY_UP) move_sel(a, -1);
        else if (ch == KEY_DOWN) move_sel(a, 1);
        else if (ch >= 32 && ch < 127 && a.filter.size() < 60) a.filter += char(tolower(ch));
        return;
    }
    switch (ch) {
    case 'q': a.quit = true; break;
    case 'j': case KEY_DOWN: move_sel(a, 1); break;
    case 'k': case KEY_UP: move_sel(a, -1); break;
    case KEY_NPAGE: case 'd': move_sel(a, a.page); break;
    case KEY_PPAGE: case 'u': move_sel(a, -a.page); break;
    case KEY_HOME: move_sel(a, -LONG_MAX / 2); break;  // oldest
    case 'g': move_sel(a, -LONG_MAX / 2); break;
    case 'G': case 'n': case KEY_END: a.live = true, a.fresh = 0, a.agg_sel.clear(); break;  // newest
    case ' ':
        if (a.view == V_PKTS) a.live = !a.live, a.fresh = 0;
        break;
    case '/': a.typing = true; break;
    case 27:
        if (a.back != V_PKTS) {  // undo the enter jump: back to the list, same row
            View b = a.back;
            std::string s = a.back_sel;
            a.filter.clear(), a.peer_filter = -1;
            set_view(a, b);
            a.agg_sel = s;
        } else if (a.view != V_PKTS) set_view(a, V_PKTS);
        else a.filter.clear(), a.peer_filter = -1;
        break;
    case '\t': a.peer_filter = a.peer_filter + 1 >= int(a.peers.size()) ? -1 : a.peer_filter + 1; break;
    case KEY_BTAB: a.peer_filter = (a.peer_filter < 0 ? int(a.peers.size()) : a.peer_filter) - 1; break;
    case '1': set_view(a, V_PKTS); break;
    case '2': case 'f': set_view(a, a.view == V_FLOWS ? V_PKTS : V_FLOWS); break;
    case '3': case 'b': set_view(a, a.view == V_BLOCKED ? V_PKTS : V_BLOCKED); break;
    case 'l': case KEY_RIGHT: set_view(a, View((a.view + 1) % 3)); break;
    case 'h': case KEY_LEFT: set_view(a, View((a.view + 2) % 3)); break;
    case 'x': a.hex = !a.hex, a.explain = false; break;
    case 'e': a.explain = !a.explain; break;
    case '?': a.help = true; break;
    case 's':
        if (a.view != V_PKTS) a.sort[a.view] = (a.sort[a.view] + 1) % int(kSorts[a.view].size()), a.agg_sel.clear();
        break;
    case '\n': case KEY_ENTER:
        if (a.view != V_PKTS) {  // jump to that flow's / domain's packets
            auto rows = agg_rows(a);
            if (rows.empty()) break;
            const Row& r = rows[agg_index(a, rows)];
            View from = a.view;
            std::string key = r.key;
            set_view(a, V_PKTS);
            a.back = from, a.back_sel = key;
            a.filter = lower(r.jump);
            a.peer_filter = r.peer;
            a.live = true, a.fresh = 0;
        }
        break;
    case 'w':
        a.msg = save_pcap(a);
        clock_gettime(CLOCK_REALTIME, &a.msg_at);
        break;
    }
}

static long ms_since(const timespec& t) {
    timespec n;
    clock_gettime(CLOCK_MONOTONIC, &n);
    return (n.tv_sec - t.tv_sec) * 1000 + (n.tv_nsec - t.tv_nsec) / 1000000;
}

// Once a second: kernel drop counter and WireGuard peer status.
static void tick(App& a, int fd) {
    tpacket_stats st{};
    socklen_t l = sizeof st;
    if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &st, &l) == 0) a.drops += st.tp_drops;  // reading resets it
    wg_refresh(a);
}

static void run_tui(App& a, int fd) {
    setlocale(LC_ALL, "");
    if (MB_CUR_MAX == 1) setlocale(LC_CTYPE, "C.UTF-8");
    // A static binary doesn't know the host's terminfo layout; point it at the usual places.
    setenv("TERMINFO_DIRS", "/etc/terminfo:/lib/terminfo:/usr/share/terminfo:/usr/lib/terminfo", 0);
    set_escdelay(25);
    if (!initscr()) die("cannot open terminal");
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    curs_set(0);
    mousemask(BUTTON1_PRESSED | BUTTON4_PRESSED | BUTTON5_PRESSED, nullptr);
    mouseinterval(0);  // no click-detection delay
    init_colors();

    bool dirty = true;
    timespec last{}, last_tick{};
    while (!g_stop && !a.quit) {
        pollfd f[2] = {{fd, POLLIN, 0}, {0, POLLIN, 0}};
        poll(f, 2, dirty ? 33 : 1000);
        if (f[0].revents) drain(a, fd, 4000), dirty = true;
        for (int ch; (ch = getch()) != ERR;) key(a, ch), dirty = true;
        if (ms_since(last_tick) >= 1000) {
            tick(a, fd);
            clock_gettime(CLOCK_MONOTONIC, &last_tick);
            dirty = true;  // handshake ages, message timeout
        }
        if (dirty && ms_since(last) >= 33) {
            draw(a);
            clock_gettime(CLOCK_MONOTONIC, &last);
            dirty = false;
        }
    }
    endwin();
}

static void run_plain(App& a, int fd) {
    auto print = [](App& a) {
        puts(text(row(a, a.buf.back())).c_str());
        a.buf.pop_back();  // plain mode keeps no history
    };
    while (!g_stop) {
        pollfd f = {fd, POLLIN, 0};
        if (poll(&f, 1, 1000) > 0) drain(a, fd, 4000, print), fflush(stdout);
    }
}

int main(int argc, char** argv) {
    App a;
    bool plain = false;
    for (int i = 1; i < argc; i++) {
        std::string s = argv[i];
        if (s == "-v" || s == "--version") return puts("wgmon " WGMON_VERSION), 0;
        if (s == "-h" || s == "--help") {
            puts("usage: wgmon [-i IFACE] [--peer IP=NAME ...] [--plain]\n"
                 "  -i IFACE        interface to watch (default wg0)\n"
                 "  --peer IP=NAME  name a peer by its tunnel address (repeatable)\n"
                 "                  -i eth0 shows the encrypted WireGuard messages themselves\n"
                 "  --plain         print one line per packet instead of the TUI\n"
                 "  -v, --version");
            return 0;
        }
        if ((s == "-i" || s == "--iface") && i + 1 < argc) a.iface = argv[++i];
        else if (s == "--plain") plain = true;
        else if (s == "--peer" && i + 1 < argc) {
            std::string v = argv[++i];
            size_t eq = v.find('=');
            std::string ip = v.substr(0, eq);
            unsigned char tmp[16];
            if (eq == std::string::npos || eq + 1 == v.size() ||
                (inet_pton(AF_INET, ip.c_str(), tmp) != 1 && inet_pton(AF_INET6, ip.c_str(), tmp) != 1))
                die("--peer wants IP=NAME, got '" + v + "'");
            a.peer_of[ip] = int(a.peers.size());
            a.peers.push_back({ip, v.substr(eq + 1)});
        } else die("unknown option '" + s + "' (see --help)");
    }

    int fd = open_capture(a.iface);
    load_subnet(a);
    wg_init(a);
    struct sigaction sa{};
    sa.sa_handler = [](int) { g_stop = 1; };
    for (int sig : {SIGINT, SIGTERM, SIGHUP}) sigaction(sig, &sa, nullptr);

    if (plain) run_plain(a, fd);
    else run_tui(a, fd);
    close(fd);
}
