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
#include <linux/if_packet.h>
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

struct Peer { std::string ip, name; uint64_t up = 0, down = 0; };

struct Pkt {
    uint64_t seq;
    timespec ts;
    uint32_t len;
    std::vector<uint8_t> raw;
    int peer;  // index into App::peers, -1 = unknown
    bool up;   // peer -> internet
    Summary s;
    std::string remote, hay;
};

struct App {
    std::string iface = "wg0";
    std::vector<Peer> peers;
    std::unordered_map<std::string, int> peer_of;
    uint32_t net = 0, mask = 0, self = 0;               // interface IPv4 subnet, to auto-detect peers
    std::unordered_map<std::string, std::string> names;  // ip -> hostname, from DNS answers / SNI / Host
    std::deque<Pkt> buf;
    uint64_t next_seq = 1, total = 0;
    // view state
    bool live = true, hex = true, typing = false, quit = false;
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
static std::string lower(std::string s) { for (auto& c : s) c = char(tolower((unsigned char)c)); return s; }

// ---------- capture ----------
static int open_capture(const std::string& ifname) {
    int fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) die(errno == EPERM ? "need root or CAP_NET_RAW (sudo setcap cap_net_raw+ep wgmon)" : strerror(errno));
    unsigned idx = if_nametoindex(ifname.c_str());
    if (!idx) die("no interface " + ifname);
    sockaddr_ll sa{};
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = int(idx);
    if (bind(fd, (sockaddr*)&sa, sizeof sa) < 0) die("bind " + ifname + ": " + strerror(errno));
    return fd;
}

static void load_subnet(App& a) {
    ifaddrs* ifs;
    if (getifaddrs(&ifs) != 0) return;
    for (ifaddrs* i = ifs; i; i = i->ifa_next)
        if (i->ifa_addr && i->ifa_netmask && i->ifa_addr->sa_family == AF_INET && a.iface == i->ifa_name) {
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

static Role peer_role(int i) { return i < 0 ? R_DIM : Role(R_PEER0 + i % 4); }

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
    p.hay = lower(pname + " " + p.s.proto + " " + p.remote + " " + text(p.s.info) + " " + p.s.src + " " + p.s.dst);

    a.buf.push_back(std::move(p));
    if (a.buf.size() > RING) a.buf.pop_front();
    a.total++;
    if (!a.live) a.fresh++;
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

static bool match(const App& a, const Pkt& p) {
    if (a.peer_filter >= 0 && p.peer != a.peer_filter) return false;
    for (size_t i = 0; i < a.filter.size();) {
        while (i < a.filter.size() && a.filter[i] == ' ') i++;
        size_t e = a.filter.find(' ', i);
        if (e == std::string::npos) e = a.filter.size();
        if (e > i && p.hay.find(a.filter.substr(i, e - i)) == std::string::npos) return false;
        i = e;
    }
    return true;
}

static std::vector<const Pkt*> visible(const App& a) {
    std::vector<const Pkt*> v;
    v.reserve(a.buf.size());
    for (auto& p : a.buf)
        if (match(a, p)) v.push_back(&p);
    return v;
}
static size_t index_of(const std::vector<const Pkt*>& v, uint64_t seq) {
    auto it = std::lower_bound(v.begin(), v.end(), seq, [](const Pkt* p, uint64_t s) { return p->seq < s; });
    return it == v.end() ? v.size() - 1 : size_t(it - v.begin());
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

static void draw(App& a) {
    erase();
    const int W = COLS, H = LINES;
    if (W < 60 || H < 8) {
        put(0, 0, {{"wgmon needs at least 60×8", R_DIM}}, W);
        refresh();
        return;
    }
    auto vis = visible(a);

    // header
    Line left = {{"wgmon", R_TEXT}, {"  " WGMON_VERSION "  " + a.iface + "  ", R_DIM}};
    if (a.live) left.push_back({"● live", R_LABEL});
    else {
        left.push_back({"‖ paused", R_WARN});
        if (a.fresh) left.push_back({"  +" + commas(a.fresh) + " newer ↓", R_DIM});
    }
    if (a.peer_filter >= 0) left.push_back({"  · " + a.peers[a.peer_filter].name, peer_role(a.peer_filter)});
    Line right;
    for (size_t i = 0; i < a.peers.size() && i < 4; i++) {
        right.push_back({a.peers[i].name, peer_role(int(i))});
        right.push_back({"  ↑ " + human(a.peers[i].up) + "  ↓ " + human(a.peers[i].down) + "   ", R_DIM});
    }
    bool filtered = a.peer_filter >= 0 || !a.filter.empty();
    Line count = {{filtered ? commas(vis.size()) + " of " + commas(a.total) : commas(a.total) + " pkts", R_DIM}};
    if (width(left) + width(right) + width(count) + 7 > size_t(W)) right.clear();
    right.insert(right.end(), count.begin(), count.end());
    put(0, 2, {left[0]}, 5, false, A_BOLD);
    put(0, 7, Line(left.begin() + 1, left.end()), W - 9);
    put(0, W - 2 - int(width(right)), right, int(width(right)));

    // layout: header, gap, titles, list, rule, detail, footer
    const int D = H >= 18 ? std::clamp(H / 3, 7, 18) : 0;
    const int list_y = 3, footer_y = H - 1;
    const int list_h = footer_y - list_y - (D ? D + 1 : 0);
    a.page = std::max(1, list_h);
    put(2, 2, kTitles, W - 4);

    const Pkt* cur = nullptr;
    if (vis.empty()) {
        std::string msg = a.buf.empty() ? "waiting for packets on " + a.iface + "…" : "no packets match";
        put(list_y + list_h / 2, std::max(2, (W - int(width(msg))) / 2), {{msg, R_DIM}}, W - 4);
    } else {
        size_t si = a.live ? vis.size() - 1 : index_of(vis, a.sel);
        size_t ti = a.live ? 0 : index_of(vis, a.top);
        if (a.live || si >= ti + size_t(list_h)) ti = si + 1 > size_t(list_h) ? si + 1 - size_t(list_h) : 0;
        if (si < ti) ti = si;
        ti = std::min(ti, vis.size() > size_t(list_h) ? vis.size() - size_t(list_h) : 0);  // no empty tail
        a.sel = vis[si]->seq;
        a.top = vis[ti]->seq;
        cur = vis[si];
        // Bottom-align like a chat log: newest is always the bottom row, even when the list is short.
        const int shown = int(std::min(vis.size() - ti, size_t(list_h)));
        for (int r = 0; r < shown; r++) {
            int y = list_h - shown + r;
            size_t i = ti + size_t(r);
            if (i == si) {
                put(list_y + y, 0, {{"▎", R_LABEL}, {" "}}, 2, true);
                put(list_y + y, 2, row(a, *vis[i]), W - 4, true);
            } else put(list_y + y, 2, row(a, *vis[i]), W - 4);
        }
    }

    // detail
    if (D && cur) {
        std::string rule;
        for (int i = 0; i < W - 4; i++) rule += "─";
        put(list_y + list_h, 2, {{rule, R_FAINT}}, W - 4);
        auto lines = detail(cur->raw.data(), cur->raw.size());
        if (cur->len > cur->raw.size())
            lines.push_back({{"       "}, {"stored first " + commas(cur->raw.size()) + " of " + commas(cur->len) + " bytes", R_DIM}});
        if (a.hex && int(lines.size()) + 2 < D) {
            lines.push_back({});
            auto hx = hexdump(cur->raw.data(), cur->raw.size(), size_t(D - 1) - lines.size());
            lines.insert(lines.end(), hx.begin(), hx.end());
        }
        for (int i = 0; i < D - 1 && size_t(i) < lines.size(); i++) put(list_y + list_h + 2 + i, 2, lines[size_t(i)], W - 4);
    }

    // footer
    auto hint = [](Line& l, const char* k, const std::string& d) {
        l.push_back({k, R_TEXT});
        l.push_back({" " + d + "   ", R_DIM});
    };
    if (a.typing) {
        put(footer_y, 2, {{"/ ", R_DIM}, {a.filter}, {"▏", R_LABEL}}, W - 30);
        Line h;
        hint(h, "enter", "apply");
        hint(h, "esc", "clear");
        put(footer_y, W - 2 - int(width(h)) + 3, h, int(width(h)));
    } else {
        Line h;
        hint(h, "j k", "move");
        if (a.live) hint(h, "space", "pause");
        else hint(h, "n", "newest");
        hint(h, "/", "filter");
        hint(h, "tab", "peer");
        hint(h, "x", "hex");
        hint(h, "q", "quit");
        if (a.filter.empty()) put(footer_y, 2, h, W - 4);
        else {
            put(footer_y, 2, {{"/ ", R_DIM}, {a.filter}}, W / 3);
            put(footer_y, W - 2 - int(width(h)) + 3, h, int(width(h)));
        }
    }
    refresh();
}

static void move_sel(App& a, long d) {
    auto v = visible(a);
    if (v.empty()) return;
    long si = long(a.live ? v.size() - 1 : index_of(v, a.sel));
    if (a.live) a.live = false, a.fresh = 0;
    a.sel = v[size_t(std::clamp(si + d, 0L, long(v.size()) - 1))]->seq;
}

static void key(App& a, int ch) {
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
    case 'G': case 'n': case KEY_END: a.live = true, a.fresh = 0; break;  // newest
    case ' ':
        a.live = !a.live;
        a.fresh = 0;
        break;
    case '/': a.typing = true; break;
    case 27: a.filter.clear(); break;
    case '\t': a.peer_filter = a.peer_filter + 1 >= int(a.peers.size()) ? -1 : a.peer_filter + 1; break;
    case 'x': a.hex = !a.hex; break;
    }
}

static long ms_since(const timespec& t) {
    timespec n;
    clock_gettime(CLOCK_MONOTONIC, &n);
    return (n.tv_sec - t.tv_sec) * 1000 + (n.tv_nsec - t.tv_nsec) / 1000000;
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
    init_colors();

    bool dirty = true;
    timespec last{};
    while (!g_stop && !a.quit) {
        pollfd f[2] = {{fd, POLLIN, 0}, {0, POLLIN, 0}};
        poll(f, 2, dirty ? 33 : 1000);
        if (f[0].revents) drain(a, fd, 4000), dirty = true;
        for (int ch; (ch = getch()) != ERR;) key(a, ch), dirty = true;
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
    struct sigaction sa{};
    sa.sa_handler = [](int) { g_stop = 1; };
    for (int sig : {SIGINT, SIGTERM, SIGHUP}) sigaction(sig, &sa, nullptr);

    if (plain) run_plain(a, fd);
    else run_tui(a, fd);
    close(fd);
}
