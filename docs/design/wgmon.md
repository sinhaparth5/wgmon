# wgmon — design

A single static binary that runs on the VPS and shows, live, the decrypted packets crossing `wg0`.
It is for one user to understand their own traffic. It is not an IDS, not a logger.

## Requirements

**Functional**
- Live list of packets on a WireGuard interface: time, peer, direction, protocol, remote, length, summary.
- Select a packet → layered breakdown (IP → TCP/UDP/ICMP → DNS/TLS/HTTP) and hex dump.
- Names instead of IPs: learned from DNS answers, TLS SNI and HTTP `Host`.
- Spot DNS answers blocked by a filtering resolver (1.1.1.3 returns `0.0.0.0`).
- Filter by text and by peer; pause to inspect.
- Flows (per connection) and blocked-domain views; plain-English explanation per packet; save to `.pcap`.
- Peer status (endpoint, last handshake) and DNS answer time per peer; kernel drop counter.
- `-i eth0`: decode the WireGuard messages themselves (handshake init/response, cookie, data, keepalive).

**Non-functional**
- One static x86_64 binary, no runtime dependencies on the VPS. `scp` and run.
- Keep up with a home VPN (2 peers, bursts of ~10k pkt/s) without dropping the UI below ~30 fps.
- Safe on hostile input: every parser is bounds-checked and fuzzed by truncation under ASan/UBSan.
- Versioned with CalVer `YYYY.0M.MICRO` from git tags.

**Out of scope (for now)**: history across runs, alerting, web UI, multiple interfaces at once, TLS decryption,
QUIC SNI (needs AES/HKDF just to read one field).

## Scale (back of the envelope)

| | |
|---|---|
| Peers | 2 |
| Typical rate | 10–500 pkt/s; streaming peaks ~10k pkt/s |
| Memory | 10,000 packets × ≤4 KB = ≤40 MB worst case, ~3 MB typical (most packets are small) |
| CPU | Parsing is a few hundred ns per packet; redraw capped at 30 fps and scans ≤10k rows |

The numbers say: one thread, one process, no database.

## Architecture

```
            ┌──────────────────── VPS ────────────────────┐
 phone ─┐   │ eth0 ── udp/51820 ── kernel WireGuard ── wg0 │──► internet
 laptop ┘   │                                   │          │
            │               AF_PACKET (SOCK_DGRAM, wg0)    │
            │                                   ▼          │
            │   wgmon: poll(socket, stdin)                 │
            │     ├─ summarize()  → ring buffer (10k)      │
            │     ├─ names map    ← DNS / SNI / Host       │
            │     └─ draw() ≤30fps (ncurses)               │
            └──────────────────────────────────────────────┘
```

- `src/parse.hpp` — pure decoding, no I/O, no ncurses; unit-tested in `src/test.cpp`.
- `src/main.cpp` — capture socket, ring buffer, peer mapping, TUI, CLI.
- `lab/` — Docker lab: `vps`, `phone` (DNS 1.1.1.3), `laptop` (DNS 1.1.1.1), each in its own network namespace.

## Decisions

| Decision | Solves | Worsens | Change it when… |
|---|---|---|---|
| Capture on `wg0`, not `eth0` | See decrypted inner packets with real IPs/ports | Can't see the WireGuard handshake/outer UDP | You want to study the tunnel itself → add `-i eth0` mode with a WireGuard-message decoder |
| Raw `AF_PACKET` socket, no libpcap/BPF | Zero deps; you see exactly what the kernel hands over | No in-kernel filtering: every packet crosses to userspace | Sustained rate > ~50k pkt/s or CPU > 20% → attach a classic BPF filter or `PACKET_MMAP` ring |
| Single thread, `poll()` on socket + stdin | No locks, no races; trivially debuggable | Slow redraw delays reading packets (kernel buffer absorbs it) | The header shows "dropped" even with the 4 MB `SO_RCVBUF` → a capture thread or `PACKET_MMAP` ring |
| In-memory ring of 10k packets, 4 KB snap | Bounded memory; scroll back and inspect | History is lost on exit / after 10k | You want to reopen a session → write `.pcap` (Wireshark-readable) |
| Names learned from DNS/SNI/Host | `youtube.com:443` instead of `142.250.x.x` | Wrong after IP reuse; blind to DoH/DoT and ECH | Clients move to DoH/ECH → run a resolver on the VPS and point peers' `DNS =` at it |
| Peers from the kernel over generic netlink (AllowedIPs, endpoint, handshake), else the tunnel subnet, or `--peer IP=NAME` | Zero-config, IPv6 too, and works on eth0 (peers matched by endpoint) | Needs `cap_net_admin`; a peer routing a whole subnet is named by key | You run wgmon somewhere `cap_net_admin` is unacceptable → the subnet fallback still works |
| Flows / blocked tables keyed by 5-tuple / domain, oldest 10% evicted past 5k | Connection view without a second capture pass | O(n) sort per redraw of those views | Flows view lags (> ~50k flows) → keep an ordered index |
| `.pcap` written from the ring on `w` | Hand any slice to Wireshark; no always-on disk writes | Only the last 10k packets | You want long captures → `--write FILE` streaming mode |
| ncurses, static (musl) | Works over any SSH session, no runtime deps | Terminfo must exist on the VPS (it does on every distro) | Never; if UI grows panes/tabs, still fine |
| Docker lab with namespaced peers | Test everything without touching the host's WiFi or the real VPS | Doesn't reproduce real phone behaviour (DoH, Private DNS) | Before each release, also run `--plain` on the real VPS for a minute |

## Failure modes

| Failure | Effect | Handling |
|---|---|---|
| Not root / no `CAP_NET_RAW` | Can't open socket | Clear error with the `setcap` command |
| No `CAP_NET_ADMIN` | No endpoint / handshake status | Status line shows the `setcap` command; everything else works |
| Kernel buffer overflows | Lost packets | 4 MB `SO_RCVBUF`; `PACKET_STATISTICS` drops shown in the header |
| `wg0` missing / goes down | No packets | Error at start; if it disappears later the UI stays up showing nothing (restart wgmon) |
| Malformed or truncated packet | — | Every read bounds-checked; truncation-fuzzed under ASan in `make test` |
| Packet flood | UI lag | Per-iteration read budget (4000), 30 fps redraw cap, kernel buffer absorbs bursts |
| Ctrl-C / SIGTERM / SSH drop (SIGHUP) | — | Signal flag → clean `endwin()`; terminal restored |
| Static binary can't find terminfo | TUI won't start | `TERMINFO_DIRS` defaulted to the usual distro paths; `--plain` needs none |

## Releasing (CalVer)

```
git tag 2026.11.0 && git push origin 2026.11.0   # CI: test, build amd64+arm64, publish GitHub Release
```
On the VPS, install and update are the same command (`install.sh`): it picks the latest release, verifies
`SHA256SUMS`, swaps the binary atomically (fine while wgmon runs) and re-applies `cap_net_raw,cap_net_admin`.
```
curl -fsSL https://raw.githubusercontent.com/sinhaparth5/wgmon/master/install.sh | sh
```
Next release in the same month → `2026.11.1`; first release next month → `2026.12.0`.

## Weakest point

Hostnames come from watching plaintext DNS and the TLS SNI. A phone using Private DNS / DoH plus a browser using
ECH hides both, and the remote column falls back to bare IPs. The fix is not in wgmon: run `unbound` on the VPS
and set `DNS = 10.8.0.1` in the peer configs, which makes every lookup visible on `wg0` again.
