# wgmon

Watch the decrypted packets crossing your WireGuard interface, live, in the terminal: peers, DNS lookups,
TLS hostnames, blocked domains, connections, and a layered breakdown, hex dump or plain-English explanation
of any packet.

## Install / update

On the WireGuard server (Linux, amd64 or arm64):

```sh
curl -fsSL https://raw.githubusercontent.com/sinhaparth5/wgmon/master/install.sh | sh
```

Run the same command again to update. Pin a version with `WGMON_VERSION=2026.11.0`.

## Use

```sh
wgmon --peer 10.8.0.2=phone --peer 10.8.0.3=laptop
```

| key | |
|---|---|
| `←` `→` · `1` `2` `3` | switch view: packets · flows · blocked (tabs in the header) |
| `j` `k` · `g` `n` | move · jump to oldest / newest |
| `space` | pause / live |
| `/` · `tab` `shift-tab` · `esc` | filter text · cycle peer · clear (or go back to the list you came from) |
| `f` | flows: one row per connection, bytes each way, duration, handshake rtt, state |
| `b` | blocked: domains your filtering resolver (1.1.1.3) answered with `0.0.0.0` |
| `enter` | (in flows / blocked) show that connection's or domain's packets; `esc` returns to the same row |
| `s` | (in flows / blocked) sort by newest, bytes, packets, duration or rtt; or click a column title |
| `e` · `x` | explain the packet in plain English · toggle hex |
| `w` | save the packets on screen to a `.pcap` (Wireshark / `tcpdump -r`) |
| `?` | all keys |
| mouse | wheel scrolls, click selects a row, tab or peer, click the selected row to open it (shift-drag still selects text) |

Under the tabs, one row per peer: a health dot (green: handshake in the last 3 min, yellow: idle), endpoint,
traffic and how fast its DNS resolver answers. Click a peer to show only its traffic. It needs `cap_net_admin`, which `install.sh` grants; a "dropped" counter appears if the kernel ever
loses packets.

`wgmon -i eth0` watches the outside of the tunnel instead: the encrypted WireGuard handshakes, keepalives and
data packets (`/wg` to hide your own SSH session). `--plain` prints one line per packet.

## Develop

```sh
make test       # parser tests (ASan/UBSan)
make lab        # Docker lab: vps + 2 peers, nothing touches your host network
docker compose -f lab/compose.yml exec vps wgmon
make lab-down
```

Versions are CalVer (`YYYY.0M.MICRO`). Pushing a tag builds and publishes a release.
Design notes: [docs/design/wgmon.md](docs/design/wgmon.md).

## License

MIT, see [LICENSE](LICENSE).
