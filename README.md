# wgmon

Watch the decrypted packets crossing your WireGuard interface, live, in the terminal: peers, DNS lookups,
TLS hostnames, blocked domains, and a layered breakdown + hex dump of any packet.

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

`j`/`k` move · `space` pause/live · `/` filter · `tab` peer · `x` hex · `q` quit · `--plain` for one line per packet.

## Develop

```sh
make test       # parser tests (ASan/UBSan)
make lab        # Docker lab: vps + 2 peers, nothing touches your host network
docker compose -f lab/compose.yml exec vps wgmon
make lab-down
```

Versions are CalVer (`YYYY.0M.MICRO`). Pushing a tag builds and publishes a release.
Design notes: [docs/design/wgmon.md](docs/design/wgmon.md).
