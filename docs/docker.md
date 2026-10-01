# Running WebFilter in a container

The binary is static — `CGO_ENABLED=0`, pure-Go SQLite, pure-Go NSFW
classifiers with embedded models — so the image is a small Alpine layer with
one executable in it. No ONNX runtime, no Python, no model downloads.

The [`Dockerfile`](../Dockerfile) and [`docker-compose.yml`](../docker-compose.yml)
at the repo root are examples meant to be read and adapted, not a
turnkey product. This page explains what they do and what to do after
`up -d`.

## Quick start

```bash
docker compose up -d
docker compose logs -f webfilter
```

That gives you:

| Port | What |
|---|---|
| `8080` | HTTP(S) forward proxy — point browsers and devices here |
| `127.0.0.1:8000` | Management UI + REST API |

SOCKS5 is configured but not published: the bootstrap settings bind it to
`socks5@127.0.0.1:1080`, which is loopback *inside* the container, so
mapping the port would only get you connection refused. If you want it,
change that entry to `socks5@0.0.0.0:1080` under Settings → Listen
addresses, restart, and uncomment the `1080:1080` mapping in
`docker-compose.yml`.

Then, in order:

1. **Install the CA.** Fetch it from
   `http://127.0.0.1:8000/api/ca-cert` (that path is deliberately
   unauthenticated — a device that cannot yet trust the proxy has to be able
   to get the certificate) or copy `certs/ca.crt` out of the volume.
   Install it on every client that will go through the proxy; without it,
   HTTPS interception fails closed and browsers show certificate errors.
2. **Set a management password.** Settings → Authentication. Management auth
   is **off** by default, which is why compose publishes port 8000 on
   loopback only.
3. **Point a client at the proxy** (`http://<host>:8080`, or the PAC file at
   `http://<host>:8000/proxy.pac`) and confirm traffic appears under Logs.

## Per-client policies need host networking

**Read this before deploying to filter more than one machine.** Policy
selection is by *source address*, tiered MAC → exact IP → CIDR →
catch-all. Docker's default bridge networking breaks that:

- With `userland-proxy` enabled (the daemon default), traffic to a
  published port is relayed by `docker-proxy`, which **rewrites the source
  address to the bridge gateway**. Every client on your LAN arrives as
  `172.x.0.1`, so they all match the same policy and per-client filtering
  silently stops working. You can see this in the request log: `client_ip`
  is the same for everyone.
- **MAC-tier matching cannot work at all** in bridge mode. It resolves the
  client's hardware address from the neighbour table, which requires being
  on the same layer-2 segment as the client. A bridged container is not.

So if you are filtering a single machine, or every client should get the
same policy, bridge networking is fine. Otherwise use host networking:

```yaml
services:
  webfilter:
    network_mode: host    # drop the `ports:` block; binds directly on the host
```

Setting `"userland-proxy": false` in `/etc/docker/daemon.json` makes Docker
use plain DNAT, which preserves the real source IP for *remote* clients (but
not for connections originating on the Docker host itself). That restores
the IP and CIDR tiers; it does not restore the MAC tier.

This is the same constraint gateway mode documents for a different reason:
anything that SNATs in front of the engine destroys per-client policy.

## Why there is nothing to configure first

`webfilter run` bootstraps its own state. On first start with an empty
volume, `config.BootstrapRuntimeFiles` writes
`/data/config/settings.json` — the proxy and management binds on `0.0.0.0`,
and **absolute** directory paths rooted at `/data` — then creates the
default policy:

```
/data
├── config/settings.json
├── policies/default.json
├── certs/           # CA + key, generated on first start
├── categories/      # empty until you populate it (see below)
└── logs/webfilter.db
```

The image deliberately does **not** ship `config/settings.example.json`.
That file binds `127.0.0.1` and uses working-directory-relative paths
(`./certs`), so a container seeded from it would publish ports that serve
nothing. Letting the bootstrap path generate the file is what makes the
zero-config start work.

Back up the `webfilter-data` volume and you have backed up the whole
instance. **Do not point two containers at one volume** — `logs/webfilter.db`
is single-writer by design.

## Category blocklists

`categories/` starts empty, and the policy editor shows its "no categories
installed yet" hint until you populate it. On desktop/server that is a CLI
step (the per-category HTTP download exists only on the Android build):

```bash
docker compose exec webfilter webfilter categories update \
  --settings /data/config/settings.json
```

That pulls the IPFire squidGuard tarball into `/data/categories`. Add
`--keep porn,gambling,malware` to install a subset instead of everything;
the full set is large. (IPFire's categories are `ads`, `dating`, `doh`,
`gambling`, `games`, `malware`, `phishing`, `piracy`, `porn`, `shopping`,
`social`, `streaming` and `violence`.) Re-run it to refresh. Lists above 100k domains are
stored as sorted hashes rather than string maps, so memory stays reasonable.

## Configuration changes

Edit settings through the UI, or edit `/data/config/settings.json` directly
and restart the container. Policies hot-reload; settings need a restart:

```bash
docker compose restart webfilter
```

`SIGTERM` is handled, so `docker stop` / `docker compose down` is a clean
shutdown rather than a kill. `stop_grace_period` is set to 20s to leave room
for teardown.

## Moving the ports

The published ports and `settings.json` have to agree — Docker only
forwards, it does not rewrite. If you change `proxy_listen` or `mgmt_port`,
change the `ports:` entries to match. A listener bound to `127.0.0.1` inside
the container is unreachable from outside it, so keep the container-side
binds on `0.0.0.0` and restrict exposure with the *host* side of the port
mapping (as compose already does for the management UI).

## What needs elevation, and what does not

A plain filtering proxy container needs **no** added capabilities. The two
modes that do are commented out in `docker-compose.yml` rather than enabled
by default:

- **TUN capture (`tun2socks`)** filters the container's *own* traffic, which
  is rarely the point of running this in a container. It needs `NET_ADMIN`,
  `NET_RAW` and `/dev/net/tun`, plus the external `tun2socks` binary. One
  trap worth knowing: `webfilter tun2socks download` installs that binary
  next to the *executable* (`internal/tun2socks/binary.go` resolves it
  against `os.Executable`, not the working directory), so it lands at
  `/usr/local/bin/bin/` inside the image and is lost on the next rebuild
  unless you mount a volume there.
- **Gateway mode** transparently filters *other* machines on the LAN, which
  means being their default gateway. It rewrites host nftables (`table ip
  webfilter`) and two sysctls, so it needs `network_mode: host` plus
  `NET_ADMIN`/`NET_RAW` — published ports do nothing in that mode. Note that
  Docker's own `FORWARD` chain has `policy drop`, which affects forwarded
  traffic the gateway does not intercept; see
  [`packaging/README.md`](../packaging/README.md).

If you want to filter other machines without gateway mode, just give them
the proxy address (or the PAC URL) explicitly — that is the no-privilege
path, and per-client policies work the same way.

## Building the image directly

```bash
docker build -t webfilter:dev .

# stamped like a release build:
docker build -t webfilter:v1.2.3 \
  --build-arg VERSION=v1.2.3 \
  --build-arg COMMIT="$(git rev-parse --short HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" .
```

The container runs as a non-root user (uid 1000). `/data` is created and
chowned in the image, so a **named** volume inherits that ownership; if you
bind-mount a host directory instead, chown it to uid 1000 first or the first
start cannot write its settings file.
