# Installing llama-web-filter

llama-web-filter is a single static binary. It downloads two things on first
run: a prebuilt [llama.cpp](https://github.com/ggml-org/llama.cpp) server for
your platform (about 16 MB on CPU, more for GPU builds) and a model in GGUF
format (about 3 GB for the default Gemma 4 E2B). Nothing else is installed.

## Requirements

| | Minimum | Comfortable |
|---|---|---|
| RAM | 6 GB free (default model) | 8 GB+ |
| CPU | x86-64 with AVX2, or 64-bit ARM | 8 cores; an NVIDIA or Vulkan-capable GPU makes verdicts several times faster |
| Disk | 4 GB in the data directory | |
| OS | Windows 10/11, macOS 12+, Linux (glibc 2.31+, e.g. Ubuntu 20.04, Debian 11) | |

## 1. Download

Grab the archive for your platform from the Releases page and unpack it
anywhere, for example `C:\webfilter`, `~/webfilter` or `/opt/webfilter`.

| Platform | Archive |
|---|---|
| Windows x64 / ARM64 | `webfilter-<version>-windows-amd64.zip` / `-arm64.zip` |
| macOS Apple Silicon / Intel | `webfilter-<version>-darwin-arm64.tar.gz` / `-amd64.tar.gz` |
| Linux x64 / ARM64 | `webfilter-<version>-linux-amd64.tar.gz` / `-arm64.tar.gz` |

Or build from source with Go 1.26+:

```sh
CGO_ENABLED=0 go build -o webfilter ./cmd/webfilter
```

## 2. Set up

```sh
./webfilter setup
```

The wizard creates `config/settings.json` and `policies/default.json` next to
the binary, lets you choose a model, and downloads the runtime and model into
`data/llm/`. It detects an NVIDIA (CUDA) or Vulkan GPU and picks the matching
llama.cpp build; `--yes` accepts the defaults, `--model qwen3.5-2b` picks a
model, `--skip-download` only writes the config.

The same thing is available later as `webfilter llm download` and from the
**LLM** page of the management UI.

## 3. Run

```sh
./webfilter run
```

| Address | What |
|---|---|
| `http://127.0.0.1:8000` | Management UI and API |
| `127.0.0.1:8080` | HTTP/HTTPS forward proxy |
| `127.0.0.1:1080` | SOCKS5 proxy |

To serve other devices on the LAN, set `proxy_listen` and `mgmt_host` to
`0.0.0.0` in Settings (or in `config/settings.json`) and restart.

## 4. Trust the CA and point devices at the proxy

The proxy decrypts HTTPS to inspect pages and images, so each client must
trust its certificate authority. Download it from **Settings → Certificates**
(or `http://<proxy>:8000/api/ca-cert`) and install it as a trusted root on
every device. Then set the device's proxy to the filter, or hand out the PAC
file at `http://<proxy>:8000/proxy.pac`.

Sites listed under a policy's **MITM Control → exclude** (banking, by default
`chase.com` in the example policy) are tunnelled without inspection.

## 5. Turn on filtering

Nothing is filtered until a policy says so. The quickest way is the
**Assistant** page: type a request such as *Block adult content and ads for everyone*,
check the proposed changes and apply them. See [policies.md](policies.md).

## Running as a service

**Linux (systemd)** — create `/etc/systemd/system/webfilter.service`:

```ini
[Unit]
Description=llama-web-filter
After=network-online.target

[Service]
ExecStart=/opt/webfilter/webfilter run --settings /opt/webfilter/config/settings.json
WorkingDirectory=/opt/webfilter
Restart=on-failure
User=webfilter

[Install]
WantedBy=multi-user.target
```

**Windows** — `webfilter service install` registers a Windows service that
runs `webfilter run`; `service uninstall` removes it.

**macOS** — use a `launchd` plist running the same `run` command, or start it
from a terminal.

**Docker** — see [docker.md](docker.md).

## Updating

Replace the binary. Settings, policies, rules, certificates, logs and the
downloaded model are all outside it. When a release pins a newer llama.cpp
build, `webfilter llm download` fetches it; the model is reused.

## Where things live

```
config/settings.json     global settings
config/rules.json        named devices (and sentence rules from earlier versions)
policies/*.json          per-client policies
certs/                   the CA and issued certificates
logs/webfilter.db        request and block log (SQLite)
data/llm/                llama.cpp runtime, models, llama-server.log, decisions.db
data/adblock/            downloaded filter lists (empty = built-in snapshot)
categories/              site-category blocklists (optional)
```
