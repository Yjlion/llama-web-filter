# llama-web-filter

A policy-based, TLS-intercepting web-filtering proxy for a household or small
office, whose content decisions are made by a **local multimodal edge LLM**
(Gemma 4 E2B by default, served by a bundled [llama.cpp](https://github.com/ggml-org/llama.cpp)).
Nothing leaves your network.

It is a fork of [gowebfilter](https://github.com/Yjlion/gowebfilter) that
replaces the embedded statistical classifiers with the model, and adds:

- **Adult text, images and video**, judged by the model: block pages, blur
  or blank images, refuse videos judged by their poster, YouTube thumbnail or
  (with ffmpeg) decoded keyframes. Every verdict is cached by content, so a
  picture is only ever judged once; near-duplicates and whole sites are
  learned.
- **Ad and tracker removal** with EasyList/EasyPrivacy (snapshot built in,
  updatable), cosmetic hiding, and the model classifying hosts the lists miss.
- **Rules in plain language** — *Blur all adult images for 10.10.10.10 from
  10am to 5pm*, *Block ads on lan, except site www.cnn.com* — compiled by the
  model into structured rules you confirm before saving, with time windows,
  device names and per-site exceptions.
- **Real-time** operation: a decision cache, a deduplicating job queue, per
  request wait budgets with policy-chosen fallbacks, image downscaling and
  speculative pre-scoring keep browsing responsive on CPU-only machines.
- **One static binary** for Windows, Linux and macOS that downloads the
  prebuilt llama.cpp runtime (CPU, CUDA, Vulkan or Metal) and the model on
  first run.

Everything gowebfilter had is still there: per-client policies (MAC, IP,
CIDR), URL and category lists, SafeSearch, YouTube channel filtering, DoH and
QUIC blocking, MITM control, SOCKS and transparent listeners, ICAP for Squid,
a management UI with logs and analytics, PAC distribution, Prometheus metrics.

## Quick start

```sh
./webfilter setup        # creates config, picks a model, downloads runtime + model
./webfilter run          # proxy on :8080 / :1080, management UI on http://127.0.0.1:8000
```

Install the CA certificate from **Settings → Certificates** on your devices,
point them at the proxy (or use `/proxy.pac`), then open **Rules** and type
what you want. Full steps in [docs/install.md](docs/install.md).

## Documentation

- [Installing](docs/install.md) — download, setup, running as a service, where files live
- [The local model](docs/llm.md) — runtime, models, how classification and caching work, tuning
- [Policies and rules](docs/policies.md) — writing rules, the rule schema, classifier and ad-block settings
- [Architecture](docs/architecture.md) — pipeline and packages
- [Docker](docs/docker.md), [ICAP with Squid](docs/icap.md), [Metrics](docs/metrics.md)

## Command line

```
webfilter run            proxy + management UI in one process
webfilter setup          first-run wizard
webfilter llm ...        status | models | download | remove | serve | probe
webfilter rules ...      list | add "<sentence>" | remove
webfilter adblock ...    status | update
webfilter categories update
webfilter proxy / mgmt   run the two halves separately
```

## Building and testing

```sh
CGO_ENABLED=0 go build ./... && go vet ./... && CGO_ENABLED=0 go test ./...
```

Go 1.26 or newer. Tests use fake model servers; nothing is downloaded.

## Status

Functional but young. Model downloads resolve file names from Hugging Face
at download time, so the catalog may need adjusting as repositories change;
`webfilter llm status` and the LLM page show what happened. Video
classification works from posters, thumbnails and (optionally) ffmpeg
keyframes; HLS/DASH segment streams are judged by their poster only.

## License

MIT.
