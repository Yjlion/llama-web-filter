# llama-web-filter

A policy-based, TLS-intercepting web-filtering proxy for a household or small
office network, whose content classification is done by a **local multimodal
edge LLM** (Gemma 4 E2B by default, served by a bundled `llama-server`).

It is a fork of [gowebfilter](https://github.com/Yjlion/gowebfilter) that
replaces the embedded statistical classifiers (Bayesian text scorer,
MobileNet NSFW detector) with the LLM, and adds:

- adult text and image detection with block / blur actions, decided by the
  model and cached so repeat visits cost nothing;
- ad removal (EasyList network and cosmetic filtering, with the model
  classifying unknown ad hosts);
- policy rules written in natural language, for example
  *"Blur all adult images for 10.10.10.10 from 10am to 5pm"* or
  *"Block ads on lan, except site www.cnn.com"*, compiled by the model into
  structured rules you confirm before saving;
- a single static binary for Windows, Linux and macOS that downloads the
  prebuilt llama.cpp runtime and model on first run.

## Status

Work in progress. See `docs/` for architecture notes as milestones land.

## Quick start (development)

```sh
CGO_ENABLED=0 go build -o webfilter ./cmd/webfilter
cp config/settings.example.json config/settings.json
./webfilter run --settings config/settings.json
```

The management UI is served at `http://127.0.0.1:8000`; clients proxy
through `127.0.0.1:8080`.

## Verify

```sh
CGO_ENABLED=0 go build ./... && go vet ./... && go test ./...
```
