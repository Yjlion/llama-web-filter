# Architecture

```
client ──► listeners (HTTP proxy, SOCKS5, transparent, ICAP)
              │   TLS is terminated with a locally issued leaf certificate
              ▼
   addon pipeline  (internal/app/engine.go, order is load-bearing)
   ManagementAccess → ProxyAuthGate → PolicyRouter → RuleEvaluator → MitmControl
   → UrlFilter → AdBlocker → QuicBlocker → DohFilter → SafeSearch → YouTubeFilter
   → TextClassifier → ImageClassifier → RequestLogger
              │
              ▼
   internal/classify/verdict        decision cache, job queue, budgets, site learning
              │
              ▼
   internal/llm                     llama-server supervisor, model catalog, chat client
```

## Packages

| Package | Role |
|---|---|
| `cmd/webfilter` | CLI: `run`, `setup`, `proxy`, `mgmt`, `llm`, `rules`, `adblock`, `categories`, `service` |
| `internal/proxy` | listeners, MITM, upstream fetching, the `FlowContext` every addon sees |
| `internal/proxy/addons` | one file per pipeline stage |
| `internal/proxy/state` | live settings, policies, rules and filter lists with hot reload |
| `internal/models` | settings and policy schema |
| `internal/policy/rules` | rule model, matching and overlay onto a policy |
| `internal/policy/nlp` | sentence → rule compiler (model + parser fallback) |
| `internal/classify/verdict` | the decision layer in front of the model |
| `internal/classify/{imageprep,phash,textextract}` | image downscaling, perceptual hashing, HTML text extraction |
| `internal/llm/runtime` | llama.cpp release download and process supervision |
| `internal/llm/catalog` | model catalog and Hugging Face downloads |
| `internal/llm/client` | OpenAI-compatible chat client with JSON-schema verdicts |
| `internal/adblock` | EasyList parser, matcher and cosmetic filtering |
| `internal/mgmtapi` + `ui/` | management REST API and the embedded web UI |

## Data flow for one page

1. `PolicyRouter` matches the client to a policy; `RuleEvaluator` overlays
   the rules that apply now and replaces `fc.Policy` with the effective one.
2. `UrlFilter` and `AdBlocker` decide on the URL alone (lists, cache, and
   for unknown ad-like hosts the model with a 500 ms budget).
3. The response is fetched identity-encoded and buffered.
4. `AdBlocker` injects cosmetic CSS; `TextClassifier` extracts the page's
   text, asks the verdict service (cache → model within the budget) and
   blocks or passes; it also hands the page's image URLs to the prefetcher.
5. `ImageClassifier` does the same per image (and per inline data URI),
   replacing adult images with a blurred, checkerboard or blank stand-in.
6. `RequestLogger` records the final action.

## Why the LLM is behind a cache and a queue

A 2–4B multimodal model on a CPU answers in roughly a second. Web pages
reference dozens of images. Two things make this workable: every verdict is
cached by content (exact hash, perceptual hash for images, text hash for
pages, registrable domain for learned sites), so anything seen once is free
forever; and the proxy never waits longer than a budget, applying a
policy-chosen fallback instead while the model finishes in the background.
Requests for the same content share one model call, and a bounded queue
refuses work rather than building a backlog nobody will wait for.

## Hot reload

`policies/*.json`, `config/settings.json` (the hot subset) and
`config/rules.json` are watched; filter lists are reloaded after an update.
The llama.cpp runtime and model are only restarted on request (LLM page,
`webfilter llm`), because loading a model takes seconds.
