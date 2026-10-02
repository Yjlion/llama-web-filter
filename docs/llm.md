# The local model

Every content decision in llama-web-filter is made by a local multimodal
language model served by [llama.cpp](https://github.com/ggml-org/llama.cpp):
whether a page is adult, whether an image is explicit, whether an unknown
host serves ads, what kind of site a host is (shopping, news, social media,
banking, …), and what you ask for on the Assistant page. Nothing
is sent to any external service.

## Runtime

`webfilter` downloads a prebuilt `llama-server` from the llama.cpp releases
(the tag is pinned in `internal/llm/runtime/platform.go`), unpacks it under
`data/llm/runtime/`, and runs it as a child process on a loopback port. It
is health-checked and restarted with backoff if it dies; its output goes to
`data/llm/llama-server.log` (shown on the LLM page).

Acceleration is detected automatically:

| Setting `llm.accel` | Build |
|---|---|
| `auto` (default) | NVIDIA driver present → CUDA; Vulkan loader present → Vulkan; otherwise CPU. macOS always uses the Metal build. |
| `cpu`, `cuda`, `vulkan` | force that build |

If a GPU build fails to download, the CPU build is used. If it downloads
but fails to start (driver too old, for example), set `llm.accel` to `cpu`
on the Settings page and restart.

To use a server you already run (another llama-server, or anything that
speaks the OpenAI chat API with image parts), set `llm.external_url`, e.g.
`http://127.0.0.1:8081`. Nothing is downloaded or spawned then.

## Models

| id | Model | Vision | Size | Notes |
|---|---|---|---|---|
| `gemma-4-e2b` | Gemma 4 E2B instruct | yes | ~2.9 GB | Default. Good balance on CPU. |
| `gemma-4-e4b` | Gemma 4 E4B instruct | yes | ~5 GB | More accurate, about twice the compute. |
| `qwen3.5-2b` / `qwen3.5-4b` | Qwen3.5 | yes | 1.8 / 3.2 GB | Strong vision. |
| `qwen3-vl-2b` | Qwen3-VL 2B | yes | ~1.7 GB | Very good image descriptions. |

Models are fetched from Hugging Face (`HF_ENDPOINT` and `HF_TOKEN` are
honoured for mirrors and gated repositories). The exact GGUF file is chosen
at download time from the repository's contents by quantization preference
(Q4_K_M first), and verified against the SHA-256 the Hub publishes. Switch
models on the Settings page, then download and restart from the LLM page.

## How requests are classified

```
request ──► decision cache (SQLite + in-memory LRU)  ──hit──► act
               │ miss
               ▼
            prefilters: tiny images, very short pages ─────► allow
               │
               ▼
            job queue (deduplicated by content hash, prioritised)
               │
               ▼  wait at most the budget
            llama-server  ──verdict──► cache ──► act
                                        │
             budget elapsed ────────────┴──► policy on_timeout action; verdict still cached
```

* **Verdicts are one-word answers.** The model is asked a yes/no question
  (is this image explicit? is this page adult? is this host an ad server?)
  and answers in a single token; the score is the probability it gave
  "yes", read from llama-server's logprobs. A site's category is the bare
  slug, two or three tokens. Generating a JSON object instead takes 30–100
  tokens, which on a small CPU is 0.2–0.5 s each. A server that returns no
  logprobs is read from its plain answer, and one that answers neither yes
  nor no is asked again with the older JSON prompt.
* **Images** are keyed by exact hash and by a perceptual hash, so the same
  picture at another size or encoding is answered from cache. They are
  downscaled to `llm.max_image_px` (384 px) before the model sees them.
* **Pages** are keyed by a hash of the extracted text (title, description,
  headings, first 3 KB of visible text). The model is shown the title and
  the first 1000 characters, since prompt tokens cost about 30 ms each on a
  small CPU.
* **Sites** are learned: after three adult verdicts on one registrable
  domain the whole site is treated as adult without further model calls.
* **Site categories** are keyed by registrable domain (`www.amazon.co.uk`
  and `smile.amazon.co.uk` share `amazon.co.uk`). Installed domain lists
  answer first; the model is asked only for sites they do not know, from
  the hostname alone on the first navigation and again with the page title
  when that first answer was unsure. Only navigations wait for it
  (`llm.budget.category_ms`, 1500 ms); sub-resources and tunnelled hosts are
  judged from what is already known.
* **Prefetch**: when a page passes, the images it references are scored in
  the background so the browser's image requests hit a warm cache.
* **Budgets** (`llm.budget`, milliseconds; per-policy `budget_ms` overrides)
  bound how long a request waits: 1500 ms for images and 2000 ms for pages
  by default. On timeout the policy's `on_timeout` applies (`blur` for
  images, `allow` for pages by default); the model keeps working and the
  verdict lands in the cache for the next load.
* **The assistant** waits up to `llm.budget.compile_ms` (180 s) for its
  answer, which is a few hundred tokens: about 15 s on a GPU and a minute
  or more on a small CPU.
* **Unavailable** (model down, text-only model asked about an image, queue
  full): the policy's `on_unavailable` applies, `allow` by default.

All of this is visible on the **Decisions** page, where any verdict can be
overridden, and in `/metrics` (`webfilter_llm_*`, `webfilter_verdict_*`).

## Tuning

| Setting | Effect |
|---|---|
| `llm.parallel_slots` | concurrent model calls (llama-server `-np`). 0 (default) picks 2 on a CPU build and 4 on a GPU. On a CPU, extra slots share the same cores, so each verdict gets slower; two stop a long assistant reply from holding up every verdict. |
| `llm.threads` | CPU threads; 0 lets llama-server choose. |
| `llm.context_size` | per-slot context (llama-server gets this × `parallel_slots`); 4096 is enough for the prompts used. |
| `llm.max_image_px` | image downscale target; smaller is faster, 256 is still usable. |
| `llm.image_max_tokens` | cap on the tokens the vision encoder makes of one image (llama-server `--image-max-tokens`). 0 (default) uses 70 on a CPU build and the model's own default on a GPU. |
| `llm.extra_args` | extra llama-server flags, for example `["--flash-attn", "on"]`. |

Rough CPU numbers with Gemma 4 E2B Q4_0 on 3 server cores (no GPU), new
content each time: a site category takes about 1 s, a host about 1 s, a page
6–10 s and an image 7–9 s. Most of that is processing the prompt and the
image, not generating the answer. Before verdicts were one-word answers the
same machine took 2.5–20 s, 5–10 s, 26–31 s and 7–25 s. When a slot has to
re-read a kind of prompt it no longer holds, that verdict pays a few extra
seconds once. 8 modern cores are roughly three times faster, and a
mid-range GPU answers in a few hundred milliseconds. A cache hit takes
microseconds.

## Command line

```
webfilter llm status      runtime/model/download state
webfilter llm models      the catalog
webfilter llm download    fetch the runtime and the configured (or named) model
webfilter llm remove ID   delete an installed model
webfilter llm serve       run llama-server in the foreground (debugging)
webfilter llm probe       show which llama.cpp build this machine would use
```
