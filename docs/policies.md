# Policies and rules

Two layers decide what happens to a request.

**Policies** (`policies/*.json`) are per-client configurations matched by
MAC, exact IP, CIDR or catch-all, inherited from gowebfilter: URL allow and
block lists, categories, SafeSearch, YouTube channel filtering, DNS-over-HTTPS
blocking, MITM control, the text and image classifiers and ad blocking. Edit
them on the **Policies** page.

**Rules** (`config/rules.json`) are sentences. Each one is matched by
client, time and site and overlaid on the client's policy for that request.
They are the quick way to say what you want, and the way to express
time-of-day and per-device exceptions.

## Writing rules

On the **Rules** page, type a sentence and press *Understand*. The local
model turns it into a structured rule under a fixed schema, the page shows a
plain-English summary rendered from that structure, and you confirm before it
is saved. Examples:

| Sentence | Result |
|---|---|
| Blur all adult images for ip address 10.10.10.10 from 10am to 5pm | adult images → blur, for 10.10.10.10, 10:00–17:00 |
| Block ads on lan, except site www.cnn.com | ads → block, for every LAN device, not on www.cnn.com |
| Block adult content for the kids tablet after 9pm | adult pages → block, for the device named kids-tablet, 21:00–23:59 |
| Block facebook.com and tiktok.com for 192.168.1.0/24 on weekdays | sites → block, Mon–Fri |
| Enforce safesearch for everyone | SafeSearch → on, for every LAN device |
| Block the internet for aa:bb:cc:dd:ee:ff between 22:00 and 06:00 | all web access → block, overnight |

If the model is not running, a simple keyword parser handles sentences of
these shapes and says so in a warning. Device names come from the **Device
names** box on the same page (`kids-tablet = 10.0.0.7, aa:bb:cc:dd:ee:ff`).

`webfilter rules add "Block ads on lan"` does the same from the command line
(`--dry-run` only shows the rule; `--yes` saves without asking).

## Rule structure

```json
{
  "id": "r_7a1c0e2d9b44",
  "enabled": true,
  "text": "Blur all adult images for ip address 10.10.10.10 from 10am to 5pm",
  "match": {
    "sources": ["10.10.10.10"],
    "time": { "start": "10:00", "end": "17:00", "days": [] },
    "sites": { "include": [], "exclude": [] }
  },
  "target": "adult_images",
  "action": "blur"
}
```

| Field | Values |
|---|---|
| `match.sources` | IPs, CIDRs, MACs, device names, `lan` (private ranges), `all`; empty = everyone |
| `match.policy` | restrict to clients whose policy has this name |
| `match.time` | `start`/`end` as HH:MM (may cross midnight), `days` as `mon`…`sun` (empty = daily) |
| `match.sites` | `include` (only on these sites) and `exclude` (not on these); domains, `*.wildcards` or URLs with paths |
| `target` | `adult_images`, `adult_text`, `ads`, `site`, `category`, `safesearch`, `youtube`, `internet` |
| `action` | `block`, `allow`, and for adult images also `blur` and `checkerboard` |
| `value` | operands for `site` (hostnames), `category` (names), `youtube` (channels) |

Rules are applied in creation order; a later rule overrides an earlier one
for the same target. The **What applies right now?** box on the Rules page
shows the result for a given client and URL at this moment.

## Classifier settings in a policy

```json
"text_classifier": { "enabled": true, "threshold": 0.8, "on_timeout": "allow", "on_unavailable": "allow", "budget_ms": 0,
                      "exclude": [], "include_only": [] },
"image_classifier": { "enabled": true, "action": "blur", "threshold": 0.4, "min_dimension": 100,
                      "on_timeout": "blur", "on_unavailable": "allow", "budget_ms": 0, "prefetch": true,
                      "exclude": [], "include_only": [] },
"adblock":          { "enabled": true, "cosmetic": true, "classify_unknown_hosts": true, "exclude": [], "include_only": [] }
```

* `threshold` is compared with the model's adult score (0–1); the model's
  explicit *adult* flag also counts.
* `on_timeout` is what the browser gets when the verdict is not back within
  the budget on first sight: `allow` or `block` for pages; `allow`, `blur`,
  `checkerboard` or `block` for images. The verdict is cached either way.
* `on_unavailable` applies when no model can answer at all.
* `prefetch` scores a page's images before the browser asks for them.
* `adblock.cosmetic` injects element-hiding CSS; `classify_unknown_hosts`
  asks the model about third-party hosts the lists do not know when they
  look like ad or tracking servers.

## Ad blocking

Ad and tracker requests are matched against EasyList and EasyPrivacy. A
snapshot is built into the binary; **Settings → Ad blocking → Update** or
`webfilter adblock update` downloads the current lists into `data/adblock/`.
Blocked sub-resources get an empty response of the right type; navigating to
an ad host shows the block page. Blocked ad requests are counted in
`/metrics` (`webfilter_blocks_total{component="adblock"}`) and appear in the
request log, but are not written to the block log.

## Decisions

The **Decisions** page lists every cached verdict (images, pages, learned
sites, hosts) with its score, source and how often it was used. Mark any of
them clean or adult, add a site or host override, or clear the model's
verdicts. Manual overrides are never overwritten by the model.
