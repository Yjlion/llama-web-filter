# Policies, the assistant and site categories

**Policies** (`policies/*.json`) are per-client configurations matched by
MAC, exact IP, CIDR or catch-all, inherited from gowebfilter: URL allow and
block lists, site categories, SafeSearch, YouTube channel filtering,
DNS-over-HTTPS blocking, MITM control, the text, image and video classifiers
and ad blocking. A policy with a schedule applies only inside its time
windows and, while active, takes priority over an unscheduled policy for
the same devices. Edit policies on the **Policies** page, or ask the
assistant.

## The assistant

On the **Assistant** page, tell the local model what you want, or ask it
for advice. It answers in plain language and proposes changes to the
policies; you tick the ones you want and press *Apply selected*. Nothing
changes until you do, and every change is checked against the current
policies first. Examples:

| Request | Proposed changes |
|---|---|
| Block shopping and social media for the kids tablet on school nights | new policy for kids-tablet, Sun–Thu 19:00–23:59, blocking shopping and social media sites |
| What would you recommend for a 10 year old? | advice, plus changes such as blocking adult, gambling and dating sites and turning on SafeSearch |
| Blur adult images for everyone and block gambling sites | default policy: blur adult images; block gambling sites |
| Block the internet for 10.0.0.7 between 22:00 and 06:00 | new overnight policy for 10.0.0.7 that blocks all web access |
| Always allow khanacademy.org for the kids policy | kids: khanacademy.org on the allow list |

Each proposed change shows what it does, and *What changes in each policy*
shows every setting before and after. A change the filter cannot make (an
unknown device, a category that does not exist) is shown greyed out with
the reason; a website or device the model added that you never mentioned is
flagged so you can untick it. The assistant needs the model to be running.

Device names come from the **Device names** box on the same page
(`kids-tablet = 10.0.0.7, aa:bb:cc:dd:ee:ff`), so you can say "the kids
tablet".

From the command line: `webfilter assistant "Block gambling for everyone"`
shows the reply and the changes and asks before applying (`--yes` applies
without asking). It talks to `llm.external_url`, `llm.port`, or `--llm-url`.

The changes the assistant can make are:

| Change | Effect |
|---|---|
| `create_policy` | a new policy for some devices, optionally scheduled, copied from `default` |
| `delete_policy`, `set_active`, `set_sources`, `set_schedule` | remove, switch off/on, retarget or reschedule a policy |
| `block_categories`, `allow_categories`, `allow_only_categories`, `set_category_filter` | site categories (below) |
| `block_sites`, `allow_sites`, `unlist_sites` | the URL block and allow lists |
| `set_adult_images` (blur, block, checkerboard), `set_adult_text`, `set_adult_video` | the classifiers |
| `set_ads`, `set_safesearch`, `set_doh_filter`, `set_youtube` | ad blocking, SafeSearch, DoH filtering, YouTube channels |
| `block_internet` | block all web access (always-allowed sites still work) |

### Rules from earlier versions

Earlier versions turned one sentence into an overlay rule in
`config/rules.json`. Those rules are still enforced, so nothing loosens on
upgrade, but new ones cannot be added. The Assistant page lists them under
**Old rules (still active)**: *Convert* sends a rule's sentence to the
assistant so you can apply it as a policy change, then *Remove* deletes the
rule. `webfilter rules list` and `webfilter rules remove <id>` do the same
from the command line.

## Site categories

Every website gets one category from a fixed list:

adult, dating, gambling, social media, chat & messaging, email, news,
shopping, banking & finance, video streaming, music & audio, games,
entertainment, sports, search engines, education, kids, government,
health, travel, jobs, religion, technology, business, ads & tracking,
malware & phishing, piracy, drugs & alcohol, weapons, violence & hate,
infrastructure (CDNs, APIs, login and asset servers), other.

```json
"category_filter": { "enabled": true, "mode": "blacklist", "categories": ["shopping", "social_media"],
                     "on_timeout": "allow", "on_unavailable": "allow", "budget_ms": 0 }
```

* `mode` `blacklist` blocks the listed categories; `whitelist` allows only
  them. Infrastructure hosts are always allowed in `whitelist` mode, and so
  are the resources an allowed page loads, or nothing would display.
* Where a category comes from: a manual override on the **Decisions** page,
  then the installed domain lists (`webfilter categories update`; porn,
  gambling, shopping, social, streaming and the other IPFire lists map onto
  the categories above), then the model's cached verdict, then the model.
  Verdicts are cached per registrable domain.
* Only a page navigation asks the model and waits for it, up to
  `budget_ms` (or `llm.budget.category_ms`, 1500 ms). If it has not decided
  by then the page gets `on_timeout` and the category is ready for the next
  visit. `on_unavailable` applies when the model is not running.
* Sub-resources (scripts, images, API calls) are judged only from what is
  already known, so one page's dozens of third-party hosts never queue model
  calls. A host already known to be in a blocked category is refused.
* Hosts that are tunnelled without inspection (MITM `exclude` sites such as
  banks) are checked from the lists and the cache when the connection
  opens, and categorized in the background for next time. Only
  `blacklist` mode is enforced there.
* The URL allow list wins over categories; the block list is checked first.
* The policy editor's **Site Categories** section has *Test a site*; the
  **Decisions** page lists every cached category (filter *Site
  categories*) and lets you set one by hand for a domain or an exact host.

`url_filter.categories` still selects raw domain lists by name, as before.

## Classifier settings in a policy

```json
"text_classifier": { "enabled": true, "threshold": 0.8, "on_timeout": "allow", "on_unavailable": "allow", "budget_ms": 0,
                      "exclude": [], "include_only": [] },
"image_classifier": { "enabled": true, "action": "blur", "threshold": 0.4, "min_dimension": 100,
                      "on_timeout": "blur", "on_unavailable": "allow", "budget_ms": 0, "prefetch": true,
                      "exclude": [], "include_only": [] },
"video_classifier": { "enabled": true, "threshold": 0.4, "on_timeout": "allow", "keyframes": false, "youtube": true,
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
* `video_classifier` judges videos through stills: the poster a page
  declares for a `<video>`, a YouTube video's thumbnail when the player
  response passes through (`youtube`), and, with `keyframes` on and ffmpeg
  installed on the proxy machine, frames decoded from the stream's opening
  seconds. A video judged adult has its sources removed from the page, its
  YouTube player response made unplayable, and later requests for the stream
  refused.

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
