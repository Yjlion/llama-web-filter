# Monitoring: `/health` and `/metrics`

Both endpoints live on the management server (default `:8000`), alongside
the UI and the REST API.

## `/health`

A liveness probe for load balancers, orchestrators and container
healthchecks:

```bash
$ curl -s http://127.0.0.1:8000/health
{"status":"ok","version":"v1.2.3","uptime_seconds":4127}
```

It is **unauthenticated by design** — a load balancer cannot log in — and
returns 200 whenever the management server is serving. It is deliberately
cheap: no database queries, no port probes, nothing that allocates much. If
you want the richer view (whether the proxy port is open, recent blocks,
TUN/gateway state) use `GET /api/status`, which is authenticated and does do
that work.

This is liveness, not readiness: it tells you the server is up, not that
every listener bound successfully. `uptime_seconds` is measured from process
start.

## `/metrics`

Prometheus text exposition format (version 0.0.4), no dependencies, no
external exporter:

```bash
$ curl -s http://127.0.0.1:8000/metrics
# HELP webfilter_requests_total Requests processed by the filtering pipeline, ...
# TYPE webfilter_requests_total counter
webfilter_requests_total{action="blocked",component="url_filter",policy="kids"} 42
webfilter_requests_total{action="ok",component="",policy="default"} 1337
...
```

| Metric | Type | Labels |
|---|---|---|
| `webfilter_requests_total` | counter | `action`, `component`, `policy` |
| `webfilter_blocks_total` | counter | `component` |
| `webfilter_classifier_duration_seconds` | histogram | `classifier` |
| `webfilter_classifier_results_total` | counter | `classifier`, `result` |
| `webfilter_upstream_errors_total` | counter | — |
| `webfilter_connections_total` | counter | `mode` |
| `webfilter_connections_active` | gauge | — |
| `webfilter_build_info` | counter (always 1) | `version`, `commit` |
| `webfilter_start_time_seconds` | gauge | — |

A few of these are worth explaining:

- **`webfilter_blocks_total` is not `webfilter_requests_total{action="blocked"}`.**
  The connection-level gate refuses some tunnels before any request exists
  (host-scoped rules on blind-spliced hosts, DoT on port 853), and the
  SOCKS5 UDP relay blocks DNS answers the same way. Those never produce a
  request row, so they are counted only in `webfilter_blocks_total` — the
  same asymmetry you see between `?kind=blocks` and `?kind=requests` in the
  logs API.
- **`webfilter_classifier_results_total{result="error"}` is the one to
  alert on.** It means content could not be scored at all — an undecodable
  image format, a corrupt model — and unscoreable content is passed
  through, not blocked. A rising error rate is a filter quietly failing
  open, which otherwise looks exactly like a quiet day.
- **`webfilter_upstream_errors_total`** counts failures to reach the origin
  (DNS, refused connections, TLS, timeouts). It rises when the proxy cannot
  reach the internet, which is a different problem from the proxy blocking
  things.

No metric is labelled by hostname, URL path, client IP or user agent. Those
are per-request values; a counter labelled with one stops being a counter
and becomes an unbounded log. Use `GET /api/analytics` (or the logs
database) for top-domain and per-device breakdowns — that is what it is for.

### Scraping with authentication

With management auth off, `/metrics` is open like the rest of the API. With
it on, a scraper cannot complete a login form, so set a bearer token in
Settings → Monitoring (or `metrics_token` in `settings.json`):

```yaml
scrape_configs:
  - job_name: webfilter
    static_configs:
      - targets: ["webfilter.example.com:8000"]
    authorization:
      type: Bearer
      credentials: "<metrics_token>"
```

The token is scoped to `/metrics` and grants read access to counters only —
it opens nothing else, and it is not a second admin password. It is stored
in plaintext in `settings.json` and shown in the UI, because it has to be
readable to be copied into a scrape config. Unauthenticated requests get a
401, never a redirect to the login page.

Set `metrics_enabled: false` to remove the endpoint entirely (404).

### The one real caveat: process model

**These are in-process counters.** `webfilter run` serves the proxy and the
management server in one process, so a scrape of that process sees
everything. But under the split deployment:

```bash
webfilter proxy --settings config/settings.json   # does the filtering
webfilter mgmt  --settings config/settings.json   # serves /metrics
```

the `mgmt` process never touches a request, so every engine-side counter it
reports reads **zero**. Only `webfilter_build_info`, `webfilter_start_time_seconds`
and the mgmt process's own uptime are meaningful there.

This is deliberate. The alternative — deriving metrics from SQL against the
log database at scrape time — would make every scrape a set of aggregate
queries against a store designed around a single writer, and would report
whatever the retention window happens to hold rather than monotonic
counters. If you run split processes and want real numbers, scrape the
process that serves traffic.

### Example alerts

```yaml
groups:
  - name: webfilter
    rules:
      # A classifier that cannot score is a filter failing open.
      - alert: WebfilterClassifierFailingOpen
        expr: rate(webfilter_classifier_results_total{result="error"}[10m]) > 0.1
        for: 15m

      # The proxy cannot reach origins.
      - alert: WebfilterUpstreamErrors
        expr: rate(webfilter_upstream_errors_total[5m]) > 1
        for: 10m

      # Connections accumulating without completing.
      - alert: WebfilterConnectionsStuck
        expr: webfilter_connections_active > 500
        for: 15m
```
