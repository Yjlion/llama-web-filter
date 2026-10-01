# ICAP: filtering for a proxy you already run

Every other mode in this project asks to *be* your proxy — a forward proxy,
a SOCKS listener, a transparent gateway, a TUN device. ICAP mode asks for
nothing of the sort. Squid stays where it is, keeps its caching, its ACLs,
its authentication and its TLS interception, and hands each request and
response to WebFilter for a verdict over
[ICAP](https://www.rfc-editor.org/rfc/rfc3507) (RFC 3507).

What you get is the same filtering brain: the same per-client policies,
category blocklists, SafeSearch rewriting, YouTube filtering and NSFW
text/image classification, applied to traffic Squid is already carrying.

## Turning it on

ICAP is a listener mode, so it is enabled the same way every other listener
is — by an entry in `proxy_listen`:

```json
{
  "proxy_listen": ["icap@0.0.0.0:1344"],
  "mgmt_port": 8000
}
```

1344 is ICAP's registered port. `icaps@0.0.0.0:11344` serves the same thing
over TLS, with a certificate minted by the runtime CA (`tls+icap@` is the
long spelling of the same option).

An ICAP-only `proxy_listen` is a perfectly valid deployment: WebFilter then
terminates nothing itself and fetches nothing itself. You can also run ICAP
alongside the normal listeners — `["0.0.0.0:8080", "icap@0.0.0.0:1344"]` —
and filter directly-configured clients and Squid's clients from one process
and one set of policies.

The tunables live in an `icap` block, all of which have working defaults:

```json
"icap": {
  "preview_size": 4096,
  "max_body_bytes": 8388608,
  "normalize_accept_encoding": true,
  "trust_client_ip_header": true
}
```

- **`preview_size`** is how many leading body bytes Squid sends before
  WebFilter decides whether it wants the rest. It is what makes it cheap to
  wave a video past without streaming it through the filter first.
- **`max_body_bytes`** caps what is buffered for inspection. Larger bodies
  pass unfiltered — see the limits below.
- **`normalize_accept_encoding`** rewrites the client's `Accept-Encoding` to
  `gzip`. Leave it on: browsers advertise `br` and `zstd`, which nothing in
  the filter can decode, and a body that cannot be decoded cannot be scanned.
- **`trust_client_ip_header`** makes WebFilter believe Squid's `X-Client-IP`.

As with every other setting, **changes need a restart**; policy edits
hot-reload.

## Wiring up Squid

Squid needs `--enable-icap-client` (every distribution package has it;
`squid -v` will tell you). Add this to `squid.conf`:

```squid
icap_enable on
icap_preview_enable on
icap_preview_size 4096

icap_send_client_ip on
icap_send_client_username on

icap_service wf_req  reqmod_precache  icap://127.0.0.1:1344/reqmod  bypass=off
icap_service wf_resp respmod_precache icap://127.0.0.1:1344/respmod bypass=off

adaptation_access wf_req  allow all
adaptation_access wf_resp allow all
```

Complete, runnable configs for each mode are in
[`docs/examples/squid/`](examples/squid/) — they are the files the mode
matrix below was verified against.

Three things in that snippet are load-bearing:

- **`icap_send_client_ip on` is not optional.** The TCP peer on the ICAP
  connection is Squid, so without this header every user in the building
  arrives as one address and the per-client policy tiers (MAC → IP → CIDR)
  quietly stop distinguishing anybody. With it, `GET /api/logs?kind=requests`
  shows the real client address and the policy that applied to it.
- **Configure both services.** They see different halves of the transaction:
  REQMOD can block or rewrite a request before Squid fetches anything,
  RESPMOD inspects what came back. With only REQMOD nothing examines response
  bodies; with only RESPMOD, requests are still filtered but the origin is
  contacted first.
- **`bypass=off` means a filter outage blocks traffic rather than silently
  passing it.** That is the right default for a filter — `bypass=on` turns
  every WebFilter restart into an unfiltered window — but it does mean Squid
  depends on the service being up. Decide deliberately.

The service path (`/reqmod`, `/respmod`) is yours to name: WebFilter
dispatches on the ICAP method, not the URI, so the two can never disagree
about which service is which.

## The four Squid modes

All four were verified end to end against Squid 7.7. What changes between
them is how much Squid can see — ICAP can only filter what Squid hands it.

| Squid mode | What the filter sees |
|---|---|
| **Forward proxy** (`http_port 3128`) | Every plaintext HTTP request and response. HTTPS appears only as a CONNECT. |
| **`ssl_bump bump all`** | Everything, decrypted: HTTPS requests, response bodies, inline images. The full feature set. |
| **Peek and splice** | Bumped hosts in full; spliced hosts only as a CONNECT (see limits). |
| **Transparent intercept** (`intercept` / `https_port intercept`) | Same as the equivalent non-intercept mode. Squid reconstructs absolute URLs, and `X-Client-IP` still carries the real client. |

### HTTPS and the CONNECT gate

When Squid bumps TLS it sends the CONNECT through REQMOD first. WebFilter
answers that with the same host-only gate that decides blind-spliced tunnels
in native proxy mode, so the two verdicts cannot drift apart. Two
consequences worth knowing:

- **A host-level block refuses the tunnel** with `403` — and the refusal
  carries the styled block page, because browsers render the body of a failed
  CONNECT. The user sees the same page they would over plain HTTP.
- **A path-level rule (`example.com/downloads`) cannot be decided from a
  hostname**, so it is skipped at CONNECT and applied to the decrypted
  request instead. `https://httpbin.org/deny` gets the block page while
  `https://httpbin.org/get` on the same host is untouched.

## Verifying it works

Blocked responses are **HTTP 200 with a block-page body**, not 4xx, so a
status code alone tells you nothing. Check the logs:

```bash
curl -s "http://127.0.0.1:8000/api/logs?kind=requests&limit=20"
curl -s "http://127.0.0.1:8000/api/logs?kind=blocks&limit=20"
```

A working setup looks like this — note the real client addresses, not
Squid's:

```
GET     example.com    200 action=ok      client=192.168.1.50 policy=default
GET     example.org    200 action=blocked client=192.168.1.50 policy=default  component=url_filter
CONNECT example.org    403 action=blocked client=192.168.1.51 policy=kiosk    component=url_filter
```

Squid's own `cache.log` should say `Adaptation support is on` at startup. If
a service is unreachable, Squid logs it there and (with `bypass=off`) starts
refusing requests.

## Limits worth knowing before you deploy it

- **Splice bypasses adaptation completely.** A spliced connection produces no
  REQMOD and no RESPMOD for anything inside it — that is what splicing *is*.
  The CONNECT is still filtered, so host and category rules still apply, but
  nothing inside that tunnel can be seen, and no request rows appear for it.
  This is the same trade the native proxy's blind-splice path makes.
- **ICAP sees only what Squid decrypts.** Without `ssl_bump`, HTTPS is a
  tunnel: host-level rules work, and nothing else does. SafeSearch enforcement,
  YouTube filtering, and both classifiers all need bumped traffic.
- **Bodies over `max_body_bytes` (8 MiB) pass uninspected.** They are still
  logged, marked with the policy that applied — "we did not inspect this" is
  something an operator needs to be able to see — but no classifier runs on
  them. Buffering whole downloads to look at them is how an ICAP service
  becomes an outage.
- **Bodies in an encoding this build cannot decode pass uninspected**, for
  the same reason and with the same log row. `normalize_accept_encoding`
  exists to make that case rare; gzip and deflate are handled.
- **Allowed CONNECTs are not logged.** A request row is written when the
  transaction produces a response — a block, or a RESPMOD that completed.
  An allowed tunnel is recorded by the requests inside it, which for a spliced
  host means not at all.
- **Proxy authentication and the management pseudo-domain belong to Squid.**
  WebFilter's own `proxy_auth` and the `web.filter` redirect are skipped for
  ICAP flows: one ICAP connection carries many users, so a 407 from here
  could never be answered, and a redirect to this host's address is not
  somewhere the browser can follow. Use Squid's own `auth_param`.
- **QUIC needs blocking at the firewall.** `block_quic` strips `Alt-Svc` from
  responses the filter inspects, but a browser that already knows an HTTP/3
  route will use it and never reach Squid at all. Drop UDP/443 at the
  perimeter.
- **The ISTag moves on every policy reload**, so Squid revalidates adapted
  objects after a policy edit rather than serving a cached verdict.

## Troubleshooting

**Every client shows up as the same address in the logs.**
`icap_send_client_ip on` is missing from `squid.conf`, or
`trust_client_ip_header` was turned off.

**`ERR_ICAP_FAILURE` / Squid refuses everything.** WebFilter is not
listening on the ICAP port, and the services are `bypass=off`. Check
`proxy_listen` has the `icap@` entry and that the process log says:

```
INFO proxy listening addr=0.0.0.0:1344 mode=icap
```

**HTTPS is not filtered beyond host rules.** Squid is not bumping. Without
`ssl_bump`, or for a spliced host, there is nothing to hand over.

**Response bodies are not being classified.** Check that
`normalize_accept_encoding` is on and that the content is not larger than
`max_body_bytes`; both cases pass through with an ordinary `action=ok` row.
