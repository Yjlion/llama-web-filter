package proxy

import (
	"net/http"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

// FlowContext carries one request/response pair through the addon
// pipeline, mirroring mitmproxy's flow.metadata dict. Request/Response
// mutations by any addon are visible to every addon that runs after it,
// exactly like the Python original's shared HTTPFlow object.
//
// ResponseBody is always the full buffered response body (Response.Body is
// never populated - the pipeline reads and closes the real body once, up
// front) since every response-hook addon that needs to inspect content
// (youtube_filter, text_classifier, image_classifier) needs the whole thing
// anyway, matching mitmproxy's own fully-buffered flow.response.text/
// raw_content semantics.
type FlowContext struct {
	Runtime  *state.Runtime
	ClientIP string
	// ClientConnID identifies the underlying TCP connection (one CONNECT
	// tunnel, or one plain-HTTP keep-alive connection) - mirrors
	// mitmproxy's flow.client_conn.id, used by proxy_auth to remember a
	// connection authenticated at the CONNECT stage.
	ClientConnID uint64
	// ProxySockName is the local address the client connected to (this
	// proxy's own address on that connection) - mirrors
	// flow.client_conn.sockname[0], used by management_access to build the
	// pseudo-domain redirect Location and to recognize management-port
	// traffic addressed to the proxy's own IP.
	ProxySockName string
	// Frontend names where this flow entered the filter. Empty (or
	// FrontendProxy) means the engine terminated the connection itself and
	// every addon applies. FrontendICAP means another proxy - Squid - owns
	// the client connection and handed us only the HTTP message; see the
	// constants for which addons that excuses.
	Frontend string

	Request      *http.Request
	Response     *http.Response
	ResponseBody []byte

	// URLAllowed mirrors flow.metadata["url_allowed"]: an allow-list match
	// short-circuits every downstream filtering addon.
	URLAllowed bool
	// MitmPassthrough mirrors flow.metadata["mitm_passthrough"]: set for
	// MITM-include-mode non-listed sites and matching User-Agent rules, or
	// by ManagementAccess for the proxy's own management traffic.
	MitmPassthrough bool
	// WFAction/WFComponent mirror flow.metadata["wf_action"/"wf_component"]
	// - the final decision RequestLogger records ("ok"/"modified"/"blocked").
	WFAction    string
	WFComponent string
	// WFLogged mirrors flow.metadata["wf_logged"]: set once RequestLogger
	// has recorded this flow, so the error hook doesn't double-log a flow
	// that already got a response hook.
	WFLogged bool

	Policy *models.Policy
	// RulesApplied lists the ids of the natural-language rules the
	// RuleEvaluator overlaid onto Policy for this flow (empty when none).
	RulesApplied []string
}

// Frontend values for FlowContext.Frontend.
//
// Two addons are front-end concerns rather than policy concerns, and both are
// wrong over ICAP:
//
//   - proxy_auth challenges the client for proxy credentials. Over ICAP the
//     client is Squid, which does its own proxy authentication, and one ICAP
//     connection carries transactions for many different end users - so the
//     per-connection "already authenticated" bookkeeping keyed on
//     ClientConnID cannot mean anything. Left enabled it would 407 every
//     request the moment proxy auth is switched on.
//   - management_access redirects the management pseudo-domain to the
//     address the client reached this proxy on. Over ICAP that address is
//     the ICAP listener's, which is not an address the end user's browser
//     can reach.
//
// Everything else - policy routing, MITM control, URL filtering, DoH,
// SafeSearch, YouTube, both classifiers, request logging - is a policy
// decision and runs identically whichever front-end delivered the flow.
const (
	FrontendProxy = "proxy"
	FrontendICAP  = "icap"
)

// SkipsFrontendAddons reports whether fc arrived through a front-end that
// owns proxy authentication and management-UI access itself.
func (fc *FlowContext) SkipsFrontendAddons() bool {
	return fc.Frontend == FrontendICAP
}

// Addon is the common interface every pipeline stage implements; concrete
// stages additionally implement RequestAddon, ResponseAddon, and/or
// ErrorAddon depending on which mitmproxy hooks their Python original
// registered.
type Addon interface {
	Name() string
}

// RequestAddon runs during the request phase, in pipeline order, for
// every flow - regardless of whether an earlier addon already set
// fc.Response. This mirrors mitmproxy's actual behavior: setting
// flow.response early skips the real upstream fetch but does NOT skip
// later addons' request() hooks, which is why several addons must guard
// on fc.URLAllowed/fc.MitmPassthrough themselves.
type RequestAddon interface {
	Addon
	HandleRequest(fc *FlowContext)
}

// ResponseAddon runs during the response phase, in pipeline order, once a
// response exists (from upstream or synthesized by a request-hook addon).
type ResponseAddon interface {
	Addon
	HandleResponse(fc *FlowContext)
}

// ErrorAddon runs when the upstream fetch itself failed (connection
// refused, DNS failure, etc.) - the response phase never runs in that
// case, mirroring mitmproxy's separate error() hook.
type ErrorAddon interface {
	Addon
	HandleError(fc *FlowContext)
}

// ConnectGate lets an addon gate a CONNECT tunnel before MITM/blind-splice
// begins. Only ProxyAuthGate implements this - mitmproxy fires a distinct
// http_connect hook for CONNECT requests, uniquely before the tunnel (and
// thus before any per-flow FlowContext) exists, so it isn't part of the
// ordinary Request/Response/Error pipeline. The engine calls this directly
// rather than through Pipeline.
type ConnectGate interface {
	Addon
	// AuthorizeConnect reports whether the CONNECT request (identified by
	// connID) may proceed. On success the addon should remember connID as
	// authorized so subsequent requests over the same tunnel aren't
	// re-challenged (mirrors ProxyAuthGate's _authed_conns).
	AuthorizeConnect(req *http.Request, connID uint64) bool
	// ClientDisconnected releases any per-connection state for connID,
	// called once the connection (CONNECT tunnel or plain-HTTP
	// connection) closes - mirrors client_disconnected.
	ClientDisconnected(connID uint64)
}

// SocksAuthGate authenticates SOCKS5 clients (RFC 1929 username/password),
// the SOCKS analogue of ConnectGate.AuthorizeConnect. Like AuthorizeConnect
// it runs at handshake time, before any per-flow FlowContext exists, so the
// engine calls it directly rather than through the Request/Response pipeline.
// Only ProxyAuthGate implements this - it's the same credential store as the
// HTTP 407 gate, just reached over a different sub-protocol.
type SocksAuthGate interface {
	Addon
	// SocksAuthRequired reports whether the SOCKS5 method-selection step
	// must demand username/password (method 0x02) rather than offering
	// no-auth (0x00).
	SocksAuthRequired() bool
	// AuthorizeSocks validates RFC 1929 credentials. On success the addon
	// should remember connID as authorized (the same bookkeeping
	// AuthorizeConnect does) so requests tunneled over the SOCKS connection
	// aren't re-challenged by the request-phase gate.
	AuthorizeSocks(username, password string, connID uint64) bool
	// ClientDisconnected releases any per-connection state for connID once
	// the SOCKS connection closes.
	ClientDisconnected(connID uint64)
}
