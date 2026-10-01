package addons

import (
	"encoding/base64"
	"net/http"
	"strings"
	"sync"

	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
	"github.com/yjlion/llama-web-filter/internal/pwhash"
)

// ProxyAuthGate implements HTTP proxy authentication (407 challenge/
// response), ported from proxy/addons/proxy_auth.py.
//
// HTTPS tunnels: auth is carried on the CONNECT request (AuthorizeConnect,
// called directly by the engine before MITM/blind-splice begins - mirrors
// mitmproxy's distinct http_connect hook). On success the connection ID is
// remembered so inner HTTP requests routed through that tunnel aren't
// re-challenged. Plain HTTP: auth is carried on every request (the browser
// resends credentials on every subsequent request in the same keep-alive
// connection after handling the first 407).
//
// Credentials are stored in settings.json as a PBKDF2-SHA256 hash, the
// same scheme used for management UI auth. SOCKS5 proxy auth (RFC 1929
// username/password) is a different sub-protocol negotiated during the
// SOCKS handshake rather than over HTTP headers; this addon covers it via
// SocksAuthRequired/AuthorizeSocks, validating the same credential store
// and sharing the same per-connection authed bookkeeping.
type ProxyAuthGate struct {
	runtime *state.Runtime

	mu          sync.Mutex
	authedConns map[uint64]bool
}

// NewProxyAuthGate constructs a ProxyAuthGate reading credentials from rt's
// settings. rt is needed directly (rather than only via FlowContext)
// because AuthorizeConnect runs at CONNECT time, before any FlowContext
// exists - see proxy.ConnectGate's doc comment.
func NewProxyAuthGate(rt *state.Runtime) *ProxyAuthGate {
	return &ProxyAuthGate{runtime: rt, authedConns: make(map[uint64]bool)}
}

func (*ProxyAuthGate) Name() string { return "proxy_auth" }

func (g *ProxyAuthGate) enabled(fc *proxy.FlowContext) bool {
	s := fc.Runtime.Settings()
	return s.ProxyAuthEnabled && s.ProxyAuthPasswordHash != ""
}

func (g *ProxyAuthGate) validRequest(fc *proxy.FlowContext) bool {
	username, password, ok := parseBasic(fc.Request.Header.Get("Proxy-Authorization"))
	if !ok {
		return false
	}
	s := fc.Runtime.Settings()
	return username == s.ProxyAuthUsername && pwhash.Verify(password, s.ProxyAuthPasswordHash)
}

func parseBasic(header string) (username, password string, ok bool) {
	const prefix = "basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", "", false
	}
	user, pass, found := strings.Cut(string(decoded), ":")
	if !found {
		return user, "", true
	}
	return user, pass, true
}

// AuthorizeConnect validates proxy credentials on a CONNECT request,
// remembering connID as authorized on success so inner tunneled requests
// aren't re-challenged. Implements proxy.ConnectGate.
func (g *ProxyAuthGate) AuthorizeConnect(req *http.Request, connID uint64) bool {
	if g.runtime == nil {
		g.markAuthed(connID)
		return true
	}
	s := g.runtime.Settings()
	if !(s.ProxyAuthEnabled && s.ProxyAuthPasswordHash != "") {
		g.markAuthed(connID)
		return true
	}
	username, password, ok := parseBasic(req.Header.Get("Proxy-Authorization"))
	if ok && username == s.ProxyAuthUsername && pwhash.Verify(password, s.ProxyAuthPasswordHash) {
		g.markAuthed(connID)
		return true
	}
	return false
}

// SocksAuthRequired reports whether SOCKS5 method selection must demand
// username/password. Implements proxy.SocksAuthGate.
func (g *ProxyAuthGate) SocksAuthRequired() bool {
	if g.runtime == nil {
		return false
	}
	s := g.runtime.Settings()
	return s.ProxyAuthEnabled && s.ProxyAuthPasswordHash != ""
}

// AuthorizeSocks validates RFC 1929 credentials from a SOCKS5 handshake,
// remembering connID as authorized on success so requests tunneled over the
// connection aren't re-challenged by HandleRequest. Implements
// proxy.SocksAuthGate. When auth is disabled it authorizes unconditionally
// (and still marks connID), mirroring AuthorizeConnect.
func (g *ProxyAuthGate) AuthorizeSocks(username, password string, connID uint64) bool {
	if g.runtime == nil {
		g.markAuthed(connID)
		return true
	}
	s := g.runtime.Settings()
	if !(s.ProxyAuthEnabled && s.ProxyAuthPasswordHash != "") {
		g.markAuthed(connID)
		return true
	}
	if username == s.ProxyAuthUsername && pwhash.Verify(password, s.ProxyAuthPasswordHash) {
		g.markAuthed(connID)
		return true
	}
	return false
}

func (g *ProxyAuthGate) markAuthed(connID uint64) {
	g.mu.Lock()
	g.authedConns[connID] = true
	g.mu.Unlock()
}

// ClientDisconnected releases per-connection auth state. Implements
// proxy.ConnectGate.
func (g *ProxyAuthGate) ClientDisconnected(connID uint64) {
	g.mu.Lock()
	delete(g.authedConns, connID)
	g.mu.Unlock()
}

// HandleRequest gates every plain-HTTP proxy request and every tunneled
// HTTPS request after the CONNECT is established (the latter already
// authenticated in AuthorizeConnect, so this is a no-op for them).
func (g *ProxyAuthGate) HandleRequest(fc *proxy.FlowContext) {
	if fc.URLAllowed {
		return
	}
	// Front-ends that do not own the client connection do their own proxy
	// auth - see proxy.FrontendICAP. Challenging there would 407 every
	// request without any way for the user to answer.
	if fc.SkipsFrontendAddons() {
		return
	}
	if !g.enabled(fc) {
		return
	}
	g.mu.Lock()
	authed := g.authedConns[fc.ClientConnID]
	g.mu.Unlock()
	if authed {
		return
	}
	if !g.validRequest(fc) {
		fc.Response = &http.Response{
			StatusCode: http.StatusProxyAuthRequired,
			Header: http.Header{
				"Proxy-Authenticate": []string{`Basic realm="WebFilter Proxy"`},
				"Content-Type":       []string{"text/plain"},
				"Proxy-Connection":   []string{"close"},
			},
		}
		fc.ResponseBody = []byte("Proxy Authentication Required")
	}
}
