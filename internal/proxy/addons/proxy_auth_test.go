package addons_test

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
	"github.com/yjlion/llama-web-filter/internal/pwhash"
)

func basicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestProxyAuthDisabledAllowsEverything(t *testing.T) {
	rt := newTestRuntime(t)
	fc := newFlow(t, rt, "http://example.com/")
	gate := addons.NewProxyAuthGate(rt)

	gate.HandleRequest(fc)

	if fc.Response != nil {
		t.Error("did not expect a 407 when proxy auth is disabled")
	}
}

func TestProxyAuthRequestRejectsMissingCredentials(t *testing.T) {
	rt := newTestRuntime(t)
	hash, err := pwhash.Hash("secret")
	if err != nil {
		t.Fatalf("pwhash.Hash: %v", err)
	}
	cfg := *rt.Settings()
	cfg.ProxyAuthEnabled = true
	cfg.ProxyAuthUsername = "alice"
	cfg.ProxyAuthPasswordHash = hash
	rt.SetSettings(cfg)

	fc := newFlow(t, rt, "http://example.com/")
	gate := addons.NewProxyAuthGate(rt)

	gate.HandleRequest(fc)

	if fc.Response == nil || fc.Response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected a 407, got %+v", fc.Response)
	}
}

func TestProxyAuthRequestAcceptsValidCredentials(t *testing.T) {
	rt := newTestRuntime(t)
	hash, err := pwhash.Hash("secret")
	if err != nil {
		t.Fatalf("pwhash.Hash: %v", err)
	}
	cfg := *rt.Settings()
	cfg.ProxyAuthEnabled = true
	cfg.ProxyAuthUsername = "alice"
	cfg.ProxyAuthPasswordHash = hash
	rt.SetSettings(cfg)

	fc := newFlow(t, rt, "http://example.com/")
	fc.Request.Header.Set("Proxy-Authorization", basicAuthHeader("alice", "secret"))
	gate := addons.NewProxyAuthGate(rt)

	gate.HandleRequest(fc)

	if fc.Response != nil {
		t.Fatalf("expected no 407 with valid credentials, got %+v", fc.Response)
	}
}

func TestProxyAuthConnectRemembersAuthedConnection(t *testing.T) {
	rt := newTestRuntime(t)
	hash, _ := pwhash.Hash("secret")
	cfg := *rt.Settings()
	cfg.ProxyAuthEnabled = true
	cfg.ProxyAuthUsername = "alice"
	cfg.ProxyAuthPasswordHash = hash
	rt.SetSettings(cfg)
	gate := addons.NewProxyAuthGate(rt)

	connectReq := &http.Request{Header: http.Header{"Proxy-Authorization": []string{basicAuthHeader("alice", "secret")}}}
	if !gate.AuthorizeConnect(connectReq, 42) {
		t.Fatal("expected CONNECT with valid credentials to be authorized")
	}

	// A subsequent inner request over the same tunnel (connID 42) must not
	// be re-challenged even without its own Proxy-Authorization header.
	fc := newFlow(t, rt, "https://example.com/")
	fc.ClientConnID = 42
	gate.HandleRequest(fc)
	if fc.Response != nil {
		t.Error("expected no re-challenge for an already-authorized connection")
	}

	gate.ClientDisconnected(42)
	fc2 := newFlow(t, rt, "https://example.com/")
	fc2.ClientConnID = 42
	gate.HandleRequest(fc2)
	if fc2.Response == nil {
		t.Error("expected a re-challenge after ClientDisconnected forgot the connection")
	}
}

func TestProxyAuthConnectRejectsBadCredentials(t *testing.T) {
	rt := newTestRuntime(t)
	hash, _ := pwhash.Hash("secret")
	cfg := *rt.Settings()
	cfg.ProxyAuthEnabled = true
	cfg.ProxyAuthUsername = "alice"
	cfg.ProxyAuthPasswordHash = hash
	rt.SetSettings(cfg)
	gate := addons.NewProxyAuthGate(rt)

	connectReq := &http.Request{Header: http.Header{"Proxy-Authorization": []string{basicAuthHeader("alice", "wrong")}}}
	if gate.AuthorizeConnect(connectReq, 1) {
		t.Fatal("expected CONNECT with wrong password to be rejected")
	}
}

func TestProxyAuthUrlAllowedBypassesGate(t *testing.T) {
	rt := newTestRuntime(t)
	hash, _ := pwhash.Hash("secret")
	cfg := *rt.Settings()
	cfg.ProxyAuthEnabled = true
	cfg.ProxyAuthUsername = "alice"
	cfg.ProxyAuthPasswordHash = hash
	rt.SetSettings(cfg)
	gate := addons.NewProxyAuthGate(rt)

	fc := newFlow(t, rt, "http://web.filter/")
	fc.URLAllowed = true // e.g. set by ManagementAccess already
	gate.HandleRequest(fc)
	if fc.Response != nil {
		t.Error("expected URLAllowed to bypass the proxy-auth gate")
	}
}
