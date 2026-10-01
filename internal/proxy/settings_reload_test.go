package proxy_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
	"github.com/yjlion/llama-web-filter/internal/pwhash"
)

// The end-to-end claim of settings hot-reload: a running engine changes
// behaviour when settings change, with no restart and no reconnection.
//
// proxy_auth is the sharpest case to test - it is read per request by
// ProxyAuthGate, and getting it wrong is visible as a 407 either appearing
// or failing to appear.
func TestProxyAuthAppliesWithoutRestart(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "upstream ok")
	}))
	defer origin.Close()

	// nil trustedOrigin: the origin is plain HTTP, so the engine's upstream
	// transport needs no extra root (and startModeEngine would dereference a
	// nil Certificate for a non-TLS server).
	proxyAddr, rt := startModeEngine(t, "regular@127.0.0.1:0", nil, nil,
		func(rt *state.Runtime) *proxy.Pipeline {
			return proxy.NewPipeline([]proxy.Addon{addons.NewProxyAuthGate(rt)})
		})

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// Auth is off in the seeded settings: the request goes through.
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("request with auth disabled: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status with auth disabled = %d, want 200", resp.StatusCode)
	}

	// Turn proxy auth on the way a settings save would - no restart, no new
	// listener, the same engine and the same client.
	hash, err := pwhash.Hash("s3cret")
	if err != nil {
		t.Fatalf("pwhash.Hash: %v", err)
	}
	next := *rt.Settings()
	next.ProxyAuthEnabled = true
	next.ProxyAuthUsername = "alice"
	next.ProxyAuthPasswordHash = hash
	if pending := rt.ApplySettings(next); len(pending) != 0 {
		t.Fatalf("proxy auth change reported restart-required fields %v; it is hot", pending)
	}

	// The very next request must be challenged.
	resp, err = client.Get(origin.URL)
	if err != nil {
		t.Fatalf("request after enabling auth: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status after enabling auth = %d, want 407 - the change did not reach the live read path",
			resp.StatusCode)
	}

	// Correct credentials work against the newly-applied settings.
	authed := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{
			Scheme: "http",
			User:   url.UserPassword("alice", "s3cret"),
			Host:   proxyAddr,
		}),
	}}
	resp, err = authed.Get(origin.URL)
	if err != nil {
		t.Fatalf("authenticated request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("authenticated status = %d, want 200", resp.StatusCode)
	}

	// And turning it back off takes effect just as immediately.
	off := *rt.Settings()
	off.ProxyAuthEnabled = false
	rt.ApplySettings(off)

	resp, err = client.Get(origin.URL)
	if err != nil {
		t.Fatalf("request after disabling auth: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status after disabling auth = %d, want 200", resp.StatusCode)
	}
}
