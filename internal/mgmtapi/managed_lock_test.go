package mgmtapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/mgmtapi"
)

func lockServer(t *testing.T, s *mgmtapi.Server) {
	t.Helper()
	if err := config.SaveManagedState(s.SettingsPath, config.ManagedState{
		Managed:        true,
		SettingsLocked: true,
	}); err != nil {
		t.Fatalf("SaveManagedState: %v", err)
	}
}

func TestManagedLockBlocksConfigMutations(t *testing.T) {
	s, ts := newTestServer(t)
	lockServer(t, s)
	client := ts.Client()

	mutations := []struct{ method, path, body string }{
		{http.MethodPut, "/api/settings", `{"log_blocks": false}`},
		{http.MethodPost, "/api/policies", `{"name": "new-policy"}`},
		{http.MethodPut, "/api/policies/default", `{"name": "default"}`},
		{http.MethodDelete, "/api/policies/default", ""},
		{http.MethodPost, "/api/certs/import", ""},
	}
	for _, m := range mutations {
		resp, err := client.Do(mustRequest(t, m.method, ts.URL+m.path, m.body))
		if err != nil {
			t.Fatalf("%s %s: %v", m.method, m.path, err)
		}
		var body map[string]string
		json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403 when locked", m.method, m.path, resp.StatusCode)
		}
		if !strings.Contains(body["detail"], "managed by your organization") {
			t.Errorf("%s %s detail = %q, want managed-lock message", m.method, m.path, body["detail"])
		}
	}

	// Reads (and the dashboard's data sources) stay open when locked.
	for _, path := range []string{"/api/settings", "/api/policies", "/api/policies/default", "/api/status", "/api/logs", "/api/ca-cert"} {
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 when locked (reads stay open)", path, resp.StatusCode)
		}
	}
}

func TestManagedButUnlockedAllowsWrites(t *testing.T) {
	s, ts := newTestServer(t)
	if err := config.SaveManagedState(s.SettingsPath, config.ManagedState{
		Managed:        true,
		SettingsLocked: false,
	}); err != nil {
		t.Fatalf("SaveManagedState: %v", err)
	}

	resp, err := ts.Client().Do(mustRequest(t, http.MethodPut, ts.URL+"/api/settings", `{"log_blocks": false}`))
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("managed-but-unlocked PUT /api/settings = %d, want 200", resp.StatusCode)
	}
}

// TestMutatingRoutesAreLockGated walks every registered POST/PUT/DELETE
// route and asserts it either rejects with 403 under a locked managed.json
// or is on the explicit allowlist below. This keeps the enforcement list
// from silently rotting when new mutating routes are added.
func TestMutatingRoutesAreLockGated(t *testing.T) {
	// Routes that legitimately stay open under lock: session management,
	// the wireguard 501 stub, and diagnostics tools (they inspect, they
	// don't reconfigure).
	allowed := map[string]bool{
		"POST /api/login":                 true,
		"POST /api/logout":                true,
		"POST /api/wireguard":             true,
		"POST /api/tools/scan":            true,
		"POST /api/tools/youtube":         true,
		"POST /api/tools/doh":             true,
		"POST /api/tools/policy-simulate": true,
		// Asking the assistant is a read: nothing is saved until
		// POST /api/assistant/apply, which is gated.
		"POST /api/assistant/ask": true,
	}

	s, ts := newTestServer(t)
	lockServer(t, s)
	client := ts.Client()

	var mutating []struct{ method, pattern string }
	err := chi.Walk(s.Router(), func(method, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		if route == "/*" {
			// The static-UI catch-all is registered for every method; it
			// serves files / FastAPI-shaped 404s, not configuration.
			return nil
		}
		switch method {
		case http.MethodPost, http.MethodPut, http.MethodDelete:
			mutating = append(mutating, struct{ method, pattern string }{method, route})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}
	if len(mutating) == 0 {
		t.Fatal("route walk found no mutating routes - walk is broken")
	}

	for _, m := range mutating {
		key := m.method + " " + m.pattern
		if allowed[key] {
			continue
		}
		// Substitute path params with a value that exists.
		path := strings.ReplaceAll(m.pattern, "{name}", "default")
		resp, err := client.Do(mustRequest(t, m.method, ts.URL+path, "{}"))
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s = %d under lock, want 403 - new mutating routes must use requireUnlocked or be added to this test's allowlist deliberately", key, resp.StatusCode)
		}
	}
}
