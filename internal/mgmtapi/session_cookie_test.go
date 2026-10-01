package mgmtapi_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSessionCookieAuthenticates covers the SessionCookie export used by the
// native desktop GUI in self-host mode: the minted cookie must be accepted by
// the auth middleware exactly like one issued through POST /api/login.
func TestSessionCookieAuthenticates(t *testing.T) {
	s, ts := newTestServer(t)

	// Turn auth on the same way the UI does.
	resp, err := ts.Client().Do(mustRequest(t, http.MethodPut, ts.URL+"/api/settings",
		`{"auth_enabled": true, "new_password": "correcthorse"}`))
	if err != nil {
		t.Fatalf("PUT /api/settings: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable auth: status = %d, want 200", resp.StatusCode)
	}

	// Sanity: without a cookie, API calls are rejected.
	resp, err = http.Get(ts.URL + "/api/settings")
	if err != nil {
		t.Fatalf("GET /api/settings: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", resp.StatusCode)
	}

	// The minted cookie must pass the middleware.
	name, value := s.SessionCookie()
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/settings", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: name, Value: value})
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET with session cookie: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("with SessionCookie: status = %d, want 200", resp.StatusCode)
	}

	// And it must be the same token POST /api/login hands to browsers.
	resp, err = http.Post(ts.URL+"/api/login", "application/json",
		strings.NewReader(`{"password": "correcthorse"}`))
	if err != nil {
		t.Fatalf("POST /api/login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}
	var loginCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == name {
			loginCookie = c
		}
	}
	if loginCookie == nil {
		t.Fatalf("login response did not set cookie %q", name)
	}
	if loginCookie.Value != value {
		t.Errorf("SessionCookie value differs from login-issued cookie")
	}
}

// The Secure flag must follow the connection actually serving the login, not
// the mgmt_tls setting. The two disagree right after mgmt_tls is saved (it is
// restart-required, so the listener is still plain HTTP) and always on
// Android (ForcePlaintext). A Secure cookie over plain HTTP is never sent
// back, so keying on the setting would lock the admin out until a restart.
func TestLoginCookieSecureFollowsConnection(t *testing.T) {
	s, ts := newTestServer(t)

	resp, err := ts.Client().Do(mustRequest(t, http.MethodPut, ts.URL+"/api/settings",
		`{"auth_enabled": true, "new_password": "correcthorse", "mgmt_tls": true}`))
	if err != nil {
		t.Fatalf("PUT /api/settings: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable auth + mgmt_tls: status = %d, want 200", resp.StatusCode)
	}

	login := func(client *http.Client, base string) *http.Cookie {
		t.Helper()
		resp, err := client.Post(base+"/api/login", "application/json",
			strings.NewReader(`{"password": "correcthorse"}`))
		if err != nil {
			t.Fatalf("POST /api/login: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login status = %d, want 200", resp.StatusCode)
		}
		name, _ := s.SessionCookie()
		for _, c := range resp.Cookies() {
			if c.Name == name {
				return c
			}
		}
		t.Fatalf("login response did not set cookie %q", name)
		return nil
	}

	if c := login(ts.Client(), ts.URL); c.Secure {
		t.Error("plain-HTTP login set a Secure cookie; the browser would never send it back")
	}

	tlsTS := httptest.NewTLSServer(s.Router())
	defer tlsTS.Close()
	if c := login(tlsTS.Client(), tlsTS.URL); !c.Secure {
		t.Error("HTTPS login did not set a Secure cookie")
	}
}
