package mgmtapi_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/mgmtapi"
	"github.com/yjlion/llama-web-filter/internal/pwhash"
)

// enableAuthOn turns on management auth with a real password hash, so the
// tests below exercise the actual middleware rather than a stubbed one.
func enableAuthOn(t *testing.T, s *mgmtapi.Server, password string) {
	t.Helper()
	hash, err := pwhash.Hash(password)
	if err != nil {
		t.Fatalf("pwhash.Hash: %v", err)
	}
	cfg := s.Settings()
	cfg.AuthEnabled = true
	cfg.PasswordHash = hash
	cfg.SecretKey = "test-secret-key"
	if err := s.SaveSettings(cfg); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
}

func TestHealthIsPublicAndCheap(t *testing.T) {
	s, ts := newTestServer(t)
	enableAuthOn(t, s, "hunter2")

	// No cookie, no token: a load balancer cannot log in, so /health must
	// answer anyway.
	resp, err := ts.Client().Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /health with auth enabled = %d, want 200", resp.StatusCode)
	}

	var body struct {
		Status        string `json:"status"`
		Version       string `json:"version"`
		UptimeSeconds int64  `json:"uptime_seconds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want %q", body.Status, "ok")
	}
	if body.Version == "" {
		t.Error("version is empty")
	}
	if body.UptimeSeconds < 0 {
		t.Errorf("uptime_seconds = %d, want >= 0", body.UptimeSeconds)
	}
}

// With auth off (the default), /metrics is reachable like the rest of the
// management API, and renders the exposition format.
func TestMetricsExposesPrometheusText(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := ts.Client().Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain...", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	for _, want := range []string{
		"# TYPE webfilter_requests_total counter",
		"# TYPE webfilter_blocks_total counter",
		"# TYPE webfilter_classifier_duration_seconds histogram",
		"webfilter_build_info{",
		"webfilter_start_time_seconds ",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in /metrics output:\n%s", want, body)
		}
	}
}

// The scrape endpoint must not be readable by an anonymous client once the
// operator has turned auth on: it carries per-policy and per-component
// counts.
func TestMetricsRequiresAuthWhenEnabled(t *testing.T) {
	s, ts := newTestServer(t)
	enableAuthOn(t, s, "hunter2")

	resp, err := ts.Client().Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /metrics with auth on = %d, want 401", resp.StatusCode)
	}
}

// A Prometheus scraper cannot hold a session cookie, so a configured bearer
// token is the supported credential.
func TestMetricsAcceptsBearerToken(t *testing.T) {
	s, ts := newTestServer(t)
	enableAuthOn(t, s, "hunter2")

	cfg := s.Settings()
	cfg.MetricsToken = "scrape-me-please"
	if err := s.SaveSettings(cfg); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer scrape-me-please")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bearer-token GET /metrics = %d, want 200", resp.StatusCode)
	}

	// A wrong token must not work...
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	bad, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer bad.Body.Close()
	if bad.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong bearer token = %d, want 401", bad.StatusCode)
	}

	// ...and the token must not unlock anything other than /metrics.
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/settings", nil)
	req.Header.Set("Authorization", "Bearer scrape-me-please")
	other, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /api/settings: %v", err)
	}
	defer other.Body.Close()
	if other.StatusCode != http.StatusUnauthorized {
		t.Errorf("metrics token opened /api/settings (%d); it must be scoped to /metrics", other.StatusCode)
	}
}

// An empty token (the default) must not mean "any empty Authorization
// header is fine" - that would publish counters to anyone.
func TestEmptyMetricsTokenDoesNotOpenMetrics(t *testing.T) {
	s, ts := newTestServer(t)
	enableAuthOn(t, s, "hunter2")

	for _, header := range []string{"", "Bearer ", "Bearer"} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/metrics", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("GET /metrics: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Authorization=%q with empty configured token = %d, want 401", header, resp.StatusCode)
		}
	}
}

func TestMetricsCanBeDisabled(t *testing.T) {
	s, ts := newTestServer(t)
	cfg := s.Settings()
	cfg.MetricsEnabled = false
	if err := s.SaveSettings(cfg); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	resp, err := ts.Client().Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /metrics with metrics_enabled=false = %d, want 404", resp.StatusCode)
	}
}

// metrics_enabled must default to true, so an existing settings.json that
// predates the field still gets the endpoint.
func TestMetricsEnabledDefaultsOnForOldSettingsFiles(t *testing.T) {
	s, _ := newTestServer(t)
	if !s.Settings().MetricsEnabled {
		t.Error("metrics_enabled defaulted to false; old settings.json files would lose the endpoint")
	}
}

func TestHealthNotGatedByMetricsEnabled(t *testing.T) {
	s, ts := newTestServer(t)
	cfg := s.Settings()
	cfg.MetricsEnabled = false
	if err := s.SaveSettings(cfg); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	resp, err := ts.Client().Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /health with metrics disabled = %d, want 200 (health is a separate concern)", resp.StatusCode)
	}
}

// A partial PUT that does not mention the monitoring fields must not reset
// them. settingsOverlay gives partial-update semantics by construction, but
// a future refactor that reintroduced a full-document unmarshal here would
// silently wipe an operator's scrape token.
func TestPartialSettingsUpdateKeepsMetricsFields(t *testing.T) {
	s, ts := newTestServer(t)
	cfg := s.Settings()
	cfg.MetricsToken = "keep-me"
	if err := s.SaveSettings(cfg); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/settings",
		strings.NewReader(`{"ui_language":"fr"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("PUT /api/settings: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d, want 200", resp.StatusCode)
	}

	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["metrics_token"] != "keep-me" {
		t.Errorf("metrics_token = %v after unrelated partial update, want %q", got["metrics_token"], "keep-me")
	}
	if got["metrics_enabled"] != true {
		t.Errorf("metrics_enabled = %v after unrelated partial update, want true", got["metrics_enabled"])
	}
	if s.Settings().MetricsToken != "keep-me" {
		t.Errorf("stored metrics_token = %q, want %q", s.Settings().MetricsToken, "keep-me")
	}
}
