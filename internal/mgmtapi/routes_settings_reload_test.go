package mgmtapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
)

// restartRequiredFrom PUTs body and returns the restart_required list.
func restartRequiredFrom(t *testing.T, url, body string) []string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, url+"/api/settings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT /api/settings: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d, want 200", resp.StatusCode)
	}
	var got struct {
		RestartRequired []string `json:"restart_required"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got.RestartRequired
}

// A change every consumer reads per request applies immediately, so the API
// must not tell the operator to restart for it.
func TestSettingsPutReportsNoRestartForHotFields(t *testing.T) {
	_, ts := newTestServer(t)

	got := restartRequiredFrom(t, ts.URL, `{"ui_language":"de"}`)
	if len(got) != 0 {
		t.Errorf("restart_required = %v, want empty for a hot-only change", got)
	}
}

// Listener and port changes need a rebind, so they must be named.
func TestSettingsPutNamesRestartRequiredFields(t *testing.T) {
	_, ts := newTestServer(t)

	got := restartRequiredFrom(t, ts.URL, `{"mgmt_port":8123,"ui_language":"fr"}`)
	if len(got) != 1 || got[0] != "mgmt_port" {
		t.Errorf("restart_required = %v, want [mgmt_port] (ui_language is hot)", got)
	}
}

// The field must always be present and an array, so the UI can check its
// length without a null guard.
func TestSettingsPutAlwaysIncludesRestartRequired(t *testing.T) {
	_, ts := newTestServer(t)

	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/settings",
		strings.NewReader(`{"ui_language":"en"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	v, ok := raw["restart_required"]
	if !ok {
		t.Fatal("response has no restart_required field")
	}
	if !strings.HasPrefix(string(v), "[") {
		t.Errorf("restart_required = %s, want a JSON array (never null)", v)
	}
}

// The in-process hook is what makes `run` apply a save instantly instead of
// waiting on the file watcher.
func TestSaveSettingsInvokesOnSettingsSaved(t *testing.T) {
	s, _ := newTestServer(t)

	var got models.GlobalSettings
	called := 0
	s.OnSettingsSaved = func(n models.GlobalSettings) {
		called++
		got = n
	}

	cfg := s.Settings()
	cfg.UILanguage = "es"
	if err := s.SaveSettings(cfg); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	if called != 1 {
		t.Errorf("OnSettingsSaved called %d times, want 1", called)
	}
	if got.UILanguage != "es" {
		t.Errorf("hook received ui_language = %q, want %q", got.UILanguage, "es")
	}
}
