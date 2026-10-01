package mgmtapi_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/mgmtapi"
	"github.com/yjlion/llama-web-filter/internal/models"
)

// newTestServer builds a Server rooted in a temp directory, matching how
// `webfilter mgmt --settings <path>` bootstraps in production. cert_dir/
// policies_dir/logs_dir are pinned to absolute paths inside the same temp
// dir - GlobalSettings' documented defaults for those fields are relative
// ("./certs" etc.), which would otherwise resolve against the test
// process's working directory and leak state between independent
// newTestServer calls (each one otherwise "isolated" only by its own
// settings.json, not by the directories that settings.json points at).
func newTestServer(t *testing.T) (*mgmtapi.Server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "config", "settings.json")

	seed := map[string]any{
		"cert_dir":     filepath.Join(dir, "certs"),
		"policies_dir": filepath.Join(dir, "policies"),
		"logs_dir":     filepath.Join(dir, "logs"),
	}
	data, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal seed settings: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(settingsPath, data, 0o644); err != nil {
		t.Fatalf("write seed settings: %v", err)
	}

	s, err := mgmtapi.NewServer(settingsPath)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.Scanner = stubScanner{}
	t.Cleanup(func() { s.Logs.Close() })
	ts := httptest.NewServer(s.Router())
	t.Cleanup(ts.Close)
	return s, ts
}

func getJSON(t *testing.T, client *http.Client, url string, out any) *http.Response {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	if out != nil {
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode response from %s: %v", url, err)
		}
	}
	return resp
}

func TestIndexServesEmbeddedUI(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html prefix", ct)
	}
}

func TestIndexDoesNotRedirectLoop(t *testing.T) {
	// Regression test: http.FileServer redirects "/index.html" -> "/",
	// which combined with a "/" -> "/index.html" rewrite is an infinite
	// redirect loop. staticHandler must avoid FileServer's canonicalization
	// entirely (see its doc comment).
	_, ts := newTestServer(t)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, path := range []string{"/", "/index.html"} {
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 (no redirect)", path, resp.StatusCode)
		}
	}
}

func TestUnknownPathReturns404JSON(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/nonexistent-xyz")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["detail"] != "Not Found" {
		t.Errorf("body = %v, want {detail: Not Found} (matches FastAPI's default 404 shape)", body)
	}
}

func TestPolicyCRUDFlow(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()

	// First-run bootstrap creates the default policy.
	var list []models.Policy
	getJSON(t, client, ts.URL+"/api/policies", &list)
	if len(list) != 1 || list[0].Name != "default" {
		t.Fatalf("initial list = %v, want bootstrapped default policy", list)
	}

	// Create.
	p := models.NewPolicy()
	p.Name = "kids"
	p.SourceIPs = []string{"192.168.1.0/24"}
	body, _ := json.Marshal(p)
	resp, err := client.Post(ts.URL+"/api/policies", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", resp.StatusCode)
	}

	// Duplicate create -> 409.
	resp2, _ := client.Post(ts.URL+"/api/policies", "application/json", strings.NewReader(string(body)))
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate create status = %d, want 409", resp2.StatusCode)
	}

	// Get.
	var got models.Policy
	r := getJSON(t, client, ts.URL+"/api/policies/kids", &got)
	if r.StatusCode != http.StatusOK || got.Name != "kids" {
		t.Fatalf("get status=%d got=%+v", r.StatusCode, got)
	}

	// Update (rename).
	got.Name = "kids-renamed"
	ub, _ := json.Marshal(got)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/policies/kids", strings.NewReader(string(ub)))
	req.Header.Set("Content-Type", "application/json")
	uresp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	uresp.Body.Close()
	if uresp.StatusCode != http.StatusOK {
		t.Fatalf("update status = %d, want 200", uresp.StatusCode)
	}

	// Old name gone, new name present.
	oldResp, _ := client.Get(ts.URL + "/api/policies/kids")
	oldResp.Body.Close()
	if oldResp.StatusCode != http.StatusNotFound {
		t.Errorf("old name after rename = %d, want 404", oldResp.StatusCode)
	}

	// Delete.
	dreq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/policies/kids-renamed", nil)
	dresp, err := client.Do(dreq)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	dresp.Body.Close()
	if dresp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", dresp.StatusCode)
	}

	// The create/update(rename)/delete sequence above must leave a matching
	// audit trail in the policy_changes log.
	var logBody struct {
		Entries []map[string]any `json:"entries"`
	}
	getJSON(t, client, ts.URL+"/api/logs?kind=policy_changes", &logBody)
	if len(logBody.Entries) != 3 {
		t.Fatalf("policy_changes entries = %d, want 3: %+v", len(logBody.Entries), logBody.Entries)
	}
	// Tail() returns newest first.
	deleted, updated, created := logBody.Entries[0], logBody.Entries[1], logBody.Entries[2]
	if created["action"] != "created" || created["policy_name"] != "kids" {
		t.Errorf("oldest entry = %+v, want created/kids", created)
	}
	if updated["action"] != "updated" || updated["policy_name"] != "kids-renamed" || updated["old_name"] != "kids" {
		t.Errorf("middle entry = %+v, want updated/kids-renamed with old_name=kids", updated)
	}
	if deleted["action"] != "deleted" || deleted["policy_name"] != "kids-renamed" {
		t.Errorf("newest entry = %+v, want deleted/kids-renamed", deleted)
	}
}

func TestPolicyUpdateAcceptsBrowserNumericStrings(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()

	p := models.NewPolicy()
	p.Name = "adult-text"
	body, _ := json.Marshal(p)
	resp, err := client.Post(ts.URL+"/api/policies", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", resp.StatusCode)
	}

	payload := `{
		"name": "adult-text",
		"source_ips": [],
		"source_macs": [],
		"text_classifier": {"enabled": true, "threshold": "0.5", "exclude": [], "include_only": []},
		"image_classifier": {"enabled": false, "action": "blur", "threshold": "0.4", "min_dimension": "100", "exclude": [], "include_only": []}
	}`
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/policies/adult-text", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	uresp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer uresp.Body.Close()
	if uresp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(uresp.Body)
		t.Fatalf("update status = %d, want 200; body=%s", uresp.StatusCode, data)
	}
	var got models.Policy
	if err := json.NewDecoder(uresp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.TextClassifier.Threshold != 0.5 {
		t.Fatalf("TextClassifier.Threshold = %v, want 0.5", got.TextClassifier.Threshold)
	}
}

func TestSettingsGetStripsSecretsAndAddsHasFlags(t *testing.T) {
	s, ts := newTestServer(t)
	cfg := s.Settings()
	cfg.PasswordHash = "pbkdf2_sha256$200000$aa$bb"
	cfg.SecretKey = "supersecret"
	if err := s.SaveSettings(cfg); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	var m map[string]any
	getJSON(t, ts.Client(), ts.URL+"/api/settings", &m)
	if _, present := m["password_hash"]; present {
		t.Errorf("response leaked password_hash: %v", m)
	}
	if _, present := m["secret_key"]; present {
		t.Errorf("response leaked secret_key: %v", m)
	}
	if m["has_password"] != true {
		t.Errorf("has_password = %v, want true", m["has_password"])
	}
}

func TestSettingsUpdateIsPartialMerge(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()

	// Only send mgmt_port; every other field should keep its default.
	resp, err := client.Do(mustRequest(t, http.MethodPut, ts.URL+"/api/settings", `{"mgmt_port": 9001}`))
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()

	if m["mgmt_port"] != float64(9001) {
		t.Errorf("mgmt_port = %v, want 9001", m["mgmt_port"])
	}
	if m["mgmt_hostname"] != "web.filter" {
		t.Errorf("mgmt_hostname = %v, want unchanged default web.filter", m["mgmt_hostname"])
	}
}

func TestSettingsRejectsAuthEnabledWithoutPassword(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := ts.Client().Do(mustRequest(t, http.MethodPut, ts.URL+"/api/settings", `{"auth_enabled": true}`))
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthFlow(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client.Jar = jar

	// Enable auth with a known password.
	resp, err := client.Do(mustRequest(t, http.MethodPut, ts.URL+"/api/settings",
		`{"auth_enabled": true, "new_password": "correcthorse"}`))
	if err != nil {
		t.Fatalf("enable auth: %v", err)
	}
	resp.Body.Close()

	// Without a session cookie, a protected endpoint is 401.
	unauth, _ := client.Get(ts.URL + "/api/status")
	unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/status = %d, want 401", unauth.StatusCode)
	}

	// Wrong password -> 401.
	wrong, _ := client.Post(ts.URL+"/api/login", "application/json", strings.NewReader(`{"password":"nope"}`))
	wrong.Body.Close()
	if wrong.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password login = %d, want 401", wrong.StatusCode)
	}

	// Correct password -> 200, sets cookie.
	right, err := client.Post(ts.URL+"/api/login", "application/json", strings.NewReader(`{"password":"correcthorse"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	right.Body.Close()
	if right.StatusCode != http.StatusOK {
		t.Fatalf("correct password login = %d, want 200", right.StatusCode)
	}

	// Now authenticated.
	authed, _ := client.Get(ts.URL + "/api/status")
	authed.Body.Close()
	if authed.StatusCode != http.StatusOK {
		t.Fatalf("authenticated /api/status = %d, want 200", authed.StatusCode)
	}

	// Logout clears the session.
	lo, _ := client.Post(ts.URL+"/api/logout", "", nil)
	lo.Body.Close()
	after, _ := client.Get(ts.URL + "/api/status")
	after.Body.Close()
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/api/status after logout = %d, want 401", after.StatusCode)
	}
}

func TestPACGeneratesDirectRulesForPrivateRanges(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/proxy.pac")
	if err != nil {
		t.Fatalf("GET /proxy.pac: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	pac := string(data)

	for _, want := range []string{
		"FindProxyForURL",
		`isInNet(host, "10.0.0.0", "255.0.0.0")`,
		`isInNet(host, "192.168.0.0", "255.255.0.0")`,
		"PROXY",
	} {
		if !strings.Contains(pac, want) {
			t.Errorf("PAC output missing %q\nfull output:\n%s", want, pac)
		}
	}
}

func mustRequest(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}
