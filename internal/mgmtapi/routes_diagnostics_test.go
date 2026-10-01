package mgmtapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
)

func TestClassifierHealthReportsScannerBackend(t *testing.T) {
	_, ts := newTestServer(t)

	var body map[string]any
	resp := getJSON(t, ts.Client(), ts.URL+"/api/tools/classifier-health", &body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	textHealth := body["text_classifier"].(map[string]any)
	if textHealth["status"] != "available" || textHealth["available"] != true {
		t.Fatalf("text_classifier = %v, want available", textHealth)
	}
	imageHealth := body["image_classifier"].(map[string]any)
	if imageHealth["status"] != "available" {
		t.Fatalf("image_classifier = %v, want available", imageHealth)
	}
}

func TestPolicySimulatorReportsBlockedURL(t *testing.T) {
	s, ts := newTestServer(t)

	p := models.NewPolicy()
	p.Name = "kids"
	p.SourceIPs = []string{"192.168.1.0/24"}
	p.UrlFilter.Enabled = true
	p.UrlFilter.Block = []string{"*.example.com"}
	if err := s.Policies.Create(p); err != nil {
		t.Fatalf("create policy: %v", err)
	}

	resp, err := ts.Client().Post(ts.URL+"/api/tools/policy-simulate", "application/json", strings.NewReader(`{
		"client_ip": "192.168.1.50",
		"url": "https://www.example.com/page"
	}`))
	if err != nil {
		t.Fatalf("POST policy-simulate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["policy"] != "kids" || body["action"] != "blocked" {
		t.Fatalf("body = %v, want kids blocked", body)
	}
	match := body["policy_match"].(map[string]any)
	if match["tier"] != "cidr" {
		t.Fatalf("policy_match = %v, want cidr tier", match)
	}
}
