package mgmtapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/llm/client"
	"github.com/yjlion/llama-web-filter/internal/models"
)

func fakeAssistantModel(t *testing.T, reply string) *client.Client {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"content": reply}, "finish_reason": "stop"}},
		})
	}))
	t.Cleanup(ts.Close)
	return client.New(ts.URL)
}

func postJSON(t *testing.T, c *http.Client, url, body string, out any) int {
	t.Helper()
	resp, err := c.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func TestAssistantAskThenApply(t *testing.T) {
	s, ts := newTestServer(t)
	c := ts.Client()
	if _, err := s.Policies.Get("default"); err != nil {
		def := models.NewPolicy()
		def.Name = "default"
		if err := s.Policies.Create(def); err != nil {
			t.Fatal(err)
		}
	}
	empty := `"enabled":false,"mode":"","image_action":"","schedule":{"days":[],"start":"","end":""}`
	cli := fakeAssistantModel(t, `{"reply":"Blocking shopping.","changes":[`+
		`{"op":"block_categories","policy":"default","values":["shopping"],`+empty+`},`+
		`{"op":"block_categories","policy":"default","values":["knitting"],`+empty+`}]}`)

	// Without a model: 503.
	if code := postJSON(t, c, ts.URL+"/api/assistant/ask", `{"message":"block shopping"}`, nil); code != http.StatusServiceUnavailable {
		t.Fatalf("no model = %d", code)
	}
	s.LLMClient = func() *client.Client { return cli }

	var ask struct {
		Reply      string `json:"reply"`
		ProposalID string `json:"proposal_id"`
		Changes    []struct {
			Summary string `json:"summary"`
			Error   string `json:"error"`
		} `json:"changes"`
	}
	if code := postJSON(t, c, ts.URL+"/api/assistant/ask", `{"message":"block shopping","history":[]}`, &ask); code != 200 {
		t.Fatalf("ask = %d", code)
	}
	if ask.ProposalID == "" || len(ask.Changes) != 2 || ask.Changes[0].Error != "" || ask.Changes[1].Error == "" {
		t.Fatalf("ask = %+v", ask)
	}
	if p, _ := s.Policies.Get("default"); p.CategoryFilter.Enabled {
		t.Fatal("asking changed the policy")
	}

	var applied struct {
		Updated []string `json:"updated"`
	}
	if code := postJSON(t, c, ts.URL+"/api/assistant/apply", `{"proposal_id":"`+ask.ProposalID+`","selected":[0,1]}`, &applied); code != 200 {
		t.Fatalf("apply = %d", code)
	}
	if len(applied.Updated) != 1 {
		t.Fatalf("applied = %+v", applied)
	}
	p, _ := s.Policies.Get("default")
	if !p.CategoryFilter.Enabled || len(p.CategoryFilter.Categories) != 1 || p.CategoryFilter.Categories[0] != "shopping" {
		t.Fatalf("policy = %+v", p.CategoryFilter)
	}
	// A proposal applies once.
	if code := postJSON(t, c, ts.URL+"/api/assistant/apply", `{"proposal_id":"`+ask.ProposalID+`","selected":[0]}`, nil); code != http.StatusGone {
		t.Fatalf("second apply = %d", code)
	}
}

func TestAssistantApplyIsLockGated(t *testing.T) {
	s, ts := newTestServer(t)
	lockServer(t, s)
	if code := postJSON(t, ts.Client(), ts.URL+"/api/assistant/apply", `{"proposal_id":"x","selected":[0]}`, nil); code != http.StatusForbidden {
		t.Fatalf("locked apply = %d", code)
	}
}
