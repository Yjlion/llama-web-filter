package mgmtapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestRulesCompileSaveListEvaluate(t *testing.T) {
	_, ts := newTestServer(t)
	c := ts.Client()

	// Compile (parser path: no model in tests).
	resp, err := c.Post(ts.URL+"/api/rules/compile", "application/json", strings.NewReader(`{"text":"Block ads on lan, except site www.cnn.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	var compiled struct {
		Rule    json.RawMessage `json:"rule"`
		Summary string          `json:"summary"`
		Source  string          `json:"source"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&compiled); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || compiled.Source != "parser" || !strings.HasPrefix(compiled.Summary, "Block ads for every device on the LAN") {
		t.Fatalf("compile = %d %+v", resp.StatusCode, compiled)
	}

	// Save.
	resp, err = c.Post(ts.URL+"/api/rules", "application/json", strings.NewReader(string(compiled.Rule)))
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		ID      string `json:"id"`
		Summary string `json:"summary"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&saved)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || saved.ID == "" {
		t.Fatalf("save = %d %+v", resp.StatusCode, saved)
	}

	// List.
	var doc struct {
		Rules []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		} `json:"rules"`
	}
	getJSON(t, c, ts.URL+"/api/rules", &doc)
	if len(doc.Rules) != 1 || doc.Rules[0].ID != saved.ID || !doc.Rules[0].Enabled {
		t.Fatalf("list = %+v", doc)
	}

	// Evaluate: LAN client on cnn.com is excluded, elsewhere it applies.
	var ev struct {
		Applied   []any `json:"applied"`
		Effective struct {
			Ads bool `json:"ads"`
		} `json:"effective"`
	}
	getJSON(t, c, ts.URL+"/api/rules/evaluate?client_ip=192.168.1.20&url=https://www.cnn.com/", &ev)
	if len(ev.Applied) != 0 || ev.Effective.Ads {
		t.Fatalf("cnn.com should be excluded: %+v", ev)
	}
	getJSON(t, c, ts.URL+"/api/rules/evaluate?client_ip=192.168.1.20&url=https://news.example/", &ev)
	if len(ev.Applied) != 1 || !ev.Effective.Ads {
		t.Fatalf("rule should apply on other sites: %+v", ev)
	}

	// Disable then delete.
	resp, _ = c.Post(ts.URL+"/api/rules/"+saved.ID+"/enable", "application/json", strings.NewReader(`{"enabled":false}`))
	resp.Body.Close()
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/rules/"+saved.ID, nil)
	resp, err = c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("delete = %v %v", resp.StatusCode, err)
	}
	resp.Body.Close()
	getJSON(t, c, ts.URL+"/api/rules", &doc)
	if len(doc.Rules) != 0 {
		t.Fatalf("rule should be gone: %+v", doc)
	}

	// Nonsense is a 422.
	resp, _ = c.Post(ts.URL+"/api/rules/compile", "application/json", strings.NewReader(`{"text":"make it so"}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("nonsense compile = %d", resp.StatusCode)
	}
}
