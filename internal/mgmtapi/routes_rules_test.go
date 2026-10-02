package mgmtapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/policy/rules"
)

// Rules saved by earlier versions can still be listed, switched off and
// removed; new rules can no longer be added.
func TestLegacyRulesListDisableDelete(t *testing.T) {
	s, ts := newTestServer(t)
	c := ts.Client()
	saved, err := s.Rules.Add(rules.Rule{Enabled: true, Text: "Block ads on lan", Target: rules.TargetAds, Action: rules.ActionBlock,
		Match: rules.Match{Sources: []string{"lan"}}})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []struct {
			ID      string `json:"id"`
			Summary string `json:"summary"`
		} `json:"rules"`
	}
	getJSON(t, c, ts.URL+"/api/rules", &doc)
	if len(doc.Rules) != 1 || doc.Rules[0].ID != saved.ID || doc.Rules[0].Summary == "" {
		t.Fatalf("list = %+v", doc)
	}
	resp, _ := c.Post(ts.URL+"/api/rules/"+saved.ID+"/enable", "application/json", strings.NewReader(`{"enabled":false}`))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("disable = %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/rules/"+saved.ID, nil)
	resp, err = c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("delete = %v %v", resp.StatusCode, err)
	}
	resp.Body.Close()
	resp, _ = c.Post(ts.URL+"/api/rules", "application/json", strings.NewReader(`{}`))
	resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		t.Fatal("adding rules should be gone")
	}
}
