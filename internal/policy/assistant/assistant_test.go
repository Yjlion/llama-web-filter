package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/llm/client"
	"github.com/yjlion/llama-web-filter/internal/models"
)

func newStore(t *testing.T, policies ...models.Policy) *config.PolicyStore {
	t.Helper()
	st := config.NewPolicyStore(t.TempDir())
	for _, p := range policies {
		if err := st.Create(p); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

func policy(name string, mut func(*models.Policy)) models.Policy {
	p := models.NewPolicy()
	p.Name = name
	if mut != nil {
		mut(&p)
	}
	return p
}

func get(t *testing.T, st *config.PolicyStore, name string) models.Policy {
	t.Helper()
	p, err := st.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApplyCreatesScheduledPolicyFromDefault(t *testing.T) {
	st := newStore(t, policy("default", func(p *models.Policy) { p.ImageClassifier.Enabled = true }))
	a := &Assistant{Policies: st, Devices: map[string][]string{"Kids-Tablet": {"10.0.0.7", "aa:bb:cc:dd:ee:ff"}}}
	changes := []Change{
		{Op: OpCreatePolicy, Policy: "kids nights", Values: []string{"kids-tablet"}, Schedule: &Schedule{Days: []string{"school_nights"}, Start: "7pm", End: "23:59"}},
		{Op: OpBlockCategories, Policy: "kids nights", Values: []string{"Social Media", "games"}},
	}
	prev, err := a.Preview(changes)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range prev.Changes {
		if c.Error != "" {
			t.Fatalf("change error: %+v", c)
		}
	}
	if len(prev.Diff) != 1 || !prev.Diff[0].Created {
		t.Fatalf("diff = %+v", prev.Diff)
	}
	res, err := a.Apply(changes)
	if err != nil || len(res.Created) != 1 {
		t.Fatalf("apply = %+v, %v", res, err)
	}
	p := get(t, st, "kids nights")
	if len(p.SourceIPs) != 1 || p.SourceIPs[0] != "10.0.0.7" || len(p.SourceMACs) != 1 {
		t.Fatalf("sources = %v %v", p.SourceIPs, p.SourceMACs)
	}
	w := p.Schedule.ActiveWindows
	if !p.Schedule.Enabled || len(w) != 1 || w[0].Start != "19:00" || len(w[0].Days) != 5 {
		t.Fatalf("schedule = %+v", p.Schedule)
	}
	if !p.ImageClassifier.Enabled {
		t.Fatal("new policy did not copy default's settings")
	}
	cf := p.CategoryFilter
	if !cf.Enabled || len(cf.Categories) != 2 || cf.Categories[0] != "social_media" || cf.Categories[1] != "gaming" {
		t.Fatalf("category filter = %+v", cf)
	}
}

func TestCategoryOpsRespectMode(t *testing.T) {
	st := newStore(t, policy("default", nil))
	a := &Assistant{Policies: st}
	if _, err := a.Apply([]Change{{Op: OpAllowOnlyCategories, Values: []string{"education", "kids"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply([]Change{{Op: OpAllowCategories, Values: []string{"news"}}, {Op: OpBlockCategories, Values: []string{"kids"}}}); err != nil {
		t.Fatal(err)
	}
	cf := get(t, st, "default").CategoryFilter
	if cf.Mode != models.UrlFilterModeWhitelist || strings.Join(cf.Categories, ",") != "education,news" {
		t.Fatalf("whitelist = %+v", cf)
	}
}

func TestFeatureAndSiteOps(t *testing.T) {
	st := newStore(t, policy("default", nil), policy("kids", func(p *models.Policy) { p.SourceIPs = []string{"10.0.0.9"} }))
	a := &Assistant{Policies: st}
	res, err := a.Apply([]Change{
		{Op: OpSetAdultImages, Policy: "Kids", Enabled: true, Action: "checkerboard"},
		{Op: OpSetSafeSearch, Policy: "kids", Enabled: true},
		{Op: OpBlockSites, Policy: "kids", Values: []string{"https://www.TikTok.com/"}},
		{Op: OpAllowSites, Policy: "kids", Values: []string{"khanacademy.org"}},
		{Op: OpBlockInternet, Policy: "kids", Enabled: true},
	})
	if err != nil || len(res.Updated) != 1 || len(res.Skipped) != 0 {
		t.Fatalf("apply = %+v %v", res, err)
	}
	p := get(t, st, "kids")
	if !p.ImageClassifier.Enabled || p.ImageClassifier.Action != models.ImageActionCheckerboard || !p.SafeSearch.Enabled {
		t.Fatalf("features = %+v %+v", p.ImageClassifier, p.SafeSearch)
	}
	if !p.UrlFilter.Enabled || strings.Join(p.UrlFilter.Block, ",") != "www.tiktok.com,*" || p.UrlFilter.Allow[0] != "khanacademy.org" {
		t.Fatalf("url filter = %+v", p.UrlFilter)
	}
	if d := get(t, st, "default"); d.SafeSearch.Enabled {
		t.Fatal("default was changed")
	}
}

func TestValidationErrorsAreSkipped(t *testing.T) {
	st := newStore(t, policy("default", nil), policy("kids", nil))
	a := &Assistant{Policies: st}
	prev, _ := a.Preview([]Change{
		{Op: OpBlockCategories, Policy: "kids", Values: []string{"knitting"}},
		{Op: OpSetAds, Policy: "nobody", Enabled: true},
		{Op: OpCreatePolicy, Policy: "x", Values: []string{"the fridge"}},
		{Op: OpSetSchedule, Policy: "kids", Schedule: &Schedule{Days: []string{"funday"}}},
		{Op: OpDeletePolicy, Policy: "default"},
		{Op: "launch_rockets", Policy: "kids"},
		{Op: OpSetAds, Policy: "kids", Enabled: true},
	})
	for i, c := range prev.Changes[:6] {
		if c.Error == "" {
			t.Errorf("change %d accepted: %+v", i, c)
		}
	}
	if prev.Changes[6].Error != "" {
		t.Errorf("valid change rejected: %+v", prev.Changes[6])
	}
	if len(prev.Diff) != 1 || prev.Diff[0].Policy != "kids" {
		t.Fatalf("diff = %+v", prev.Diff)
	}
}

func TestParseClock(t *testing.T) {
	for in, want := range map[string]string{"9pm": "21:00", "9:30 am": "09:30", "21": "21:00", "12am": "00:00", "24:00": "23:59", "noon": "12:00"} {
		if got, err := parseClock(in, ""); err != nil || got != want {
			t.Errorf("parseClock(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := parseClock("25:00", ""); err == nil {
		t.Error("25:00 accepted")
	}
}

func fakeModel(t *testing.T, reply any, sawPrompt *string) *client.Client {
	t.Helper()
	content, _ := json.Marshal(reply)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if sawPrompt != nil {
			*sawPrompt = string(body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"content": string(content)}, "finish_reason": "stop"}},
		})
	}))
	t.Cleanup(ts.Close)
	return client.New(ts.URL)
}

func TestAskReturnsCheckedProposalWithEchoWarnings(t *testing.T) {
	st := newStore(t, policy("default", nil))
	var prompt string
	cli := fakeModel(t, map[string]any{
		"reply": "I'll block shopping and those sites.",
		"changes": []map[string]any{
			{"op": "block_categories", "policy": "default", "values": []string{"shopping"}, "enabled": false, "mode": "", "image_action": "", "schedule": map[string]any{"days": []string{}, "start": "", "end": ""}},
			{"op": "block_sites", "policy": "default", "values": []string{"amazon.com", "ebay.com"}, "enabled": false, "mode": "", "image_action": "", "schedule": map[string]any{"days": []string{}, "start": "", "end": ""}},
		},
	}, &prompt)
	a := &Assistant{Policies: st, Client: func() *client.Client { return cli }}
	p, err := a.Ask(context.Background(), []Turn{{Role: "user", Content: "hi"}, {Role: "assistant", Content: "hello"}}, "Block shopping, especially amazon")
	if err != nil {
		t.Fatal(err)
	}
	if p.Reply == "" || len(p.Changes) != 2 || p.Changes[0].Error != "" {
		t.Fatalf("proposal = %+v", p)
	}
	if len(p.Changes[1].Warnings) != 1 || !strings.Contains(p.Changes[1].Warnings[0], "ebay.com") {
		t.Fatalf("warnings = %v", p.Changes[1].Warnings)
	}
	for _, want := range []string{`"policy_assistant"`, `Policy \"default\"`, "Request: Block shopping", `"hello"`} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt lacks %s", want)
		}
	}
	// Nothing is saved by asking.
	if get(t, st, "default").CategoryFilter.Enabled {
		t.Fatal("Ask saved changes")
	}
}

func TestAskWithoutModel(t *testing.T) {
	a := &Assistant{Policies: newStore(t), Client: func() *client.Client { return nil }}
	if _, err := a.Ask(context.Background(), nil, "block games"); !errors.Is(err, ErrNoModel) {
		t.Fatalf("err = %v", err)
	}
}

func TestSummarizeIsBounded(t *testing.T) {
	var ps []models.Policy
	for i := 0; i < 200; i++ {
		ps = append(ps, policy(strings.Repeat("p", 30)+string(rune('a'+i%26)), func(p *models.Policy) {
			p.UrlFilter.Enabled = true
			p.UrlFilter.Block = []string{"a.com", "b.com", "c.com", "d.com", "e.com", "f.com", "g.com", "h.com", "i.com", "j.com", "k.com", "l.com"}
		}))
	}
	s := Summarize(ps, nil)
	if len(s) > 6100 || !strings.Contains(s, "(+2 more)") {
		t.Fatalf("summary length %d", len(s))
	}
}
