package nlp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/llm/client"
	"github.com/yjlion/llama-web-filter/internal/policy/rules"
)

func TestParserHandlesTheReferenceSentences(t *testing.T) {
	c := &Compiler{Devices: map[string][]string{"kids-tablet": {"10.0.0.7"}}, Categories: []string{"gambling", "social"}}
	cases := []struct {
		text    string
		want    string
		target  rules.Target
		action  rules.Action
		sources []string
	}{
		{"Blur all adult images for ip address 10.10.10.10 from 10am to 5pm", "Blur adult images for 10.10.10.10 between 10:00 and 17:00.", rules.TargetAdultImages, rules.ActionBlur, []string{"10.10.10.10"}},
		{"Block ads on lan, except site www.cnn.com", "Block ads for every device on the LAN, except on www.cnn.com.", rules.TargetAds, rules.ActionBlock, []string{"lan"}},
		{"Block adult content for the kids-tablet after 9pm", "Block adult pages for kids-tablet between 21:00 and 23:59.", rules.TargetAdultText, rules.ActionBlock, []string{"kids-tablet"}},
		{"block facebook.com and tiktok.com for 192.168.1.0/24 on weekdays", "Block facebook.com and tiktok.com for 192.168.1.0/24 between 00:00 and 23:59 on mon, tue, wed, thu, fri.", rules.TargetSite, rules.ActionBlock, []string{"192.168.1.0/24"}},
		{"allow ads on www.cnn.com", "Allow ads for everyone on www.cnn.com.", rules.TargetAds, rules.ActionAllow, nil},
		{"Block the gambling category for everyone", "Block the gambling category for every device on the LAN.", rules.TargetCategory, rules.ActionBlock, []string{"lan"}},
		{"Enforce safesearch for the kids-tablet", "Enforce SafeSearch for kids-tablet.", rules.TargetSafeSearch, rules.ActionBlock, []string{"kids-tablet"}},
		{"block the internet for aa:bb:cc:dd:ee:ff between 22:00 and 06:00", "Block all web access for aa:bb:cc:dd:ee:ff between 22:00 and 06:00.", rules.TargetInternet, rules.ActionBlock, []string{"aa:bb:cc:dd:ee:ff"}},
	}
	for _, tc := range cases {
		got, err := c.Compile(context.Background(), tc.text)
		if err != nil {
			t.Errorf("%q: %v", tc.text, err)
			continue
		}
		if got.Summary != tc.want {
			t.Errorf("%q:\n  got  %q\n  want %q", tc.text, got.Summary, tc.want)
		}
		if got.Rule.Target != tc.target || got.Rule.Action != tc.action {
			t.Errorf("%q: target/action = %s/%s", tc.text, got.Rule.Target, got.Rule.Action)
		}
		if strings.Join(got.Rule.Match.Sources, ",") != strings.Join(tc.sources, ",") {
			t.Errorf("%q: sources = %v want %v", tc.text, got.Rule.Match.Sources, tc.sources)
		}
		if got.Source != "parser" || len(got.Warnings) == 0 {
			t.Errorf("%q: parser-only compile must warn that the model was not used: %+v", tc.text, got)
		}
	}
	if _, err := c.Compile(context.Background(), "make it so"); err == nil {
		t.Error("nonsense must fail")
	}
}

func TestCompileUsesModelWhenAvailable(t *testing.T) {
	var seen map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&seen)
		reply := map[string]any{"target": "adult_images", "action": "blur", "value": []string{}, "sources": []string{"10.10.10.10"}, "policy": "",
			"time": map[string]any{"start": "10:00", "end": "17:00", "days": []string{}}, "has_time": true, "sites_include": []string{}, "sites_exclude": []string{}, "confidence": 0.9}
		content, _ := json.Marshal(reply)
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": string(content)}}}})
	}))
	defer ts.Close()
	cli := client.New(ts.URL)
	c := &Compiler{Client: func() *client.Client { return cli }, Devices: map[string][]string{"tv": {"10.0.0.3"}}}
	got, err := c.Compile(context.Background(), "Blur all adult images for ip address 10.10.10.10 from 10am to 5pm")
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "llm" || got.Summary != "Blur adult images for 10.10.10.10 between 10:00 and 17:00." || len(got.Warnings) != 0 {
		t.Fatalf("compiled = %+v", got)
	}
	if !strings.Contains(seen["messages"].([]any)[1].(map[string]any)["content"].(string), "Known device names: tv") {
		t.Fatal("device names must be offered to the model")
	}
	if seen["response_format"].(map[string]any)["json_schema"].(map[string]any)["name"] != "policy_rule" {
		t.Fatal("rule schema must constrain the reply")
	}
}

func TestCompileFlagsHallucinatedOperands(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply := map[string]any{"target": "site", "action": "block", "value": []string{"evil.example"}, "sources": []string{}, "policy": "",
			"time": map[string]any{"start": "", "end": "", "days": []string{}}, "has_time": false, "sites_include": []string{}, "sites_exclude": []string{}, "confidence": 0.4}
		content, _ := json.Marshal(reply)
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": string(content)}}}})
	}))
	defer ts.Close()
	cli := client.New(ts.URL)
	c := &Compiler{Client: func() *client.Client { return cli }}
	got, err := c.Compile(context.Background(), "block that bad site")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Warnings) < 2 {
		t.Fatalf("expected low-confidence and echo warnings, got %v", got.Warnings)
	}
}

func TestParseClock(t *testing.T) {
	cases := map[string]string{"10am": "10:00", "5 pm": "17:00", "12am": "00:00", "12pm": "12:00", "17:30": "17:30", "9": "09:00", "9:05pm": "21:05"}
	for in, want := range cases {
		if got, ok := parseClock(in, false); !ok || got != want {
			t.Errorf("parseClock(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
}
