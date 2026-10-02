package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// sequenceServer answers the n-th completion with replies[n] (the last one
// repeats) and records whether each request carried a grammar.
func sequenceServer(t *testing.T, replies []string, withSchema *[]bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		_, has := req["response_format"]
		*withSchema = append(*withSchema, has)
		reply := replies[min(len(*withSchema), len(replies))-1]
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"content": reply}, "finish_reason": "stop"}},
		})
	}))
}

const goodText = `{"adult":true,"categories":["pornography"],"confidence":0.95,"reason":"explicit site"}`

func TestClassifyRetriesWithSchemaOnBadReply(t *testing.T) {
	for name, first := range map[string]string{
		"prose":       "This page looks like a news site.",
		"missing key": `{"adult":true,"categories":["pornography"],"reason":"no confidence"}`,
		"unknown key": `{"adult":true,"categories":[],"confidence":0.9,"reason":"x","verdict":"block"}`,
		"broken JSON": `{"adult":true,"categories":["porn`,
	} {
		t.Run(name, func(t *testing.T) {
			var schemas []bool
			ts := sequenceServer(t, []string{first, goodText}, &schemas)
			defer ts.Close()
			v, _, err := New(ts.URL).ClassifyText(context.Background(), "https://x", "X", "some text")
			if err != nil {
				t.Fatal(err)
			}
			if !v.Adult || v.Confidence != 0.95 || len(v.Categories) != 1 {
				t.Fatalf("verdict = %+v, want the retry's answer", v)
			}
			if len(schemas) != 2 || schemas[0] || !schemas[1] {
				t.Fatalf("requests with schema = %v, want [false true]", schemas)
			}
		})
	}
}

func TestClassifyAcceptsCompactReplyInOneRequest(t *testing.T) {
	var schemas []bool
	ts := sequenceServer(t, []string{"Sure: " + goodText + "\n"}, &schemas)
	defer ts.Close()
	v, _, err := New(ts.URL).ClassifyText(context.Background(), "https://x", "X", "some text")
	if err != nil || !v.Adult {
		t.Fatalf("verdict = %+v, err = %v", v, err)
	}
	if len(schemas) != 1 || schemas[0] {
		t.Fatalf("requests with schema = %v, want one request without", schemas)
	}
}

func TestClassifyHostDecodesWithoutGrammar(t *testing.T) {
	var schemas []bool
	ts := sequenceServer(t, []string{`{"is_ad_or_tracker":true,"category":"ads","confidence":0.8}`}, &schemas)
	defer ts.Close()
	v, _, err := New(ts.URL).ClassifyHost(context.Background(), "ads.example", []string{"/banner.js"})
	if err != nil || !v.IsAdOrTracker || v.Category != "ads" || len(schemas) != 1 {
		t.Fatalf("verdict = %+v, err = %v, schemas = %v", v, err, schemas)
	}
}

func TestClassifySite(t *testing.T) {
	var schemas []bool
	ts := sequenceServer(t, []string{`{"category":"Social Media","confidence":0.8}`}, &schemas)
	defer ts.Close()
	v, _, err := New(ts.URL).ClassifySite(context.Background(), "www.facebook.com", "", "")
	if err != nil || v.Category != "social_media" || v.Confidence != 0.8 {
		t.Fatalf("v=%+v err=%v", v, err)
	}
	if len(schemas) != 1 || schemas[0] {
		t.Fatalf("schemas = %v, want one ungrammared request", schemas)
	}
}

func TestClassifySiteRetriesOffListCategory(t *testing.T) {
	var schemas []bool
	ts := sequenceServer(t, []string{`{"category":"recipes","confidence":0.7}`, `{"category":"other","confidence":0.6}`}, &schemas)
	defer ts.Close()
	v, _, err := New(ts.URL).ClassifySite(context.Background(), "cook.example", "Recipes", "")
	if err != nil || v.Category != "other" {
		t.Fatalf("v=%+v err=%v", v, err)
	}
	if len(schemas) != 2 || !schemas[1] {
		t.Fatalf("schemas = %v, want grammar retry", schemas)
	}
}
