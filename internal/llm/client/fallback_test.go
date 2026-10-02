package client

import (
	"context"
	"encoding/json"
	"io"
	"math"
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
			ts := sequenceServer(t, []string{first, first, goodText}, &schemas)
			defer ts.Close()
			v, _, err := New(ts.URL).ClassifyText(context.Background(), "https://x", "X", "some text")
			if err != nil {
				t.Fatal(err)
			}
			if !v.Adult || v.Confidence != 0.95 || len(v.Categories) != 1 {
				t.Fatalf("verdict = %+v, want the retry's answer", v)
			}
			// The one-word question, the JSON prompt, then the grammar.
			if len(schemas) != 3 || schemas[0] || schemas[1] || !schemas[2] {
				t.Fatalf("requests with schema = %v, want [false false true]", schemas)
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
	if len(schemas) != 2 || schemas[0] || schemas[1] {
		t.Fatalf("requests with schema = %v, want the question and the JSON prompt, both without", schemas)
	}
}

func TestClassifyHostDecodesWithoutGrammar(t *testing.T) {
	var schemas []bool
	ts := sequenceServer(t, []string{`{"is_ad_or_tracker":true,"category":"ads","confidence":0.8}`}, &schemas)
	defer ts.Close()
	v, _, err := New(ts.URL).ClassifyHost(context.Background(), "ads.example", []string{"/banner.js"})
	if err != nil || !v.IsAdOrTracker || v.Category != "ads" || len(schemas) != 2 || schemas[1] {
		t.Fatalf("verdict = %+v, err = %v, schemas = %v", v, err, schemas)
	}
}

func TestClassifySite(t *testing.T) {
	var schemas []bool
	ts := sequenceServer(t, []string{"Social Media\n"}, &schemas)
	defer ts.Close()
	v, _, err := New(ts.URL).ClassifySite(context.Background(), "www.facebook.com", "", "")
	if err != nil || v.Category != "social_media" || v.Confidence != 0.7 {
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

// logprobServer answers like llama-server with logprobs on: content plus
// the first token's candidates and their probabilities.
func logprobServer(t *testing.T, content string, top map[string]float64, capture *map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if capture != nil {
			_ = json.Unmarshal(body, capture)
		}
		var cands []any
		for tok, p := range top {
			cands = append(cands, map[string]any{"token": tok, "logprob": math.Log(p)})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{
				"message":       map[string]any{"content": content},
				"finish_reason": "length",
				"logprobs":      map[string]any{"content": []any{map[string]any{"token": content, "logprob": math.Log(top[content]), "top_logprobs": cands}}},
			}},
		})
	}))
}

func TestOneWordVerdictsReadLogprobs(t *testing.T) {
	var got map[string]any
	ts := logprobServer(t, "yes", map[string]float64{"yes": 0.6, "Yes": 0.2, "no": 0.1, "Based": 0.1}, &got)
	defer ts.Close()
	c := New(ts.URL)

	v, _, err := c.ClassifyText(context.Background(), "https://x", "X", "some text")
	if err != nil {
		t.Fatal(err)
	}
	// yes+Yes = 0.8 against no = 0.1.
	if !v.Adult || math.Abs(v.Score()-0.8/0.9) > 1e-9 {
		t.Fatalf("text verdict = %+v score=%.3f", v, v.Score())
	}
	if got["max_tokens"].(float64) != 1 || got["logprobs"] != true || got["top_logprobs"].(float64) < 2 {
		t.Fatalf("want a one-token request with logprobs, got %v", got)
	}
	if _, ok := got["response_format"]; ok {
		t.Fatal("the one-word question needs no grammar")
	}

	img, _, err := c.ClassifyImage(context.Background(), "image/jpeg", []byte{0xff, 0xd8}, "")
	if err != nil || !img.Adult || img.Nudity < 2 || img.Score() < 0.8 {
		t.Fatalf("image verdict = %+v err=%v", img, err)
	}
	host, _, err := c.ClassifyHost(context.Background(), "ads.example", nil)
	if err != nil || !host.IsAdOrTracker || host.Confidence < 0.8 {
		t.Fatalf("host verdict = %+v err=%v", host, err)
	}
}

func TestOneWordVerdictWithoutLogprobs(t *testing.T) {
	var schemas []bool
	ts := sequenceServer(t, []string{"No."}, &schemas)
	defer ts.Close()
	v, _, err := New(ts.URL).ClassifyText(context.Background(), "https://x", "X", "some text")
	if err != nil || v.Adult || v.Score() >= 0.5 || len(schemas) != 1 {
		t.Fatalf("verdict = %+v err=%v requests=%d", v, err, len(schemas))
	}
}

func TestClassifySiteConfidenceFromLogprobs(t *testing.T) {
	ts := logprobServer(t, "news", map[string]float64{"news": 0.55, "sports": 0.45}, nil)
	defer ts.Close()
	v, _, err := New(ts.URL).ClassifySite(context.Background(), "obscure.example", "", "")
	if err != nil || v.Category != "news" || math.Abs(v.Confidence-0.55) > 1e-9 {
		t.Fatalf("v=%+v err=%v", v, err)
	}
}
