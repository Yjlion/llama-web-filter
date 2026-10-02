package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Gemma 4 and Qwen3.5 think by default; without the switch the whole token
// budget goes to reasoning_content and content comes back empty.
func TestRequestsDisableThinking(t *testing.T) {
	var got map[string]any
	ts := fakeServer(t, `{"is_ad_or_tracker":false,"category":"cdn","confidence":0.9}`, &got)
	defer ts.Close()
	if _, _, err := New(ts.URL).ClassifyHost(context.Background(), "cdn.example", nil); err != nil {
		t.Fatal(err)
	}
	kw, ok := got["chat_template_kwargs"].(map[string]any)
	if !ok || kw["enable_thinking"] != false {
		t.Fatalf("chat_template_kwargs = %v, want enable_thinking=false", got["chat_template_kwargs"])
	}
}

func TestTruncatedStructuredReplyIsReportedAsCutOff(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"content": "{\n  \"adult\": fal"}, "finish_reason": "length"}},
		})
	}))
	defer ts.Close()
	_, _, err := New(ts.URL).ClassifyText(context.Background(), "https://x", "X", "some text")
	if err == nil || !strings.Contains(err.Error(), "cut off at the 120-token limit") {
		t.Fatalf("err = %v, want a cut-off error", err)
	}
}
