package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeServer(t *testing.T, reply string, capture *map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(200)
		case "/v1/chat/completions":
			body, _ := io.ReadAll(r.Body)
			var req map[string]any
			_ = json.Unmarshal(body, &req)
			if capture != nil {
				*capture = req
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []any{map[string]any{"message": map[string]any{"content": reply}, "finish_reason": "stop"}},
				"usage":   map[string]any{"prompt_tokens": 40, "completion_tokens": 12},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestClassifyImageSendsSchemaAndImagePart(t *testing.T) {
	var got map[string]any
	ts := fakeServer(t, `{"adult":true,"nudity":3,"violence":0,"is_ad":false,"confidence":0.9,"description":"explicit"}`, &got)
	defer ts.Close()
	c := New(ts.URL)
	v, res, err := c.ClassifyImage(context.Background(), "image/jpeg", []byte{0xff, 0xd8}, "from example.com")
	if err != nil {
		t.Fatalf("ClassifyImage: %v", err)
	}
	if !v.Adult || v.Nudity != 3 || v.Score() < 0.9 {
		t.Fatalf("verdict = %+v score=%.2f", v, v.Score())
	}
	if res.PromptTokens != 40 || res.CompletionTokens != 12 {
		t.Errorf("usage not captured: %+v", res)
	}
	rf := got["response_format"].(map[string]any)
	if rf["type"] != "json_schema" {
		t.Fatalf("response_format = %v", rf)
	}
	msgs := got["messages"].([]any)
	user := msgs[1].(map[string]any)
	parts := user["content"].([]any)
	img := parts[0].(map[string]any)
	if img["type"] != "image_url" || !strings.HasPrefix(img["image_url"].(map[string]any)["url"].(string), "data:image/jpeg;base64,") {
		t.Fatalf("first part should be the image: %v", img)
	}
	if got["temperature"].(float64) != 0 || got["cache_prompt"] != true {
		t.Errorf("want temperature 0 and cache_prompt true: %v", got)
	}
}

func TestClassifyTextToleratesCodeFence(t *testing.T) {
	ts := fakeServer(t, "```json\n{\"adult\":false,\"categories\":[\"news\"],\"confidence\":0.8,\"reason\":\"news site\"}\n```", nil)
	defer ts.Close()
	v, _, err := New(ts.URL).ClassifyText(context.Background(), "https://x", "X", "some text")
	if err != nil {
		t.Fatal(err)
	}
	if v.Adult || v.Score() > 0.2 || v.Categories[0] != "news" {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestUnavailableOn503AndConnectionError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{"error":{"message":"Loading model"}}`))
	}))
	c := New(ts.URL)
	_, _, err := c.ClassifyHost(context.Background(), "ads.example", nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable on 503, got %v", err)
	}
	ts.Close()
	_, _, err = c.ClassifyHost(context.Background(), "ads.example", nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable on connection error, got %v", err)
	}
}

func TestScoresAreOrdered(t *testing.T) {
	if (ImageVerdict{Nudity: 0, Confidence: 1}).Score() >= (ImageVerdict{Nudity: 1, Confidence: 1}).Score() {
		t.Error("nudity 0 must score below nudity 1")
	}
	if (ImageVerdict{Nudity: 2, Confidence: 1}).Score() >= (ImageVerdict{Nudity: 3, Confidence: 1}).Score() {
		t.Error("nudity 2 must score below nudity 3")
	}
	if (TextVerdict{Adult: true, Confidence: 0.1}).Score() <= 0.5 || (TextVerdict{Adult: false, Confidence: 0.1}).Score() >= 0.5 {
		t.Error("adult flag must decide which side of 0.5 a text verdict lands")
	}
}
