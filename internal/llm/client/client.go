// Package client is a small OpenAI-compatible chat client aimed at
// llama-server: text and image message parts, JSON-schema-constrained
// output, and nothing else.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client sends chat completions to one server.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	// Model is sent as the request's model field; llama-server ignores it
	// (it serves one model) but other OpenAI-compatible servers need it.
	Model string
}

// New returns a client for an OpenAI-compatible base URL such as
// "http://127.0.0.1:8081".
func New(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 120 * time.Second},
		Model:   "default",
	}
}

// Message is one chat turn. Content is either a plain string or a slice of
// Part for multimodal turns.
type Message struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

// Part is one content part of a multimodal message.
type Part struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	ImageURL *ImageURL `json:"image_url,omitempty"`
}

// ImageURL carries an image as a data: URI.
type ImageURL struct {
	URL string `json:"url"`
}

// TextPart builds a text content part.
func TextPart(s string) Part { return Part{Type: "text", Text: s} }

// ImagePart builds an image content part from encoded image bytes.
func ImagePart(mime string, data []byte) Part {
	return Part{Type: "image_url", ImageURL: &ImageURL{URL: "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)}}
}

// Request is a chat completion request. Schema, when set, constrains the
// output to that JSON schema (llama-server's grammar sampler enforces it,
// so the reply always parses).
type Request struct {
	Messages    []Message
	Schema      map[string]any
	SchemaName  string
	MaxTokens   int
	Temperature float64
}

// Response is the first choice's content plus usage, which the status page
// turns into tokens/second.
type Response struct {
	Content          string
	PromptTokens     int
	CompletionTokens int
	Elapsed          time.Duration
}

type wireRequest struct {
	Model          string    `json:"model"`
	Messages       []Message `json:"messages"`
	MaxTokens      int       `json:"max_tokens,omitempty"`
	Temperature    float64   `json:"temperature"`
	Stream         bool      `json:"stream"`
	ResponseFormat any       `json:"response_format,omitempty"`
	CachePrompt    bool      `json:"cache_prompt"`
}

type wireResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// ErrUnavailable is returned when the server cannot be reached or is not
// ready (model still loading).
var ErrUnavailable = errors.New("llm server unavailable")

// Chat performs one completion.
func (c *Client) Chat(ctx context.Context, req Request) (Response, error) {
	wr := wireRequest{
		Model:       c.Model,
		Messages:    req.Messages,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		CachePrompt: true,
	}
	if wr.MaxTokens == 0 {
		wr.MaxTokens = 256
	}
	if req.Schema != nil {
		name := req.SchemaName
		if name == "" {
			name = "response"
		}
		wr.ResponseFormat = map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   name,
				"strict": true,
				"schema": req.Schema,
			},
		}
	}
	body, err := json.Marshal(wr)
	if err != nil {
		return Response{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	started := time.Now()
	resp, err := c.http().Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return Response{}, err
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return Response{}, fmt.Errorf("%w: HTTP 503 %s", ErrUnavailable, strings.TrimSpace(string(data)))
	}
	var wres wireResponse
	if err := json.Unmarshal(data, &wres); err != nil {
		return Response{}, fmt.Errorf("llm: HTTP %d: %s", resp.StatusCode, truncate(string(data), 200))
	}
	if wres.Error != nil {
		return Response{}, fmt.Errorf("llm: %s", wres.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("llm: HTTP %d: %s", resp.StatusCode, truncate(string(data), 200))
	}
	if len(wres.Choices) == 0 {
		return Response{}, errors.New("llm: empty response")
	}
	return Response{
		Content:          wres.Choices[0].Message.Content,
		PromptTokens:     wres.Usage.PromptTokens,
		CompletionTokens: wres.Usage.CompletionTokens,
		Elapsed:          time.Since(started),
	}, nil
}

// ChatJSON performs a schema-constrained completion and decodes the reply
// into out.
func (c *Client) ChatJSON(ctx context.Context, req Request, out any) (Response, error) {
	res, err := c.Chat(ctx, req)
	if err != nil {
		return res, err
	}
	content := strings.TrimSpace(res.Content)
	// Some models wrap JSON in a code fence despite the grammar; tolerate it.
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	if err := json.Unmarshal([]byte(strings.TrimSpace(content)), out); err != nil {
		return res, fmt.Errorf("llm: reply is not the expected JSON: %w (%s)", err, truncate(content, 200))
	}
	return res, nil
}

// Healthy reports whether the server answers /health with 200.
func (c *Client) Healthy(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
