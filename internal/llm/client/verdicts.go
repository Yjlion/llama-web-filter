package client

import (
	"context"
	"fmt"
	"strings"
)

// The system prompts are fixed strings so llama-server's prompt cache
// (--cache-reuse) reuses their KV state across requests; only the user turn
// changes. Keep them short: every token here is paid on every miss. Each
// spells out the reply's exact shape, because requests are first sent
// without a grammar (see classify).

const imageSystemPrompt = `You are a strict content-safety classifier for a family web filter. Look at the image.
nudity scale: 0 = none, 1 = suggestive or swimwear/underwear, 2 = partial nudity (exposed breasts or buttocks), 3 = explicit nudity or sexual activity.
violence scale: 0 = none, 1 = mild, 2 = graphic injury or weapons in use, 3 = gore.
adult is true when nudity >= 2 or the image is pornographic or sexually explicit.
is_ad is true when the image is an advertisement banner, promo creative or sponsored product shot.
Reply with exactly one line of compact JSON and nothing else:
{"adult":false,"nudity":0,"violence":0,"is_ad":false,"confidence":0.9,"description":"at most 12 words"}`

const textSystemPrompt = `You are a strict content classifier for a family web filter. You are given the title, URL and visible text excerpt of a web page.
adult is true when the page is pornographic, sexually explicit, an escort/adult-dating site, or primarily sells sexual services or adult products. Sex education, medical information and news reporting are NOT adult.
categories is a short list from: pornography, adult_dating, gambling, violence, drugs, weapons, hate, news, shopping, social, education, entertainment, technology, other.
Reply with exactly one line of compact JSON and nothing else:
{"adult":false,"categories":["news"],"confidence":0.9,"reason":"one short sentence"}`

const hostSystemPrompt = `You are classifying a web hostname for an ad blocker. Decide whether the host primarily serves advertisements, tracking/analytics beacons, or affiliate redirects, based on its name and the example URL paths. Be conservative: content delivery networks, APIs and first-party assets are NOT ads.
category is one of: ads, tracking, affiliate, cdn, api, content, other.
Reply with exactly one line of compact JSON and nothing else:
{"is_ad_or_tracker":false,"category":"cdn","confidence":0.9}`

// classify asks for a verdict without a grammar first. llama-server's
// JSON-schema grammar costs tens of milliseconds per output token with a
// large vocabulary (Gemma's is 262k) and is not parallelised across slots,
// which measured at half the speed of an unconstrained reply. The prompts
// give the exact shape, so the reply nearly always decodes; when it does
// not (prose, missing or unknown keys, cut off), the request is repeated
// with the schema enforced.
func (c *Client) classify(ctx context.Context, req Request, out any) (Response, error) {
	schema := req.Schema
	req.Schema = nil
	res, err := c.Chat(ctx, req)
	if err != nil {
		return res, err
	}
	required, _ := schema["required"].([]string)
	if err = decodeStrict(res.Content, required, out); err == nil {
		return res, nil
	}
	req.Schema = schema
	retry, err := c.ChatJSON(ctx, req, out)
	retry.Elapsed += res.Elapsed
	return retry, err
}

// ImageVerdict is the model's structured answer for one image.
type ImageVerdict struct {
	Adult       bool    `json:"adult"`
	Nudity      int     `json:"nudity"`
	Violence    int     `json:"violence"`
	IsAd        bool    `json:"is_ad"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

// Score folds the verdict into a single 0..1 adult probability, which is
// the shape the policy thresholds and the Tools page expect.
func (v ImageVerdict) Score() float64 {
	base := []float64{0.02, 0.3, 0.75, 0.97}[clampInt(v.Nudity, 0, 3)]
	if v.Adult && base < 0.9 {
		base = 0.9
	}
	// Scale toward 0.5 by lack of confidence.
	c := clamp(v.Confidence, 0, 1)
	return 0.5 + (base-0.5)*(0.5+0.5*c)
}

// TextVerdict is the model's structured answer for a page's text.
type TextVerdict struct {
	Adult      bool     `json:"adult"`
	Categories []string `json:"categories"`
	Confidence float64  `json:"confidence"`
	Reason     string   `json:"reason"`
}

// Score folds the verdict into a 0..1 adult probability.
func (v TextVerdict) Score() float64 {
	c := clamp(v.Confidence, 0, 1)
	if v.Adult {
		return 0.6 + 0.39*c
	}
	return 0.4 - 0.39*c
}

// HostVerdict is the model's structured answer for an unknown hostname.
type HostVerdict struct {
	IsAdOrTracker bool    `json:"is_ad_or_tracker"`
	Category      string  `json:"category"`
	Confidence    float64 `json:"confidence"`
}

var imageSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"adult":       map[string]any{"type": "boolean"},
		"nudity":      map[string]any{"type": "integer", "minimum": 0, "maximum": 3},
		"violence":    map[string]any{"type": "integer", "minimum": 0, "maximum": 3},
		"is_ad":       map[string]any{"type": "boolean"},
		"confidence":  map[string]any{"type": "number", "minimum": 0, "maximum": 1},
		"description": map[string]any{"type": "string", "maxLength": 120},
	},
	"required":             []string{"adult", "nudity", "violence", "is_ad", "confidence", "description"},
	"additionalProperties": false,
}

var textSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"adult":      map[string]any{"type": "boolean"},
		"categories": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 4},
		"confidence": map[string]any{"type": "number", "minimum": 0, "maximum": 1},
		"reason":     map[string]any{"type": "string", "maxLength": 200},
	},
	"required":             []string{"adult", "categories", "confidence", "reason"},
	"additionalProperties": false,
}

var hostSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"is_ad_or_tracker": map[string]any{"type": "boolean"},
		"category":         map[string]any{"type": "string", "enum": []string{"ads", "tracking", "affiliate", "cdn", "api", "content", "other"}},
		"confidence":       map[string]any{"type": "number", "minimum": 0, "maximum": 1},
	},
	"required":             []string{"is_ad_or_tracker", "category", "confidence"},
	"additionalProperties": false,
}

// ClassifyImage asks the model about one image. mime is the encoded type
// ("image/jpeg"); callers downscale first (see imageprep).
func (c *Client) ClassifyImage(ctx context.Context, mime string, data []byte, hint string) (ImageVerdict, Response, error) {
	user := []Part{ImagePart(mime, data)}
	q := "Classify this image."
	if hint = strings.TrimSpace(hint); hint != "" {
		q += " Context: " + truncate(hint, 200)
	}
	user = append(user, TextPart(q))
	var v ImageVerdict
	res, err := c.classify(ctx, Request{
		Messages:   []Message{{Role: "system", Content: imageSystemPrompt}, {Role: "user", Content: user}},
		Schema:     imageSchema,
		SchemaName: "image_verdict",
		MaxTokens:  96,
	}, &v)
	return v, res, err
}

// ClassifyText asks the model about a page's visible text.
func (c *Client) ClassifyText(ctx context.Context, url, title, text string) (TextVerdict, Response, error) {
	prompt := fmt.Sprintf("URL: %s\nTitle: %s\n\nText:\n%s", truncate(url, 300), truncate(title, 200), truncate(text, 3000))
	var v TextVerdict
	res, err := c.classify(ctx, Request{
		Messages:   []Message{{Role: "system", Content: textSystemPrompt}, {Role: "user", Content: prompt}},
		Schema:     textSchema,
		SchemaName: "text_verdict",
		MaxTokens:  120,
	}, &v)
	return v, res, err
}

// ClassifyHost asks the model whether a hostname is an ad/tracker host.
func (c *Client) ClassifyHost(ctx context.Context, host string, samplePaths []string) (HostVerdict, Response, error) {
	prompt := "Host: " + host
	if len(samplePaths) > 0 {
		prompt += "\nExample paths:\n"
		for i, p := range samplePaths {
			if i >= 5 {
				break
			}
			prompt += "- " + truncate(p, 120) + "\n"
		}
	}
	var v HostVerdict
	res, err := c.classify(ctx, Request{
		Messages:   []Message{{Role: "system", Content: hostSystemPrompt}, {Role: "user", Content: prompt}},
		Schema:     hostSchema,
		SchemaName: "host_verdict",
		MaxTokens:  48,
	}, &v)
	return v, res, err
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
