package client

import (
	"context"
	"fmt"
	"strings"

	"github.com/yjlion/llama-web-filter/internal/sitecat"
)

// Verdicts are asked as one-word questions first (see yesNo): the model
// answers yes or no in a single token and the verdict's score is that
// token's probability. Generating a JSON object instead costs 30-100 output
// tokens, which on a small CPU is 0.2-0.5 s each. The JSON prompts below are
// the fallback for servers that return no logprobs and give no plain answer.

const imageQuestionPrompt = `You are a strict content-safety classifier for a family web filter. Look at the image.
Answer yes when it shows nudity (exposed breasts, buttocks or genitals) or sexual activity, or is pornographic or sexually explicit. Swimwear, underwear and suggestive poses alone: answer no.
Answer with one word: yes or no.`

const textQuestionPrompt = `You are a strict content classifier for a family web filter. You are given the title, URL and visible text excerpt of a web page.
Answer yes when the page is pornographic, sexually explicit, an escort/adult-dating site, or primarily sells sexual services or adult products. Sex education, medical information and news reporting are not adult: answer no.
Answer with one word: yes or no.`

const hostQuestionPrompt = `You are classifying a web hostname for an ad blocker, given its name and example URL paths.
Answer yes when the host primarily serves advertisements, tracking/analytics beacons, or affiliate redirects. Be conservative: content delivery networks, APIs and first-party assets are not ads: answer no.
Answer with one word: yes or no.`

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

// siteSystemPrompt names the taxonomy's slugs, with a note only where a
// slug alone is ambiguous. It is built once from internal/sitecat and never
// changes at runtime. It is kept short because the per-slot prompt cache
// cannot hold every kind of prompt at once on a small machine, and each
// time this one is evicted its tokens are paid again (about 30 ms each on
// a small CPU).
var siteSystemPrompt = "You sort websites into categories for a family web filter, from the hostname and, when known, the page title and description. Judge what the site is mainly used for, using what you know about well-known sites.\n" +
	"Categories: " + strings.Join(sitecat.Slugs(), ", ") + "\n" +
	"Notes: chat_messaging is messengers and chat rooms; streaming_video is video sites such as YouTube and Netflix; business is company sites and office tools; ads_tracking is ad networks and analytics; infrastructure is CDNs, APIs, login and asset servers people do not visit directly; other fits nothing else.\n" +
	"Reply with the category only, exactly as written, and nothing else."

// siteJSONPrompt is the full taxonomy with descriptions, for the
// grammar-constrained retry when the short prompt's answer is off-list.
var siteJSONPrompt = func() string {
	var b strings.Builder
	b.WriteString("You sort websites into categories for a family web filter. You are given a hostname and, when known, the page title and description. Judge what the site is mainly used for, using what you know about well-known sites.\n")
	b.WriteString("category is exactly one of:\n")
	for _, c := range sitecat.All() {
		b.WriteString("- " + c.Slug + ": " + c.Description + "\n")
	}
	b.WriteString("Use infrastructure only for hosts people do not visit directly. confidence is 0..1; use a low value when guessing from an unfamiliar name.\n")
	b.WriteString("Reply with exactly one line of compact JSON and nothing else:\n")
	b.WriteString(`{"category":"news","confidence":0.9}`)
	return b.String()
}()

// yesNo asks a one-word question and returns the probability of "yes",
// normalised over yes and no. ok is false when the reply is neither, which
// sends the caller to the JSON prompt. A server without logprobs is read
// from its plain answer with a fixed confidence.
func (c *Client) yesNo(ctx context.Context, system string, user any) (p float64, ok bool, res Response, err error) {
	res, err = c.Chat(ctx, Request{
		Messages:    []Message{{Role: "system", Content: system}, {Role: "user", Content: user}},
		MaxTokens:   1,
		TopLogprobs: 10,
	})
	if err != nil {
		return 0, false, res, err
	}
	var yes, no float64
	for tok, prob := range res.Top {
		switch strings.ToLower(strings.TrimSpace(tok)) {
		case "yes":
			yes += prob
		case "no":
			no += prob
		}
	}
	if yes+no >= 0.5 {
		return yes / (yes + no), true, res, nil
	}
	if res.Top == nil {
		switch strings.ToLower(strings.Trim(res.Content, " \t\n.!")) {
		case "yes":
			return 0.85, true, res, nil
		case "no":
			return 0.15, true, res, nil
		}
	}
	return 0, false, res, nil
}

// odds formats a probability for a verdict's detail text.
func odds(what string, p float64) string { return fmt.Sprintf("p(%s)=%.2f", what, p) }

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
	// Prob is the model's probability of "adult" when the verdict was a
	// one-word answer (FromProb); it is the score as is.
	Prob     float64 `json:"-"`
	FromProb bool    `json:"-"`
}

// Score folds the verdict into a single 0..1 adult probability, which is
// the shape the policy thresholds and the Tools page expect.
func (v ImageVerdict) Score() float64 {
	if v.FromProb {
		return v.Prob
	}
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
	// Prob and FromProb are as in ImageVerdict.
	Prob     float64 `json:"-"`
	FromProb bool    `json:"-"`
}

// Score folds the verdict into a 0..1 adult probability.
func (v TextVerdict) Score() float64 {
	if v.FromProb {
		return v.Prob
	}
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

// SiteVerdict is the model's category for a website.
type SiteVerdict struct {
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
}

var siteSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"category":   map[string]any{"type": "string", "enum": sitecat.Slugs()},
		"confidence": map[string]any{"type": "number", "minimum": 0, "maximum": 1},
	},
	"required":             []string{"category", "confidence"},
	"additionalProperties": false,
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
	if p, ok, res, err := c.yesNo(ctx, imageQuestionPrompt, user); err != nil || ok {
		return ImageVerdict{Adult: p >= 0.5, Nudity: nudityOf(p), Confidence: max(p, 1-p), Description: odds("adult", p), Prob: p, FromProb: true}, res, err
	}
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
	prompt := fmt.Sprintf("URL: %s\nTitle: %s\n\nText:\n%s", truncate(url, 300), truncate(title, 200), truncate(text, textExcerpt))
	if p, ok, res, err := c.yesNo(ctx, textQuestionPrompt, prompt); err != nil || ok {
		return TextVerdict{Adult: p >= 0.5, Confidence: max(p, 1-p), Reason: odds("adult", p), Prob: p, FromProb: true}, res, err
	}
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
	if p, ok, res, err := c.yesNo(ctx, hostQuestionPrompt, prompt); err != nil || ok {
		return HostVerdict{IsAdOrTracker: p >= 0.5, Category: odds("ad", p), Confidence: max(p, 1-p)}, res, err
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

// ClassifySite asks the model which taxonomy category a website belongs to.
// title and description are optional page context; with neither the model
// judges from the hostname (and what it knows about the site).
func (c *Client) ClassifySite(ctx context.Context, host, title, description string) (SiteVerdict, Response, error) {
	prompt := "Host: " + host
	if title = strings.TrimSpace(title); title != "" {
		prompt += "\nTitle: " + truncate(title, 200)
	}
	if description = strings.TrimSpace(description); description != "" {
		prompt += "\nDescription: " + truncate(description, 300)
	}
	res, err := c.Chat(ctx, Request{
		Messages:    []Message{{Role: "system", Content: siteSystemPrompt}, {Role: "user", Content: prompt}},
		MaxTokens:   8,
		Stop:        []string{"\n"},
		TopLogprobs: 1,
	})
	if err != nil {
		return SiteVerdict{}, res, err
	}
	if slug := sitecat.Normalize(strings.Trim(res.Content, " \t\n.\"`*")); slug != "" {
		conf := res.FirstProb
		if res.Top == nil {
			conf = 0.7 // no logprobs: a plain answer, moderately sure
		}
		return SiteVerdict{Category: slug, Confidence: clamp(conf, 0, 1)}, res, nil
	}
	// An off-list category: ask again with the enum enforced by grammar.
	var v SiteVerdict
	retry, err := c.ChatJSON(ctx, Request{
		Messages:   []Message{{Role: "system", Content: siteJSONPrompt}, {Role: "user", Content: prompt}},
		Schema:     siteSchema,
		SchemaName: "site_category",
		MaxTokens:  32,
	}, &v)
	retry.Elapsed += res.Elapsed
	if err == nil {
		// The grammar holds the reply to the enum; a server without
		// grammar support may still answer in its own words.
		if v.Category = sitecat.Normalize(v.Category); v.Category == "" {
			v.Category = sitecat.Other
		}
	}
	v.Confidence = clamp(v.Confidence, 0, 1)
	return v, retry, err
}

// textExcerpt bounds the page text sent to the model. Prompt tokens cost
// about 30 ms each on a small CPU, and a page's title and first paragraphs
// say whether it is adult.
const textExcerpt = 1000

// nudityOf maps a one-word verdict's probability onto the nudity scale of
// the JSON verdict, so callers that test Nudity agree with Adult.
func nudityOf(p float64) int {
	switch {
	case p >= 0.5:
		return 2
	case p >= 0.25:
		return 1
	}
	return 0
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
