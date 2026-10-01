// Package nlp compiles a natural-language sentence into a structured rule.
// The edge model does the understanding, constrained by a JSON schema so
// the answer always parses; a small keyword parser covers the common
// sentence shapes when the model is unavailable, and doubles as a
// deterministic test oracle.
package nlp

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/yjlion/llama-web-filter/internal/llm/client"
	"github.com/yjlion/llama-web-filter/internal/policy/rules"
)

// Compiled is the result shown to the user before saving.
type Compiled struct {
	Rule     rules.Rule `json:"rule"`
	Summary  string     `json:"summary"`  // deterministic paraphrase of Rule
	Source   string     `json:"source"`   // "llm" or "parser"
	Warnings []string   `json:"warnings"` // things the user should check
}

// Compiler turns text into rules.
type Compiler struct {
	// Client is the model; nil means parser-only.
	Client func() *client.Client
	// Devices are the known device aliases, offered to the model.
	Devices map[string][]string
	// Policies are the known policy names.
	Policies []string
	// Categories are the known blocklist category names.
	Categories []string
}

const systemPrompt = `You convert one sentence of a home web-filter policy into a JSON rule. Answer only with JSON matching the schema.

Fields:
- target: what the sentence is about. adult_images (nude/explicit pictures), adult_text (adult/porn web pages), ads (advertisements and trackers), site (specific websites, put the hostnames in value), category (a blocklist category name, put it in value), safesearch, youtube (channel names in value), internet (all web access).
- action: block, allow, blur (adult_images only), checkerboard (adult_images only). "Hide", "censor", "pixelate" mean blur. "Stop", "ban", "disable", "no" mean block. "Permit", "let", "enable", "unblock" mean allow.
- sources: who the rule is for. IP addresses, CIDR ranges, MAC addresses, device names from the list, "lan" for the whole local network, or empty for everyone. "lan", "the network", "all devices", "everyone at home" mean ["lan"].
- time: a daily window {start:"HH:MM", end:"HH:MM", days:["mon",...]} in 24-hour time, only when the sentence gives one. "10am to 5pm" is 10:00-17:00. "school nights" are sun-thu evenings. Omit days when every day.
- sites_include: only apply on these sites, when the sentence restricts it ("on youtube.com").
- sites_exclude: do not apply on these sites ("except www.cnn.com").
Never invent hosts, devices or times that are not in the sentence.`

var schema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"target":        map[string]any{"type": "string", "enum": targetsAsStrings()},
		"action":        map[string]any{"type": "string", "enum": actionsAsStrings()},
		"value":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 20},
		"sources":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 20},
		"policy":        map[string]any{"type": "string"},
		"time":          map[string]any{"type": "object", "properties": map[string]any{"start": map[string]any{"type": "string"}, "end": map[string]any{"type": "string"}, "days": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}, "required": []string{"start", "end", "days"}, "additionalProperties": false},
		"has_time":      map[string]any{"type": "boolean"},
		"sites_include": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 20},
		"sites_exclude": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 20},
		"confidence":    map[string]any{"type": "number", "minimum": 0, "maximum": 1},
	},
	"required":             []string{"target", "action", "value", "sources", "policy", "time", "has_time", "sites_include", "sites_exclude", "confidence"},
	"additionalProperties": false,
}

func targetsAsStrings() []string {
	out := []string{}
	for _, t := range rules.Targets {
		out = append(out, string(t))
	}
	return out
}

func actionsAsStrings() []string {
	out := []string{}
	for _, a := range rules.Actions {
		out = append(out, string(a))
	}
	return out
}

type modelRule struct {
	Target       string           `json:"target"`
	Action       string           `json:"action"`
	Value        []string         `json:"value"`
	Sources      []string         `json:"sources"`
	Policy       string           `json:"policy"`
	Time         rules.TimeWindow `json:"time"`
	HasTime      bool             `json:"has_time"`
	SitesInclude []string         `json:"sites_include"`
	SitesExclude []string         `json:"sites_exclude"`
	Confidence   float64          `json:"confidence"`
}

// ErrEmpty is returned for a blank sentence.
var ErrEmpty = errors.New("enter a sentence")

// Compile turns text into a validated rule. It tries the model first and
// falls back to the parser; a model answer that fails validation is also
// retried with the parser, and the error reported when both fail.
func (c *Compiler) Compile(ctx context.Context, text string) (Compiled, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return Compiled{}, ErrEmpty
	}
	var cli *client.Client
	if c.Client != nil {
		cli = c.Client()
	}
	var firstErr error
	if cli != nil {
		out, err := c.compileLLM(ctx, cli, text)
		if err == nil {
			return out, nil
		}
		firstErr = err
	}
	out, err := c.compileParser(text)
	if err != nil {
		if firstErr != nil {
			return Compiled{}, fmt.Errorf("model: %v; parser: %w", firstErr, err)
		}
		return Compiled{}, err
	}
	switch {
	case cli == nil:
		out.Warnings = append(out.Warnings, "The model is not running; this rule was built by the simple parser. Check it carefully.")
	case firstErr != nil:
		out.Warnings = append(out.Warnings, "The model's answer could not be used ("+firstErr.Error()+"); this rule was built by the simple parser. Check it carefully.")
	}
	return out, nil
}

func (c *Compiler) compileLLM(ctx context.Context, cli *client.Client, text string) (Compiled, error) {
	var ctxLines []string
	if names := rules.DeviceNames(c.Devices); len(names) > 0 {
		ctxLines = append(ctxLines, "Known device names: "+strings.Join(names, ", "))
	}
	if len(c.Policies) > 0 {
		ctxLines = append(ctxLines, "Known policy names: "+strings.Join(c.Policies, ", "))
	}
	if len(c.Categories) > 0 {
		ctxLines = append(ctxLines, "Known categories: "+strings.Join(c.Categories, ", "))
	}
	user := "Sentence: " + text
	if len(ctxLines) > 0 {
		user = strings.Join(ctxLines, "\n") + "\n\n" + user
	}
	var mr modelRule
	_, err := cli.ChatJSON(ctx, client.Request{
		Messages:   []client.Message{{Role: "system", Content: systemPrompt}, {Role: "user", Content: user}},
		Schema:     schema,
		SchemaName: "policy_rule",
		MaxTokens:  256,
	}, &mr)
	if err != nil {
		return Compiled{}, err
	}
	r := rules.Rule{
		Enabled: true,
		Text:    text,
		Target:  rules.Target(strings.ToLower(mr.Target)),
		Action:  rules.Action(strings.ToLower(mr.Action)),
		Value:   mr.Value,
		Match: rules.Match{
			Sources: mr.Sources,
			Policy:  mr.Policy,
			Sites:   rules.Sites{Include: mr.SitesInclude, Exclude: mr.SitesExclude},
		},
	}
	if mr.HasTime || (mr.Time.Start != "" && mr.Time.End != "") {
		t := mr.Time
		r.Match.Time = &t
	}
	out := Compiled{Rule: r, Source: "llm"}
	if err := rules.Validate(&out.Rule, c.Devices); err != nil {
		return Compiled{}, err
	}
	out.Summary = rules.Describe(out.Rule)
	if mr.Confidence > 0 && mr.Confidence < 0.6 {
		out.Warnings = append(out.Warnings, "The model was not confident about this reading.")
	}
	out.Warnings = append(out.Warnings, checkEcho(text, out.Rule)...)
	return out, nil
}

// checkEcho flags operands the model produced that do not appear in the
// sentence, the usual sign of a hallucinated host or address.
func checkEcho(text string, r rules.Rule) []string {
	lt := strings.ToLower(text)
	var w []string
	for _, v := range append(append(append([]string{}, r.Value...), r.Match.Sites.Include...), r.Match.Sites.Exclude...) {
		if !strings.Contains(lt, strings.ToLower(strings.TrimPrefix(v, "*."))) {
			w = append(w, fmt.Sprintf("%q does not appear in the sentence.", v))
		}
	}
	for _, s := range r.Match.Sources {
		if s == "lan" || s == "all" {
			continue
		}
		if !strings.Contains(lt, strings.ToLower(s)) {
			w = append(w, fmt.Sprintf("source %q does not appear in the sentence.", s))
		}
	}
	return w
}

// ---- keyword parser ----

var (
	reIP     = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?\b`)
	reMAC    = regexp.MustCompile(`\b([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\b`)
	reHost   = regexp.MustCompile(`\b((?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+)\b`)
	reExcept = regexp.MustCompile(`(?i)\b(?:except|excluding|but not|apart from|other than)\b(?:\s+(?:for|on|the|site|sites|website|websites))*\s+(.+?)(?:[,;]|\.\s|\.$|$| from | between | for | on )`)
	reOnSite = regexp.MustCompile(`(?i)\b(?:only on|on the site|on site|only for site)\s+((?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+)`)
	reRange  = regexp.MustCompile(`(?i)\b(?:from|between)\s+(\d{1,2}(?::\d{2})?\s*(?:am|pm)?)\s*(?:to|-|until|till|and)\s*(\d{1,2}(?::\d{2})?\s*(?:am|pm)?)`)
	reAfter  = regexp.MustCompile(`(?i)\bafter\s+(\d{1,2}(?::\d{2})?\s*(?:am|pm)?)`)
	reBefore = regexp.MustCompile(`(?i)\bbefore\s+(\d{1,2}(?::\d{2})?\s*(?:am|pm)?)`)
	reDays   = regexp.MustCompile(`(?i)\b(mon|tue|wed|thu|fri|sat|sun)[a-z]*\b`)
)

func (c *Compiler) compileParser(text string) (Compiled, error) {
	lt := strings.ToLower(text)
	r := rules.Rule{Enabled: true, Text: text}
	var warnings []string

	// Action. Whole words only: "tablet" contains "let", "stop" is in
	// "stop blocking", so order and boundaries both matter.
	switch {
	case hasWord(lt, "blur", "blurred", "pixelate", "censor", "obscure") || strings.Contains(lt, "hide adult"):
		r.Action = rules.ActionBlur
	case hasWord(lt, "checkerboard"):
		r.Action = rules.ActionCheckerboard
	case hasAny(lt, "don't block", "do not block", "stop blocking", "stop filtering") || hasWord(lt, "allow", "allowed", "permit", "unblock", "let", "enable", "whitelist"):
		r.Action = rules.ActionAllow
	case hasWord(lt, "block", "ban", "stop", "disable", "no", "forbid", "deny", "remove", "filter", "enforce", "require", "force", "turn on"):
		r.Action = rules.ActionBlock
	default:
		return Compiled{}, errors.New("could not tell whether to block, blur or allow")
	}

	// Target.
	exceptPart := ""
	if m := reExcept.FindStringSubmatch(text); m != nil {
		exceptPart = m[1]
	}
	body := text
	if exceptPart != "" {
		body = strings.Replace(body, exceptPart, "", 1)
	}
	lb := strings.ToLower(body)
	switch {
	case hasAny(lb, "adult image", "adult picture", "adult photo", "nude", "nudity", "explicit image", "nsfw image", "porn image", "adult pics", "images"):
		r.Target = rules.TargetAdultImages
	case hasAny(lb, "adult text", "adult page", "adult site", "adult content", "porn", "adult website", "explicit page", "adult material"):
		r.Target = rules.TargetAdultText
	case hasAny(lb, " ads", "advert", "adverts", "advertising", "tracker", "ad "):
		r.Target = rules.TargetAds
	case hasAny(lb, "safesearch", "safe search"):
		r.Target = rules.TargetSafeSearch
	case hasAny(lb, "youtube channel"):
		r.Target = rules.TargetYouTube
	case hasAny(lb, "internet", "all web", "everything", "web access", "the web"):
		r.Target = rules.TargetInternet
	case hasAny(lb, "category"):
		r.Target = rules.TargetCategory
	default:
		r.Target = rules.TargetSite
	}
	if r.Target == rules.TargetAdultImages && r.Action == rules.ActionBlock && hasAny(lt, "blur") {
		r.Action = rules.ActionBlur
	}
	if r.Action == rules.ActionBlur && r.Target != rules.TargetAdultImages {
		r.Action = rules.ActionBlock
	}

	// Sources.
	srcText := body
	for _, m := range reIP.FindAllStringSubmatch(srcText, -1) {
		r.Match.Sources = append(r.Match.Sources, m[1]+m[2])
	}
	for _, m := range reMAC.FindAllStringSubmatch(srcText, -1) {
		r.Match.Sources = append(r.Match.Sources, m[1])
	}
	if hasAny(lb, " lan", "local network", "whole network", "all devices", "every device", "everyone", "the network") {
		r.Match.Sources = append(r.Match.Sources, "lan")
	}
	for name := range c.Devices {
		if strings.Contains(lb, strings.ToLower(name)) {
			r.Match.Sources = append(r.Match.Sources, name)
		}
	}
	for _, p := range c.Policies {
		if p != "" && strings.Contains(lb, "policy "+strings.ToLower(p)) {
			r.Match.Policy = p
		}
	}

	// Hosts: for site targets they are the value; otherwise sites_include.
	hosts := []string{}
	for _, m := range reHost.FindAllStringSubmatch(lb, -1) {
		h := m[1]
		if reIP.MatchString(h) || strings.HasSuffix(h, ".") {
			continue
		}
		hosts = append(hosts, h)
	}
	if exceptPart != "" {
		for _, m := range reHost.FindAllStringSubmatch(strings.ToLower(exceptPart), -1) {
			if !reIP.MatchString(m[1]) {
				r.Match.Sites.Exclude = append(r.Match.Sites.Exclude, m[1])
			}
		}
		if len(r.Match.Sites.Exclude) == 0 {
			ipsExcept := reIP.FindAllStringSubmatch(exceptPart, -1)
			if len(ipsExcept) > 0 {
				warnings = append(warnings, "Exceptions by IP address are not supported; add a second rule for that device instead.")
			}
		}
	}
	if m := reOnSite.FindStringSubmatch(text); m != nil && r.Target != rules.TargetSite {
		r.Match.Sites.Include = append(r.Match.Sites.Include, strings.ToLower(m[1]))
		hosts = removeFrom(hosts, strings.ToLower(m[1]))
	}
	switch r.Target {
	case rules.TargetSite:
		r.Value = hosts
		if len(hosts) == 0 {
			return Compiled{}, errors.New("could not find a website or a recognised target in the sentence")
		}
	case rules.TargetCategory:
		for _, cat := range c.Categories {
			if strings.Contains(lb, strings.ToLower(cat)) {
				r.Value = append(r.Value, cat)
			}
		}
		if len(r.Value) == 0 {
			return Compiled{}, errors.New("no known category named in the sentence")
		}
	case rules.TargetYouTube:
		return Compiled{}, errors.New("YouTube channel rules need the model; use the policy editor's YouTube section instead")
	default:
		if len(hosts) > 0 && len(r.Match.Sites.Include) == 0 {
			r.Match.Sites.Include = hosts
		}
	}

	// Time.
	if m := reRange.FindStringSubmatch(text); m != nil {
		start, ok1 := parseClock(m[1], false)
		end, ok2 := parseClock(m[2], true)
		if ok1 && ok2 {
			r.Match.Time = &rules.TimeWindow{Start: start, End: end}
		}
	} else if m := reAfter.FindStringSubmatch(text); m != nil {
		if start, ok := parseClock(m[1], false); ok {
			r.Match.Time = &rules.TimeWindow{Start: start, End: "23:59"}
		}
	} else if m := reBefore.FindStringSubmatch(text); m != nil {
		if end, ok := parseClock(m[1], true); ok {
			r.Match.Time = &rules.TimeWindow{Start: "00:00", End: end}
		}
	}
	if days := reDays.FindAllStringSubmatch(lt, -1); len(days) > 0 {
		if r.Match.Time == nil {
			r.Match.Time = &rules.TimeWindow{Start: "00:00", End: "23:59"}
		}
		for _, d := range days {
			r.Match.Time.Days = append(r.Match.Time.Days, strings.ToLower(d[1]))
		}
	}
	if hasAny(lt, "weekday", "school day") {
		if r.Match.Time == nil {
			r.Match.Time = &rules.TimeWindow{Start: "00:00", End: "23:59"}
		}
		r.Match.Time.Days = []string{"mon", "tue", "wed", "thu", "fri"}
	}
	if hasAny(lt, "weekend") {
		if r.Match.Time == nil {
			r.Match.Time = &rules.TimeWindow{Start: "00:00", End: "23:59"}
		}
		r.Match.Time.Days = []string{"sat", "sun"}
	}

	if err := rules.Validate(&r, c.Devices); err != nil {
		return Compiled{}, err
	}
	return Compiled{Rule: r, Summary: rules.Describe(r), Source: "parser", Warnings: warnings}, nil
}

// hasWord reports whether any of the words appears in s as a whole word.
func hasWord(s string, words ...string) bool {
	for _, w := range words {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(w) + `\b`).MatchString(s) {
			return true
		}
	}
	return false
}

func hasAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func removeFrom(list []string, v string) []string {
	out := list[:0:0]
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// parseClock turns "10am", "5 pm", "17:30", "9" into HH:MM. A bare hour
// without am/pm is taken as 24-hour; isEnd nudges "12" toward noon.
func parseClock(s string, isEnd bool) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	ampm := ""
	if strings.HasSuffix(s, "am") || strings.HasSuffix(s, "pm") {
		ampm = s[len(s)-2:]
		s = strings.TrimSpace(s[:len(s)-2])
	}
	h, m := 0, 0
	if strings.Contains(s, ":") {
		parts := strings.SplitN(s, ":", 2)
		var err1, err2 error
		h, err1 = strconv.Atoi(parts[0])
		m, err2 = strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return "", false
		}
	} else {
		var err error
		if h, err = strconv.Atoi(s); err != nil {
			return "", false
		}
	}
	switch ampm {
	case "am":
		if h == 12 {
			h = 0
		}
	case "pm":
		if h < 12 {
			h += 12
		}
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return "", false
	}
	return fmt.Sprintf("%02d:%02d", h, m), true
}
