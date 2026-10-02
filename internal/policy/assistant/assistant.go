// Package assistant lets a person change the filter's policies by talking
// to the edge LLM: "block shopping and social media on the kids' tablet on
// school nights", "what would you recommend for a ten-year-old?". The model
// answers in plain language and proposes a list of small typed changes;
// this package checks each against the real policies, shows the before and
// after, and applies only what the person confirms.
package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/yjlion/llama-web-filter/internal/llm/client"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/sitecat"
)

// PolicyStore is the part of config.PolicyStore the assistant uses.
type PolicyStore interface {
	List() ([]models.Policy, error)
	Create(p models.Policy) error
	Update(oldName string, p models.Policy) error
	Delete(name string) error
}

// Turn is one message of the conversation so far.
type Turn struct {
	Role    string `json:"role"` // "user" or "assistant"
	Content string `json:"content"`
}

// Assistant answers requests about the policies.
type Assistant struct {
	// Client returns the model client, or nil when the model is not ready.
	Client   func() *client.Client
	Policies PolicyStore
	// Devices maps friendly device names to IPs/MACs/CIDRs.
	Devices map[string][]string
}

// ChangeView is a proposed change as the person sees it.
type ChangeView struct {
	Change
	Summary  string   `json:"summary"`
	Error    string   `json:"error,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// FieldDiff is one setting that would change.
type FieldDiff struct {
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// PolicyDiff is everything that would change in one policy.
type PolicyDiff struct {
	Policy  string      `json:"policy"`
	Created bool        `json:"created,omitempty"`
	Deleted bool        `json:"deleted,omitempty"`
	Fields  []FieldDiff `json:"fields,omitempty"`
}

// Proposal is the assistant's answer to one message.
type Proposal struct {
	Reply   string       `json:"reply"`
	Changes []ChangeView `json:"changes"`
	Diff    []PolicyDiff `json:"diff"`
}

// ErrNoModel is returned when the model is not running.
var ErrNoModel = errors.New("the model is not running, so the assistant cannot answer; check the LLM page")

// maxHistory is how many earlier turns are sent back to the model; the
// per-slot context is small.
const maxHistory = 6

// Ask sends message (with the recent history) to the model and returns its
// reply and checked proposal.
func (a *Assistant) Ask(ctx context.Context, history []Turn, message string) (Proposal, error) {
	message = strings.TrimSpace(message)
	if message == "" {
		return Proposal{}, errors.New("type what you would like to change or ask")
	}
	var cli *client.Client
	if a.Client != nil {
		cli = a.Client()
	}
	if cli == nil {
		return Proposal{}, ErrNoModel
	}
	// A whole reply can outlast the client's per-request timeout on a CPU;
	// the caller's context (llm.budget.compile_ms) bounds it instead.
	long := *cli
	long.HTTP = &http.Client{}
	cli = &long
	policies, err := a.Policies.List()
	if err != nil {
		return Proposal{}, err
	}
	msgs := []client.Message{{Role: "system", Content: systemPrompt}}
	if len(history) > maxHistory {
		history = history[len(history)-maxHistory:]
	}
	for _, t := range history {
		role := "user"
		if t.Role == "assistant" {
			role = "assistant"
		}
		msgs = append(msgs, client.Message{Role: role, Content: truncate(t.Content, 1200)})
	}
	msgs = append(msgs, client.Message{Role: "user", Content: "Current setup:\n" + Summarize(policies, a.Devices) + "\nRequest: " + message})

	var out modelReply
	if _, err := cli.ChatJSON(ctx, client.Request{
		Messages: msgs, Schema: replySchema, SchemaName: "policy_assistant", MaxTokens: 1600,
	}, &out); err != nil {
		return Proposal{}, fmt.Errorf("the model's answer could not be used: %w", err)
	}
	p := a.preview(policies, out.Changes)
	p.Reply = strings.TrimSpace(out.Reply)
	if p.Reply == "" && len(p.Changes) == 0 {
		p.Reply = "I did not understand that. Try saying who it is for and what to block or allow."
	}
	echoWarnings(&p, message, history, a.Devices, policies)
	return p, nil
}

// Preview checks changes against the current policies without saving.
func (a *Assistant) Preview(changes []Change) (Proposal, error) {
	policies, err := a.Policies.List()
	if err != nil {
		return Proposal{}, err
	}
	return a.preview(policies, changes), nil
}

func (a *Assistant) preview(policies []models.Policy, changes []Change) Proposal {
	w := newWorkset(policies, lowerKeys(a.Devices))
	p := Proposal{Changes: []ChangeView{}}
	seen := map[string]bool{}
	for _, c := range changes {
		c.Op = Op(strings.ToLower(strings.TrimSpace(string(c.Op))))
		// Small models sometimes repeat a change verbatim; show it once.
		if k, _ := json.Marshal(c); seen[string(k)] {
			continue
		} else {
			seen[string(k)] = true
		}
		v := ChangeView{Change: c}
		if sum, err := w.apply(c); err != nil {
			v.Error = err.Error()
			v.Summary = describeFailed(c)
		} else {
			v.Summary = sum
		}
		p.Changes = append(p.Changes, v)
	}
	p.Diff = w.diff()
	return p
}

// Applied reports what Apply wrote.
type Applied struct {
	Created []string `json:"created"`
	Updated []string `json:"updated"`
	Deleted []string `json:"deleted"`
	Skipped []string `json:"skipped"`
}

// Apply re-checks changes against the policies as they are now and saves
// the ones that still apply. A change that fails is skipped, not fatal.
func (a *Assistant) Apply(changes []Change) (Applied, error) {
	policies, err := a.Policies.List()
	if err != nil {
		return Applied{}, err
	}
	w := newWorkset(policies, lowerKeys(a.Devices))
	res := Applied{Created: []string{}, Updated: []string{}, Deleted: []string{}, Skipped: []string{}}
	for _, c := range changes {
		c.Op = Op(strings.ToLower(strings.TrimSpace(string(c.Op))))
		if _, err := w.apply(c); err != nil {
			res.Skipped = append(res.Skipped, describeFailed(c)+": "+err.Error())
		}
	}
	for _, k := range w.order {
		switch {
		case w.deleted[k] && w.created[k]:
			continue
		case w.deleted[k]:
			if err := a.Policies.Delete(w.original[k].Name); err != nil {
				return res, err
			}
			res.Deleted = append(res.Deleted, w.original[k].Name)
		case w.created[k]:
			if err := a.Policies.Create(*w.byName[k]); err != nil {
				return res, err
			}
			res.Created = append(res.Created, w.byName[k].Name)
		default:
			if len(diffPolicies(w.original[k], *w.byName[k])) == 0 {
				continue
			}
			if err := a.Policies.Update(w.original[k].Name, *w.byName[k]); err != nil {
				return res, err
			}
			res.Updated = append(res.Updated, w.byName[k].Name)
		}
	}
	return res, nil
}

func describeFailed(c Change) string {
	s := strings.ReplaceAll(string(c.Op), "_", " ")
	if c.Policy != "" {
		s = c.Policy + ": " + s
	}
	if len(c.Values) > 0 {
		s += " " + strings.Join(c.Values, ", ")
	}
	return s
}

func lowerKeys(m map[string][]string) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[strings.ToLower(k)] = v
	}
	return out
}

// ---- diff ----

func (w *workset) diff() []PolicyDiff {
	out := []PolicyDiff{}
	for _, k := range w.order {
		switch {
		case w.deleted[k] && w.created[k]:
		case w.deleted[k]:
			out = append(out, PolicyDiff{Policy: w.original[k].Name, Deleted: true})
		case w.created[k]:
			out = append(out, PolicyDiff{Policy: w.byName[k].Name, Created: true, Fields: diffPolicies(models.Policy{}, *w.byName[k])})
		default:
			if f := diffPolicies(w.original[k], *w.byName[k]); len(f) > 0 {
				out = append(out, PolicyDiff{Policy: w.byName[k].Name, Fields: f})
			}
		}
	}
	return out
}

// diffPolicies lists the settings that differ, by dotted JSON path. A new
// policy (before = zero value) lists only its notable settings.
func diffPolicies(before, after models.Policy) []FieldDiff {
	isNew := before.Name == "" && after.Name != ""
	b, a := flatten(before), flatten(after)
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var out []FieldDiff
	for _, k := range keys {
		if b[k] == a[k] {
			continue
		}
		if isNew && !notableOnCreate(k, a[k]) {
			continue
		}
		before := b[k]
		if isNew {
			before = ""
		}
		out = append(out, FieldDiff{Field: k, Before: before, After: a[k]})
	}
	return out
}

func notableOnCreate(field, value string) bool {
	switch {
	case field == "name", field == "source_ips", field == "source_macs", strings.HasPrefix(field, "schedule"):
		return value != "" && value != "[]" && value != "false"
	case strings.HasSuffix(field, ".enabled"):
		return value == "true"
	case field == "category_filter.categories", field == "category_filter.mode",
		field == "url_filter.block", field == "url_filter.allow":
		return value != "[]"
	}
	return false
}

func flatten(p models.Policy) map[string]string {
	raw, _ := json.Marshal(p)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	out := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		if obj, ok := v.(map[string]any); ok && prefix != "safesearch.engines" {
			for k, child := range obj {
				key := k
				if prefix != "" {
					key = prefix + "." + k
				}
				walk(key, child)
			}
			return
		}
		b, _ := json.Marshal(v)
		out[prefix] = string(b)
	}
	walk("", m)
	return out
}

// ---- context for the model ----

// Summarize renders the policies compactly for the model's prompt.
func Summarize(policies []models.Policy, devices map[string][]string) string {
	var b strings.Builder
	for _, p := range policies {
		fmt.Fprintf(&b, "Policy %q", p.Name)
		if p.Inactive {
			b.WriteString(" (turned off)")
		}
		b.WriteString(": for ")
		srcs := append(append([]string{}, p.SourceIPs...), p.SourceMACs...)
		if len(srcs) == 0 {
			b.WriteString("every device not matched by another policy")
		} else {
			b.WriteString(strings.Join(limit(srcs, 8), ", "))
		}
		if p.Schedule.Enabled && len(p.Schedule.ActiveWindows) > 0 {
			var ws []string
			for _, w := range p.Schedule.ActiveWindows {
				var ds []string
				for _, d := range w.Days {
					if d >= 0 && d < 7 {
						ds = append(ds, strings.ToLower(dayNames[d]))
					}
				}
				ws = append(ws, strings.Join(ds, ",")+" "+w.Start+"-"+w.End)
			}
			b.WriteString("; active only " + strings.Join(ws, "; "))
		}
		b.WriteString("\n  ")
		var on []string
		if p.ImageClassifier.Enabled {
			on = append(on, string(p.ImageClassifier.Action)+" adult images")
		}
		if p.TextClassifier.Enabled {
			on = append(on, "block adult pages")
		}
		if p.VideoClassifier.Enabled {
			on = append(on, "block adult videos")
		}
		if p.AdBlock.Enabled {
			on = append(on, "block ads")
		}
		if p.SafeSearch.Enabled {
			on = append(on, "SafeSearch")
		}
		if p.Doh.Enabled {
			on = append(on, "DoH filter")
		}
		if p.YouTube.Enabled {
			on = append(on, fmt.Sprintf("YouTube %s %s", p.YouTube.Mode, strings.Join(limit(p.YouTube.Channels, 5), ",")))
		}
		if len(on) == 0 {
			on = append(on, "no content filters")
		}
		b.WriteString(strings.Join(on, "; "))
		cf := p.CategoryFilter
		if cf.Enabled {
			if cf.Mode == models.UrlFilterModeWhitelist {
				b.WriteString("\n  site categories: allow only " + strings.Join(cf.Categories, ", "))
			} else if len(cf.Categories) > 0 {
				b.WriteString("\n  site categories blocked: " + strings.Join(cf.Categories, ", "))
			}
		}
		if p.UrlFilter.Enabled {
			if len(p.UrlFilter.Block) > 0 {
				b.WriteString("\n  blocked sites: " + strings.Join(limit(p.UrlFilter.Block, 10), ", "))
			}
			if len(p.UrlFilter.Allow) > 0 {
				b.WriteString("\n  always-allowed sites: " + strings.Join(limit(p.UrlFilter.Allow, 10), ", "))
			}
		}
		b.WriteString("\n")
	}
	if len(policies) == 0 {
		b.WriteString("No policies exist yet.\n")
	}
	if len(devices) > 0 {
		names := make([]string, 0, len(devices))
		for n, v := range devices {
			names = append(names, n+" = "+strings.Join(v, " "))
		}
		sort.Strings(names)
		b.WriteString("Named devices: " + strings.Join(limit(names, 30), "; ") + "\n")
	}
	return truncate(b.String(), 6000)
}

func limit(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string{}, s[:n]...), fmt.Sprintf("(+%d more)", len(s)-n))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---- hallucination check ----

// echoWarnings flags sites and devices the model put in a change that the
// person never mentioned and that do not already exist - small models
// sometimes invent them.
func echoWarnings(p *Proposal, message string, history []Turn, devices map[string][]string, policies []models.Policy) {
	var said strings.Builder
	said.WriteString(strings.ToLower(message))
	for _, t := range history {
		said.WriteString(" " + strings.ToLower(t.Content))
	}
	known := map[string]bool{}
	for n, members := range devices {
		known[strings.ToLower(n)] = true
		for _, m := range members {
			known[strings.ToLower(m)] = true
		}
	}
	for _, pol := range policies {
		for _, l := range [][]string{pol.SourceIPs, pol.SourceMACs, pol.UrlFilter.Block, pol.UrlFilter.Allow} {
			for _, v := range l {
				known[strings.ToLower(v)] = true
			}
		}
	}
	text := said.String()
	for i := range p.Changes {
		c := &p.Changes[i]
		switch c.Op {
		case OpCreatePolicy, OpSetSources, OpBlockSites, OpAllowSites, OpUnlistSites:
		default:
			continue
		}
		for _, v := range c.Values {
			lv := strings.ToLower(strings.TrimSpace(v))
			stem := strings.TrimPrefix(lv, "www.")
			if lv == "" || known[lv] || strings.Contains(text, stem) {
				continue
			}
			// "block facebook" names facebook.com.
			if name := strings.SplitN(stem, ".", 2)[0]; len(name) > 2 && strings.ContainsAny(name, "abcdefghijklmnopqrstuvwxyz") && strings.Contains(text, name) {
				continue
			}
			c.Warnings = append(c.Warnings, fmt.Sprintf("%q was not in your request; check it is what you meant", v))
		}
	}
}

// ---- model I/O ----

type modelReply struct {
	Reply   string   `json:"reply"`
	Changes []Change `json:"changes"`
}

var replySchema = func() map[string]any {
	ops := make([]string, len(Ops))
	for i, o := range Ops {
		ops[i] = string(o)
	}
	str := map[string]any{"type": "string"}
	strs := map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 20}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"reply": map[string]any{"type": "string", "maxLength": 1200},
			"changes": map[string]any{
				"type":     "array",
				"maxItems": 10,
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"op":           map[string]any{"type": "string", "enum": ops},
						"policy":       str,
						"values":       strs,
						"enabled":      map[string]any{"type": "boolean"},
						"mode":         str,
						"image_action": str,
						"schedule": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"days":  strs,
								"start": str,
								"end":   str,
							},
							"required":             []string{"days", "start", "end"},
							"additionalProperties": false,
						},
					},
					"required":             []string{"op", "policy", "values", "enabled", "mode", "image_action", "schedule"},
					"additionalProperties": false,
				},
			},
		},
		"required":             []string{"reply", "changes"},
		"additionalProperties": false,
	}
}()

// systemPrompt is fixed so llama-server can reuse its KV cache.
var systemPrompt = func() string {
	var b strings.Builder
	b.WriteString(`You are the assistant of a home web filter. The person manages the filter by talking to you. Answer with JSON: "reply" is your answer in plain, friendly language (short; say what you propose, or answer their question). Nothing is changed until the person applies it, so never say a change is already made: write "I propose…" or "I can…", and "changes" is a list of settings changes to propose. The person reviews and confirms every change, so propose changes whenever they ask for something; when they only ask a question or ask for advice, answer it and propose sensible changes they could apply. Leave "changes" empty if nothing should change. Never invent devices, addresses or websites the person did not mention.

How the filter works: each policy applies to some devices (IP addresses, networks, MAC addresses or named devices). The policy with no devices covers everyone else. A policy can have a schedule; while it is active it overrides the device's normal policy, and outside it the normal policy applies. So for "the kids tablet after 9pm" create a policy for that device with a schedule, then change that new policy.

Each change has: op, policy (the policy name), values (list), enabled (true/false), mode, image_action, schedule {days, start, end}. Fill unused fields with "", [], false and an empty schedule {"days":[],"start":"","end":""}.
Ops:
- create_policy: new policy named policy, for the devices in values, optional schedule. It starts as a copy of "default". Later changes in the same answer can change it.
- delete_policy: remove the policy.
- set_sources: replace which devices the policy is for (values).
- set_schedule: when the policy is active; days are mon tue wed thu fri sat sun weekdays weekends school_nights, times are HH:MM (24h). Empty schedule = always.
- set_active: enabled=false turns the policy off, true turns it on.
- block_categories / allow_categories: block or allow website categories (values = category names below).
- allow_only_categories: allow only these categories, block every other kind of site.
- set_category_filter: enabled=false stops category filtering.
- block_sites / allow_sites: block, or always allow, websites (values = domains like example.com). unlist_sites removes them from both lists.
- set_adult_images: enabled; image_action = blur, block or checkerboard.
- set_adult_text: block adult pages. set_adult_video: block adult videos. set_ads: block ads and trackers. set_safesearch: force SafeSearch. set_doh_filter: filter DNS-over-HTTPS.
- set_youtube: enabled; mode = blacklist (block the channels in values) or whitelist (allow only them).
- block_internet: enabled=true blocks all web access for the policy (always-allowed sites still work); false undoes it.
Rules for changes: use each op once per policy; to block or allow categories use block_categories or allow_categories, never another create_policy. Only create a policy when the person asks for something that applies to particular devices or times and no existing policy fits; otherwise change an existing policy. Only add a schedule when the person mentions days or times.
Website categories: `)
	b.WriteString(strings.Join(sitecat.Slugs(), ", "))
	b.WriteString(".\n")
	b.WriteString(`Example: "What do you recommend for young children?" ->
{"reply":"For young children I recommend blocking adult, gambling, dating and violent sites, blurring adult images and forcing SafeSearch. I can apply this to the default policy.","changes":[{"op":"block_categories","policy":"default","values":["adult","gambling","dating","violence_hate"],"enabled":false,"mode":"","image_action":"","schedule":{"days":[],"start":"","end":""}},{"op":"set_adult_images","policy":"default","values":[],"enabled":true,"mode":"","image_action":"blur","schedule":{"days":[],"start":"","end":""}},{"op":"set_safesearch","policy":"default","values":[],"enabled":true,"mode":"","image_action":"","schedule":{"days":[],"start":"","end":""}}]}
`)
	b.WriteString(`Example: "No social media or games for the kids tablet on school nights" ->
{"reply":"I propose a school-night policy for the kids tablet that blocks social media and games from 7pm.","changes":[{"op":"create_policy","policy":"kids-tablet-school-nights","values":["kids-tablet"],"enabled":false,"mode":"","image_action":"","schedule":{"days":["school_nights"],"start":"19:00","end":"23:59"}},{"op":"block_categories","policy":"kids-tablet-school-nights","values":["social_media","gaming"],"enabled":false,"mode":"","image_action":"","schedule":{"days":[],"start":"","end":""}}]}`)
	return b.String()
}()
