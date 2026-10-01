// Package rules is the natural-language-friendly policy layer: a flat list
// of rules such as "blur adult images for 10.10.10.10 from 10:00 to 17:00"
// or "block ads on the LAN except www.cnn.com", each with a source match,
// an optional time window, optional site include/exclude lists, a target
// and an action. Rules are overlaid on the client's matched policy per
// request by the RuleEvaluator addon, so every existing addon keeps
// reading one effective Policy.
package rules

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yjlion/llama-web-filter/internal/macutil"
	"github.com/yjlion/llama-web-filter/internal/models"
)

// Target is what a rule acts on.
type Target string

const (
	TargetAdultImages Target = "adult_images"
	TargetAdultText   Target = "adult_text"
	TargetAds         Target = "ads"
	TargetSite        Target = "site"     // Value lists the sites
	TargetCategory    Target = "category" // Value lists category names
	TargetSafeSearch  Target = "safesearch"
	TargetYouTube     Target = "youtube"  // Value lists channels (block/allow)
	TargetInternet    Target = "internet" // everything: block = no web at all
)

// Action is what the rule does to its target.
type Action string

const (
	ActionBlock        Action = "block"
	ActionBlur         Action = "blur"
	ActionCheckerboard Action = "checkerboard"
	ActionAllow        Action = "allow"
)

// Targets and Actions list the valid values for validation and the model's
// schema.
var (
	Targets = []Target{TargetAdultImages, TargetAdultText, TargetAds, TargetSite, TargetCategory, TargetSafeSearch, TargetYouTube, TargetInternet}
	Actions = []Action{ActionBlock, ActionBlur, ActionCheckerboard, ActionAllow}
)

// Rule is one entry.
type Rule struct {
	ID      string    `json:"id"`
	Enabled bool      `json:"enabled"`
	Text    string    `json:"text"` // the sentence it was compiled from (or a label)
	Created time.Time `json:"created"`
	Match   Match     `json:"match"`
	Target  Target    `json:"target"`
	Action  Action    `json:"action"`
	// Value carries the target's operands: sites for "site", category
	// names for "category", channels for "youtube".
	Value []string `json:"value,omitempty"`
}

// Match is who and when a rule applies to.
type Match struct {
	// Sources are IPs, CIDRs, MACs, device aliases, or the words "lan"
	// (private + link-local ranges) and "all". Empty means every client.
	Sources []string `json:"sources,omitempty"`
	// Policy restricts the rule to clients whose matched policy has this
	// name. Empty means any policy.
	Policy string `json:"policy,omitempty"`
	// Time restricts the rule to a daily window; nil means always.
	Time *TimeWindow `json:"time,omitempty"`
	// Sites scopes the rule to (or away from) sites. Patterns are domains,
	// *.wildcards or URLs with paths, as everywhere else in the policies.
	Sites Sites `json:"sites"`
}

// TimeWindow is a daily window on the listed days ("mon".."sun"; empty =
// every day). Windows crossing midnight (22:00-06:00) are allowed.
type TimeWindow struct {
	Start string   `json:"start"` // HH:MM
	End   string   `json:"end"`   // HH:MM
	Days  []string `json:"days,omitempty"`
}

// Sites scopes a rule by site.
type Sites struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// File is the on-disk rules document.
type File struct {
	// Devices maps a friendly name ("kids-tablet") to IPs/MACs/CIDRs, so a
	// sentence can say "for the kids tablet".
	Devices map[string][]string `json:"devices"`
	Rules   []Rule              `json:"rules"`
}

var dayNames = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

func dayIndex(s string) (int, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) >= 3 {
		s = s[:3]
	}
	for i, d := range dayNames {
		if d == s {
			return i, true
		}
	}
	return 0, false
}

// Validate checks a rule and normalises it in place (lowercases hosts,
// canonicalises MACs and times, drops empty values).
func Validate(r *Rule, devices map[string][]string) error {
	if r == nil {
		return errors.New("nil rule")
	}
	r.Text = strings.TrimSpace(r.Text)
	found := false
	for _, t := range Targets {
		if r.Target == t {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("unknown target %q (valid: %v)", r.Target, Targets)
	}
	found = false
	for _, a := range Actions {
		if r.Action == a {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("unknown action %q (valid: %v)", r.Action, Actions)
	}
	if (r.Action == ActionBlur || r.Action == ActionCheckerboard) && r.Target != TargetAdultImages {
		return fmt.Errorf("action %q only applies to adult_images", r.Action)
	}
	r.Value = cleanList(r.Value)
	switch r.Target {
	case TargetSite, TargetCategory, TargetYouTube:
		if len(r.Value) == 0 {
			return fmt.Errorf("target %q needs at least one value", r.Target)
		}
	}
	r.Match.Sources = cleanList(r.Match.Sources)
	for i, src := range r.Match.Sources {
		n, err := normalizeSource(src, devices)
		if err != nil {
			return err
		}
		r.Match.Sources[i] = n
	}
	r.Match.Policy = strings.TrimSpace(r.Match.Policy)
	r.Match.Sites.Include = cleanList(r.Match.Sites.Include)
	r.Match.Sites.Exclude = cleanList(r.Match.Sites.Exclude)
	if r.Match.Time != nil {
		t := r.Match.Time
		if t.Start == "" && t.End == "" && len(t.Days) == 0 {
			r.Match.Time = nil
		} else {
			var ok bool
			if t.Start == "" {
				t.Start = "00:00"
			}
			if t.End == "" {
				t.End = "23:59"
			}
			if t.Start, ok = normHHMM(t.Start); !ok {
				return fmt.Errorf("bad start time %q (use HH:MM)", t.Start)
			}
			if t.End, ok = normHHMM(t.End); !ok {
				return fmt.Errorf("bad end time %q (use HH:MM)", t.End)
			}
			days := []string{}
			for _, d := range t.Days {
				i, ok := dayIndex(d)
				if !ok {
					return fmt.Errorf("bad day %q", d)
				}
				days = append(days, dayNames[i])
			}
			t.Days = days
		}
	}
	return nil
}

func cleanList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[strings.ToLower(v)] {
			continue
		}
		seen[strings.ToLower(v)] = true
		out = append(out, v)
	}
	return out
}

func normHHMM(v string) (string, bool) {
	v = strings.TrimSpace(v)
	parts := strings.SplitN(v, ":", 2)
	if len(parts) != 2 {
		return "", false
	}
	h, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	m, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return "", false
	}
	return fmt.Sprintf("%02d:%02d", h, m), true
}

// normalizeSource accepts an IP, CIDR, MAC, "lan", "all" or a device alias.
func normalizeSource(src string, devices map[string][]string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(src))
	switch s {
	case "lan", "all", "":
		return s, nil
	}
	if net.ParseIP(s) != nil {
		return s, nil
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return s, nil
	}
	if m := macutil.Normalize(s); m != "" {
		return m, nil
	}
	if devices != nil {
		if _, ok := devices[s]; ok {
			return s, nil
		}
		for name := range devices {
			if strings.ToLower(name) == s {
				return name, nil
			}
		}
	}
	return "", fmt.Errorf("unknown source %q: use an IP, CIDR, MAC, \"lan\", \"all\" or a device name", src)
}

// Client is what a rule is matched against.
type Client struct {
	IP     string
	MAC    string // may be empty
	Policy string // matched policy name
	Host   string // request host (lowercase)
	URL    string // full request URL
	Now    time.Time
}

// Applies reports whether r is in force for the client right now. Site
// scoping is applied here as well, so a rule with sites.exclude simply
// does not apply on those sites.
func (r Rule) Applies(c Client, devices map[string][]string, urlInList func(host, url string, patterns []string) bool) bool {
	if !r.Enabled {
		return false
	}
	if r.Match.Policy != "" && !strings.EqualFold(r.Match.Policy, c.Policy) {
		return false
	}
	if !sourcesMatch(r.Match.Sources, c, devices, 0) {
		return false
	}
	if r.Match.Time != nil && !r.Match.Time.Active(c.Now) {
		return false
	}
	if len(r.Match.Sites.Include) > 0 && !urlInList(c.Host, c.URL, r.Match.Sites.Include) {
		return false
	}
	if len(r.Match.Sites.Exclude) > 0 && urlInList(c.Host, c.URL, r.Match.Sites.Exclude) {
		return false
	}
	return true
}

func sourcesMatch(sources []string, c Client, devices map[string][]string, depth int) bool {
	if len(sources) == 0 {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(c.IP))
	for _, src := range sources {
		s := strings.ToLower(src)
		switch {
		case s == "all":
			return true
		case s == "lan":
			if ip != nil && isLAN(ip) {
				return true
			}
		case strings.Contains(s, "/"):
			if _, n, err := net.ParseCIDR(s); err == nil && ip != nil && n.Contains(ip) {
				return true
			}
		case net.ParseIP(s) != nil:
			if ip != nil && ip.Equal(net.ParseIP(s)) {
				return true
			}
		case macutil.Normalize(s) != "":
			if c.MAC != "" && macutil.Normalize(c.MAC) == macutil.Normalize(s) {
				return true
			}
		default:
			if depth < 2 && devices != nil {
				if members, ok := devices[s]; ok && sourcesMatch(members, c, nil, depth+1) {
					return true
				}
				for name, members := range devices {
					if strings.ToLower(name) == s && sourcesMatch(members, c, nil, depth+1) {
						return true
					}
				}
			}
		}
	}
	return false
}

var lanNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

func isLAN(ip net.IP) bool {
	for _, n := range lanNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Active reports whether now falls inside the window (local time).
func (t TimeWindow) Active(now time.Time) bool {
	if len(t.Days) > 0 {
		today := (int(now.Weekday()) + 6) % 7
		yesterday := (today + 6) % 7
		ok := false
		start, _ := normHHMM(t.Start)
		end, _ := normHHMM(t.End)
		overnight := start > end
		for _, d := range t.Days {
			i, _ := dayIndex(d)
			if i == today {
				ok = true
			}
			if overnight && i == yesterday {
				// Second half of an overnight window that started yesterday.
				hm := fmt.Sprintf("%02d:%02d", now.Hour(), now.Minute())
				if hm <= end {
					return true
				}
			}
		}
		if !ok {
			return false
		}
	}
	hm := fmt.Sprintf("%02d:%02d", now.Hour(), now.Minute())
	start, _ := normHHMM(t.Start)
	end, _ := normHHMM(t.End)
	if start == "" {
		start = "00:00"
	}
	if end == "" {
		end = "23:59"
	}
	if start <= end {
		return hm >= start && hm <= end
	}
	return hm >= start || hm <= end
}

// Apply overlays the rules that apply to the client onto a copy of base
// and returns the effective policy plus the ids of the rules used. Later
// rules win over earlier ones for the same target.
func Apply(base models.Policy, all []Rule, c Client, devices map[string][]string, urlInList func(host, url string, patterns []string) bool) (models.Policy, []string) {
	p := base
	// Slices inside the policy are shared with the base; copy the ones we
	// append to so the stored policy is never mutated.
	p.UrlFilter.Block = append([]string(nil), p.UrlFilter.Block...)
	p.UrlFilter.Allow = append([]string(nil), p.UrlFilter.Allow...)
	p.UrlFilter.Categories = append([]string(nil), p.UrlFilter.Categories...)
	p.YouTube.Channels = append([]string(nil), p.YouTube.Channels...)
	var used []string
	for _, r := range all {
		if !r.Applies(c, devices, urlInList) {
			continue
		}
		used = append(used, r.ID)
		switch r.Target {
		case TargetAdultImages:
			switch r.Action {
			case ActionAllow:
				p.ImageClassifier.Enabled = false
			case ActionBlur:
				p.ImageClassifier.Enabled, p.ImageClassifier.Action = true, models.ImageActionBlur
			case ActionCheckerboard:
				p.ImageClassifier.Enabled, p.ImageClassifier.Action = true, models.ImageActionCheckerboard
			case ActionBlock:
				p.ImageClassifier.Enabled, p.ImageClassifier.Action = true, models.ImageActionBlock
			}
		case TargetAdultText:
			p.TextClassifier.Enabled = r.Action != ActionAllow
		case TargetAds:
			p.AdBlock.Enabled = r.Action != ActionAllow
		case TargetSafeSearch:
			p.SafeSearch.Enabled = r.Action != ActionAllow
		case TargetSite:
			p.UrlFilter.Enabled = true
			if r.Action == ActionAllow {
				p.UrlFilter.Allow = append(p.UrlFilter.Allow, r.Value...)
			} else {
				p.UrlFilter.Block = append(p.UrlFilter.Block, r.Value...)
			}
		case TargetCategory:
			p.UrlFilter.Enabled = true
			if r.Action == ActionAllow {
				p.UrlFilter.Categories = removeAll(p.UrlFilter.Categories, r.Value)
			} else {
				p.UrlFilter.Categories = appendUnique(p.UrlFilter.Categories, r.Value)
			}
		case TargetYouTube:
			p.YouTube.Enabled = true
			if r.Action == ActionAllow {
				p.YouTube.Mode = models.YouTubeModeWhitelist
			} else {
				p.YouTube.Mode = models.YouTubeModeBlacklist
			}
			p.YouTube.Channels = appendUnique(p.YouTube.Channels, r.Value)
		case TargetInternet:
			if r.Action == ActionAllow {
				p.UrlFilter.Enabled = false
			} else {
				p.UrlFilter.Enabled = true
				p.UrlFilter.Block = appendUnique(p.UrlFilter.Block, []string{"*"})
			}
		}
	}
	return p, used
}

func appendUnique(dst []string, add []string) []string {
	seen := map[string]bool{}
	for _, v := range dst {
		seen[strings.ToLower(v)] = true
	}
	for _, v := range add {
		if !seen[strings.ToLower(v)] {
			dst = append(dst, v)
			seen[strings.ToLower(v)] = true
		}
	}
	return dst
}

func removeAll(dst []string, rm []string) []string {
	drop := map[string]bool{}
	for _, v := range rm {
		drop[strings.ToLower(v)] = true
	}
	out := dst[:0:0]
	for _, v := range dst {
		if !drop[strings.ToLower(v)] {
			out = append(out, v)
		}
	}
	return out
}

// Describe renders a rule as one plain sentence, built from the structure
// (not the model), so the user confirms what will actually be enforced.
func Describe(r Rule) string {
	var b strings.Builder
	switch r.Target {
	case TargetAdultImages:
		switch r.Action {
		case ActionAllow:
			b.WriteString("Do not filter adult images")
		case ActionBlock:
			b.WriteString("Block adult images")
		case ActionCheckerboard:
			b.WriteString("Replace adult images with a checkerboard")
		default:
			b.WriteString("Blur adult images")
		}
	case TargetAdultText:
		if r.Action == ActionAllow {
			b.WriteString("Do not block adult pages")
		} else {
			b.WriteString("Block adult pages")
		}
	case TargetAds:
		if r.Action == ActionAllow {
			b.WriteString("Allow ads")
		} else {
			b.WriteString("Block ads")
		}
	case TargetSafeSearch:
		if r.Action == ActionAllow {
			b.WriteString("Do not enforce SafeSearch")
		} else {
			b.WriteString("Enforce SafeSearch")
		}
	case TargetSite:
		if r.Action == ActionAllow {
			b.WriteString("Always allow ")
		} else {
			b.WriteString("Block ")
		}
		b.WriteString(joinOr(r.Value))
	case TargetCategory:
		if r.Action == ActionAllow {
			b.WriteString("Allow the ")
		} else {
			b.WriteString("Block the ")
		}
		b.WriteString(joinOr(r.Value))
		if len(r.Value) > 1 {
			b.WriteString(" categories")
		} else {
			b.WriteString(" category")
		}
	case TargetYouTube:
		if r.Action == ActionAllow {
			b.WriteString("Only allow the YouTube channels ")
		} else {
			b.WriteString("Block the YouTube channels ")
		}
		b.WriteString(joinOr(r.Value))
	case TargetInternet:
		if r.Action == ActionAllow {
			b.WriteString("Allow all web access")
		} else {
			b.WriteString("Block all web access")
		}
	}
	if len(r.Match.Sources) > 0 {
		b.WriteString(" for ")
		parts := make([]string, 0, len(r.Match.Sources))
		for _, s := range r.Match.Sources {
			switch s {
			case "lan":
				parts = append(parts, "every device on the LAN")
			case "all":
				parts = append(parts, "everyone")
			default:
				parts = append(parts, s)
			}
		}
		b.WriteString(strings.Join(parts, ", "))
	} else {
		b.WriteString(" for everyone")
	}
	if r.Match.Policy != "" {
		b.WriteString(" (policy " + r.Match.Policy + ")")
	}
	if t := r.Match.Time; t != nil {
		b.WriteString(" between " + t.Start + " and " + t.End)
		if len(t.Days) > 0 && len(t.Days) < 7 {
			b.WriteString(" on " + strings.Join(t.Days, ", "))
		}
	}
	if len(r.Match.Sites.Include) > 0 {
		b.WriteString(" on " + joinOr(r.Match.Sites.Include))
	}
	if len(r.Match.Sites.Exclude) > 0 {
		b.WriteString(", except on " + joinOr(r.Match.Sites.Exclude))
	}
	b.WriteString(".")
	return b.String()
}

func joinOr(v []string) string {
	if len(v) == 0 {
		return ""
	}
	if len(v) == 1 {
		return v[0]
	}
	return strings.Join(v[:len(v)-1], ", ") + " and " + v[len(v)-1]
}

// SortStable orders rules by creation time, which is the evaluation order
// (later rules override earlier ones).
func SortStable(rs []Rule) {
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Created.Before(rs[j].Created) })
}
