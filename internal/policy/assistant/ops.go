package assistant

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/yjlion/llama-web-filter/internal/macutil"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/sitecat"
)

// Op names one kind of policy edit. Each is small and typed so a small model
// can emit it reliably; the server, not the model, turns it into policy JSON.
type Op string

const (
	OpCreatePolicy        Op = "create_policy"         // policy=new name, values=devices/IPs/MACs, schedule optional
	OpDeletePolicy        Op = "delete_policy"         // policy
	OpSetSources          Op = "set_sources"           // values=devices/IPs/MACs/CIDRs (replaces)
	OpSetSchedule         Op = "set_schedule"          // schedule (empty days+times = always)
	OpSetActive           Op = "set_active"            // enabled
	OpBlockCategories     Op = "block_categories"      // values=category slugs
	OpAllowCategories     Op = "allow_categories"      // values=category slugs
	OpAllowOnlyCategories Op = "allow_only_categories" // values=category slugs (allow-only mode)
	OpSetCategoryFilter   Op = "set_category_filter"   // enabled
	OpBlockSites          Op = "block_sites"           // values=domains/URLs
	OpAllowSites          Op = "allow_sites"           // values=domains/URLs
	OpUnlistSites         Op = "unlist_sites"          // values=domains/URLs, removed from both lists
	OpSetAdultImages      Op = "set_adult_images"      // enabled, image_action=blur|block|checkerboard
	OpSetAdultText        Op = "set_adult_text"        // enabled
	OpSetAdultVideo       Op = "set_adult_video"       // enabled
	OpSetAds              Op = "set_ads"               // enabled
	OpSetSafeSearch       Op = "set_safesearch"        // enabled
	OpSetDoh              Op = "set_doh_filter"        // enabled
	OpSetYouTube          Op = "set_youtube"           // enabled, mode, values=channels
	OpBlockInternet       Op = "block_internet"        // enabled (true = block every site)
)

// Ops lists every op in the order the prompt documents them.
var Ops = []Op{OpCreatePolicy, OpDeletePolicy, OpSetSources, OpSetSchedule, OpSetActive,
	OpBlockCategories, OpAllowCategories, OpAllowOnlyCategories, OpSetCategoryFilter,
	OpBlockSites, OpAllowSites, OpUnlistSites,
	OpSetAdultImages, OpSetAdultText, OpSetAdultVideo, OpSetAds, OpSetSafeSearch, OpSetDoh, OpSetYouTube,
	OpBlockInternet}

// Schedule is a weekly window in the model's vocabulary.
type Schedule struct {
	Days  []string `json:"days"`
	Start string   `json:"start"`
	End   string   `json:"end"`
}

func (s *Schedule) empty() bool {
	return s == nil || (len(s.Days) == 0 && strings.TrimSpace(s.Start) == "" && strings.TrimSpace(s.End) == "")
}

// Change is one proposed edit.
type Change struct {
	Op       Op        `json:"op"`
	Policy   string    `json:"policy"`
	Values   []string  `json:"values"`
	Enabled  bool      `json:"enabled"`
	Mode     string    `json:"mode"`
	Action   string    `json:"image_action"`
	Schedule *Schedule `json:"schedule,omitempty"`
}

// workset is the policies being edited, by lowercased name.
type workset struct {
	order    []string
	byName   map[string]*models.Policy
	created  map[string]bool
	deleted  map[string]bool
	original map[string]models.Policy
	devices  map[string][]string
}

func newWorkset(policies []models.Policy, devices map[string][]string) *workset {
	w := &workset{byName: map[string]*models.Policy{}, created: map[string]bool{}, deleted: map[string]bool{},
		original: map[string]models.Policy{}, devices: devices}
	for _, p := range policies {
		k := strings.ToLower(p.Name)
		cp := clonePolicy(p)
		w.byName[k] = &cp
		w.original[k] = clonePolicy(p)
		w.order = append(w.order, k)
	}
	return w
}

func clonePolicy(p models.Policy) models.Policy {
	b, _ := json.Marshal(p)
	var out models.Policy
	_ = json.Unmarshal(b, &out)
	return out
}

// resolve finds the policy a change targets. An empty name means the only
// policy, or "default".
func (w *workset) resolve(name string) (*models.Policy, string, error) {
	k := strings.ToLower(strings.TrimSpace(name))
	if k == "" {
		live := w.live()
		switch {
		case len(live) == 1:
			k = live[0]
		case w.byName["default"] != nil && !w.deleted["default"]:
			k = "default"
		default:
			return nil, "", fmt.Errorf("say which policy to change")
		}
	}
	p, ok := w.byName[k]
	if !ok || w.deleted[k] {
		return nil, "", fmt.Errorf("there is no policy named %q", name)
	}
	return p, k, nil
}

func (w *workset) live() []string {
	var out []string
	for _, k := range w.order {
		if !w.deleted[k] {
			out = append(out, k)
		}
	}
	return out
}

// apply applies one change, returning a one-line description of it.
func (w *workset) apply(c Change) (string, error) {
	if c.Op == OpCreatePolicy {
		return w.create(c)
	}
	p, key, err := w.resolve(c.Policy)
	if err != nil {
		return "", err
	}
	name := p.Name
	on := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	switch c.Op {
	case OpDeletePolicy:
		if key == "default" {
			return "", fmt.Errorf("the default policy cannot be deleted")
		}
		w.deleted[key] = true
		return fmt.Sprintf("Delete policy %q", name), nil
	case OpSetSources:
		ips, macs, err := w.sources(c.Values)
		if err != nil {
			return "", err
		}
		p.SourceIPs, p.SourceMACs = ips, macs
		return fmt.Sprintf("%s: applies to %s", name, describeSources(ips, macs)), nil
	case OpSetSchedule:
		sc, desc, err := toSchedule(c.Schedule)
		if err != nil {
			return "", err
		}
		p.Schedule = sc
		return fmt.Sprintf("%s: active %s", name, desc), nil
	case OpSetActive:
		p.Inactive = !c.Enabled
		if c.Enabled {
			return fmt.Sprintf("%s: turn the policy on", name), nil
		}
		return fmt.Sprintf("%s: turn the policy off", name), nil
	case OpBlockCategories, OpAllowCategories, OpAllowOnlyCategories:
		slugs, err := categorySlugs(c.Values)
		if err != nil {
			return "", err
		}
		cf := &p.CategoryFilter
		cf.Enabled = true
		labels := categoryLabels(slugs)
		switch c.Op {
		case OpAllowOnlyCategories:
			cf.Mode = models.UrlFilterModeWhitelist
			cf.Categories = slugs
			return fmt.Sprintf("%s: allow only %s sites", name, labels), nil
		case OpBlockCategories:
			if cf.Mode == models.UrlFilterModeWhitelist {
				cf.Categories = without(cf.Categories, slugs)
			} else {
				cf.Categories = union(cf.Categories, slugs)
			}
			return fmt.Sprintf("%s: block %s sites", name, labels), nil
		default:
			if cf.Mode == models.UrlFilterModeWhitelist {
				cf.Categories = union(cf.Categories, slugs)
			} else {
				cf.Categories = without(cf.Categories, slugs)
			}
			return fmt.Sprintf("%s: allow %s sites", name, labels), nil
		}
	case OpSetCategoryFilter:
		p.CategoryFilter.Enabled = c.Enabled
		return fmt.Sprintf("%s: site-category filtering %s", name, on(c.Enabled)), nil
	case OpBlockSites, OpAllowSites, OpUnlistSites:
		sites, err := siteList(c.Values)
		if err != nil {
			return "", err
		}
		uf := &p.UrlFilter
		switch c.Op {
		case OpBlockSites:
			uf.Enabled = true
			uf.Allow = without(uf.Allow, sites)
			uf.Block = union(uf.Block, sites)
			return fmt.Sprintf("%s: block %s", name, strings.Join(sites, ", ")), nil
		case OpAllowSites:
			uf.Enabled = true
			uf.Block = without(uf.Block, sites)
			uf.Allow = union(uf.Allow, sites)
			return fmt.Sprintf("%s: always allow %s", name, strings.Join(sites, ", ")), nil
		default:
			uf.Block = without(uf.Block, sites)
			uf.Allow = without(uf.Allow, sites)
			return fmt.Sprintf("%s: remove %s from the site lists", name, strings.Join(sites, ", ")), nil
		}
	case OpSetAdultImages:
		p.ImageClassifier.Enabled = c.Enabled
		if !c.Enabled {
			return fmt.Sprintf("%s: adult image filtering off", name), nil
		}
		if a := strings.ToLower(strings.TrimSpace(c.Action)); a != "" {
			switch models.ImageClassifierAction(a) {
			case models.ImageActionBlur, models.ImageActionBlock, models.ImageActionCheckerboard:
				p.ImageClassifier.Action = models.ImageClassifierAction(a)
			default:
				// Small models sometimes echo the op name here; keep the
				// current action rather than refuse the change.
			}
		}
		return fmt.Sprintf("%s: %s adult images", name, p.ImageClassifier.Action), nil
	case OpSetAdultText:
		p.TextClassifier.Enabled = c.Enabled
		return fmt.Sprintf("%s: block adult pages %s", name, on(c.Enabled)), nil
	case OpSetAdultVideo:
		p.VideoClassifier.Enabled = c.Enabled
		return fmt.Sprintf("%s: block adult videos %s", name, on(c.Enabled)), nil
	case OpSetAds:
		p.AdBlock.Enabled = c.Enabled
		return fmt.Sprintf("%s: ad and tracker blocking %s", name, on(c.Enabled)), nil
	case OpSetSafeSearch:
		p.SafeSearch.Enabled = c.Enabled
		return fmt.Sprintf("%s: SafeSearch %s", name, on(c.Enabled)), nil
	case OpSetDoh:
		p.Doh.Enabled = c.Enabled
		return fmt.Sprintf("%s: DNS-over-HTTPS filtering %s", name, on(c.Enabled)), nil
	case OpSetYouTube:
		yt := &p.YouTube
		yt.Enabled = c.Enabled
		if !c.Enabled {
			return fmt.Sprintf("%s: YouTube channel filtering off", name), nil
		}
		switch strings.ToLower(strings.TrimSpace(c.Mode)) {
		case "whitelist", "allow", "allow_only":
			yt.Mode = models.YouTubeModeWhitelist
		case "blacklist", "block":
			yt.Mode = models.YouTubeModeBlacklist
		}
		yt.Channels = union(yt.Channels, cleanList(c.Values))
		verb := "block channels"
		if yt.Mode == models.YouTubeModeWhitelist {
			verb = "allow only channels"
		}
		return fmt.Sprintf("%s: YouTube %s %s", name, verb, strings.Join(yt.Channels, ", ")), nil
	case OpBlockInternet:
		uf := &p.UrlFilter
		if c.Enabled {
			uf.Enabled = true
			uf.Block = union(uf.Block, []string{"*"})
			return fmt.Sprintf("%s: block all web access (except always-allowed sites)", name), nil
		}
		uf.Block = without(uf.Block, []string{"*"})
		return fmt.Sprintf("%s: stop blocking all web access", name), nil
	}
	return "", fmt.Errorf("unknown change %q", c.Op)
}

func (w *workset) create(c Change) (string, error) {
	name := strings.TrimSpace(c.Policy)
	if name == "" {
		return "", fmt.Errorf("a new policy needs a name")
	}
	if strings.ContainsAny(name, `/\`) || len(name) > 64 {
		return "", fmt.Errorf("%q is not a usable policy name", name)
	}
	k := strings.ToLower(name)
	if p, ok := w.byName[k]; ok && !w.deleted[k] {
		return "", fmt.Errorf("a policy named %q already exists", p.Name)
	}
	// Start from the default policy so the new one keeps its protections.
	base := models.NewPolicy()
	if d, ok := w.byName["default"]; ok && !w.deleted["default"] {
		base = clonePolicy(*d)
	}
	base.Name = name
	base.Inactive = false
	ips, macs, err := w.sources(c.Values)
	if err != nil {
		return "", err
	}
	if len(ips)+len(macs) == 0 {
		return "", fmt.Errorf("say which devices the new policy %q is for", name)
	}
	base.SourceIPs, base.SourceMACs = ips, macs
	desc := ""
	if !c.Schedule.empty() {
		sc, d, err := toSchedule(c.Schedule)
		if err != nil {
			return "", err
		}
		base.Schedule = sc
		desc = ", active " + d
	} else {
		base.Schedule = models.NewScheduleConfig()
	}
	w.byName[k] = &base
	w.created[k] = true
	delete(w.deleted, k)
	w.order = append(w.order, k)
	return fmt.Sprintf("New policy %q for %s%s (starts as a copy of default)", name, describeSources(ips, macs), desc), nil
}

// sources resolves device names, IPs, CIDRs and MACs.
func (w *workset) sources(values []string) (ips, macs []string, err error) {
	ips, macs = []string{}, []string{}
	var expand func(v string, depth int) error
	expand = func(v string, depth int) error {
		v = strings.TrimSpace(v)
		if v == "" {
			return nil
		}
		if members, ok := w.devices[strings.ToLower(v)]; ok && depth < 3 {
			for _, m := range members {
				if err := expand(m, depth+1); err != nil {
					return err
				}
			}
			return nil
		}
		if mac := macutil.Normalize(v); mac != "" && strings.ContainsAny(v, ":-") && net.ParseIP(v) == nil {
			macs = union(macs, []string{mac})
			return nil
		}
		if ip := net.ParseIP(v); ip != nil {
			ips = union(ips, []string{ip.String()})
			return nil
		}
		if _, n, err := net.ParseCIDR(v); err == nil {
			ips = union(ips, []string{n.String()})
			return nil
		}
		return fmt.Errorf("%q is not a known device name, IP address, network or MAC address", v)
	}
	for _, v := range values {
		if err := expand(v, 0); err != nil {
			return nil, nil, err
		}
	}
	return ips, macs, nil
}

func describeSources(ips, macs []string) string {
	all := append(append([]string{}, ips...), macs...)
	if len(all) == 0 {
		return "every device not matched by another policy"
	}
	return strings.Join(all, ", ")
}

var dayIndex = map[string][]int{
	"mon": {0}, "tue": {1}, "wed": {2}, "thu": {3}, "fri": {4}, "sat": {5}, "sun": {6},
	"weekdays": {0, 1, 2, 3, 4}, "weekends": {5, 6}, "weekend": {5, 6},
	"daily": {0, 1, 2, 3, 4, 5, 6}, "everyday": {0, 1, 2, 3, 4, 5, 6}, "all": {0, 1, 2, 3, 4, 5, 6},
	"school_nights": {6, 0, 1, 2, 3},
}

var dayNames = []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

// toSchedule turns the model's window into a ScheduleConfig. An empty
// window means always (schedule off).
func toSchedule(s *Schedule) (models.ScheduleConfig, string, error) {
	if s.empty() {
		return models.NewScheduleConfig(), "at all times", nil
	}
	var days []int
	seen := map[int]bool{}
	for _, d := range s.Days {
		k := strings.ToLower(strings.TrimSpace(d))
		k = strings.ReplaceAll(strings.ReplaceAll(k, " ", "_"), "-", "_")
		if len(k) > 3 && dayIndex[k] == nil {
			k = k[:3]
		}
		idx, ok := dayIndex[k]
		if !ok {
			return models.ScheduleConfig{}, "", fmt.Errorf("%q is not a day", d)
		}
		for _, i := range idx {
			if !seen[i] {
				seen[i] = true
				days = append(days, i)
			}
		}
	}
	if len(days) == 0 {
		days = []int{0, 1, 2, 3, 4, 5, 6}
	}
	sort.Ints(days)
	start, err := parseClock(s.Start, "00:00")
	if err != nil {
		return models.ScheduleConfig{}, "", err
	}
	end, err := parseClock(s.End, "23:59")
	if err != nil {
		return models.ScheduleConfig{}, "", err
	}
	if start == end {
		return models.ScheduleConfig{}, "", fmt.Errorf("the time window %s–%s is empty", start, end)
	}
	w := models.TimeWindow{Days: days, Start: start, End: end}
	names := make([]string, len(days))
	for i, d := range days {
		names[i] = dayNames[d]
	}
	dayDesc := strings.Join(names, ", ")
	if len(days) == 7 {
		dayDesc = "every day"
	}
	return models.ScheduleConfig{Enabled: true, ActiveWindows: []models.TimeWindow{w}},
		fmt.Sprintf("%s %s–%s", dayDesc, start, end), nil
}

// parseClock accepts "21:00", "9pm", "9:30 am", "21", "noon", "midnight".
func parseClock(v, def string) (string, error) {
	s := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(v), " ", ""))
	switch s {
	case "":
		return def, nil
	case "noon":
		return "12:00", nil
	case "midnight":
		return "00:00", nil
	}
	pm, am := strings.HasSuffix(s, "pm"), strings.HasSuffix(s, "am")
	s = strings.TrimSuffix(strings.TrimSuffix(s, "pm"), "am")
	hs, ms, _ := strings.Cut(s, ":")
	h, err1 := strconv.Atoi(hs)
	m := 0
	var err2 error
	if ms != "" {
		m, err2 = strconv.Atoi(ms)
	}
	if err1 != nil || err2 != nil || h < 0 || m < 0 || m > 59 {
		return "", fmt.Errorf("%q is not a time of day", v)
	}
	if pm && h < 12 {
		h += 12
	}
	if am && h == 12 {
		h = 0
	}
	if h == 24 && m == 0 {
		h, m = 23, 59
	}
	if h > 23 {
		return "", fmt.Errorf("%q is not a time of day", v)
	}
	return fmt.Sprintf("%02d:%02d", h, m), nil
}

func categorySlugs(values []string) ([]string, error) {
	var out []string
	for _, v := range values {
		slug := sitecat.Normalize(v)
		if slug == "" {
			return nil, fmt.Errorf("%q is not a site category", v)
		}
		out = union(out, []string{slug})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("name at least one site category")
	}
	return out, nil
}

func categoryLabels(slugs []string) string {
	labels := make([]string, len(slugs))
	for i, s := range slugs {
		labels[i] = strings.ToLower(sitecat.Label(s))
	}
	return strings.Join(labels, ", ")
}

// siteList cleans domains and URLs for the URL filter lists.
func siteList(values []string) ([]string, error) {
	var out []string
	for _, v := range values {
		s := strings.ToLower(strings.TrimSpace(v))
		s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
		s = strings.TrimSuffix(s, "/")
		if s == "" {
			continue
		}
		if strings.ContainsAny(s, " \t") || !strings.Contains(s, ".") {
			return nil, fmt.Errorf("%q is not a website address", v)
		}
		out = union(out, []string{s})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("name at least one website")
	}
	return out, nil
}

func cleanList(values []string) []string {
	var out []string
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = union(out, []string{v})
		}
	}
	return out
}

func union(a, b []string) []string {
	out := append([]string{}, a...)
	for _, v := range b {
		found := false
		for _, x := range out {
			if strings.EqualFold(x, v) {
				found = true
				break
			}
		}
		if !found {
			out = append(out, v)
		}
	}
	return out
}

func without(a, b []string) []string {
	out := []string{}
	for _, v := range a {
		drop := false
		for _, x := range b {
			if strings.EqualFold(x, v) {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, v)
		}
	}
	return out
}
