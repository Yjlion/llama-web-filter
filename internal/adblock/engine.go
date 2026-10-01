package adblock

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Request is what the engine matches.
type Request struct {
	URL        string // full URL
	Host       string // lowercase hostname
	Type       Type
	SourceHost string // the page making the request (Referer/Origin host), "" if unknown
}

// Verdict is the engine's answer.
type Verdict struct {
	Block bool
	Rule  string // the raw filter that decided (block or exception)
}

// Engine holds compiled lists.
type Engine struct {
	hostRules   map[string][]*NetRule // || rules keyed by HostPart
	tokenRules  map[string][]*NetRule // other rules keyed by token
	untokened   []*NetRule
	exceptions  *Engine         // exception rules live in a nested engine with the same indexes
	genericHide map[string]bool // sites with $generichide / $elemhide exceptions
	elemHide    map[string]bool

	cosmeticGeneric   []cosmeticSel
	cosmeticByDomain  map[string][]CosmeticRule // includes ~ exclusions via NotDoms on the rule
	cosmeticExcept    map[string][]string       // domain -> selectors excepted
	cosmeticExceptAll []string                  // generic exceptions (rare)

	stats Stats
}

type cosmeticSel struct {
	Selector string
	Key      string // id/class/quoted value that must appear in the page, "" = always
	NotDoms  []string
}

// Stats summarises what was loaded.
type Stats struct {
	NetworkRules  int `json:"network_rules"`
	Exceptions    int `json:"exceptions"`
	CosmeticRules int `json:"cosmetic_rules"`
	Skipped       int `json:"skipped"`
	Lists         int `json:"lists"`
}

func newEngine() *Engine {
	return &Engine{
		hostRules: map[string][]*NetRule{}, tokenRules: map[string][]*NetRule{},
		genericHide: map[string]bool{}, elemHide: map[string]bool{},
		cosmeticByDomain: map[string][]CosmeticRule{}, cosmeticExcept: map[string][]string{},
	}
}

// Build compiles parsed lists into an engine.
func Build(lists ...Parsed) *Engine {
	e := newEngine()
	e.exceptions = newEngine()
	for _, p := range lists {
		e.stats.Lists++
		e.stats.Skipped += p.Skipped
		for _, r := range p.Network {
			if r.GenericHide || r.ElemHide {
				if r.Exception && r.HostAnch && r.HostPart != "" {
					if r.GenericHide {
						e.genericHide[r.HostPart] = true
					}
					if r.ElemHide {
						e.elemHide[r.HostPart] = true
					}
				}
				if r.Pattern == r.HostPart+"^" || r.Pattern == r.HostPart {
					continue // pure cosmetic exception, not a network rule
				}
			}
			if r.Exception {
				e.exceptions.add(r)
				e.stats.Exceptions++
			} else {
				e.add(r)
				e.stats.NetworkRules++
			}
		}
		for _, c := range p.Cosmetic {
			e.stats.CosmeticRules++
			switch {
			case c.Exception && len(c.Domains) == 0:
				e.cosmeticExceptAll = append(e.cosmeticExceptAll, c.Selector)
			case c.Exception:
				for _, d := range c.Domains {
					e.cosmeticExcept[d] = append(e.cosmeticExcept[d], c.Selector)
				}
			case len(c.Domains) == 0:
				e.cosmeticGeneric = append(e.cosmeticGeneric, cosmeticSel{Selector: c.Selector, Key: selectorKey(c.Selector), NotDoms: c.NotDoms})
			default:
				for _, d := range c.Domains {
					e.cosmeticByDomain[d] = append(e.cosmeticByDomain[d], c)
				}
			}
		}
	}
	return e
}

func (e *Engine) add(r *NetRule) {
	switch {
	case r.HostAnch && r.HostPart != "":
		e.hostRules[r.HostPart] = append(e.hostRules[r.HostPart], r)
	case r.token != "":
		e.tokenRules[r.token] = append(e.tokenRules[r.token], r)
	default:
		e.untokened = append(e.untokened, r)
	}
}

// Stats reports what the engine holds.
func (e *Engine) Stats() Stats {
	if e == nil {
		return Stats{}
	}
	return e.stats
}

// Match decides a request.
func (e *Engine) Match(req Request) Verdict {
	if e == nil {
		return Verdict{}
	}
	req.Host = strings.ToLower(req.Host)
	lurl := strings.ToLower(req.URL)
	if req.Type == 0 {
		req.Type = TypeOther
	}
	block := e.find(req, lurl)
	if block == nil {
		return Verdict{}
	}
	if !block.Important {
		if exc := e.exceptions.find(req, lurl); exc != nil {
			return Verdict{Block: false, Rule: exc.Raw}
		}
	}
	return Verdict{Block: true, Rule: block.Raw}
}

// find returns the first rule in this engine that matches.
func (e *Engine) find(req Request, lurl string) *NetRule {
	// Host-anchored rules: walk the host's suffixes.
	h := req.Host
	for {
		if rs, ok := e.hostRules[h]; ok {
			for _, r := range rs {
				if r.matches(req, lurl) {
					return r
				}
			}
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	// Token-indexed rules.
	seen := map[*NetRule]bool{}
	for _, tok := range urlTokens(lurl) {
		for _, r := range e.tokenRules[tok] {
			if seen[r] {
				continue
			}
			seen[r] = true
			if r.matches(req, lurl) {
				return r
			}
		}
	}
	for _, r := range e.untokened {
		if r.matches(req, lurl) {
			return r
		}
	}
	return nil
}

// matches checks options then the pattern.
func (r *NetRule) matches(req Request, lurl string) bool {
	if r.Types != 0 && req.Type&r.Types == 0 {
		return false
	}
	if r.NotTypes != 0 && req.Type&r.NotTypes != 0 {
		return false
	}
	if r.Party != 0 {
		third := isThirdParty(req.Host, req.SourceHost)
		if (r.Party == 1 && !third) || (r.Party == -1 && third) {
			return false
		}
	}
	if len(r.Domains) > 0 || len(r.NotDoms) > 0 {
		src := req.SourceHost
		if src == "" {
			src = req.Host // a navigation: the page is its own source
		}
		if len(r.Domains) > 0 && !domainIn(src, r.Domains) {
			return false
		}
		if len(r.NotDoms) > 0 && domainIn(src, r.NotDoms) {
			return false
		}
	}
	if r.Regex != nil {
		return r.Regex.MatchString(req.URL)
	}
	if r.Pattern == "" {
		return true
	}
	if r.plain {
		return r.plainMatch(req.Host, lurl)
	}
	return r.patternRegex().MatchString(lurl)
}

// plainMatch handles patterns without wildcards (the vast majority).
func (r *NetRule) plainMatch(host, lurl string) bool {
	p := strings.TrimSuffix(r.Pattern, "^")
	sepAtEnd := strings.HasSuffix(r.Pattern, "^")
	switch {
	case r.HostAnch:
		// p is host[/path...]; must match at a host label boundary.
		after := lurl
		if i := strings.Index(after, "://"); i >= 0 {
			after = after[i+3:]
		}
		idx := 0
		for {
			k := strings.Index(after[idx:], p)
			if k < 0 {
				return false
			}
			pos := idx + k
			hostEnd := strings.IndexAny(after, "/?#:")
			if hostEnd < 0 {
				hostEnd = len(after)
			}
			if (pos == 0 || after[pos-1] == '.') && pos <= hostEnd {
				end := pos + len(p)
				if r.EndAnch && end != len(after) {
					idx = pos + 1
					continue
				}
				if sepAtEnd && end < len(after) && !isSeparator(after[end]) {
					idx = pos + 1
					continue
				}
				return true
			}
			idx = pos + 1
			if idx >= len(after) {
				return false
			}
		}
	case r.StartAnch:
		if !strings.HasPrefix(lurl, p) {
			return false
		}
		if r.EndAnch && len(lurl) != len(p) {
			return false
		}
		if sepAtEnd && len(lurl) > len(p) && !isSeparator(lurl[len(p)]) {
			return false
		}
		return true
	default:
		idx := 0
		for {
			k := strings.Index(lurl[idx:], p)
			if k < 0 {
				return false
			}
			pos := idx + k
			end := pos + len(p)
			if r.EndAnch && end != len(lurl) {
				idx = pos + 1
				continue
			}
			if sepAtEnd && end < len(lurl) && !isSeparator(lurl[end]) {
				idx = pos + 1
				continue
			}
			return true
		}
	}
}

func isSeparator(c byte) bool {
	return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '%')
}

func urlTokens(lurl string) []string {
	var toks []string
	n := len(lurl)
	i := 0
	for i < n {
		if !isTokenChar(lurl[i]) {
			i++
			continue
		}
		j := i
		for j < n && isTokenChar(lurl[j]) {
			j++
		}
		if j-i >= 3 {
			toks = append(toks, lurl[i:j])
		}
		i = j
	}
	return toks
}

func domainIn(host string, doms []string) bool {
	for _, d := range doms {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// isThirdParty compares registrable domains; an unknown source counts as
// first-party so $third-party rules do not fire on direct navigations.
func isThirdParty(host, source string) bool {
	if source == "" {
		return false
	}
	return site(host) != site(source)
}

func site(h string) string {
	if net.ParseIP(h) != nil {
		return h
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
		return d
	}
	return h
}

// ---- resource type and source detection ----

// TypeOf infers a request's resource type from fetch metadata headers,
// the Accept header and the URL's extension, in that order of trust.
func TypeOf(u *url.URL, dest, accept, requestedWith string) Type {
	switch strings.ToLower(dest) {
	case "document":
		return TypeDocument
	case "iframe", "frame", "embed", "fencedframe":
		return TypeSubdocument
	case "script", "worker", "sharedworker", "serviceworker":
		return TypeScript
	case "image":
		return TypeImage
	case "style":
		return TypeStylesheet
	case "font":
		return TypeFont
	case "audio", "video", "track", "audioworklet", "paintworklet":
		return TypeMedia
	case "object":
		return TypeObject
	case "empty":
		return TypeXHR
	case "websocket":
		return TypeWebsocket
	}
	a := strings.ToLower(accept)
	switch {
	case strings.HasPrefix(a, "text/html"):
		return TypeDocument
	case strings.HasPrefix(a, "image/"):
		return TypeImage
	case strings.HasPrefix(a, "text/css"):
		return TypeStylesheet
	case strings.HasPrefix(a, "application/json") || requestedWith != "":
		return TypeXHR
	}
	if u != nil {
		p := strings.ToLower(u.Path)
		if i := strings.LastIndexByte(p, '.'); i >= 0 && i > strings.LastIndexByte(p, '/') {
			switch p[i+1:] {
			case "js", "mjs":
				return TypeScript
			case "css":
				return TypeStylesheet
			case "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "avif", "bmp":
				return TypeImage
			case "woff", "woff2", "ttf", "otf", "eot":
				return TypeFont
			case "mp4", "webm", "mp3", "m4a", "ogg", "m3u8", "ts", "mpd", "wav":
				return TypeMedia
			case "html", "htm", "php", "asp", "aspx":
				return TypeDocument
			case "json":
				return TypeXHR
			}
		}
	}
	return TypeOther
}

// SourceOf extracts the page host from Referer or Origin.
func SourceOf(referer, origin string) string {
	for _, v := range []string{referer, origin} {
		if v == "" {
			continue
		}
		if u, err := url.Parse(v); err == nil && u.Host != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	return ""
}

// ---- cosmetic filtering ----

var (
	reID    = regexp.MustCompile(`#([A-Za-z0-9_-]+)`)
	reClass = regexp.MustCompile(`\.([A-Za-z0-9_-]+)`)
	reQuote = regexp.MustCompile(`["']([^"']{3,})["']`)
	reAttrs = regexp.MustCompile(`(?i)\b(?:id|class)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
)

// selectorKey picks the id, class or quoted attribute value a selector
// needs present in the page; "" means the selector is always emitted.
func selectorKey(sel string) string {
	if m := reID.FindStringSubmatch(sel); m != nil {
		return "#" + m[1]
	}
	if m := reClass.FindStringSubmatch(sel); m != nil && !strings.Contains(sel, ":") {
		return "." + m[1]
	}
	if m := reClass.FindStringSubmatch(sel); m != nil {
		return "." + m[1]
	}
	if m := reQuote.FindStringSubmatch(sel); m != nil {
		return "\"" + m[1]
	}
	return ""
}

// CosmeticCSS returns the element-hiding CSS for a page on host, limited
// to generic selectors whose id/class/attribute value actually occurs in
// body plus every site-specific selector. Empty when nothing applies.
func (e *Engine) CosmeticCSS(host string, body []byte) string {
	if e == nil {
		return ""
	}
	host = strings.ToLower(host)
	var sels []string
	seen := map[string]bool{}
	excepted := map[string]bool{}
	for _, s := range e.cosmeticExceptAll {
		excepted[s] = true
	}
	h := host
	for {
		for _, s := range e.cosmeticExcept[h] {
			excepted[s] = true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	addSel := func(s string) {
		if !seen[s] && !excepted[s] {
			seen[s] = true
			sels = append(sels, s)
		}
	}
	// Site-specific first (small, always relevant).
	h = host
	for {
		for _, c := range e.cosmeticByDomain[h] {
			if domainIn(host, c.NotDoms) {
				continue
			}
			addSel(c.Selector)
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	if !e.genericHidden(host) && len(e.cosmeticGeneric) > 0 {
		ids, classes := pageIDsAndClasses(body)
		lbody := strings.ToLower(string(body))
		for _, c := range e.cosmeticGeneric {
			if len(c.NotDoms) > 0 && domainIn(host, c.NotDoms) {
				continue
			}
			switch {
			case c.Key == "":
				addSel(c.Selector)
			case c.Key[0] == '#':
				if ids[c.Key[1:]] {
					addSel(c.Selector)
				}
			case c.Key[0] == '.':
				if classes[c.Key[1:]] {
					addSel(c.Selector)
				}
			case c.Key[0] == '"':
				if strings.Contains(lbody, strings.ToLower(c.Key[1:])) {
					addSel(c.Selector)
				}
			}
		}
	}
	if len(sels) == 0 {
		return ""
	}
	sort.Strings(sels)
	var b strings.Builder
	// Chunk selectors: one invalid selector in a group voids the whole
	// rule, so keep groups small to limit the blast radius.
	for i := 0; i < len(sels); i += 50 {
		j := min(i+50, len(sels))
		b.WriteString(strings.Join(sels[i:j], ",\n"))
		b.WriteString(" { display: none !important; }\n")
	}
	return b.String()
}

func (e *Engine) genericHidden(host string) bool {
	h := host
	for {
		if e.genericHide[h] || e.elemHide[h] {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return false
		}
		h = h[i+1:]
	}
}

func pageIDsAndClasses(body []byte) (ids, classes map[string]bool) {
	ids, classes = map[string]bool{}, map[string]bool{}
	for _, m := range reAttrs.FindAllSubmatch(body, -1) {
		val := m[1]
		if len(val) == 0 {
			val = m[2]
		}
		if len(val) == 0 {
			val = m[3]
		}
		isID := len(m[0]) > 1 && (m[0][0] == 'i' || m[0][0] == 'I')
		for _, f := range strings.Fields(string(val)) {
			if isID {
				ids[f] = true
			} else {
				classes[f] = true
			}
		}
	}
	return ids, classes
}
