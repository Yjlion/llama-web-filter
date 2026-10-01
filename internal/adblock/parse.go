// Package adblock is an EasyList-compatible ad and tracker blocker: it
// parses Adblock Plus filter lists into network rules (which requests to
// refuse) and cosmetic rules (which page elements to hide), and matches
// requests against them fast enough for a proxy's request path.
//
// Supported syntax: ||host^ anchors, |start and end| anchors, * and ^
// wildcards, /regex/ patterns, @@ exceptions, and the common options
// (third-party, domain=, the resource types, important, generichide/
// elemhide). Rules using options this engine cannot honour (popup,
// redirect, csp, removeparam, rewrite, replace, header, badfilter) are
// skipped rather than misapplied, as are procedural (#?#) and scriptlet
// (#$# / #%#) cosmetic rules.
package adblock

import (
	"bufio"
	"io"
	"regexp"
	"strings"
	"sync"
)

// Type is a request resource type, as a bit.
type Type uint32

const (
	TypeScript Type = 1 << iota
	TypeImage
	TypeStylesheet
	TypeObject
	TypeXHR
	TypeSubdocument
	TypeDocument
	TypeFont
	TypeMedia
	TypePing
	TypeWebsocket
	TypeOther
	typeAll = TypeScript | TypeImage | TypeStylesheet | TypeObject | TypeXHR | TypeSubdocument | TypeDocument | TypeFont | TypeMedia | TypePing | TypeWebsocket | TypeOther
)

var typeNames = map[string]Type{
	"script": TypeScript, "image": TypeImage, "stylesheet": TypeStylesheet, "css": TypeStylesheet,
	"object": TypeObject, "xmlhttprequest": TypeXHR, "xhr": TypeXHR, "subdocument": TypeSubdocument,
	"frame": TypeSubdocument, "document": TypeDocument, "doc": TypeDocument, "font": TypeFont,
	"media": TypeMedia, "ping": TypePing, "beacon": TypePing, "websocket": TypeWebsocket,
	"other": TypeOther, "object-subrequest": TypeObject,
}

// NetRule is one parsed network filter.
type NetRule struct {
	Raw       string
	Pattern   string // lowercase, anchors stripped
	HostPart  string // for || rules: the host portion of Pattern (up to the first / ^ * |)
	Exception bool
	HostAnch  bool // ||
	StartAnch bool // leading |
	EndAnch   bool // trailing |
	Regex     *regexp.Regexp
	Types     Type // 0 = any
	NotTypes  Type // excluded types
	Party     int8 // 0 any, 1 third-party only, -1 first-party only
	Domains   []string
	NotDoms   []string
	Important bool
	// cosmetic exceptions attached to network syntax
	GenericHide bool
	ElemHide    bool

	token   string
	reOnce  sync.Once
	compile *regexp.Regexp
	plain   bool // pattern has no wildcards: substring/prefix checks suffice
}

// CosmeticRule is one element-hiding filter.
type CosmeticRule struct {
	Selector  string
	Domains   []string // empty = generic
	NotDoms   []string
	Exception bool // #@#
}

// reCosmeticSep recognises every cosmetic separator (##, #@#, #?#, #$#,
// #%# and their combinations) so no cosmetic line is mistaken for a
// network pattern.
var reCosmeticSep = regexp.MustCompile(`#[@?$%]*#`)

// Parsed is the output of one list.
type Parsed struct {
	Network  []*NetRule
	Cosmetic []CosmeticRule
	Skipped  int
	Lines    int
}

// Parse reads a filter list.
func Parse(r io.Reader) Parsed {
	var out Parsed
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		out.Lines++
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		if reCosmeticSep.MatchString(line) {
			if c, ok := parseCosmetic(line); ok {
				out.Cosmetic = append(out.Cosmetic, c)
			} else {
				out.Skipped++
			}
			continue
		}
		if n, ok := parseNetwork(line); ok {
			out.Network = append(out.Network, n)
		} else {
			out.Skipped++
		}
	}
	return out
}

func parseCosmetic(line string) (CosmeticRule, bool) {
	// Reject procedural / scriptlet / snippet forms.
	for _, bad := range []string{"#?#", "#$#", "#%#", "#$?#", "#@?#", "#@$#", "#@%#"} {
		if strings.Contains(line, bad) {
			return CosmeticRule{}, false
		}
	}
	sep := "##"
	exception := false
	if i := strings.Index(line, "#@#"); i >= 0 {
		sep = "#@#"
		exception = true
	}
	i := strings.Index(line, sep)
	if i < 0 {
		return CosmeticRule{}, false
	}
	doms := strings.TrimSpace(line[:i])
	sel := strings.TrimSpace(line[i+len(sep):])
	if sel == "" || strings.ContainsAny(sel, "\n\r") {
		return CosmeticRule{}, false
	}
	// uBlock-only extended selectors cannot be expressed in plain CSS.
	if strings.Contains(sel, ":has(") || strings.Contains(sel, ":-abp-") || strings.Contains(sel, ":matches-css") || strings.Contains(sel, ":xpath") || strings.Contains(sel, ":upward") || strings.Contains(sel, ":remove") || strings.Contains(sel, ":style(") || strings.Contains(sel, ":contains") {
		return CosmeticRule{}, false
	}
	c := CosmeticRule{Selector: sel, Exception: exception}
	if doms != "" {
		for _, d := range strings.Split(doms, ",") {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" {
				continue
			}
			if strings.HasPrefix(d, "~") {
				c.NotDoms = append(c.NotDoms, d[1:])
			} else {
				c.Domains = append(c.Domains, d)
			}
		}
	}
	return c, true
}

func parseNetwork(line string) (*NetRule, bool) {
	r := &NetRule{Raw: line}
	s := line
	if strings.HasPrefix(s, "@@") {
		r.Exception = true
		s = s[2:]
	}
	// A regex rule is /.../ optionally followed by $options; a pattern that
	// merely starts with "/" (a path) is not one.
	if end := strings.LastIndex(s, "/"); strings.HasPrefix(s, "/") && end > 0 && (end == len(s)-1 || s[end+1] == '$') {
		opts := ""
		if end+1 < len(s) {
			opts = s[end+2:]
		}
		re, err := regexp.Compile("(?i)" + s[1:end])
		if err != nil {
			return nil, false
		}
		r.Regex = re
		if !r.applyOptions(opts) {
			return nil, false
		}
		return r, true
	}
	if i := strings.LastIndex(s, "$"); i >= 0 {
		if !r.applyOptions(s[i+1:]) {
			return nil, false
		}
		s = s[:i]
	}
	if strings.HasPrefix(s, "||") {
		r.HostAnch = true
		s = s[2:]
	} else if strings.HasPrefix(s, "|") {
		r.StartAnch = true
		s = s[1:]
	}
	if strings.HasSuffix(s, "|") {
		r.EndAnch = true
		s = s[:len(s)-1]
	}
	s = strings.ToLower(s)
	// A bare "*" pattern (with options) matches everything.
	if s == "*" {
		s = ""
	}
	r.Pattern = s
	if r.HostAnch {
		end := strings.IndexAny(s, "/^*|")
		if end < 0 {
			end = len(s)
		}
		r.HostPart = s[:end]
		if r.HostPart == "" {
			return nil, false
		}
	}
	r.plain = !strings.ContainsAny(strings.TrimSuffix(s, "^"), "*^")
	r.token = chooseToken(s, r.HostAnch || r.StartAnch, r.EndAnch)
	if r.Pattern == "" && r.Types == 0 && r.Party == 0 && len(r.Domains) == 0 {
		// Would match everything with no qualifier: never intended.
		return nil, false
	}
	return r, true
}

var unsupportedOptions = map[string]bool{
	"popup": true, "redirect": true, "redirect-rule": true, "csp": true, "removeparam": true, "rewrite": true,
	"replace": true, "header": true, "badfilter": true, "inline-script": true, "inline-font": true,
	"mp4": true, "empty": true, "permissions": true, "urltransform": true, "uritransform": true, "cookie": true,
	"strict1p": true, "strict3p": true, "all": true, "method": true, "ipaddress": true, "to": true, "from": true,
	"denyallow": true, "ehide": true, "ghide": true, "shide": true, "specifichide": true,
}

// applyOptions parses the $-options; ok=false means the rule is skipped.
func (r *NetRule) applyOptions(opts string) bool {
	if strings.TrimSpace(opts) == "" {
		return true
	}
	for _, o := range strings.Split(opts, ",") {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		neg := strings.HasPrefix(o, "~")
		if neg {
			o = o[1:]
		}
		key, val, hasVal := strings.Cut(o, "=")
		key = strings.ToLower(key)
		switch {
		case key == "third-party" || key == "3p":
			if neg {
				r.Party = -1
			} else {
				r.Party = 1
			}
		case key == "first-party" || key == "1p":
			if neg {
				r.Party = 1
			} else {
				r.Party = -1
			}
		case key == "domain" && hasVal:
			for _, d := range strings.Split(strings.ToLower(val), "|") {
				d = strings.TrimSpace(d)
				if d == "" {
					continue
				}
				if strings.HasPrefix(d, "~") {
					r.NotDoms = append(r.NotDoms, d[1:])
				} else {
					r.Domains = append(r.Domains, d)
				}
			}
		case key == "important":
			r.Important = true
		case key == "match-case":
		case key == "generichide":
			r.GenericHide = true
		case key == "elemhide":
			r.ElemHide = true
		case unsupportedOptions[key]:
			return false
		default:
			if t, ok := typeNames[key]; ok {
				if neg {
					r.NotTypes |= t
				} else {
					r.Types |= t
				}
				continue
			}
			// Unknown option: skip the rule rather than guess.
			return false
		}
	}
	return true
}

// chooseToken picks an alphanumeric run of the pattern that must appear
// verbatim in any matching URL, for the token index. A run next to a
// wildcard or at an unanchored pattern edge may be a partial word in the
// URL, so only fully delimited runs qualify.
func chooseToken(p string, startAnchored, endAnchored bool) string {
	best := ""
	n := len(p)
	i := 0
	for i < n {
		if !isTokenChar(p[i]) {
			i++
			continue
		}
		j := i
		for j < n && isTokenChar(p[j]) {
			j++
		}
		leftOK := (i == 0 && startAnchored) || (i > 0 && p[i-1] != '*')
		rightOK := (j == n && endAnchored) || (j < n && p[j] != '*')
		if j-i >= 3 && leftOK && rightOK && j-i > len(best) {
			best = p[i:j]
		}
		i = j
	}
	return best
}

func isTokenChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
}

// patternRegex converts an ABP pattern to a regexp (lazily, once).
func (r *NetRule) patternRegex() *regexp.Regexp {
	r.reOnce.Do(func() {
		var b strings.Builder
		b.WriteString("(?i)")
		if r.HostAnch {
			b.WriteString(`^[a-z][a-z0-9+.-]*://(?:[^/?#]*\.)?`)
		} else if r.StartAnch {
			b.WriteString("^")
		}
		for i := 0; i < len(r.Pattern); i++ {
			c := r.Pattern[i]
			switch c {
			case '*':
				b.WriteString(".*")
			case '^':
				b.WriteString(`(?:[^\w.%-]|$)`)
			default:
				b.WriteString(regexp.QuoteMeta(string(c)))
			}
		}
		if r.EndAnch {
			b.WriteString("$")
		}
		re, err := regexp.Compile(b.String())
		if err != nil {
			re = regexp.MustCompile(`\A\z.`) // never matches
		}
		r.compile = re
	})
	return r.compile
}
