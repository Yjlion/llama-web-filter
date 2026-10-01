package proxy

import (
	"regexp"
	"strings"
	"sync"
)

// HostMatches reports an exact, "*.wildcard" (subdomain), or glob host
// match, ported from proxy/matching.py's host_matches.
func HostMatches(host, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return fnmatch(host, pattern)
}

// UrlMatches reports whether url matches pattern. Patterns containing '/'
// match the full URL (glob or prefix); otherwise the pattern is treated as
// a host pattern. Path patterns may include or omit the scheme - a
// scheme-less pattern like "example.com/path" is checked against both the
// full URL and against the URL with its scheme stripped. Ported from
// proxy/matching.py's url_matches.
func UrlMatches(host, url, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if strings.Contains(pattern, "/") {
		if fnmatch(url, pattern) || strings.HasPrefix(url, pattern) {
			return true
		}
		for _, prefix := range []string{"https://", "http://"} {
			if strings.HasPrefix(url, prefix) {
				urlNoScheme := url[len(prefix):]
				if fnmatch(urlNoScheme, pattern) || strings.HasPrefix(urlNoScheme, pattern) {
					return true
				}
				break
			}
		}
		return false
	}
	return HostMatches(host, pattern)
}

// UrlInList reports whether any pattern in patterns matches url via
// UrlMatches. Ported from proxy/matching.py's url_in_list.
func UrlInList(host, url string, patterns []string) bool {
	for _, p := range patterns {
		if strings.TrimSpace(p) != "" && UrlMatches(host, url, p) {
			return true
		}
	}
	return false
}

// DomainInList is a domain-only suffix match (exact host or any
// subdomain). Strips a leading "*." so "*.example.com" and "example.com"
// behave the same. Ported from proxy/matching.py's domain_in_list.
func DomainInList(host string, patterns []string) bool {
	for _, p := range patterns {
		s := strings.TrimPrefix(strings.TrimSpace(p), "*.")
		if s == "" {
			continue
		}
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// fnmatch mirrors Python's fnmatch.fnmatchcase: '*' matches any sequence of
// characters (including '/' and none), '?' matches any single character,
// '[seq]'/'[!seq]' are character classes. Deliberately case-sensitive on
// every platform (fnmatch.fnmatch's case sensitivity otherwise varies by
// OS via os.path.normcase, which would make block-list matching behave
// differently between a Windows and a Linux deployment of the same
// policies/*.json - a single, predictable behavior is preferable to
// reproducing that platform quirk).
func fnmatch(name, pattern string) bool {
	re := fnmatchRegexp(pattern)
	return re.MatchString(name)
}

var (
	fnmatchMu    sync.Mutex
	fnmatchCache = make(map[string]*regexp.Regexp)
)

func fnmatchRegexp(pattern string) *regexp.Regexp {
	fnmatchMu.Lock()
	if re, ok := fnmatchCache[pattern]; ok {
		fnmatchMu.Unlock()
		return re
	}
	fnmatchMu.Unlock()

	re := regexp.MustCompile("(?s)^" + fnmatchTranslate(pattern) + "$")
	fnmatchMu.Lock()
	fnmatchCache[pattern] = re
	fnmatchMu.Unlock()
	return re
}

// fnmatchTranslate converts an fnmatch-style glob into a regexp body,
// following the same translation fnmatch.translate() performs.
func fnmatchTranslate(pattern string) string {
	var b strings.Builder
	i, n := 0, len(pattern)
	for i < n {
		c := pattern[i]
		i++
		switch c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '[':
			j := i
			if j < n && (pattern[j] == '!' || pattern[j] == ']') {
				j++
			}
			for j < n && pattern[j] != ']' {
				j++
			}
			if j >= n {
				b.WriteString(`\[`)
				continue
			}
			class := pattern[i:j]
			class = strings.ReplaceAll(class, `\`, `\\`)
			i = j + 1
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			} else if strings.HasPrefix(class, "^") {
				class = `\` + class
			}
			b.WriteString("[" + class + "]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}
