// Package sitecat is the fixed website taxonomy the model sorts sites into
// (shopping, news, social media, banking, ...) and that policies block or
// allow by. The slugs are stable identifiers stored in policies/*.json and
// the decision cache; labels and descriptions are for people and for the
// model's prompt.
package sitecat

import (
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Category is one entry of the taxonomy.
type Category struct {
	Slug        string `json:"slug"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// Infrastructure is the category for CDNs, APIs, login and asset hosts. It is
// always allowed in allow-only-listed mode, or every site would break.
const Infrastructure = "infrastructure"

// Other is the catch-all.
const Other = "other"

var all = []Category{
	{"adult", "Adult", "pornography, sexually explicit material, escort and adult-content sites"},
	{"dating", "Dating", "dating apps and personals"},
	{"gambling", "Gambling", "casinos, betting, lotteries, poker"},
	{"social_media", "Social media", "social networks and feeds: Facebook, Instagram, TikTok, X, Reddit, Snapchat"},
	{"chat_messaging", "Chat & messaging", "messengers, chat rooms, Discord, WhatsApp web"},
	{"email", "Email", "webmail services"},
	{"news", "News", "news outlets, newspapers, magazines, current affairs"},
	{"shopping", "Shopping", "online stores, marketplaces, auctions, deals"},
	{"banking_finance", "Banking & finance", "banks, payments, investing, insurance, crypto exchanges"},
	{"streaming_video", "Video streaming", "video sites and streaming services: YouTube, Netflix, Twitch"},
	{"music_audio", "Music & audio", "music streaming, radio, podcasts"},
	{"gaming", "Games", "online games, game stores and gaming communities"},
	{"entertainment", "Entertainment", "celebrities, humor, movies and TV information, fan sites"},
	{"sports", "Sports", "sports news, teams, leagues, scores"},
	{"search", "Search engines", "web search and portals"},
	{"education", "Education", "schools, universities, courses, reference, encyclopedias"},
	{"kids", "Kids", "sites made for children"},
	{"government", "Government", "government services, public agencies, politics"},
	{"health", "Health", "medical information, hospitals, pharmacies, fitness"},
	{"travel", "Travel", "airlines, hotels, booking, maps, tourism"},
	{"jobs", "Jobs", "job boards, recruiting, careers"},
	{"religion", "Religion", "religious organisations and content"},
	{"technology", "Technology", "software, developer sites, tech news, hardware"},
	{"business", "Business", "company sites, B2B services, productivity and office tools"},
	{"ads_tracking", "Ads & tracking", "advertising networks, analytics and tracking"},
	{"malware_phishing", "Malware & phishing", "malicious, scam and phishing sites"},
	{"piracy", "Piracy", "illegal downloads, torrents, warez, unlicensed streams"},
	{"drugs_alcohol", "Drugs & alcohol", "recreational drugs, alcohol and tobacco sales or promotion"},
	{"weapons", "Weapons", "guns, weapons sales and accessories"},
	{"violence_hate", "Violence & hate", "gore, extremism, hate speech"},
	{Infrastructure, "Infrastructure", "CDNs, APIs, login, update and static asset servers, not a site people visit"},
	{Other, "Other", "anything that fits nowhere else"},
}

var bySlug = func() map[string]Category {
	m := make(map[string]Category, len(all))
	for _, c := range all {
		m[c.Slug] = c
	}
	return m
}()

// All returns the taxonomy in display order.
func All() []Category { return append([]Category(nil), all...) }

// Slugs returns every slug in display order.
func Slugs() []string {
	out := make([]string, len(all))
	for i, c := range all {
		out[i] = c.Slug
	}
	return out
}

// Valid reports whether slug is in the taxonomy.
func Valid(slug string) bool { _, ok := bySlug[slug]; return ok }

// Label returns the display label for slug (the slug itself if unknown).
func Label(slug string) string {
	if c, ok := bySlug[slug]; ok {
		return c.Label
	}
	return slug
}

// Normalize lowercases and trims slug and maps common spellings ("social
// media", "banking") onto the taxonomy. It returns "" when nothing fits.
func Normalize(slug string) string {
	s := strings.ToLower(strings.TrimSpace(slug))
	s = strings.NewReplacer(" & ", "_", "&", "_", " ", "_", "-", "_").Replace(s)
	if Valid(s) {
		return s
	}
	if v, ok := aliases[s]; ok {
		return v
	}
	return ""
}

var aliases = map[string]string{
	"porn": "adult", "pornography": "adult", "social": "social_media", "socialmedia": "social_media",
	"social_networks": "social_media", "chat": "chat_messaging", "messaging": "chat_messaging",
	"webmail": "email", "banking": "banking_finance", "banks": "banking_finance", "bank": "banking_finance",
	"finance": "banking_finance", "video": "streaming_video", "streaming": "streaming_video",
	"music": "music_audio", "games": "gaming", "game": "gaming", "sport": "sports",
	"ads": "ads_tracking", "advertising": "ads_tracking", "tracking": "ads_tracking",
	"malware": "malware_phishing", "phishing": "malware_phishing", "drugs": "drugs_alcohol",
	"alcohol": "drugs_alcohol", "violence": "violence_hate", "hate": "violence_hate",
	"cdn": Infrastructure, "api": Infrastructure, "tech": "technology", "dating_sites": "dating",
	"online_shopping": "shopping", "search_engines": "search", "children": "kids",
}

// ListMap maps the IPFire domain-list names (internal/categories) onto the
// taxonomy. Lists not named here (doh, smart-tv) say nothing about a site's
// category.
var ListMap = map[string]string{
	"porn":      "adult",
	"dating":    "dating",
	"gambling":  "gambling",
	"games":     "gaming",
	"shopping":  "shopping",
	"social":    "social_media",
	"streaming": "streaming_video",
	"ads":       "ads_tracking",
	"malware":   "malware_phishing",
	"phishing":  "malware_phishing",
	"piracy":    "piracy",
	"violence":  "violence_hate",
}

// listOrder fixes the lookup order so a host on several lists gets a
// deterministic answer, most restrictive first.
var listOrder = []string{"malware", "phishing", "porn", "gambling", "dating", "piracy", "violence",
	"ads", "social", "streaming", "games", "shopping"}

// ListMatcher is the part of categories.Store FromLists needs.
type ListMatcher interface {
	HostMatches(host, name string) bool
}

// FromLists returns the taxonomy slug the installed domain lists give host,
// or "" when no mapped list knows it.
func FromLists(lists ListMatcher, host string) string {
	if lists == nil || host == "" {
		return ""
	}
	for _, name := range listOrder {
		if lists.HostMatches(host, name) {
			return ListMap[name]
		}
	}
	return ""
}

// SiteKey reduces a host (or URL) to the registrable domain categories are
// cached under: www.amazon.co.uk and smile.amazon.co.uk share amazon.co.uk.
func SiteKey(urlOrHost string) string {
	h := HostOf(urlOrHost)
	if h == "" || net.ParseIP(h) != nil {
		return h
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
		return d
	}
	return h
}

// HostOf strips scheme, path and port and lowercases.
func HostOf(urlOrHost string) string {
	s := strings.TrimSpace(urlOrHost)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// Contains reports whether slug is in list.
func Contains(list []string, slug string) bool {
	for _, s := range list {
		if s == slug {
			return true
		}
	}
	return false
}
