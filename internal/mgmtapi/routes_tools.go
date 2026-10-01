package mgmtapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yjlion/llama-web-filter/internal/neighbors"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
)

// registerToolsRoutes wires the diagnostic /api/tools/* endpoints that back
// the Tools page and the policy editor's "scan network" MAC picker:
//
//	POST /api/tools/scan       — NSFW scan of a URL, using the same LLM
//	                             classification backend as the proxy pipeline.
//	POST /api/tools/youtube    — parse a YouTube URL + fetch oEmbed metadata.
//	POST /api/tools/doh        — query a DoH resolver and report block status.
//	GET  /api/tools/public-ip  — discover the host's public IP.
//	GET  /api/tools/neighbors  — list the ARP/NDP neighbor table (IP/MAC).
func (s *Server) registerToolsRoutes(r chi.Router) {
	r.Post("/api/tools/scan", s.handleToolsScan)
	r.Post("/api/tools/youtube", s.handleToolsYouTube)
	r.Post("/api/tools/doh", s.handleToolsDoh)
	r.Get("/api/tools/public-ip", s.handleToolsPublicIP)
	r.Get("/api/tools/neighbors", s.handleToolsNeighbors)
}

// toolsHTTPClient deliberately bypasses any configured system proxy (which
// could be this proxy itself) so diagnostic lookups go out directly -
// mirrors the Python original's httpx.AsyncClient(trust_env=False).
var toolsHTTPClient = &http.Client{
	Timeout:   8 * time.Second,
	Transport: &http.Transport{Proxy: nil},
}

// ---------------------------------------------------------------------------
// POST /api/tools/scan
// ---------------------------------------------------------------------------

// Scan tuning defaults, matching the Tools page's own input defaults so an
// explicit value and the placeholder behave identically.
const (
	defaultScanTextThreshold  = 0.80
	defaultScanImageThreshold = 0.40
	defaultScanMaxImages      = 50
	maxScanMaxImages          = 200

	// Page bodies are only ever fed to the text classifier, so a modest cap is
	// plenty; images have to be decoded, so they get a bigger one.
	scanPageByteLimit  = 4 << 20
	scanImageByteLimit = 16 << 20
)

// handleToolsScan fetches a URL and classifies it with the same backend the
// proxy pipeline uses (Server.Scanner, the LLM verdict service), behind
// addons.KeywordScore's pre-filter for page text. A nil Scanner reports the
// scan as an error rather than silently calling everything clean.
//
// The response shape is dictated by ui/tools.html's result markup: "image",
// "page", "other" and "error" types, each with its own fields.
func (s *Server) handleToolsScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		URL            string   `json:"url"`
		TextThreshold  *float64 `json:"text_threshold"`
		ImageThreshold *float64 `json:"image_threshold"`
		MaxImages      *int     `json:"max_images"`
	}
	_ = readJSON(r, &payload)

	raw := strings.TrimSpace(payload.URL)
	if raw == "" {
		writeJSONError(w, http.StatusBadRequest, "url is required")
		return
	}
	target, err := url.Parse(raw)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
		writeJSONError(w, http.StatusBadRequest, "url must be an absolute http:// or https:// URL")
		return
	}

	textThreshold := clampFloat(payload.TextThreshold, defaultScanTextThreshold)
	imageThreshold := clampFloat(payload.ImageThreshold, defaultScanImageThreshold)
	maxImages := defaultScanMaxImages
	if payload.MaxImages != nil && *payload.MaxImages > 0 {
		maxImages = min(*payload.MaxImages, maxScanMaxImages)
	}

	resp, body, err := fetchForScan(target.String(), scanPageByteLimit)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"type": "error", "error": err.Error(), "url": target.String()})
		return
	}

	ct := resp.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "image/"):
		writeJSON(w, http.StatusOK, s.scanImageBytes(r.Context(), target.String(), body, imageThreshold))
	case strings.Contains(ct, "text/html"):
		writeJSON(w, http.StatusOK, s.scanPage(r.Context(), target, body, textThreshold, imageThreshold, maxImages))
	default:
		writeJSON(w, http.StatusOK, map[string]any{
			"type":         "other",
			"url":          target.String(),
			"content_type": ct,
		})
	}
}

func clampFloat(v *float64, def float64) float64 {
	if v == nil || *v < 0 || *v > 1 {
		return def
	}
	return *v
}

func (s *Server) scanImageBytes(ctx context.Context, u string, body []byte, threshold float64) map[string]any {
	if s.Scanner == nil {
		return map[string]any{"type": "image", "url": u, "error": "no classification backend available"}
	}
	res, err := s.Scanner.ScanImage(ctx, body)
	if err != nil {
		// An undecodable or unscorable image is an error, never "clean" -
		// reporting it as safe is the failure mode this tool exists to catch.
		return map[string]any{"type": "image", "url": u, "error": err.Error()}
	}
	return map[string]any{
		"type":       "image",
		"url":        u,
		"nsfw":       res.Adult || res.Score >= threshold,
		"score":      res.Score,
		"threshold":  threshold,
		"detections": res.Detections,
		"source":     res.Source,
	}
}

// imgSrcRe pulls src="..." out of <img> tags. A regex rather than a parser
// keeps this dependency-free and matches how the proxy's own inline-image
// scanning works; over-matching only costs an extra fetch that reports its
// own error.
var imgSrcRe = regexp.MustCompile(`(?i)<img\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']`)

func (s *Server) scanPage(ctx context.Context, page *url.URL, body []byte, textThreshold, imageThreshold float64, maxImages int) map[string]any {
	text := addons.StripHTML(string(body))
	keyword := addons.KeywordScore(text)

	nsfwText := keyword >= 1.0
	var mlScore any
	var mlError any
	if !nsfwText && s.Scanner != nil {
		if res, err := s.Scanner.ScanText(ctx, text); err == nil {
			mlScore = res.Score
			nsfwText = res.Adult || res.Score >= textThreshold
		} else {
			mlError = err.Error()
		}
	}

	result := map[string]any{
		"type": "page",
		"url":  page.String(),
		"text": map[string]any{
			"nsfw":          nsfwText,
			"keyword_score": keyword,
			"ml_score":      mlScore,
			"ml_error":      mlError,
			"threshold":     textThreshold,
		},
	}

	result["images"] = s.scanPageImages(ctx, page, body, imageThreshold, maxImages)
	return result
}

func (s *Server) scanPageImages(ctx context.Context, page *url.URL, body []byte, threshold float64, maxImages int) []map[string]any {
	seen := make(map[string]bool)
	var targets []*url.URL
	for _, m := range imgSrcRe.FindAllStringSubmatch(string(body), -1) {
		ref, err := url.Parse(strings.TrimSpace(m[1]))
		if err != nil {
			continue
		}
		abs := page.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			continue // skip data: URIs and anything else non-fetchable
		}
		if seen[abs.String()] {
			continue
		}
		seen[abs.String()] = true
		targets = append(targets, abs)
		if len(targets) >= maxImages {
			break
		}
	}

	out := make([]map[string]any, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8) // bounded: this runs on the mgmt server
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t *url.URL) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			_, imgBody, err := fetchForScan(t.String(), scanImageByteLimit)
			if err != nil {
				// Per-image failures are reported in the row, not fatal to the
				// whole scan - one dead thumbnail shouldn't lose every verdict.
				out[i] = map[string]any{"url": t.String(), "nsfw": false, "error": err.Error()}
				return
			}
			out[i] = s.scanImageBytes(ctx, t.String(), imgBody, threshold)
		}(i, t)
	}
	wg.Wait()
	return out
}

// fetchForScan retrieves a URL for scanning, capping how much it will read.
func fetchForScan(rawURL string, limit int64) (*http.Response, []byte, error) {
	resp, err := toolsHTTPClient.Get(rawURL)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, &httpStatusError{resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, nil, err
	}
	return resp, body, nil
}

// ---------------------------------------------------------------------------
// POST /api/tools/youtube
// ---------------------------------------------------------------------------

var (
	ytVideoRE     = regexp.MustCompile(`(?:youtube\.com/(?:watch\?(?:.*&)?v=|embed/|shorts/)|youtu\.be/)([\w-]{11})`)
	ytChannelIDRE = regexp.MustCompile(`youtube\.com/channel/(UC[\w-]{22})`)
	ytHandleRE    = regexp.MustCompile(`youtube\.com/(@[\w.\-]+)`)
	ytCustomRE    = regexp.MustCompile(`youtube\.com/(?:c|user)/([\w.\-]+)`)
)

// parseYouTubeURL mirrors tools.py's _parse_youtube_url.
func parseYouTubeURL(u string) (kind, videoID, channel string) {
	if m := ytVideoRE.FindStringSubmatch(u); m != nil {
		return "video", m[1], ""
	}
	if m := ytChannelIDRE.FindStringSubmatch(u); m != nil {
		return "channel", "", m[1]
	}
	if m := ytHandleRE.FindStringSubmatch(u); m != nil {
		return "channel", "", m[1]
	}
	if m := ytCustomRE.FindStringSubmatch(u); m != nil {
		return "channel", "", m[1]
	}
	return "unknown", "", ""
}

func (s *Server) handleToolsYouTube(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		URL string `json:"url"`
	}
	_ = readJSON(r, &payload)
	u := strings.TrimSpace(payload.URL)
	if u == "" {
		writeJSONError(w, http.StatusBadRequest, "url is required")
		return
	}

	kind, videoID, channel := parseYouTubeURL(u)
	result := map[string]any{
		"kind":     kind,
		"video_id": nilIfEmpty(videoID),
		"channel":  nilIfEmpty(channel),
		"url":      u,
	}

	if kind == "video" {
		oembedURL := "https://www.youtube.com/oembed?url=" + url.QueryEscape(u) + "&format=json"
		if oembed, err := fetchJSON(oembedURL); err != nil {
			result["oembed_error"] = err.Error()
		} else {
			result["title"] = oembed["title"]
			result["author_name"] = oembed["author_name"]
			result["author_url"] = oembed["author_url"]
			result["thumbnail_url"] = oembed["thumbnail_url"]
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// ---------------------------------------------------------------------------
// POST /api/tools/doh
// ---------------------------------------------------------------------------

func (s *Server) handleToolsDoh(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Domain string `json:"domain"`
		Server string `json:"server"`
	}
	_ = readJSON(r, &payload)
	domain := strings.TrimSpace(payload.Domain)
	if domain == "" {
		writeJSONError(w, http.StatusBadRequest, "domain is required")
		return
	}
	server := strings.TrimSpace(payload.Server)
	if server == "" {
		server = s.defaultDohServer()
	}
	writeJSON(w, http.StatusOK, addons.QueryDohDetailed(domain, server))
}

// defaultDohServer returns the DoH endpoint from the first policy that
// configures one, falling back to Cloudflare's family resolver - mirrors
// tools.py's _default_doh_server.
func (s *Server) defaultDohServer() string {
	policies, err := s.Policies.List()
	if err == nil {
		for _, p := range policies {
			if srv := strings.TrimSpace(p.Doh.Server); srv != "" {
				return srv
			}
		}
	}
	return "https://1.1.1.3/dns-query"
}

// ---------------------------------------------------------------------------
// GET /api/tools/public-ip
// ---------------------------------------------------------------------------

func (s *Server) handleToolsPublicIP(w http.ResponseWriter, r *http.Request) {
	// ipify returns {"ip": "..."}; ifconfig.me returns a bare IP string.
	if body, err := fetchJSON("https://api.ipify.org?format=json"); err == nil {
		writeJSON(w, http.StatusOK, body)
		return
	}
	if ip, err := fetchText("https://ifconfig.me/ip"); err == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ip": strings.TrimSpace(ip)})
		return
	}
	// Use the same {"detail": ...} envelope as every other handler; the Tools
	// page reads body.detail on any non-2xx.
	writeJSONError(w, http.StatusBadGateway, "all public-ip providers failed")
}

// ---------------------------------------------------------------------------
// GET /api/tools/neighbors
// ---------------------------------------------------------------------------

func (s *Server) handleToolsNeighbors(w http.ResponseWriter, r *http.Request) {
	neighbors.ConfigureOUI(s.Settings().OuiPath)
	entries := neighbors.Scan()
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{
			"ip":     e.IP,
			"mac":    e.MAC,
			"iface":  e.Iface,
			"vendor": e.Vendor,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"neighbors": out})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func fetchText(rawURL string) (string, error) {
	resp, err := toolsHTTPClient.Get(rawURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", &httpStatusError{resp.StatusCode}
	}
	return string(body), nil
}

func fetchJSON(rawURL string) (map[string]any, error) {
	resp, err := toolsHTTPClient.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &httpStatusError{resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string {
	return "unexpected HTTP status " + strconv.Itoa(e.code)
}
