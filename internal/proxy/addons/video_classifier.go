package addons

import (
	"bytes"
	"container/list"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yjlion/llama-web-filter/internal/metrics"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
)

// ImageFetcher fetches an image the page references (a poster, a
// thumbnail) so it can be judged before the video plays.
type ImageFetcher interface {
	FetchImage(ctx context.Context, rawURL string, headers http.Header) ([]byte, error)
}

// VideoClassifier blocks adult videos. The model only sees stills, so a
// video is judged by its poster (<video poster=...>), by its YouTube
// thumbnail (from the player response), or, with ffmpeg on PATH and
// keyframes enabled, by keyframes decoded from the stream. Verdicts are
// remembered per video URL so the stream request itself is refused on
// later plays. Independent of the YouTube channel filter.
type VideoClassifier struct {
	Classifier ContentClassifier
	Fetcher    ImageFetcher

	mu   sync.Mutex
	mem  map[string]*list.Element
	lru  *list.List
	size int
}

type videoVerdict struct {
	key   string
	adult bool
}

// NewVideoClassifier returns an addon with a bounded verdict memory.
func NewVideoClassifier(c ContentClassifier, f ImageFetcher) *VideoClassifier {
	return &VideoClassifier{Classifier: c, Fetcher: f, mem: map[string]*list.Element{}, lru: list.New(), size: 4096}
}

func (*VideoClassifier) Name() string { return "video_classifier" }

func (vc *VideoClassifier) remember(key string, adult bool) {
	if vc.mem == nil {
		vc.mem, vc.lru, vc.size = map[string]*list.Element{}, list.New(), 4096
	}
	vc.mu.Lock()
	defer vc.mu.Unlock()
	if e, ok := vc.mem[key]; ok {
		e.Value.(*videoVerdict).adult = adult
		vc.lru.MoveToFront(e)
		return
	}
	vc.mem[key] = vc.lru.PushFront(&videoVerdict{key: key, adult: adult})
	for vc.lru.Len() > vc.size {
		last := vc.lru.Back()
		vc.lru.Remove(last)
		delete(vc.mem, last.Value.(*videoVerdict).key)
	}
}

func (vc *VideoClassifier) lookup(key string) (adult, known bool) {
	if vc.mem == nil {
		return false, false
	}
	vc.mu.Lock()
	defer vc.mu.Unlock()
	if e, ok := vc.mem[key]; ok {
		vc.lru.MoveToFront(e)
		return e.Value.(*videoVerdict).adult, true
	}
	return false, false
}

// videoKey normalises a stream URL: scheme, host and path without query,
// since players request ranges with changing query strings.
func videoKey(u *url.URL) string {
	return strings.ToLower(u.Scheme + "://" + u.Host + u.Path)
}

func videoShouldFilter(host, rawURL string, cfg models.VideoClassifierConfig) bool {
	if len(cfg.IncludeOnly) > 0 {
		return proxy.UrlInList(host, rawURL, cfg.IncludeOnly)
	}
	if len(cfg.Exclude) > 0 {
		return !proxy.UrlInList(host, rawURL, cfg.Exclude)
	}
	return true
}

var videoExt = map[string]bool{".mp4": true, ".webm": true, ".m4v": true, ".mov": true, ".m3u8": true, ".mpd": true, ".ts": true, ".m4s": true, ".flv": true}

func looksLikeVideoRequest(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Dest"), "video") {
		return true
	}
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Accept")), "video/") {
		return true
	}
	return videoExt[strings.ToLower(filepath.Ext(r.URL.Path))] || strings.Contains(r.URL.Path, "/videoplayback")
}

// HandleRequest refuses streams already judged adult.
func (vc *VideoClassifier) HandleRequest(fc *proxy.FlowContext) {
	if fc.URLAllowed || fc.MitmPassthrough || fc.Policy == nil || !fc.Policy.VideoClassifier.Enabled || fc.Response != nil {
		return
	}
	cfg := fc.Policy.VideoClassifier
	host := strings.ToLower(fc.Request.URL.Hostname())
	if !videoShouldFilter(host, fc.Request.URL.String(), cfg) || !looksLikeVideoRequest(fc.Request) {
		return
	}
	if adult, known := vc.lookup(videoKey(fc.Request.URL)); known && adult {
		vc.refuse(fc, "video previously judged adult")
	}
}

func (vc *VideoClassifier) refuse(fc *proxy.FlowContext, why string) {
	metrics.Blocks.Inc("video_classifier")
	fc.Response = &http.Response{
		StatusCode: http.StatusForbidden,
		Status:     "403 Forbidden",
		Header:     http.Header{"Content-Type": []string{"text/plain"}, "Content-Length": []string{"0"}, "X-WebFilter": []string{"video_classifier"}},
	}
	fc.ResponseBody = nil
	fc.WFAction = "blocked"
	fc.WFComponent = "video_classifier"
	fc.LogBlock("Adult video blocked ("+why+")", "video_classifier")
}

// HandleResponse judges posters in HTML, YouTube player thumbnails, and
// (optionally) keyframes of video responses.
func (vc *VideoClassifier) HandleResponse(fc *proxy.FlowContext) {
	if fc.URLAllowed || fc.MitmPassthrough || fc.Policy == nil || !fc.Policy.VideoClassifier.Enabled || fc.Response == nil || vc.Classifier == nil {
		return
	}
	cfg := fc.Policy.VideoClassifier
	host := strings.ToLower(fc.Request.URL.Hostname())
	if !videoShouldFilter(host, fc.Request.URL.String(), cfg) {
		return
	}
	ct := fc.Response.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "text/html"):
		vc.handleHTML(fc, cfg)
	case cfg.YouTube && isYouTube(host) && fc.Request.URL.Path == playerPath && strings.Contains(ct, "json"):
		vc.handleYouTubePlayer(fc, cfg)
	case strings.HasPrefix(ct, "video/") && cfg.Keyframes:
		vc.handleVideoBody(fc, cfg)
	}
}

var (
	reVideoTag  = regexp.MustCompile(`(?is)<video\b[^>]*>(?:.*?</video>)?`)
	reAttr      = regexp.MustCompile(`(?i)\b(poster|src)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	reSourceTag = regexp.MustCompile(`(?is)<source\b[^>]*>`)
	reSrcAttr   = regexp.MustCompile(`(?i)\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)')`)
)

// handleHTML finds <video poster=...> elements, judges the posters and
// remembers the verdict for each of the video's sources. Posters are
// fetched and scored within the image budget; a verdict that arrives
// later is remembered by the prefetched image's cache entry only.
func (vc *VideoClassifier) handleHTML(fc *proxy.FlowContext, cfg models.VideoClassifierConfig) {
	if vc.Fetcher == nil || !bytes.Contains(fc.ResponseBody, []byte("<video")) {
		return
	}
	page := fc.Request.URL
	n := 0
	for _, m := range reVideoTag.FindAll(fc.ResponseBody, -1) {
		if n >= 5 {
			break
		}
		poster, srcs := "", []string{}
		for _, a := range reAttr.FindAllSubmatch(m, -1) {
			val := string(a[2])
			if val == "" {
				val = string(a[3])
			}
			if strings.EqualFold(string(a[1]), "poster") {
				poster = val
			} else {
				srcs = append(srcs, val)
			}
		}
		for _, tag := range reSourceTag.FindAll(m, -1) {
			if a := reSrcAttr.FindSubmatch(tag); a != nil {
				val := string(a[1])
				if val == "" {
					val = string(a[2])
				}
				srcs = append(srcs, val)
			}
		}
		if poster == "" || len(srcs) == 0 {
			continue
		}
		n++
		pu, err := url.Parse(strings.TrimSpace(poster))
		if err != nil {
			continue
		}
		posterURL := page.ResolveReference(pu)
		keys := []string{}
		for _, s := range srcs {
			if su, err := url.Parse(strings.TrimSpace(s)); err == nil {
				keys = append(keys, videoKey(page.ResolveReference(su)))
			}
		}
		adult, known := vc.judgeImageURL(fc, cfg, posterURL.String())
		if !known {
			continue
		}
		for _, k := range keys {
			vc.remember(k, adult)
		}
		if adult {
			// Strip the sources so the page does not even start the stream,
			// and mark the element so the change is visible in the DOM.
			stripped := reSourceTag.ReplaceAll(m, []byte("<!-- webfilter: adult video source removed -->"))
			stripped = reSrcAttr.ReplaceAll(stripped, []byte(`data-webfilter-removed-src=""`))
			stripped = bytes.Replace(stripped, []byte("<video"), []byte(`<video data-webfilter-blocked="adult video"`), 1)
			fc.ResponseBody = bytes.Replace(fc.ResponseBody, m, stripped, 1)
			fc.Response.Header.Set("Content-Length", strconv.Itoa(len(fc.ResponseBody)))
			if fc.WFAction == "" {
				fc.WFAction = "modified"
				fc.WFComponent = "video_classifier"
			}
		}
	}
}

// judgeImageURL fetches an image and asks the classifier within the image
// budget; known=false when it could not be fetched or timed out (then the
// policy's on_timeout decides, block meaning adult=true).
func (vc *VideoClassifier) judgeImageURL(fc *proxy.FlowContext, cfg models.VideoClassifierConfig, imgURL string) (adult, known bool) {
	budget := budgetFor(fc, 0, "image")
	ctx, cancel := context.WithTimeout(fc.Request.Context(), budget+5*time.Second)
	defer cancel()
	data, err := vc.Fetcher.FetchImage(ctx, imgURL, fc.Request.Header)
	if err != nil || len(data) == 0 {
		return false, false
	}
	started := time.Now()
	v := vc.Classifier.ClassifyImage(ctx, ImageRequest{URL: imgURL, Data: data, Budget: budget})
	switch {
	case v.Known:
		adult = v.Adult || v.Score >= cfg.Threshold
		if adult {
			metrics.ObserveClassifier("video", started, metrics.ResultNSFW)
		} else {
			metrics.ObserveClassifier("video", started, metrics.ResultClean)
		}
		return adult, true
	case v.TimedOut:
		metrics.ObserveClassifier("video", started, metrics.ResultTimeout)
		return cfg.OnTimeout == models.FallbackBlock, cfg.OnTimeout == models.FallbackBlock
	default:
		metrics.ObserveClassifier("video", started, metrics.ResultError)
		return false, false
	}
}

// handleYouTubePlayer judges a YouTube video by its largest thumbnail and
// makes the player response unplayable when it is adult.
func (vc *VideoClassifier) handleYouTubePlayer(fc *proxy.FlowContext, cfg models.VideoClassifierConfig) {
	if vc.Fetcher == nil {
		return
	}
	var data map[string]any
	if err := json.Unmarshal(fc.ResponseBody, &data); err != nil {
		return
	}
	vd, _ := getMap(data, "videoDetails")
	videoID := getString(vd, "videoId")
	if videoID == "" {
		return
	}
	key := "yt:" + videoID
	adult, known := vc.lookup(key)
	if !known {
		thumb := youtubeThumbnail(vd)
		if thumb == "" {
			thumb = "https://i.ytimg.com/vi/" + videoID + "/hqdefault.jpg"
		}
		adult, known = vc.judgeImageURL(fc, cfg, thumb)
		if !known {
			return
		}
		vc.remember(key, adult)
	}
	if !adult {
		return
	}
	msg := fc.Policy.BlockPage.Message
	if msg == "" {
		msg = "This video is blocked by your network policy."
	}
	data["playabilityStatus"] = map[string]any{
		"status": "ERROR",
		"reason": msg,
		"errorScreen": map[string]any{
			"playerErrorMessageRenderer": map[string]any{
				"reason":    map[string]any{"simpleText": msg},
				"subreason": map[string]any{"simpleText": "Adult video"},
			},
		},
	}
	delete(data, "streamingData")
	encodeJSONResponse(fc, data)
	fc.Response.Header.Set("Content-Length", strconv.Itoa(len(fc.ResponseBody)))
	fc.LogBlock("YouTube video "+videoID+" judged adult", "video_classifier")
}

// youtubeThumbnail returns the largest thumbnail URL in videoDetails.
func youtubeThumbnail(vd map[string]any) string {
	th, _ := getMap(vd, "thumbnail")
	list, _ := th["thumbnails"].([]any)
	best, bestW := "", 0.0
	for _, t := range list {
		m, _ := t.(map[string]any)
		w, _ := m["width"].(float64)
		u := getString(m, "url")
		if u != "" && w >= bestW {
			best, bestW = u, w
		}
	}
	return best
}

// handleVideoBody decodes a few keyframes from a buffered video response
// with ffmpeg and refuses the stream if any is adult.
func (vc *VideoClassifier) handleVideoBody(fc *proxy.FlowContext, cfg models.VideoClassifierConfig) {
	key := videoKey(fc.Request.URL)
	if adult, known := vc.lookup(key); known {
		if adult {
			vc.refuse(fc, "keyframes judged adult")
		}
		return
	}
	if len(fc.ResponseBody) < 1<<10 {
		return
	}
	frames, err := ExtractKeyframes(fc.ResponseBody, 3)
	if err != nil || len(frames) == 0 {
		return
	}
	budget := budgetFor(fc, 0, "image")
	adult := false
	known := true
	for i, f := range frames {
		started := time.Now()
		v := vc.Classifier.ClassifyImage(fc.Request.Context(), ImageRequest{URL: key + "#frame" + strconv.Itoa(i), Data: f, Budget: budget})
		switch {
		case v.Known:
			if v.Adult || v.Score >= cfg.Threshold {
				adult = true
				metrics.ObserveClassifier("video", started, metrics.ResultNSFW)
			} else {
				metrics.ObserveClassifier("video", started, metrics.ResultClean)
			}
		case v.TimedOut:
			metrics.ObserveClassifier("video", started, metrics.ResultTimeout)
			if cfg.OnTimeout == models.FallbackBlock {
				adult = true
			} else {
				known = false
			}
		default:
			metrics.ObserveClassifier("video", started, metrics.ResultError)
			known = false
		}
		if adult {
			break
		}
	}
	if known {
		vc.remember(key, adult)
	}
	if adult {
		vc.refuse(fc, "keyframes judged adult")
	}
}

// ffmpegPath caches the ffmpeg lookup.
var ffmpegPath = sync.OnceValue(func() string {
	p, err := exec.LookPath("ffmpeg")
	if err != nil {
		return ""
	}
	return p
})

// FFmpegAvailable reports whether keyframe extraction can work.
func FFmpegAvailable() bool { return ffmpegPath() != "" }

// ExtractKeyframes writes the (possibly partial) video to a temp file and
// asks ffmpeg for up to n frames from its opening seconds as JPEGs.
func ExtractKeyframes(video []byte, n int) ([][]byte, error) {
	ff := ffmpegPath()
	if ff == "" {
		return nil, exec.ErrNotFound
	}
	dir, err := os.MkdirTemp("", "wfvideo-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	in := filepath.Join(dir, "in.bin")
	if err := os.WriteFile(in, video, 0o600); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// One frame every 2 seconds from the first 2n seconds, scaled to the
	// model's working size; -frames:v caps the count and -t bounds how much
	// is decoded. A partial file decodes as far as it goes.
	cmd := exec.CommandContext(ctx, ff, "-v", "error", "-nostdin", "-t", strconv.Itoa(2*n+1), "-i", in,
		"-vf", "fps=1/2,scale=384:-2", "-frames:v", strconv.Itoa(n), "-q:v", "5", "-f", "image2", filepath.Join(dir, "f%d.jpg"))
	_ = cmd.Run() // partial input ends with an error even when frames were written
	var out [][]byte
	for i := 1; i <= n; i++ {
		data, err := os.ReadFile(filepath.Join(dir, "f"+strconv.Itoa(i)+".jpg"))
		if err != nil || len(data) == 0 {
			break
		}
		out = append(out, data)
	}
	return out, nil
}
