package addons

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/draw"
	_ "image/gif"
	"image/jpeg"
	"image/png"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/disintegration/imaging"
	// Registers the WebP decoder for image.Decode/DecodeConfig below, matching
	// internal/classify/image's detector. Decode-only (x/image has no WebP
	// encoder), which is fine: replacements are always re-encoded as
	// JPEG/PNG/GIF and Content-Type is rewritten to match.
	_ "golang.org/x/image/webp"

	"github.com/yjlion/llama-web-filter/internal/metrics"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
)

// minImageBytes is a cheap floor to discard genuine tracking pixels/
// spacers without decoding - real filtering is gated on pixel dimensions
// (imageTooSmall), since heavily compressed thumbnails can be only a few
// KB.
const minImageBytes = 1024

// ImageClassifier detects and blurs/blocks/checkerboards NSFW images.
// Ported from proxy/addons/image_classifier.py.
type ImageClassifier struct {
	// Classifier is the verdict backend; nil means every image passes
	// through unmodified.
	Classifier ContentClassifier
}

func (ImageClassifier) Name() string { return "image_classifier" }

// decide asks the backend about one image and maps the answer (or its
// absence) to the action to apply: "" for pass-through, else one of the
// ImageClassifierAction values.
func (ic ImageClassifier) decide(fc *proxy.FlowContext, cfg models.ImageClassifierConfig, imageBytes []byte, url string) models.ImageClassifierAction {
	if ic.Classifier == nil {
		return fallbackImageAction(cfg.OnUnavailable)
	}
	started := time.Now()
	v := ic.Classifier.ClassifyImage(fc.Request.Context(), ImageRequest{URL: url, Data: imageBytes, Budget: budgetFor(fc, cfg.BudgetMs, "image")})
	switch {
	case v.Known:
		if v.Adult || v.Score >= cfg.Threshold {
			metrics.ObserveClassifier("image", started, metrics.ResultNSFW)
			return cfg.Action
		}
		metrics.ObserveClassifier("image", started, metrics.ResultClean)
		return ""
	case v.TimedOut:
		metrics.ObserveClassifier("image", started, metrics.ResultTimeout)
		return fallbackImageAction(cfg.OnTimeout)
	default:
		metrics.ObserveClassifier("image", started, metrics.ResultError)
		return fallbackImageAction(cfg.OnUnavailable)
	}
}

func fallbackImageAction(f models.FallbackAction) models.ImageClassifierAction {
	switch f {
	case models.FallbackBlur:
		return models.ImageActionBlur
	case models.FallbackCheckerboard:
		return models.ImageActionCheckerboard
	case models.FallbackBlock:
		return models.ImageActionBlock
	}
	return ""
}

// blurImage heavily blurs the entire image, radius scaled to its size.
// Ported from _blur_image.
func blurImage(imageBytes []byte) []byte {
	img, _, err := image.Decode(bytes.NewReader(imageBytes))
	if err != nil {
		return imageBytes
	}
	b := img.Bounds()
	radius := float64(b.Dx())
	if b.Dy() < b.Dx() {
		radius = float64(b.Dy())
	}
	radius /= 8
	if radius < 12 {
		radius = 12
	}
	blurred := imaging.Blur(img, radius)

	var out bytes.Buffer
	if err := jpeg.Encode(&out, blurred, &jpeg.Options{Quality: 80}); err != nil {
		return imageBytes
	}
	return out.Bytes()
}

// checkerboardImage replaces the image with a neutral checkerboard
// placeholder of the same size. Ported from _checkerboard.
func checkerboardImage(imageBytes []byte) []byte {
	w, h := 320, 240
	if cfg, _, err := image.DecodeConfig(bytes.NewReader(imageBytes)); err == nil {
		w, h = cfg.Width, cfg.Height
	}
	tile := minInt(w, h) / 10
	if tile < 8 {
		tile = 8
	}
	light := color.RGBA{R: 245, G: 245, B: 240, A: 255}
	dark := color.RGBA{R: 220, G: 220, B: 212, A: 255}

	board := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(board, board.Bounds(), &image.Uniform{C: light}, image.Point{}, draw.Src)
	for y, ty := 0, 0; y < h; y, ty = y+tile, ty+1 {
		for x, tx := 0, 0; x < w; x, tx = x+tile, tx+1 {
			if (tx+ty)%2 != 0 {
				rect := image.Rect(x, y, x+tile, y+tile).Intersect(board.Bounds())
				draw.Draw(board, rect, &image.Uniform{C: dark}, image.Point{}, draw.Src)
			}
		}
	}

	var out bytes.Buffer
	if err := png.Encode(&out, board); err != nil {
		return transparentGIF
	}
	return out.Bytes()
}

// transparentGIF is a 1x1 transparent GIF, used for the "block" action.
var transparentGIF = []byte{
	'G', 'I', 'F', '8', '9', 'a', 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21,
	0xf9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
}

// imageTooSmall reports whether the image's largest side is under
// minDimension pixels, reading only the image header (no full decode via
// image.DecodeConfig - the Go stdlib equivalent of PIL's lazy Image.open
// size read). If dimensions can't be determined, returns false so the
// image still gets classified. Ported from _too_small.
func imageTooSmall(imageBytes []byte, minDimension int) bool {
	if minDimension <= 0 {
		return false
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(imageBytes))
	if err != nil {
		return false
	}
	largest := cfg.Width
	if cfg.Height > largest {
		largest = cfg.Height
	}
	return largest < minDimension
}

func imageClassifierShouldFilter(host, url string, cfg models.ImageClassifierConfig) bool {
	if len(cfg.IncludeOnly) > 0 {
		return proxy.UrlInList(host, url, cfg.IncludeOnly)
	}
	if len(cfg.Exclude) > 0 {
		return !proxy.UrlInList(host, url, cfg.Exclude)
	}
	return true
}

func (ic ImageClassifier) HandleResponse(fc *proxy.FlowContext) {
	if fc.URLAllowed || fc.MitmPassthrough {
		return
	}
	policy := fc.Policy
	if policy == nil || !policy.ImageClassifier.Enabled {
		return
	}
	if fc.Response == nil {
		return
	}

	host := fc.Request.URL.Hostname()
	url := fc.Request.URL.String()
	cfg := policy.ImageClassifier
	if !imageClassifierShouldFilter(host, url, cfg) {
		return
	}

	ct := fc.Response.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "image/"):
		ic.filterImageResponse(fc, cfg)
	case isScannableText(ct):
		ic.filterInlineImages(fc, cfg)
	}
}

// filterImageResponse handles a whole-response image (Content-Type
// image/*), replacing the entire body when it classifies as NSFW.
func (ic ImageClassifier) filterImageResponse(fc *proxy.FlowContext, cfg models.ImageClassifierConfig) {
	body := fc.ResponseBody
	if len(body) < minImageBytes {
		return
	}
	if imageTooSmall(body, cfg.MinDimension) {
		return
	}
	action := ic.decide(fc, cfg, body, fc.Request.URL.String())
	if action == "" {
		return
	}

	newBody, ctype := replacementImage(body, action)
	fc.ResponseBody = newBody
	fc.Response.Header.Set("Content-Type", ctype)
	fc.Response.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
	fc.WFAction = "modified"
	fc.WFComponent = "image_classifier"
}

// replacementImage renders the configured action's stand-in for a
// classified-NSFW image, returning the new bytes and their MIME type.
func replacementImage(body []byte, action models.ImageClassifierAction) ([]byte, string) {
	switch action {
	case models.ImageActionCheckerboard:
		return checkerboardImage(body), "image/png"
	case models.ImageActionBlock:
		return transparentGIF, "image/gif"
	default: // blur
		return blurImage(body), "image/jpeg"
	}
}

// scannableTextPrefixes are the Content-Types whose bodies commonly inline
// images as base64 data URIs. Google Images embeds its entire initial
// result grid this way inside the search HTML (and later batches inside
// script/JSON payloads), so filtering only image/* responses misses every
// initially-visible thumbnail - the browser renders them from the HTML
// before the separately fetched (and filtered) network copies arrive.
var scannableTextPrefixes = []string{
	"text/html", "application/xhtml+xml", "text/css",
	"text/javascript", "application/javascript", "application/json",
}

func isScannableText(ct string) bool {
	for _, p := range scannableTextPrefixes {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return false
}

// inlineImageRe matches a base64 image data URI in HTML, CSS, JS, or JSON,
// limited to formats a registered decoder can read (stdlib JPEG/PNG/GIF plus
// x/image's WebP - keep this alternation in sync with the blank imports at the
// top of the file). JS/JSON string contexts may escape characters of the
// base64 alphabet (`\/` in JSON, and Google's inline scripts escape the `=`
// padding as `\x3d`/`=`), so those escape sequences are matched as part of
// the URI and undone by decodeInlineImage before base64 decoding.
var inlineImageRe = regexp.MustCompile(`data:image\\?/(?:jpe?g|png|gif|webp);base64,(?:[A-Za-z0-9+=]|\\?/|\\x3[dD]|\\u003[dD])+`)

var inlineEscapes = strings.NewReplacer(
	"\\/", "/",
	"\\x3d", "=", "\\x3D", "=",
	"\\u003d", "=", "\\u003D", "=",
)

// decodeInlineImage extracts and decodes the base64 payload of one matched
// data URI, tolerating JS/JSON escapes and missing `=` padding.
func decodeInlineImage(uri []byte) []byte {
	i := bytes.IndexByte(uri, ',')
	if i < 0 {
		return nil
	}
	b64 := inlineEscapes.Replace(string(uri[i+1:]))
	if b, err := base64.StdEncoding.DecodeString(b64); err == nil {
		return b
	}
	if b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(b64, "=")); err == nil {
		return b
	}
	return nil
}

// filterInlineImages scans a text body for base64 image data URIs and
// replaces each one that classifies as NSFW with the configured action's
// stand-in, re-encoded as a plain (unescaped) data URI - base64 plus the
// data: prefix contains nothing that needs escaping in HTML-attribute,
// JS-string, or JSON-string contexts. Safe images and undecodable matches
// are left byte-for-byte intact.
func (ic ImageClassifier) filterInlineImages(fc *proxy.FlowContext, cfg models.ImageClassifierConfig) {
	if ic.Classifier == nil {
		return
	}
	body := fc.ResponseBody
	if !bytes.Contains(body, []byte("data:image")) {
		return
	}

	var out bytes.Buffer
	last := 0
	modified := false
	for _, m := range inlineImageRe.FindAllIndex(body, -1) {
		img := decodeInlineImage(body[m[0]:m[1]])
		if len(img) < minImageBytes {
			continue
		}
		if imageTooSmall(img, cfg.MinDimension) {
			continue
		}
		action := ic.decide(fc, cfg, img, fc.Request.URL.String()+"#inline")
		if action == "" {
			continue
		}
		repl, mime := replacementImage(img, action)
		out.Write(body[last:m[0]])
		out.WriteString("data:")
		out.WriteString(mime)
		out.WriteString(";base64,")
		out.WriteString(base64.StdEncoding.EncodeToString(repl))
		last = m[1]
		modified = true
	}
	if !modified {
		return
	}
	out.Write(body[last:])

	fc.ResponseBody = out.Bytes()
	fc.Response.Header.Set("Content-Length", strconv.Itoa(len(fc.ResponseBody)))
	fc.WFAction = "modified"
	fc.WFComponent = "image_classifier"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
