package addons_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/color"
	"image/jpeg"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
	"github.com/yjlion/llama-web-filter/internal/webptest"
)

// fakeDetector always reports the given score for every image; ok=false
// means the backend is unavailable.
type fakeDetector struct {
	score float64
	ok    bool
}

func (d fakeDetector) ClassifyImage(_ context.Context, req addons.ImageRequest) addons.Verdict {
	if !d.ok {
		return addons.Verdict{Unavailable: true}
	}
	return addons.Verdict{Known: true, Score: d.score, Adult: d.score >= 0.9, Source: "stub"}
}

func (d fakeDetector) ClassifyText(_ context.Context, req addons.TextRequest) addons.Verdict {
	return addons.Verdict{Known: true, Score: 0, Source: "stub"}
}

func (d fakeDetector) ClassifyHost(_ context.Context, req addons.HostRequest) addons.Verdict {
	return addons.Verdict{Known: true, Score: 0, Source: "stub"}
}

// timeoutDetector reports a timeout for every image.
type timeoutDetector struct{}

func (timeoutDetector) ClassifyImage(context.Context, addons.ImageRequest) addons.Verdict {
	return addons.Verdict{TimedOut: true}
}
func (timeoutDetector) ClassifyText(context.Context, addons.TextRequest) addons.Verdict {
	return addons.Verdict{TimedOut: true}
}
func (timeoutDetector) ClassifyHost(context.Context, addons.HostRequest) addons.Verdict {
	return addons.Verdict{TimedOut: true}
}

// testJPEG builds a solid-color JPEG of the given size, padded past the
// 1KB floor with irrelevant EXIF-like comment bytes if needed.
func testJPEG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x % 256), G: uint8(y % 256), B: 128, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 95}); err != nil {
		t.Fatalf("encode test jpeg: %v", err)
	}
	return buf.Bytes()
}

func newImageFlow(t *testing.T, body []byte) (*models.Policy, *http.Response) {
	t.Helper()
	resp := &http.Response{Header: http.Header{"Content-Type": []string{"image/jpeg"}}}
	policy := models.NewPolicy()
	policy.ImageClassifier = models.NewImageClassifierConfig()
	policy.ImageClassifier.Enabled = true
	return &policy, resp
}

func TestImageClassifierBlursNSFWImage(t *testing.T) {
	rt := newTestRuntime(t)
	body := testJPEG(t, 200, 200)
	policy, resp := newImageFlow(t, body)
	fc := newFlow(t, rt, "http://example.com/pic.jpg")
	fc.Response = resp
	fc.ResponseBody = body
	fc.Policy = policy

	ic := addons.ImageClassifier{Classifier: fakeDetector{score: 0.9, ok: true}}
	ic.HandleResponse(fc)

	if fc.WFAction != "modified" || fc.WFComponent != "image_classifier" {
		t.Fatalf("WFAction/WFComponent = %q/%q", fc.WFAction, fc.WFComponent)
	}
	if fc.Response.Header.Get("Content-Type") != "image/jpeg" {
		t.Errorf("Content-Type = %q, want image/jpeg (blur re-encodes as jpeg)", fc.Response.Header.Get("Content-Type"))
	}
	if bytes.Equal(fc.ResponseBody, body) {
		t.Error("expected the image body to change after blurring")
	}
	// The blurred output must still decode as a valid image of the same size.
	img, _, err := image.Decode(bytes.NewReader(fc.ResponseBody))
	if err != nil {
		t.Fatalf("decode blurred image: %v", err)
	}
	if img.Bounds().Dx() != 200 || img.Bounds().Dy() != 200 {
		t.Errorf("blurred image size = %v, want 200x200", img.Bounds())
	}
}

// TestImageClassifierFiltersWebPResponse guards the WebP decoder
// registration. image/webp already reached filterImageResponse (the gate is a
// bare "image/" prefix), but with no decoder registered imageTooSmall could
// not read the dimensions and the replacement actions could not re-render the
// image - so the practical effect was that WebP passed through untouched.
//
// Checkerboard is the action under test because it is the one that reads the
// original's dimensions back out (via image.DecodeConfig), so a decode
// regression shows up as a wrong-sized replacement rather than a silent pass.
func TestImageClassifierFiltersWebPResponse(t *testing.T) {
	rt := newTestRuntime(t)
	// Noisy (rather than Flat) so the body clears the 1 KB minImageBytes floor.
	body := webptest.Noisy(200, 200, color.RGBA{R: 200, G: 60, B: 90, A: 255}, 210)
	if len(body) < 1024 {
		t.Fatalf("fixture is %d bytes, need > 1024 to clear minImageBytes", len(body))
	}
	policy, resp := newImageFlow(t, body)
	resp.Header.Set("Content-Type", "image/webp")
	policy.ImageClassifier.Action = models.ImageActionCheckerboard
	fc := newFlow(t, rt, "http://example.com/thumb.webp")
	fc.Response = resp
	fc.ResponseBody = body
	fc.Policy = policy

	ic := addons.ImageClassifier{Classifier: fakeDetector{score: 0.9, ok: true}}
	ic.HandleResponse(fc)

	if fc.WFAction != "modified" || fc.WFComponent != "image_classifier" {
		t.Fatalf("WFAction/WFComponent = %q/%q, want modified/image_classifier", fc.WFAction, fc.WFComponent)
	}
	// x/image/webp is decode-only, so the stand-in is re-encoded as PNG and
	// the Content-Type must be rewritten to match or the browser mis-renders it.
	if ct := fc.Response.Header.Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
	img, _, err := image.Decode(bytes.NewReader(fc.ResponseBody))
	if err != nil {
		t.Fatalf("decode replacement image: %v", err)
	}
	if img.Bounds().Dx() != 200 || img.Bounds().Dy() != 200 {
		t.Errorf("replacement size = %v, want 200x200 (dimensions read from the WebP header)", img.Bounds())
	}
}

// TestImageClassifierSkipsSmallWebP pins the other half of decoding: a WebP
// under min_dimension must be recognized as too small and left alone. Without
// a WebP decoder imageTooSmall returns false (fail-open to "classify it"), so
// this case would wrongly get replaced.
func TestImageClassifierSkipsSmallWebP(t *testing.T) {
	rt := newTestRuntime(t)
	body := webptest.Noisy(50, 50, color.RGBA{R: 200, G: 60, B: 90, A: 255}, 210)
	body = append(body, make([]byte, 2048)...) // clear minImageBytes; trailing bytes are ignored
	policy, resp := newImageFlow(t, body)
	resp.Header.Set("Content-Type", "image/webp")
	fc := newFlow(t, rt, "http://example.com/icon.webp")
	fc.Response = resp
	fc.ResponseBody = body
	fc.Policy = policy

	ic := addons.ImageClassifier{Classifier: fakeDetector{score: 0.9, ok: true}}
	ic.HandleResponse(fc)

	if fc.WFAction != "" {
		t.Errorf("WFAction = %q, want empty (a 50x50 WebP is under min_dimension)", fc.WFAction)
	}
	if !bytes.Equal(fc.ResponseBody, body) {
		t.Error("expected the undersized WebP body to be left untouched")
	}
}

func TestImageClassifierCheckerboardAction(t *testing.T) {
	rt := newTestRuntime(t)
	body := testJPEG(t, 150, 100)
	policy, resp := newImageFlow(t, body)
	policy.ImageClassifier.Action = models.ImageActionCheckerboard
	fc := newFlow(t, rt, "http://example.com/pic.jpg")
	fc.Response = resp
	fc.ResponseBody = body
	fc.Policy = policy

	ic := addons.ImageClassifier{Classifier: fakeDetector{score: 0.9, ok: true}}
	ic.HandleResponse(fc)

	if fc.Response.Header.Get("Content-Type") != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", fc.Response.Header.Get("Content-Type"))
	}
	img, _, err := image.Decode(bytes.NewReader(fc.ResponseBody))
	if err != nil {
		t.Fatalf("decode checkerboard image: %v", err)
	}
	if img.Bounds().Dx() != 150 || img.Bounds().Dy() != 100 {
		t.Errorf("checkerboard size = %v, want 150x100", img.Bounds())
	}
}

func TestImageClassifierBlockAction(t *testing.T) {
	rt := newTestRuntime(t)
	body := testJPEG(t, 200, 200)
	policy, resp := newImageFlow(t, body)
	policy.ImageClassifier.Action = models.ImageActionBlock
	fc := newFlow(t, rt, "http://example.com/pic.jpg")
	fc.Response = resp
	fc.ResponseBody = body
	fc.Policy = policy

	ic := addons.ImageClassifier{Classifier: fakeDetector{score: 0.9, ok: true}}
	ic.HandleResponse(fc)

	if fc.Response.Header.Get("Content-Type") != "image/gif" {
		t.Errorf("Content-Type = %q, want image/gif", fc.Response.Header.Get("Content-Type"))
	}
	if len(fc.ResponseBody) == 0 {
		t.Error("expected a non-empty transparent GIF body")
	}
}

func TestImageClassifierSkipsBelowThreshold(t *testing.T) {
	rt := newTestRuntime(t)
	body := testJPEG(t, 200, 200)
	policy, resp := newImageFlow(t, body)
	policy.ImageClassifier.Threshold = 0.8
	fc := newFlow(t, rt, "http://example.com/pic.jpg")
	fc.Response = resp
	fc.ResponseBody = body
	fc.Policy = policy

	ic := addons.ImageClassifier{Classifier: fakeDetector{score: 0.5, ok: true}} // below threshold
	ic.HandleResponse(fc)

	if !bytes.Equal(fc.ResponseBody, body) {
		t.Error("did not expect modification for a score below threshold")
	}
}

func TestImageClassifierSkipsWhenNotOK(t *testing.T) {
	rt := newTestRuntime(t)
	body := testJPEG(t, 200, 200)
	policy, resp := newImageFlow(t, body)
	fc := newFlow(t, rt, "http://example.com/pic.jpg")
	fc.Response = resp
	fc.ResponseBody = body
	fc.Policy = policy

	ic := addons.ImageClassifier{Classifier: fakeDetector{score: 0.99, ok: false}} // scoring failed/unavailable
	ic.HandleResponse(fc)

	if !bytes.Equal(fc.ResponseBody, body) {
		t.Error("did not expect modification when the backend is unavailable (on_unavailable defaults to allow)")
	}
}

func TestImageClassifierAppliesOnTimeoutFallback(t *testing.T) {
	rt := newTestRuntime(t)
	body := testJPEG(t, 200, 200)
	policy, resp := newImageFlow(t, body)
	fc := newFlow(t, rt, "http://example.com/pic.jpg")
	fc.Response = resp
	fc.ResponseBody = body
	fc.Policy = policy

	// Default on_timeout is blur: the browser gets a blurred stand-in while
	// the model finishes in the background.
	addons.ImageClassifier{Classifier: timeoutDetector{}}.HandleResponse(fc)
	if bytes.Equal(fc.ResponseBody, body) || fc.Response.Header.Get("Content-Type") != "image/jpeg" {
		t.Fatal("expected the on_timeout blur fallback to replace the image")
	}

	// on_timeout=allow passes the original through.
	fc2 := newFlow(t, rt, "http://example.com/pic.jpg")
	fc2.Response = &http.Response{Header: http.Header{"Content-Type": []string{"image/jpeg"}}}
	fc2.ResponseBody = body
	p2 := *policy
	p2.ImageClassifier.OnTimeout = models.FallbackAllow
	fc2.Policy = &p2
	addons.ImageClassifier{Classifier: timeoutDetector{}}.HandleResponse(fc2)
	if !bytes.Equal(fc2.ResponseBody, body) {
		t.Fatal("on_timeout=allow must pass the image through")
	}
}

func TestImageClassifierSkipsSmallImages(t *testing.T) {
	rt := newTestRuntime(t)
	body := testJPEG(t, 50, 50) // under default min_dimension of 100
	policy, resp := newImageFlow(t, body)
	fc := newFlow(t, rt, "http://example.com/icon.jpg")
	fc.Response = resp
	fc.ResponseBody = body
	fc.Policy = policy

	ic := addons.ImageClassifier{Classifier: fakeDetector{score: 0.99, ok: true}}
	ic.HandleResponse(fc)

	if !bytes.Equal(fc.ResponseBody, body) {
		t.Error("expected small (icon-sized) images to be skipped regardless of detection")
	}
}

func TestImageClassifierSkipsTinyByteFloor(t *testing.T) {
	rt := newTestRuntime(t)
	body := []byte{0xFF, 0xD8, 0xFF} // way under the 1KB floor, not even valid
	policy, resp := newImageFlow(t, body)
	fc := newFlow(t, rt, "http://example.com/pixel.jpg")
	fc.Response = resp
	fc.ResponseBody = body
	fc.Policy = policy

	ic := addons.ImageClassifier{Classifier: fakeDetector{score: 0.99, ok: true}}
	ic.HandleResponse(fc)

	if !bytes.Equal(fc.ResponseBody, body) {
		t.Error("expected sub-1KB bodies to be skipped before any decode is attempted")
	}
}

func TestImageClassifierNilDetectorNeverBlocks(t *testing.T) {
	rt := newTestRuntime(t)
	body := testJPEG(t, 200, 200)
	policy, resp := newImageFlow(t, body)
	fc := newFlow(t, rt, "http://example.com/pic.jpg")
	fc.Response = resp
	fc.ResponseBody = body
	fc.Policy = policy

	addons.ImageClassifier{}.HandleResponse(fc) // no Detector wired

	if !bytes.Equal(fc.ResponseBody, body) {
		t.Error("expected a nil Detector to never modify the image")
	}
}

// newInlineFlow builds a text-type response carrying body for the inline
// data-URI scanning tests.
func newInlineFlow(t *testing.T, contentType string, body []byte) (*models.Policy, *http.Response) {
	t.Helper()
	resp := &http.Response{Header: http.Header{"Content-Type": []string{contentType}}}
	policy := models.NewPolicy()
	policy.ImageClassifier = models.NewImageClassifierConfig()
	policy.ImageClassifier.Enabled = true
	return &policy, resp
}

func TestImageClassifierReplacesInlineNSFWDataURI(t *testing.T) {
	rt := newTestRuntime(t)
	big := base64.StdEncoding.EncodeToString(testJPEG(t, 200, 200))
	icon := base64.StdEncoding.EncodeToString(testJPEG(t, 50, 50)) // under min_dimension
	html := `<html><body>` +
		`<img src="data:image/jpeg;base64,` + big + `">` +
		`<img src="data:image/jpeg;base64,` + icon + `">` +
		`</body></html>`
	policy, resp := newInlineFlow(t, "text/html; charset=UTF-8", []byte(html))
	policy.ImageClassifier.Action = models.ImageActionCheckerboard
	fc := newFlow(t, rt, "http://example.com/search?q=x")
	fc.Response = resp
	fc.ResponseBody = []byte(html)
	fc.Policy = policy

	ic := addons.ImageClassifier{Classifier: fakeDetector{score: 0.9, ok: true}}
	ic.HandleResponse(fc)

	if fc.WFAction != "modified" || fc.WFComponent != "image_classifier" {
		t.Fatalf("WFAction/WFComponent = %q/%q", fc.WFAction, fc.WFComponent)
	}
	got := string(fc.ResponseBody)
	if strings.Contains(got, big) {
		t.Error("expected the large NSFW inline image to be replaced")
	}
	if !strings.Contains(got, icon) {
		t.Error("expected the icon-sized inline image to be left intact")
	}
	if fc.Response.Header.Get("Content-Type") != "text/html; charset=UTF-8" {
		t.Errorf("Content-Type = %q, want the page's own type preserved", fc.Response.Header.Get("Content-Type"))
	}
	if cl := fc.Response.Header.Get("Content-Length"); cl != strconv.Itoa(len(fc.ResponseBody)) {
		t.Errorf("Content-Length = %q, want %d", cl, len(fc.ResponseBody))
	}

	// The replacement must be a decodable PNG data URI of the original size.
	m := regexp.MustCompile(`data:image/png;base64,([A-Za-z0-9+/=]+)`).FindStringSubmatch(got)
	if m == nil {
		t.Fatal("expected a data:image/png replacement URI in the body")
	}
	raw, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		t.Fatalf("decode replacement base64: %v", err)
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode replacement image: %v", err)
	}
	if img.Bounds().Dx() != 200 || img.Bounds().Dy() != 200 {
		t.Errorf("replacement size = %v, want 200x200", img.Bounds())
	}
}

// TestImageClassifierReplacesInlineWebPDataURI covers inlineImageRe's format
// alternation, which is a separate gate from the decoder registration: even
// with x/image/webp imported, a `data:image/webp;base64,...` URI is invisible
// to the scanner unless the regex lists webp.
func TestImageClassifierReplacesInlineWebPDataURI(t *testing.T) {
	rt := newTestRuntime(t)
	webp := base64.StdEncoding.EncodeToString(
		webptest.Noisy(200, 200, color.RGBA{R: 200, G: 60, B: 90, A: 255}, 210))
	html := `<html><body><img src="data:image/webp;base64,` + webp + `"></body></html>`
	policy, resp := newInlineFlow(t, "text/html; charset=UTF-8", []byte(html))
	policy.ImageClassifier.Action = models.ImageActionCheckerboard
	fc := newFlow(t, rt, "http://example.com/search?q=x")
	fc.Response = resp
	fc.ResponseBody = []byte(html)
	fc.Policy = policy

	ic := addons.ImageClassifier{Classifier: fakeDetector{score: 0.9, ok: true}}
	ic.HandleResponse(fc)

	if fc.WFAction != "modified" {
		t.Fatalf("WFAction = %q, want modified", fc.WFAction)
	}
	got := string(fc.ResponseBody)
	if strings.Contains(got, webp) {
		t.Error("expected the inline NSFW WebP data URI to be replaced")
	}
	if !strings.Contains(got, "data:image/png;base64,") {
		t.Error("expected a PNG replacement data URI in the body")
	}
}

func TestImageClassifierReplacesEscapedInlineDataURI(t *testing.T) {
	rt := newTestRuntime(t)
	b64 := base64.StdEncoding.EncodeToString(testJPEG(t, 200, 200))
	// Google's inline scripts escape `=` padding as \x3d; JSON escapes `/`
	// as \/ - the scanner must see through both.
	escaped := strings.NewReplacer("/", "\\/", "=", "\\x3d").Replace(b64)
	js := `var s='data:image\/jpeg;base64,` + escaped + `';`
	policy, resp := newInlineFlow(t, "text/javascript; charset=UTF-8", []byte(js))
	policy.ImageClassifier.Action = models.ImageActionBlock
	fc := newFlow(t, rt, "http://example.com/async.js")
	fc.Response = resp
	fc.ResponseBody = []byte(js)
	fc.Policy = policy

	ic := addons.ImageClassifier{Classifier: fakeDetector{score: 0.9, ok: true}}
	ic.HandleResponse(fc)

	if fc.WFAction != "modified" {
		t.Fatalf("WFAction = %q, want modified", fc.WFAction)
	}
	got := string(fc.ResponseBody)
	if strings.Contains(got, escaped) {
		t.Error("expected the escaped NSFW inline image to be replaced")
	}
	if !strings.Contains(got, "data:image/gif;base64,") {
		t.Error("expected a transparent-GIF replacement URI for the block action")
	}
	// The surrounding JS string syntax must survive the splice.
	if !strings.HasPrefix(got, "var s='data:image") || !strings.HasSuffix(got, "';") {
		t.Errorf("surrounding JS was damaged: %q", got[:min(40, len(got))])
	}
}

func TestImageClassifierInlineBelowThresholdUntouched(t *testing.T) {
	rt := newTestRuntime(t)
	html := `<img src="data:image/jpeg;base64,` +
		base64.StdEncoding.EncodeToString(testJPEG(t, 200, 200)) + `">`
	policy, resp := newInlineFlow(t, "text/html", []byte(html))
	policy.ImageClassifier.Threshold = 0.8
	fc := newFlow(t, rt, "http://example.com/page")
	fc.Response = resp
	fc.ResponseBody = []byte(html)
	fc.Policy = policy

	ic := addons.ImageClassifier{Classifier: fakeDetector{score: 0.5, ok: true}}
	ic.HandleResponse(fc)

	if string(fc.ResponseBody) != html {
		t.Error("did not expect modification for an inline image below threshold")
	}
	if fc.WFAction != "" {
		t.Errorf("WFAction = %q, want unset", fc.WFAction)
	}
}

func TestImageClassifierInlineIgnoresNonScannableContentType(t *testing.T) {
	rt := newTestRuntime(t)
	body := `data:image/jpeg;base64,` +
		base64.StdEncoding.EncodeToString(testJPEG(t, 200, 200))
	policy, resp := newInlineFlow(t, "application/octet-stream", []byte(body))
	fc := newFlow(t, rt, "http://example.com/blob")
	fc.Response = resp
	fc.ResponseBody = []byte(body)
	fc.Policy = policy

	ic := addons.ImageClassifier{Classifier: fakeDetector{score: 0.9, ok: true}}
	ic.HandleResponse(fc)

	if string(fc.ResponseBody) != body {
		t.Error("did not expect scanning inside non-text content types")
	}
}

func TestImageClassifierDisabledIsNoop(t *testing.T) {
	rt := newTestRuntime(t)
	body := testJPEG(t, 200, 200)
	policy, resp := newImageFlow(t, body)
	policy.ImageClassifier.Enabled = false
	fc := newFlow(t, rt, "http://example.com/pic.jpg")
	fc.Response = resp
	fc.ResponseBody = body
	fc.Policy = policy

	ic := addons.ImageClassifier{Classifier: fakeDetector{score: 0.99, ok: true}}
	ic.HandleResponse(fc)

	if !bytes.Equal(fc.ResponseBody, body) {
		t.Error("did not expect any effect when image_classifier is disabled")
	}
}
