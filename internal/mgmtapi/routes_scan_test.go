package mgmtapi_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pngFixture builds a small solid-colour PNG. The scanner behind these
// tests is a stub, so the verdict is deterministic - these tests are about
// the endpoint's plumbing and response shape, not the model's judgement.
func pngFixture(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			img.Set(x, y, color.RGBA{R: 90, G: 110, B: 130, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png fixture: %v", err)
	}
	return buf.Bytes()
}

func scanJSON(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode scan response: %v (body %s)", err, rr.Body.String())
	}
	return out
}

func TestScanImageURL(t *testing.T) {
	imgBytes := pngFixture(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(imgBytes)
	}))
	defer origin.Close()

	s := newServerWithCategories(t, "", nil)
	got := scanJSON(t, doRequest(t, s, http.MethodPost, "/api/tools/scan",
		fmt.Sprintf(`{"url":%q}`, origin.URL+"/pic.png")))

	if got["type"] != "image" {
		t.Fatalf("type = %v, want image (body %v)", got["type"], got)
	}
	if got["error"] != nil {
		t.Fatalf("unexpected error: %v", got["error"])
	}
	dets, ok := got["detections"].([]any)
	if !ok || len(dets) == 0 {
		t.Fatalf("detections = %v, want per-class rows", got["detections"])
	}
	// The UI reads detections[0] as the "top detection", so ordering matters.
	first := dets[0].(map[string]any)
	prev := first["score"].(float64)
	for _, d := range dets[1:] {
		score := d.(map[string]any)["score"].(float64)
		if score > prev {
			t.Errorf("detections are not sorted highest-score-first: %v", dets)
		}
		prev = score
	}
	if _, hasClass := first["class"]; !hasClass {
		t.Errorf("detection rows must carry a class name: %v", first)
	}
}

func TestScanUndecodableImageIsAnErrorNotClean(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("this is not a png"))
	}))
	defer origin.Close()

	s := newServerWithCategories(t, "", nil)
	got := scanJSON(t, doRequest(t, s, http.MethodPost, "/api/tools/scan",
		fmt.Sprintf(`{"url":%q}`, origin.URL+"/broken.png")))

	if got["error"] == nil {
		t.Fatalf("an undecodable image must report an error, not a clean verdict: %v", got)
	}
	if got["nsfw"] == true {
		t.Errorf("undecodable image should not claim an NSFW verdict")
	}
}

func TestScanPageWithImages(t *testing.T) {
	imgBytes := pngFixture(t)
	var origin *httptest.Server
	origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/missing.png":
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, ".png"):
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(imgBytes)
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, `<html><body><p>Some ordinary words on a page.</p>
				<img src="/a.png"><img src="%s/b.png"><img src="/missing.png">
				<img src="data:image/png;base64,AAAA"></body></html>`, origin.URL)
		}
	}))
	defer origin.Close()

	s := newServerWithCategories(t, "", nil)
	got := scanJSON(t, doRequest(t, s, http.MethodPost, "/api/tools/scan",
		fmt.Sprintf(`{"url":%q}`, origin.URL+"/page")))

	if got["type"] != "page" {
		t.Fatalf("type = %v, want page (body %v)", got["type"], got)
	}
	text, ok := got["text"].(map[string]any)
	if !ok {
		t.Fatalf("page result must carry a text verdict: %v", got)
	}
	for _, key := range []string{"nsfw", "keyword_score", "threshold"} {
		if _, present := text[key]; !present {
			t.Errorf("text verdict missing %q, which ui/tools.html renders: %v", key, text)
		}
	}
	if text["nsfw"] == true {
		t.Errorf("innocuous page text should not be flagged: %v", text)
	}

	images, ok := got["images"].([]any)
	if !ok {
		t.Fatalf("page result must carry an images array: %v", got)
	}
	// Relative and absolute srcs are both fetched; the data: URI is skipped
	// because it isn't fetchable.
	if len(images) != 3 {
		t.Fatalf("scanned %d images, want 3 (relative + absolute + the 404): %v", len(images), images)
	}
	var withError int
	for _, raw := range images {
		row := raw.(map[string]any)
		if row["url"] == nil {
			t.Errorf("image row missing url: %v", row)
		}
		if row["error"] != nil {
			withError++
		}
	}
	// A dead image must be reported per-row, not abort the whole scan.
	if withError != 1 {
		t.Errorf("expected exactly the 404 image to carry an error, got %d: %v", withError, images)
	}
}

func TestScanPageRespectsMaxImages(t *testing.T) {
	imgBytes := pngFixture(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".png") {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(imgBytes)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		var sb strings.Builder
		sb.WriteString("<html><body>")
		for i := 0; i < 8; i++ {
			fmt.Fprintf(&sb, `<img src="/img%d.png">`, i)
		}
		sb.WriteString("</body></html>")
		_, _ = w.Write([]byte(sb.String()))
	}))
	defer origin.Close()

	s := newServerWithCategories(t, "", nil)
	got := scanJSON(t, doRequest(t, s, http.MethodPost, "/api/tools/scan",
		fmt.Sprintf(`{"url":%q,"max_images":2}`, origin.URL+"/page")))

	images, _ := got["images"].([]any)
	if len(images) != 2 {
		t.Errorf("scanned %d images, want max_images=2 to be honored: %v", len(images), images)
	}
}

func TestScanNonHTMLNonImageReportsOther(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		_, _ = w.Write([]byte("%PDF-1.4"))
	}))
	defer origin.Close()

	s := newServerWithCategories(t, "", nil)
	got := scanJSON(t, doRequest(t, s, http.MethodPost, "/api/tools/scan",
		fmt.Sprintf(`{"url":%q}`, origin.URL+"/doc.pdf")))

	if got["type"] != "other" {
		t.Fatalf("type = %v, want other", got["type"])
	}
	if ct, _ := got["content_type"].(string); !strings.Contains(ct, "application/pdf") {
		t.Errorf("content_type = %q, want it to name the served type", ct)
	}
}

func TestScanUnreachableURLReportsErrorType(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := origin.URL
	origin.Close() // nothing is listening now

	s := newServerWithCategories(t, "", nil)
	got := scanJSON(t, doRequest(t, s, http.MethodPost, "/api/tools/scan",
		fmt.Sprintf(`{"url":%q}`, url+"/gone")))

	if got["type"] != "error" {
		t.Fatalf("type = %v, want error (body %v)", got["type"], got)
	}
	if got["error"] == nil {
		t.Errorf("error type must carry an error string the UI can show: %v", got)
	}
}
