package addons_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"net/http"
	"os/exec"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
)

type fakeFetcher struct{ images map[string][]byte }

func (f fakeFetcher) FetchImage(_ context.Context, u string, _ http.Header) ([]byte, error) {
	if d, ok := f.images[u]; ok {
		return d, nil
	}
	return nil, errors.New("not found: " + u)
}

// urlScorer judges images by whether their URL (or hint) contains "bad".
type urlScorer struct{}

func (urlScorer) ClassifyText(context.Context, addons.TextRequest) addons.Verdict {
	return addons.Verdict{Known: true}
}
func (urlScorer) ClassifyHost(context.Context, addons.HostRequest) addons.Verdict {
	return addons.Verdict{Known: true}
}
func (urlScorer) ClassifyImage(_ context.Context, req addons.ImageRequest) addons.Verdict {
	bad := strings.Contains(req.URL, "bad") || bytes.Contains(req.Data, []byte("BADFRAME"))
	return addons.Verdict{Known: true, Adult: bad, Score: map[bool]float64{true: 0.95, false: 0.05}[bad], Source: "stub"}
}

func videoPolicy() *models.Policy {
	p := models.NewPolicy()
	p.Name = "default"
	p.VideoClassifier.Enabled = true
	return &p
}

func TestVideoClassifierJudgesPostersAndRefusesStreams(t *testing.T) {
	rt := newTestRuntime(t)
	img := testJPEG(t, 200, 200)
	vc := addons.NewVideoClassifier(urlScorer{}, fakeFetcher{images: map[string][]byte{
		"http://site.example/bad-poster.jpg":  img,
		"http://site.example/good-poster.jpg": img,
	}})
	html := `<html><body>
<video poster="/bad-poster.jpg" controls><source src="/media/bad.mp4" type="video/mp4"></video>
<video poster="good-poster.jpg" src="/media/fine.mp4"></video>
</body></html>`
	fc := newFlow(t, rt, "http://site.example/page")
	fc.Policy = videoPolicy()
	fc.Response = &http.Response{Header: http.Header{"Content-Type": []string{"text/html"}}}
	fc.ResponseBody = []byte(html)
	vc.HandleResponse(fc)
	body := string(fc.ResponseBody)
	if strings.Contains(body, "/media/bad.mp4") || !strings.Contains(body, `data-webfilter-blocked`) {
		t.Fatalf("adult video sources should be stripped:\n%s", body)
	}
	if !strings.Contains(body, "/media/fine.mp4") {
		t.Fatalf("clean video must be untouched:\n%s", body)
	}

	// The stream request itself is refused on later plays.
	req := newFlow(t, rt, "http://site.example/media/bad.mp4?range=0-")
	req.Request.Header.Set("Sec-Fetch-Dest", "video")
	req.Policy = videoPolicy()
	vc.HandleRequest(req)
	if req.Response == nil || req.Response.StatusCode != http.StatusForbidden || req.WFComponent != "video_classifier" {
		t.Fatalf("adult stream should be refused: %+v", req.Response)
	}
	req = newFlow(t, rt, "http://site.example/media/fine.mp4")
	req.Request.Header.Set("Sec-Fetch-Dest", "video")
	req.Policy = videoPolicy()
	vc.HandleRequest(req)
	if req.Response != nil {
		t.Fatal("clean stream must pass")
	}
}

func TestVideoClassifierYouTubePlayer(t *testing.T) {
	rt := newTestRuntime(t)
	img := testJPEG(t, 200, 200)
	vc := addons.NewVideoClassifier(urlScorer{}, fakeFetcher{images: map[string][]byte{
		"https://i.ytimg.com/vi/bad123/maxresdefault.jpg": img,
		"https://i.ytimg.com/vi/ok456/hqdefault.jpg":      img,
	}})
	player := func(id, thumb string) []byte {
		b, _ := json.Marshal(map[string]any{
			"videoDetails": map[string]any{"videoId": id, "thumbnail": map[string]any{"thumbnails": []any{
				map[string]any{"url": thumb, "width": 1280},
			}}},
			"streamingData":     map[string]any{"formats": []any{}},
			"playabilityStatus": map[string]any{"status": "OK"},
		})
		return b
	}
	fc := newFlow(t, rt, "https://www.youtube.com/youtubei/v1/player")
	fc.Policy = videoPolicy()
	fc.Response = &http.Response{Header: http.Header{"Content-Type": []string{"application/json"}}}
	fc.ResponseBody = player("bad123", "https://i.ytimg.com/vi/bad123/maxresdefault.jpg")
	vc.HandleResponse(fc)
	var out map[string]any
	_ = json.Unmarshal(fc.ResponseBody, &out)
	if ps, _ := out["playabilityStatus"].(map[string]any); ps["status"] != "ERROR" || out["streamingData"] != nil {
		t.Fatalf("adult YouTube video should be made unplayable: %s", fc.ResponseBody)
	}

	fc = newFlow(t, rt, "https://www.youtube.com/youtubei/v1/player")
	fc.Policy = videoPolicy()
	fc.Response = &http.Response{Header: http.Header{"Content-Type": []string{"application/json"}}}
	fc.ResponseBody = player("ok456", "https://i.ytimg.com/vi/ok456/hqdefault.jpg")
	vc.HandleResponse(fc)
	_ = json.Unmarshal(fc.ResponseBody, &out)
	if ps, _ := out["playabilityStatus"].(map[string]any); ps["status"] != "OK" {
		t.Fatalf("clean YouTube video must stay playable: %s", fc.ResponseBody)
	}
}

func TestVideoClassifierKeyframesWithFFmpeg(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not installed")
	}
	// Build a tiny MP4 with ffmpeg from a generated frame sequence.
	frames := makeTestVideo(t)
	fr, err := addons.ExtractKeyframes(frames, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(fr) == 0 {
		t.Fatal("expected at least one keyframe")
	}
	if _, _, err := image.Decode(bytes.NewReader(fr[0])); err != nil {
		t.Fatalf("keyframe is not a decodable image: %v", err)
	}

	rt := newTestRuntime(t)
	vc := addons.NewVideoClassifier(urlScorer{}, nil)
	fc := newFlow(t, rt, "http://site.example/clip/bad.mp4")
	p := videoPolicy()
	p.VideoClassifier.Keyframes = true
	fc.Policy = p
	fc.Response = &http.Response{Header: http.Header{"Content-Type": []string{"video/mp4"}}}
	fc.ResponseBody = frames
	vc.HandleResponse(fc)
	if fc.Response.StatusCode != http.StatusForbidden || fc.WFAction != "blocked" {
		t.Fatalf("video with adult keyframes should be refused: %d %q", fc.Response.StatusCode, fc.WFAction)
	}
}

// makeTestVideo renders 3 seconds of colour frames to an MP4 (needs ffmpeg).
func makeTestVideo(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	for i := 0; i < 6; i++ {
		img := image.NewRGBA(image.Rect(0, 0, 160, 120))
		for y := 0; y < 120; y++ {
			for x := 0; x < 160; x++ {
				img.Set(x, y, color.RGBA{uint8(x + i*20), uint8(y), 100, 255})
			}
		}
		var buf bytes.Buffer
		_ = jpeg.Encode(&buf, img, nil)
		if err := writeFile(dir+"/f"+string(rune('0'+i))+".jpg", buf.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	out := dir + "/out.mp4"
	cmd := exec.Command("ffmpeg", "-v", "error", "-y", "-framerate", "2", "-i", dir+"/f%d.jpg", "-c:v", "libx264", "-pix_fmt", "yuv420p", "-movflags", "+faststart", out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("ffmpeg cannot encode test video: %v %s", err, b)
	}
	data, err := readFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
