package imageprep

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func pngOf(t *testing.T, w, h int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), 128, 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestPrepareDownscalesToMaxPx(t *testing.T) {
	p, err := Prepare(pngOf(t, 1000, 500), 384)
	if err != nil {
		t.Fatal(err)
	}
	if p.Width != 1000 || p.Height != 500 || p.MIME != "image/jpeg" {
		t.Fatalf("prepared = %+v", p)
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(p.Data))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Width != 384 || cfg.Height != 192 {
		t.Fatalf("output size = %dx%d, want 384x192", cfg.Width, cfg.Height)
	}
}

func TestPrepareRejectsTinyAndGarbage(t *testing.T) {
	if _, err := Prepare(pngOf(t, 32, 32), 384); !errors.Is(err, ErrTooSmall) {
		t.Fatalf("want ErrTooSmall, got %v", err)
	}
	if _, err := Prepare([]byte("not an image"), 384); err == nil {
		t.Fatal("garbage must error")
	}
}
