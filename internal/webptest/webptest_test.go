package webptest_test

import (
	"bytes"
	"image"
	"image/color"
	"testing"

	_ "golang.org/x/image/webp"

	"github.com/yjlion/llama-web-filter/internal/webptest"
)

// The fixtures this package produces are only useful if x/image/webp - the
// exact decoder the classifier relies on - accepts them, so assert the
// round-trip rather than the byte layout.

func TestFlatRoundTrips(t *testing.T) {
	want := color.RGBA{R: 241, G: 194, B: 125, A: 255}
	data := webptest.Flat(120, 90, want)

	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("DecodeConfig: %v", err)
	}
	if format != "webp" {
		t.Errorf("format = %q, want webp", format)
	}
	if cfg.Width != 120 || cfg.Height != 90 {
		t.Errorf("dimensions = %dx%d, want 120x90", cfg.Width, cfg.Height)
	}

	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if b := img.Bounds(); b.Dx() != 120 || b.Dy() != 90 {
		t.Fatalf("bounds = %v, want 120x90", b)
	}
	for _, p := range []image.Point{{X: 0, Y: 0}, {X: 119, Y: 89}, {X: 60, Y: 45}} {
		r, g, b, a := img.At(p.X, p.Y).RGBA()
		got := color.RGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8)}
		if got != want {
			t.Errorf("pixel %v = %+v, want %+v", p, got, want)
		}
	}
}

// Noisy's reason to exist is its encoded size: ~1 bit per pixel, so callers
// can clear ImageClassifier's 1 KB floor. Flat, by contrast, must stay tiny.
func TestNoisyIsOneBitPerPixel(t *testing.T) {
	base := color.RGBA{R: 200, G: 60, B: 90, A: 255}
	data := webptest.Noisy(200, 200, base, 210)

	if want := 200 * 200 / 8; len(data) < want || len(data) > want+64 {
		t.Errorf("len = %d, want ~%d (1 bit per pixel plus a small header)", len(data), want)
	}
	if flat := webptest.Flat(200, 200, base); len(flat) > 64 {
		t.Errorf("Flat len = %d, want a header-sized file", len(flat))
	}

	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// (x^y)&1 selects the green symbol: 0 -> base.G, 1 -> altGreen.
	for _, tc := range []struct {
		x, y      int
		wantGreen uint8
	}{{0, 0, 60}, {1, 0, 210}, {0, 1, 210}, {1, 1, 60}, {199, 199, 60}} {
		r, g, b, _ := img.At(tc.x, tc.y).RGBA()
		if uint8(g>>8) != tc.wantGreen {
			t.Errorf("pixel (%d,%d) green = %d, want %d", tc.x, tc.y, uint8(g>>8), tc.wantGreen)
		}
		if uint8(r>>8) != base.R || uint8(b>>8) != base.B {
			t.Errorf("pixel (%d,%d) red/blue = %d/%d, want %d/%d", tc.x, tc.y, uint8(r>>8), uint8(b>>8), base.R, base.B)
		}
	}
}
