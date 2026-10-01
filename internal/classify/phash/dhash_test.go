package phash

import (
	"image"
	"image/color"
	"testing"

	"github.com/disintegration/imaging"
)

func gradient(w, h int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			v := uint8(255 * x / w)
			img.Set(x, y, color.RGBA{v, v, v, 255})
		}
	}
	return img
}

func TestResizedImageHashesClose(t *testing.T) {
	a := gradient(400, 300)
	b := imaging.Resize(a, 120, 90, imaging.Lanczos)
	ha, hb := Compute(a), Compute(b)
	if d := ha.Distance(hb); d > 4 {
		t.Fatalf("distance between an image and its downscale = %d, want <= 4", d)
	}
	if len(ha.String()) != 16 {
		t.Fatalf("String() = %q", ha.String())
	}
	// A left-to-right gradient has every bit clear; the mirrored one has
	// them set, so the two must be far apart.
	m := imaging.FlipH(a)
	if d := ha.Distance(Compute(m)); d < 40 {
		t.Fatalf("mirrored gradient distance = %d, want far", d)
	}
}
