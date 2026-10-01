// Package imageprep turns arbitrary web images into what the vision model
// should see: a bounded-size JPEG. The vision encoder's cost grows with
// pixel count and a few hundred pixels on the long side is enough to tell
// what an image depicts, so every image is downscaled before it is sent.
package imageprep

import (
	"bytes"
	"errors"
	"image"
	"image/jpeg"
	_ "image/gif"
	_ "image/png"

	"github.com/disintegration/imaging"
	_ "golang.org/x/image/webp"
)

// Prepared is an image ready for the model.
type Prepared struct {
	Data   []byte
	MIME   string
	Width  int // original dimensions
	Height int
}

// ErrTooSmall marks images below the size floor (icons, spacers,
// tracking pixels) that are not worth a model call.
var ErrTooSmall = errors.New("image too small to classify")

// MinSide is the floor on the shorter side below which an image is not
// classified.
const MinSide = 64

// Prepare decodes src, rejects images smaller than MinSide on their shorter
// side, downscales so the longer side is at most maxPx, and re-encodes as
// JPEG. Animated formats contribute their first frame.
func Prepare(src []byte, maxPx int) (Prepared, error) {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(src))
	if err != nil {
		return Prepared{}, err
	}
	if cfg.Width < MinSide || cfg.Height < MinSide {
		return Prepared{Width: cfg.Width, Height: cfg.Height}, ErrTooSmall
	}
	img, _, err := image.Decode(bytes.NewReader(src))
	if err != nil {
		return Prepared{}, err
	}
	if maxPx < MinSide {
		maxPx = 384
	}
	if cfg.Width > maxPx || cfg.Height > maxPx {
		if cfg.Width >= cfg.Height {
			img = imaging.Resize(img, maxPx, 0, imaging.Box)
		} else {
			img = imaging.Resize(img, 0, maxPx, imaging.Box)
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 70}); err != nil {
		return Prepared{}, err
	}
	return Prepared{Data: buf.Bytes(), MIME: "image/jpeg", Width: cfg.Width, Height: cfg.Height}, nil
}
