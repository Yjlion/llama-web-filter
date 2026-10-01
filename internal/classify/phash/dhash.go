// Package phash computes a difference hash (dHash) for near-duplicate image
// lookup: the same picture served at different sizes, re-encoded, or with
// a different quality setting hashes to the same or a very close value, so
// one model verdict covers all of them.
package phash

import (
	"encoding/hex"
	"image"
	"image/color"
	"math/bits"

	"github.com/disintegration/imaging"
)

// DHash is a 64-bit difference hash.
type DHash uint64

// Compute resizes img to 9x8 greyscale and sets a bit for each pixel that
// is brighter than its right-hand neighbour.
func Compute(img image.Image) DHash {
	small := imaging.Resize(img, 9, 8, imaging.Box)
	var h uint64
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			l := luma(small.At(x, y))
			r := luma(small.At(x+1, y))
			h <<= 1
			if l > r {
				h |= 1
			}
		}
	}
	return DHash(h)
}

func luma(c color.Color) uint32 {
	r, g, b, _ := c.RGBA()
	return (299*r + 587*g + 114*b) / 1000
}

// Distance is the Hamming distance between two hashes; 0 is identical and
// values up to ~6 are near-duplicates of the same picture.
func (h DHash) Distance(o DHash) int { return bits.OnesCount64(uint64(h ^ o)) }

// String renders the hash as 16 hex characters, which is the cache key.
func (h DHash) String() string {
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(h)
		h >>= 8
	}
	return hex.EncodeToString(b[:])
}
