// Package webptest builds tiny, valid lossless WebP (VP8L) images for tests.
//
// It exists because Go has no WebP *encoder*: golang.org/x/image/webp is
// decode-only, and the stdlib has nothing. Without this, testing that the NSFW
// image classifier actually handles WebP would mean committing an opaque
// binary fixture with murky provenance. Generating one from a documented
// bitstream writer is both smaller and auditable.
//
// Only the sliver of VP8L needed for test fixtures is implemented: no
// transforms, no color cache, no LZ77 back-references, and Huffman trees
// restricted to VP8L's "simple code" form (1 or 2 symbols). That is enough to
// emit an image of any size in a handful of bytes, which is all a decoder test
// needs. This package is imported only from _test.go files, so it is never
// linked into the shipped binary.
//
// Bitstream reference: https://developers.google.com/speed/webp/docs/riff_container
package webptest

import (
	"encoding/binary"
	"image/color"
)

// Flat encodes a solid-color w×h WebP. Every Huffman tree is a single-symbol
// simple code, so each symbol decodes from zero bits and the whole image body
// is empty - the result is on the order of 25 bytes regardless of dimensions.
//
// Useful when a test needs correct dimensions and a real decode but does not
// care about the pixels. When the test also needs the encoded size to clear
// ImageClassifier's 1 KB minImageBytes floor, use Noisy instead.
func Flat(w, h int, c color.RGBA) []byte {
	bw := &bitWriter{}
	writeVP8LHeader(bw, w, h)
	writeSimpleTree(bw, c.G)    // green
	writeSimpleTree(bw, c.R)    // red
	writeSimpleTree(bw, c.B)    // blue
	writeSimpleTree(bw, c.A)    // alpha
	writeSimpleTree(bw, 0)      // distance (unused; LZ77 is never emitted)
	return riffWrap(bw.bytes()) // pixel body is 0 bits wide
}

// Noisy encodes a w×h WebP whose pixels alternate between c and the same color
// with its green channel replaced by altGreen, one bit per pixel, in a
// deterministic checker pattern.
//
// The two-symbol green tree is what makes each pixel cost a bit, so the
// encoded size is ~w*h/8 bytes - the point of this variant. Only the green
// channel varies because VP8L's simple codes cap a tree at two symbols, and
// spending that budget on one channel keeps the encoder trivial; tests that
// need real image content should not be using a hand-rolled encoder anyway.
func Noisy(w, h int, c color.RGBA, altGreen uint8) []byte {
	bw := &bitWriter{}
	writeVP8LHeader(bw, w, h)
	writeSimpleTree(bw, c.G, altGreen) // green: 2 symbols => 1 bit per pixel
	writeSimpleTree(bw, c.R)
	writeSimpleTree(bw, c.B)
	writeSimpleTree(bw, c.A)
	writeSimpleTree(bw, 0)

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			// symbols[0] is code 0 and symbols[1] is code 1 for a two-symbol
			// simple code, so the bit directly selects the green value.
			bw.write(uint32((x^y)&1), 1)
		}
	}
	return riffWrap(bw.bytes())
}

// writeVP8LHeader writes the VP8L signature, dimensions, and the flags that
// declare "no transforms, no color cache, one Huffman group".
func writeVP8LHeader(bw *bitWriter, w, h int) {
	bw.write(0x2f, 8)         // VP8L signature byte
	bw.write(uint32(w-1), 14) // width - 1
	bw.write(uint32(h-1), 14) // height - 1
	bw.write(0, 1)            // alpha_is_used hint (decoders ignore it)
	bw.write(0, 3)            // version_number, must be 0
	bw.write(0, 1)            // no transform follows
	bw.write(0, 1)            // no color cache
	bw.write(0, 1)            // no meta-Huffman image
}

// writeSimpleTree writes one Huffman tree in VP8L's "simple code" form. With
// one symbol the tree decodes from zero bits; with two, from exactly one bit
// (symbols[0] -> 0, symbols[1] -> 1). Symbols are always written in the 8-bit
// form so any byte value is representable.
func writeSimpleTree(bw *bitWriter, symbols ...uint8) {
	if len(symbols) < 1 || len(symbols) > 2 {
		panic("webptest: a VP8L simple code holds 1 or 2 symbols")
	}
	bw.write(1, 1)                      // use_simple_code
	bw.write(uint32(len(symbols)-1), 1) // num_symbols - 1
	bw.write(1, 1)                      // first symbol is 8 bits wide
	bw.write(uint32(symbols[0]), 8)
	if len(symbols) == 2 {
		bw.write(uint32(symbols[1]), 8)
	}
}

// riffWrap packages a VP8L bitstream as a RIFF/WEBP file. A trailing zero byte
// is appended to the payload so the decoder's symbol reader always has a byte
// available: it reads ahead before consuming, and zero-width symbols would
// otherwise push it onto its EOF path.
func riffWrap(payload []byte) []byte {
	payload = append(payload, 0)
	if len(payload)%2 == 1 {
		payload = append(payload, 0) // RIFF chunks are word-aligned
	}

	out := make([]byte, 0, 12+8+len(payload))
	out = append(out, "RIFF"...)
	out = binary.LittleEndian.AppendUint32(out, uint32(4+8+len(payload)))
	out = append(out, "WEBP"...)
	out = append(out, "VP8L"...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(payload)))
	return append(out, payload...)
}

// bitWriter emits bits least-significant-bit first within each byte, which is
// the order VP8L's bit reader consumes them in.
type bitWriter struct {
	buf []byte
	cur uint32
	n   uint
}

func (b *bitWriter) write(v uint32, bits uint) {
	b.cur |= (v & (1<<bits - 1)) << b.n
	b.n += bits
	for b.n >= 8 {
		b.buf = append(b.buf, byte(b.cur))
		b.cur >>= 8
		b.n -= 8
	}
}

// bytes flushes any partial trailing byte and returns the stream.
func (b *bitWriter) bytes() []byte {
	if b.n > 0 {
		b.buf = append(b.buf, byte(b.cur))
		b.cur, b.n = 0, 0
	}
	return b.buf
}
