package mgmtapi_test

import (
	"bytes"
	"context"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"

	"github.com/yjlion/llama-web-filter/internal/mgmtapi"
)

// stubScanner is a deterministic ContentScanner for endpoint-plumbing tests:
// text is never adult, images are clean when they decode and an error
// otherwise. The real backend is the
// LLM verdict service, which is exercised by its own package tests.
type stubScanner struct{}

func (stubScanner) ScanText(_ context.Context, text string) (mgmtapi.TextScan, error) {
	return mgmtapi.TextScan{Adult: false, Score: 0.01, Source: "stub"}, nil
}

func (stubScanner) ScanImage(_ context.Context, img []byte) (mgmtapi.ImageScan, error) {
	if _, _, err := image.DecodeConfig(bytes.NewReader(img)); err != nil {
		return mgmtapi.ImageScan{}, fmt.Errorf("image could not be decoded: %w", err)
	}
	return mgmtapi.ImageScan{
		Adult: false, Score: 0.02, Source: "stub",
		Detections: []map[string]any{
			{"class": "neutral", "score": 0.98},
			{"class": "adult", "score": 0.02},
		},
	}, nil
}

func (stubScanner) Health(context.Context) mgmtapi.ScannerHealth {
	return mgmtapi.ScannerHealth{Available: true, Status: "available", Model: "stub"}
}
