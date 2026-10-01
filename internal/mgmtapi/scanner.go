package mgmtapi

import "context"

// ContentScanner is the content-classification backend behind the Tools
// page's URL scanner and the classifier-health endpoint. The process that
// owns the LLM verdict service sets Server.Scanner; nil means classification
// is unavailable in this process (standalone `mgmt`, or the LLM runtime is
// disabled), which the endpoints report rather than guessing.
type ContentScanner interface {
	// ScanText classifies page text for adult content.
	ScanText(ctx context.Context, text string) (TextScan, error)
	// ScanImage classifies encoded image bytes for adult content.
	ScanImage(ctx context.Context, img []byte) (ImageScan, error)
	// Health reports whether the backend is ready to classify.
	Health(ctx context.Context) ScannerHealth
}

// TextScan is a text verdict in the shape the Tools page renders.
type TextScan struct {
	Adult      bool     `json:"adult"`
	Score      float64  `json:"score"`
	Categories []string `json:"categories,omitempty"`
	Source     string   `json:"source,omitempty"`
}

// ImageScan is an image verdict in the shape the Tools page renders.
type ImageScan struct {
	Adult      bool             `json:"adult"`
	Score      float64          `json:"score"`
	Detections []map[string]any `json:"detections,omitempty"`
	Source     string           `json:"source,omitempty"`
}

// ScannerHealth is the classifier-health payload.
type ScannerHealth struct {
	Available bool   `json:"available"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
	Model     string `json:"model,omitempty"`
}
