package models

import "encoding/json"

// VideoClassifierConfig controls adult-video detection. Videos are judged
// through still images the model can see: the poster a page declares for
// a <video>, a YouTube video's thumbnail, and, when ffmpeg is installed and
// Keyframes is on, a few keyframes decoded from the stream itself. A video
// judged adult is refused (there is no useful "blur" for a stream).
type VideoClassifierConfig struct {
	Enabled bool `json:"enabled"`
	// Threshold is compared with the image verdict's adult score.
	Threshold float64 `json:"threshold"`
	// OnTimeout is applied when the verdict is not back within the image
	// budget: "allow" (default) or "block".
	OnTimeout FallbackAction `json:"on_timeout"`
	// Keyframes decodes keyframes from video responses with an ffmpeg found
	// on PATH. Off by default: it costs CPU per video.
	Keyframes bool `json:"keyframes"`
	// YouTube judges YouTube videos by their thumbnail when the player
	// response passes through. Independent of the YouTube channel filter.
	YouTube     bool     `json:"youtube"`
	Exclude     []string `json:"exclude"`
	IncludeOnly []string `json:"include_only"`
}

func NewVideoClassifierConfig() VideoClassifierConfig {
	return VideoClassifierConfig{
		Threshold:   0.4,
		OnTimeout:   FallbackAllow,
		YouTube:     true,
		Exclude:     []string{},
		IncludeOnly: []string{},
	}
}

type videoClassifierConfigAlias VideoClassifierConfig

func (c *VideoClassifierConfig) UnmarshalJSON(data []byte) error {
	*c = NewVideoClassifierConfig()
	if err := json.Unmarshal(data, (*videoClassifierConfigAlias)(c)); err != nil {
		return err
	}
	if c.Threshold <= 0 || c.Threshold > 1 {
		c.Threshold = 0.4
	}
	c.OnTimeout = normalizeFallback(c.OnTimeout, FallbackAllow, false)
	if c.Exclude == nil {
		c.Exclude = []string{}
	}
	if c.IncludeOnly == nil {
		c.IncludeOnly = []string{}
	}
	return nil
}
