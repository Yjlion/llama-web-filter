package models

import (
	"encoding/json"
	"strings"
)

// LLMConfig configures the local edge-LLM runtime that does all content
// classification (adult text, adult images, unknown ad hosts) and compiles
// natural-language policy rules.
//
// The runtime is a prebuilt llama.cpp `llama-server` the filter downloads
// on first run and supervises as a child process. Everything it needs
// lives under DataDir: the runtime build, the model files, and the server
// log. Alternatively ExternalURL points at an OpenAI-compatible server that
// is already running (another llama-server, or anything speaking
// /v1/chat/completions with image parts), in which case nothing is
// downloaded or spawned.
type LLMConfig struct {
	// Enabled turns the runtime on. Off means the classifier addons pass
	// content through (keyword-only for text) and the policy compiler is
	// unavailable; the proxy itself still works.
	Enabled bool `json:"enabled"`

	// DataDir holds the downloaded runtime, models and logs. Empty means
	// <project root>/data/llm, resolved at bootstrap like the other dirs.
	DataDir string `json:"data_dir"`

	// Model is a catalog id (internal/llm/catalog), e.g. "gemma-4-e2b".
	Model string `json:"model"`

	// Accel selects the llama.cpp build: "auto" probes for NVIDIA (CUDA) and
	// Vulkan and falls back to CPU; "cpu", "cuda", "vulkan" force one. macOS
	// builds always include Metal, so the value is ignored there.
	Accel string `json:"accel"`

	// Threads is the CPU thread count for inference; 0 lets llama-server
	// pick (physical cores).
	Threads int `json:"threads"`

	// GPULayers is how many layers to offload (-ngl). 99 means everything
	// that fits, which is the right default for the 2-4B models in the
	// catalog; 0 keeps the model on the CPU even on a GPU build.
	GPULayers int `json:"gpu_layers"`

	// ParallelSlots is llama-server's -np: concurrent sequences. Image
	// verdicts for one page fan out across these.
	ParallelSlots int `json:"parallel_slots"`

	// ContextSize is the per-slot context (-c). Classification prompts are
	// small; 4096 leaves room for a page excerpt plus an image's tokens.
	ContextSize int `json:"context_size"`

	// MaxImagePx caps the longest side of an image sent to the model. The
	// vision encoder's cost scales with pixels, and 384px is plenty to tell
	// what a picture is of.
	MaxImagePx int `json:"max_image_px"`

	// Port is the loopback port llama-server listens on; 0 picks a free one.
	Port int `json:"port"`

	// ExternalURL, when set, disables the managed runtime and sends requests
	// to this OpenAI-compatible base URL (e.g. "http://127.0.0.1:8081").
	ExternalURL string `json:"external_url"`

	// ExtraArgs are appended to the llama-server command line verbatim.
	ExtraArgs []string `json:"extra_args"`

	// Budget bounds how long a request waits for a verdict before the
	// policy's on_timeout action applies. The LLM job keeps running past the
	// budget so its verdict still lands in the decision cache.
	Budget LLMBudget `json:"budget"`
}

// LLMBudget is the per-kind wait budget, in milliseconds.
type LLMBudget struct {
	ImageMs int `json:"image_ms"`
	TextMs  int `json:"text_ms"`
	HostMs  int `json:"host_ms"`
	// CategoryMs is how long a navigation to a not-yet-categorized site
	// waits for the model's category.
	CategoryMs int `json:"category_ms"`
	CompileMs  int `json:"compile_ms"`
}

// DefaultLLMModel is the catalog id installed when nothing is configured.
const DefaultLLMModel = "gemma-4-e2b"

// NewLLMConfig returns the documented defaults: enabled, Gemma 4 E2B,
// auto-detected acceleration.
func NewLLMConfig() LLMConfig {
	return LLMConfig{
		Enabled:       true,
		Model:         DefaultLLMModel,
		Accel:         "auto",
		GPULayers:     99,
		ParallelSlots: 4,
		ContextSize:   4096,
		MaxImagePx:    384,
		ExtraArgs:     []string{},
		Budget:        LLMBudget{ImageMs: 1500, TextMs: 2000, HostMs: 500, CategoryMs: 1500, CompileMs: 180000},
	}
}

type llmConfigAlias LLMConfig

func (c *LLMConfig) UnmarshalJSON(data []byte) error {
	*c = NewLLMConfig()
	if err := json.Unmarshal(data, (*llmConfigAlias)(c)); err != nil {
		return err
	}
	c.Model = strings.TrimSpace(c.Model)
	if c.Model == "" {
		c.Model = DefaultLLMModel
	}
	c.Accel = strings.ToLower(strings.TrimSpace(c.Accel))
	switch c.Accel {
	case "auto", "cpu", "cuda", "vulkan", "metal":
	default:
		c.Accel = "auto"
	}
	c.DataDir = strings.TrimSpace(c.DataDir)
	c.ExternalURL = strings.TrimRight(strings.TrimSpace(c.ExternalURL), "/")
	if c.ParallelSlots <= 0 {
		c.ParallelSlots = 4
	}
	if c.ContextSize < 1024 {
		c.ContextSize = 4096
	}
	if c.MaxImagePx < 64 {
		c.MaxImagePx = 384
	}
	if c.GPULayers < 0 {
		c.GPULayers = 99
	}
	if c.Threads < 0 {
		c.Threads = 0
	}
	if c.Port < 0 || c.Port > 65535 {
		c.Port = 0
	}
	if c.ExtraArgs == nil {
		c.ExtraArgs = []string{}
	}
	d := NewLLMConfig().Budget
	if c.Budget.ImageMs <= 0 {
		c.Budget.ImageMs = d.ImageMs
	}
	if c.Budget.TextMs <= 0 {
		c.Budget.TextMs = d.TextMs
	}
	if c.Budget.HostMs <= 0 {
		c.Budget.HostMs = d.HostMs
	}
	if c.Budget.CategoryMs <= 0 {
		c.Budget.CategoryMs = d.CategoryMs
	}
	if c.Budget.CompileMs <= 0 {
		c.Budget.CompileMs = d.CompileMs
	}
	return nil
}
