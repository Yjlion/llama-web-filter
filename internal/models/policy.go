// Package models defines the shared JSON schema for policies/*.json and
// config/settings.json - the single source of truth for both the proxy
// engine and the management API, mirroring Python's shared/models.py.
//
// Every struct here implements a custom UnmarshalJSON that first populates
// itself with the same field defaults as the Pydantic v2 models (so an
// absent field takes the documented default, exactly like Pydantic), then
// overlays whatever the input JSON actually specifies. This is the one
// piece of boilerplate needed to get Pydantic-default-on-missing-field
// semantics out of encoding/json, which otherwise only gives Go zero
// values for absent fields.
package models

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/yjlion/llama-web-filter/internal/macutil"
)

// ---- DohConfig ----

type DohConfig struct {
	Enabled     bool     `json:"enabled"`
	Server      string   `json:"server"`
	Exclude     []string `json:"exclude"`
	IncludeOnly []string `json:"include_only"`
}

func NewDohConfig() DohConfig {
	return DohConfig{
		Server:      "https://1.1.1.3/dns-query",
		Exclude:     []string{},
		IncludeOnly: []string{},
	}
}

type dohConfigAlias DohConfig

func (c *DohConfig) UnmarshalJSON(data []byte) error {
	*c = NewDohConfig()
	if err := json.Unmarshal(data, (*dohConfigAlias)(c)); err != nil {
		return err
	}
	c.Server = trimSpace(c.Server)
	return nil
}

// ---- TextClassifierConfig ----

type TextClassifierConfig struct {
	Enabled     bool     `json:"enabled"`
	Threshold   float64  `json:"threshold"`
	Exclude     []string `json:"exclude"`
	IncludeOnly []string `json:"include_only"`
	// OnTimeout is what happens when the model has not answered within the
	// budget on a page's first sighting: "allow" (default) or "block".
	OnTimeout FallbackAction `json:"on_timeout"`
	// OnUnavailable is what happens when no model is available at all.
	OnUnavailable FallbackAction `json:"on_unavailable"`
	// BudgetMs overrides the global llm.budget.text_ms for this policy
	// (0 = use the global value).
	BudgetMs int `json:"budget_ms"`
}

// FallbackAction is a classifier's behaviour when no verdict is available.
type FallbackAction string

const (
	FallbackAllow        FallbackAction = "allow"
	FallbackBlock        FallbackAction = "block"
	FallbackBlur         FallbackAction = "blur"         // images only
	FallbackCheckerboard FallbackAction = "checkerboard" // images only
)

func normalizeFallback(v FallbackAction, def FallbackAction, image bool) FallbackAction {
	switch v {
	case FallbackAllow, FallbackBlock:
		return v
	case FallbackBlur, FallbackCheckerboard:
		if image {
			return v
		}
	}
	return def
}

func NewTextClassifierConfig() TextClassifierConfig {
	return TextClassifierConfig{
		Threshold:     0.80,
		Exclude:       []string{},
		IncludeOnly:   []string{},
		OnTimeout:     FallbackAllow,
		OnUnavailable: FallbackAllow,
	}
}

type textClassifierConfigAlias TextClassifierConfig

func (c *TextClassifierConfig) UnmarshalJSON(data []byte) error {
	*c = NewTextClassifierConfig()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if v, ok := raw["enabled"]; ok {
		if err := json.Unmarshal(v, &c.Enabled); err != nil {
			return err
		}
	}
	if v, ok := raw["threshold"]; ok {
		f, err := decodeJSONFloat(v)
		if err != nil {
			return fmt.Errorf("text_classifier.threshold: %w", err)
		}
		c.Threshold = f
	}
	if v, ok := raw["exclude"]; ok {
		if err := json.Unmarshal(v, &c.Exclude); err != nil {
			return err
		}
	}
	if v, ok := raw["include_only"]; ok {
		if err := json.Unmarshal(v, &c.IncludeOnly); err != nil {
			return err
		}
	}
	if v, ok := raw["on_timeout"]; ok {
		_ = json.Unmarshal(v, &c.OnTimeout)
	}
	if v, ok := raw["on_unavailable"]; ok {
		_ = json.Unmarshal(v, &c.OnUnavailable)
	}
	if v, ok := raw["budget_ms"]; ok {
		if i, err := decodeJSONInt(v); err == nil && i >= 0 {
			c.BudgetMs = i
		}
	}
	c.OnTimeout = normalizeFallback(c.OnTimeout, FallbackAllow, false)
	c.OnUnavailable = normalizeFallback(c.OnUnavailable, FallbackAllow, false)
	return nil
}

// ---- ImageClassifierConfig ----

type ImageClassifierAction string

const (
	ImageActionBlur         ImageClassifierAction = "blur"
	ImageActionBlock        ImageClassifierAction = "block"
	ImageActionCheckerboard ImageClassifierAction = "checkerboard"
)

type ImageClassifierConfig struct {
	Enabled      bool                  `json:"enabled"`
	Action       ImageClassifierAction `json:"action"`
	Threshold    float64               `json:"threshold"`
	MinDimension int                   `json:"min_dimension"`
	Exclude      []string              `json:"exclude"`
	IncludeOnly  []string              `json:"include_only"`
	// OnTimeout is applied to an image whose verdict did not arrive within
	// the budget: "allow", "blur" (default), "checkerboard" or "block". The
	// verdict still lands in the cache for the next load.
	OnTimeout FallbackAction `json:"on_timeout"`
	// OnUnavailable is applied when no model (or no vision model) is
	// available: default "allow".
	OnUnavailable FallbackAction `json:"on_unavailable"`
	// BudgetMs overrides the global llm.budget.image_ms (0 = global).
	BudgetMs int `json:"budget_ms"`
	// Prefetch scores the images a page references before the browser
	// requests them, so they are served from cache. Default on.
	Prefetch bool `json:"prefetch"`
}

func NewImageClassifierConfig() ImageClassifierConfig {
	return ImageClassifierConfig{
		Action:        ImageActionBlur,
		Threshold:     0.4,
		MinDimension:  100,
		Exclude:       []string{},
		IncludeOnly:   []string{},
		OnTimeout:     FallbackBlur,
		OnUnavailable: FallbackAllow,
		Prefetch:      true,
	}
}

type imageClassifierConfigAlias ImageClassifierConfig

func (c *ImageClassifierConfig) UnmarshalJSON(data []byte) error {
	*c = NewImageClassifierConfig()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if v, ok := raw["enabled"]; ok {
		if err := json.Unmarshal(v, &c.Enabled); err != nil {
			return err
		}
	}
	if v, ok := raw["action"]; ok {
		if err := json.Unmarshal(v, &c.Action); err != nil {
			return err
		}
	}
	if v, ok := raw["threshold"]; ok {
		f, err := decodeJSONFloat(v)
		if err != nil {
			return fmt.Errorf("image_classifier.threshold: %w", err)
		}
		c.Threshold = f
	}
	if v, ok := raw["min_dimension"]; ok {
		i, err := decodeJSONInt(v)
		if err != nil {
			return fmt.Errorf("image_classifier.min_dimension: %w", err)
		}
		c.MinDimension = i
	}
	if v, ok := raw["exclude"]; ok {
		if err := json.Unmarshal(v, &c.Exclude); err != nil {
			return err
		}
	}
	if v, ok := raw["include_only"]; ok {
		if err := json.Unmarshal(v, &c.IncludeOnly); err != nil {
			return err
		}
	}
	if v, ok := raw["on_timeout"]; ok {
		_ = json.Unmarshal(v, &c.OnTimeout)
	}
	if v, ok := raw["on_unavailable"]; ok {
		_ = json.Unmarshal(v, &c.OnUnavailable)
	}
	if v, ok := raw["budget_ms"]; ok {
		if i, err := decodeJSONInt(v); err == nil && i >= 0 {
			c.BudgetMs = i
		}
	}
	if v, ok := raw["prefetch"]; ok {
		_ = json.Unmarshal(v, &c.Prefetch)
	}
	c.OnTimeout = normalizeFallback(c.OnTimeout, FallbackBlur, true)
	c.OnUnavailable = normalizeFallback(c.OnUnavailable, FallbackAllow, true)
	return nil
}

// ---- SafeSearch ----

// SafeSearchEngines lists the engines configurable per-policy; also used to
// migrate the legacy flat schema (global block_*_tab flags) into the
// engines map, one entry per known engine.
var SafeSearchEngines = []string{"google", "bing", "duckduckgo", "yahoo", "youtube", "brave", "yandex"}

type SafeSearchEngineConfig struct {
	Enabled        bool `json:"enabled"`
	BlockImagesTab bool `json:"block_images_tab"`
	BlockVideosTab bool `json:"block_videos_tab"`
	BlockAiTab     bool `json:"block_ai_tab"`
}

func NewSafeSearchEngineConfig() SafeSearchEngineConfig {
	return SafeSearchEngineConfig{Enabled: true}
}

type safeSearchEngineConfigAlias SafeSearchEngineConfig

func (c *SafeSearchEngineConfig) UnmarshalJSON(data []byte) error {
	*c = NewSafeSearchEngineConfig()
	return json.Unmarshal(data, (*safeSearchEngineConfigAlias)(c))
}

type SafeSearchConfig struct {
	Enabled     bool                              `json:"enabled"`
	Engines     map[string]SafeSearchEngineConfig `json:"engines"`
	Exclude     []string                          `json:"exclude"`
	IncludeOnly []string                          `json:"include_only"`
}

func NewSafeSearchConfig() SafeSearchConfig {
	return SafeSearchConfig{
		Engines:     map[string]SafeSearchEngineConfig{},
		Exclude:     []string{},
		IncludeOnly: []string{},
	}
}

// legacySafeSearchFlags captures the pre-engines-map flat schema, so old
// policy files (or a manually hand-edited one) still load correctly.
type legacySafeSearchFlags struct {
	BlockImagesTab *bool `json:"block_images_tab"`
	BlockVideosTab *bool `json:"block_videos_tab"`
	BlockAiTab     *bool `json:"block_ai_tab"`
}

type safeSearchConfigAlias SafeSearchConfig

func (c *SafeSearchConfig) UnmarshalJSON(data []byte) error {
	*c = NewSafeSearchConfig()
	if err := json.Unmarshal(data, (*safeSearchConfigAlias)(c)); err != nil {
		return err
	}
	// Legacy migration: if the input has top-level block_*_tab flags and no
	// engines map was provided, upgrade to a per-engine map covering every
	// known engine, mirroring the Pydantic model_validator(mode="before").
	var legacy legacySafeSearchFlags
	_ = json.Unmarshal(data, &legacy)
	hasLegacy := legacy.BlockImagesTab != nil || legacy.BlockVideosTab != nil || legacy.BlockAiTab != nil
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(data, &raw)
	_, hasEngines := raw["engines"]
	if hasLegacy && !hasEngines {
		flags := SafeSearchEngineConfig{Enabled: true}
		if legacy.BlockImagesTab != nil {
			flags.BlockImagesTab = *legacy.BlockImagesTab
		}
		if legacy.BlockVideosTab != nil {
			flags.BlockVideosTab = *legacy.BlockVideosTab
		}
		if legacy.BlockAiTab != nil {
			flags.BlockAiTab = *legacy.BlockAiTab
		}
		for _, name := range SafeSearchEngines {
			c.Engines[name] = flags
		}
	}
	return nil
}

// ---- YouTubeConfig ----

type YouTubeMode string

const (
	YouTubeModeBlacklist YouTubeMode = "blacklist"
	YouTubeModeWhitelist YouTubeMode = "whitelist"
)

type YouTubeConfig struct {
	Enabled               bool        `json:"enabled"`
	Mode                  YouTubeMode `json:"mode"`
	Channels              []string    `json:"channels"`
	Exclude               []string    `json:"exclude"`
	IncludeOnly           []string    `json:"include_only"`
	BlockHome             bool        `json:"block_home"`
	RemoveComments        bool        `json:"remove_comments"`
	RemoveRecommendations bool        `json:"remove_recommendations"`
}

func NewYouTubeConfig() YouTubeConfig {
	return YouTubeConfig{
		Mode:        YouTubeModeBlacklist,
		Channels:    []string{},
		Exclude:     []string{},
		IncludeOnly: []string{},
		BlockHome:   true,
	}
}

type youTubeConfigAlias YouTubeConfig

func (c *YouTubeConfig) UnmarshalJSON(data []byte) error {
	*c = NewYouTubeConfig()
	return json.Unmarshal(data, (*youTubeConfigAlias)(c))
}

// ---- MitmConfig ----

type MitmMode string

const (
	MitmModeExclude MitmMode = "exclude"
	MitmModeInclude MitmMode = "include"
)

type MitmUAMode string

const (
	MitmUAModeOff     MitmUAMode = "off"
	MitmUAModeExclude MitmUAMode = "exclude"
	MitmUAModeInclude MitmUAMode = "include"
)

type MitmConfig struct {
	Mode       MitmMode   `json:"mode"`
	Sites      []string   `json:"sites"`
	UAMode     MitmUAMode `json:"ua_mode"`
	UserAgents []string   `json:"user_agents"`
}

func NewMitmConfig() MitmConfig {
	return MitmConfig{
		Mode:       MitmModeExclude,
		Sites:      []string{},
		UAMode:     MitmUAModeOff,
		UserAgents: []string{},
	}
}

type mitmConfigAlias MitmConfig

func (c *MitmConfig) UnmarshalJSON(data []byte) error {
	*c = NewMitmConfig()
	return json.Unmarshal(data, (*mitmConfigAlias)(c))
}

// ---- UrlFilterConfig ----

type UrlFilterMode string

const (
	UrlFilterModeBlacklist UrlFilterMode = "blacklist"
	UrlFilterModeWhitelist UrlFilterMode = "whitelist"
)

type UrlFilterConfig struct {
	Enabled    bool          `json:"enabled"`
	Allow      []string      `json:"allow"`
	Block      []string      `json:"block"`
	Mode       UrlFilterMode `json:"mode"`
	Categories []string      `json:"categories"`
	BlockQuic  bool          `json:"block_quic"`
}

// NewUrlFilterConfig defaults BlockQuic on: stripping Alt-Svc is a
// header-only change with no false-positive cost, and leaving it off by
// default meant a filtering proxy silently let browsers discover HTTP/3 and
// leave the pipeline. It is independent of Enabled - QuicBlocker is about
// keeping traffic inspectable, not about URL rules.
func NewUrlFilterConfig() UrlFilterConfig {
	return UrlFilterConfig{
		Allow:      []string{},
		Block:      []string{},
		Mode:       UrlFilterModeBlacklist,
		Categories: []string{},
		BlockQuic:  true,
	}
}

type urlFilterConfigAlias UrlFilterConfig

func (c *UrlFilterConfig) UnmarshalJSON(data []byte) error {
	*c = NewUrlFilterConfig()
	return json.Unmarshal(data, (*urlFilterConfigAlias)(c))
}

// ---- BlockPageConfig ----

type BlockPageConfig struct {
	Template string `json:"template"`
	Message  string `json:"message"`
}

func NewBlockPageConfig() BlockPageConfig {
	return BlockPageConfig{Template: "default"}
}

type blockPageConfigAlias BlockPageConfig

func (c *BlockPageConfig) UnmarshalJSON(data []byte) error {
	*c = NewBlockPageConfig()
	return json.Unmarshal(data, (*blockPageConfigAlias)(c))
}

// ---- ScheduleConfig defaults wiring ----

func NewScheduleConfig() ScheduleConfig {
	return ScheduleConfig{ActiveWindows: []TimeWindow{}}
}

type scheduleConfigAlias ScheduleConfig

func (c *ScheduleConfig) UnmarshalJSON(data []byte) error {
	*c = NewScheduleConfig()
	if err := json.Unmarshal(data, (*scheduleConfigAlias)(c)); err != nil {
		return err
	}
	for i := range c.ActiveWindows {
		c.ActiveWindows[i].Normalize()
	}
	return nil
}

// ---- Policy ----

type Policy struct {
	Name            string                `json:"name"`
	Inactive        bool                  `json:"inactive"`
	SourceIPs       []string              `json:"source_ips"`
	SourceMACs      []string              `json:"source_macs"`
	Schedule        ScheduleConfig        `json:"schedule"`
	Doh             DohConfig             `json:"doh"`
	TextClassifier  TextClassifierConfig  `json:"text_classifier"`
	ImageClassifier ImageClassifierConfig `json:"image_classifier"`
	SafeSearch      SafeSearchConfig      `json:"safesearch"`
	YouTube         YouTubeConfig         `json:"youtube"`
	Mitm            MitmConfig            `json:"mitm"`
	UrlFilter       UrlFilterConfig       `json:"url_filter"`
	AdBlock         AdBlockConfig         `json:"adblock"`
	BlockPage       BlockPageConfig       `json:"block_page"`
}

// NewPolicy returns a Policy with every sub-config at its documented
// default - equivalent to Pydantic's Policy() with only `name` supplied.
func NewPolicy() Policy {
	return Policy{
		SourceIPs:       []string{},
		SourceMACs:      []string{},
		Schedule:        NewScheduleConfig(),
		Doh:             NewDohConfig(),
		TextClassifier:  NewTextClassifierConfig(),
		ImageClassifier: NewImageClassifierConfig(),
		SafeSearch:      NewSafeSearchConfig(),
		YouTube:         NewYouTubeConfig(),
		Mitm:            NewMitmConfig(),
		UrlFilter:       NewUrlFilterConfig(),
		AdBlock:         NewAdBlockConfig(),
		BlockPage:       NewBlockPageConfig(),
	}
}

type policyAlias Policy

func (p *Policy) UnmarshalJSON(data []byte) error {
	*p = NewPolicy()
	if err := json.Unmarshal(data, (*policyAlias)(p)); err != nil {
		return err
	}
	// Normalize source_macs: canonicalize, drop unparseable entries -
	// mirrors the Pydantic field_validator("source_macs").
	normalized := make([]string, 0, len(p.SourceMACs))
	for _, m := range p.SourceMACs {
		if n := macutil.Normalize(m); n != "" {
			normalized = append(normalized, n)
		}
	}
	p.SourceMACs = normalized
	return nil
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func decodeJSONFloat(raw json.RawMessage) (float64, error) {
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return f, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, err
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, err
	}
	return f, nil
}

func decodeJSONInt(raw json.RawMessage) (int, error) {
	var i int
	if err := json.Unmarshal(raw, &i); err == nil {
		return i, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, err
	}
	i, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	return i, nil
}
