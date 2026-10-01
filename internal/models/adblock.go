package models

import "encoding/json"

// AdBlockConfig controls ad and tracker removal for a policy: EasyList-style
// network rules (requests to ad hosts are answered with an empty body of
// the right type) and cosmetic rules (ad containers hidden with injected
// CSS), with the edge LLM classifying hosts the lists do not know.
type AdBlockConfig struct {
	Enabled bool `json:"enabled"`
	// Cosmetic injects element-hiding CSS into HTML pages. Off leaves
	// pages' layout untouched and only blocks the ad requests.
	Cosmetic bool `json:"cosmetic"`
	// ClassifyUnknownHosts asks the model about third-party hosts the lists
	// do not cover and caches the verdict.
	ClassifyUnknownHosts bool `json:"classify_unknown_hosts"`
	// Exclude lists sites (domain, *.wildcard or URL) where no ad blocking
	// is done; IncludeOnly restricts it to the listed sites.
	Exclude     []string `json:"exclude"`
	IncludeOnly []string `json:"include_only"`
}

func NewAdBlockConfig() AdBlockConfig {
	return AdBlockConfig{
		Cosmetic:             true,
		ClassifyUnknownHosts: true,
		Exclude:              []string{},
		IncludeOnly:          []string{},
	}
}

type adBlockConfigAlias AdBlockConfig

func (c *AdBlockConfig) UnmarshalJSON(data []byte) error {
	*c = NewAdBlockConfig()
	if err := json.Unmarshal(data, (*adBlockConfigAlias)(c)); err != nil {
		return err
	}
	if c.Exclude == nil {
		c.Exclude = []string{}
	}
	if c.IncludeOnly == nil {
		c.IncludeOnly = []string{}
	}
	return nil
}
