package state

import (
	"context"
	"time"
)

// CategoryLookup asks for a website's category (see internal/sitecat).
type CategoryLookup struct {
	Host               string
	Title, Description string
	// Enqueue lets the model be asked when nothing is known yet; without it
	// the lookup answers from the domain lists and the cache only.
	Enqueue bool
	// Budget is how long to wait for the model (0 = do not wait).
	Budget time.Duration
}

// CategoryAnswer is a categorizer's reply. When Known is false, TimedOut or
// Unavailable say why; neither is set for a cache-only miss.
type CategoryAnswer struct {
	Category    string
	Source      string
	Confidence  float64
	Known       bool
	TimedOut    bool
	Unavailable bool
}

// SiteCategorizer sorts websites into categories: the installed domain
// lists first, then the edge LLM, with every verdict cached per site.
type SiteCategorizer interface {
	Categorize(ctx context.Context, q CategoryLookup) CategoryAnswer
}

type categorizerBox struct{ c SiteCategorizer }

// SetSiteCategorizer installs the categorizer (nil removes it). Safe to call
// while flows are running.
func (rt *Runtime) SetSiteCategorizer(c SiteCategorizer) {
	rt.categorizer.Store(&categorizerBox{c})
}

// SiteCategorizer returns the installed categorizer, or nil.
func (rt *Runtime) SiteCategorizer() SiteCategorizer {
	if rt == nil {
		return nil
	}
	if b := rt.categorizer.Load(); b != nil {
		return b.c
	}
	return nil
}
