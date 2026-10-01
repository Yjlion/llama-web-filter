package app

import (
	"context"
	"net/http"
	"time"

	"github.com/yjlion/llama-web-filter/internal/adblock"
	"github.com/yjlion/llama-web-filter/internal/mgmtapi"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

// AdBlockAdapter presents the runtime's filter lists to the management API.
type AdBlockAdapter struct {
	Runtime *state.Runtime
}

var _ mgmtapi.AdBlockController = (*AdBlockAdapter)(nil)

func (a *AdBlockAdapter) Status() any {
	st := a.Runtime.AdBlockStatus()
	return struct {
		Managed bool `json:"managed"`
		state.AdBlockInfo
		SnapshotDate string                 `json:"snapshot_date"`
		Sources      []models.AdBlockSource `json:"sources"`
	}{true, st, adblock.SnapshotDate, sourcesOf(a.Runtime.Settings())}
}

func (a *AdBlockAdapter) Update(ctx context.Context) (any, error) {
	settings := a.Runtime.Settings()
	st, err := UpdateAdBlockLists(ctx, settings)
	if err != nil {
		return st, err
	}
	a.Runtime.ReloadAdBlock()
	return a.Status(), nil
}

func sourcesOf(s *models.GlobalSettings) []models.AdBlockSource {
	if len(s.AdBlockSources) > 0 {
		return s.AdBlockSources
	}
	out := make([]models.AdBlockSource, 0, len(adblock.DefaultSources))
	for _, d := range adblock.DefaultSources {
		out = append(out, models.AdBlockSource{Name: d.Name, URL: d.URL})
	}
	return out
}

// UpdateAdBlockLists downloads the configured filter lists into the
// settings' adblock directory.
func UpdateAdBlockLists(ctx context.Context, s *models.GlobalSettings) (adblock.State, error) {
	var sources []adblock.Source
	for _, src := range s.AdBlockSources {
		sources = append(sources, adblock.Source{Name: src.Name, URL: src.URL})
	}
	dir := s.AdBlockDir
	if dir == "" {
		dir = "./data/adblock"
	}
	return adblock.Update(ctx, dir, sources, &http.Client{Timeout: 3 * time.Minute})
}
