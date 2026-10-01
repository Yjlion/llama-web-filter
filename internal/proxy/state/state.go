// Package state holds the proxy engine's shared, hot-reloaded runtime
// state: the current settings.json snapshot, the current policies/*.json
// snapshot, and the CA/log-store/category-store instances every addon
// reads from. It replaces the several independent module-level globals
// each proxy/addons/*.py file keeps in the Python original with one
// consistently-updated object.
//
// Both policies/*.json and settings.json hot-reload, via fsnotify watchers
// (the policy one mirrors policy_router.py's watchfiles-based loop).
//
// The two reloads are not equivalent. A policy reload swaps the whole set,
// because nothing in the engine is built from a policy at startup. A
// settings reload only applies the fields whose consumers read them per
// request - settingsvc.MergeHot decides which - and leaves everything that
// was baked in at construction (bound listeners, the CA, the log store, the
// tun2socks/gateway supervisors) at the value that is actually in effect.
// PUT /api/settings reports the fields that still need a restart so the UI
// can say so rather than implying the change took hold.
package state

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/yjlion/llama-web-filter/internal/categories"
	"github.com/yjlion/llama-web-filter/internal/certs"
	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/logstore"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/neighbors"
	"github.com/yjlion/llama-web-filter/internal/policy/rules"
	"github.com/yjlion/llama-web-filter/internal/settingsvc"
)

// Runtime is the shared state passed to every addon.
type Runtime struct {
	SettingsPath string

	// settings is swapped wholesale by ApplySettings; readers take the
	// pointer, never the struct. It was a plain value field until settings
	// hot-reload landed, which was safe only because nothing ever wrote it -
	// every per-connection goroutine reads it.
	settings atomic.Pointer[models.GlobalSettings]

	CA         *certs.CA
	LeafIssuer *certs.LeafIssuer
	Logs       *logstore.Store
	Categories *categories.Store

	policyStore *config.PolicyStore
	policies    atomic.Pointer[[]models.Policy]
	ruleStore   *rules.Store
	rules       atomic.Pointer[rules.File]
	mitmBypass  atomic.Pointer[[]string] // aggregated exclude-mode mitm domains, lowercased
	generation  atomic.Uint64            // bumped on every policy reload
}

// New loads settings.json once and wires up the CA, log store, category
// store, and an initial policies load.
func New(settingsPath string) (*Runtime, error) {
	s, err := config.LoadSettings(settingsPath)
	if err != nil {
		return nil, err
	}

	ca, err := certs.LoadOrCreateCA(s.CertDir)
	if err != nil {
		return nil, err
	}
	leafIssuer, err := certs.NewLeafIssuer(ca)
	if err != nil {
		return nil, err
	}
	logs, err := logstore.Configure(s.DBPath(), s.LogRetentionDays, s.LogRequests, s.LogBlocks)
	if err != nil {
		return nil, err
	}

	rt := &Runtime{
		SettingsPath: settingsPath,
		CA:           ca,
		LeafIssuer:   leafIssuer,
		Logs:         logs,
		Categories:   categories.NewStore(s.CategoriesDir),
		policyStore:  config.NewPolicyStore(s.PoliciesDir),
		ruleStore:    rules.NewStore(rules.PathFor(settingsPath)),
	}
	rt.settings.Store(&s)
	rt.ReloadPolicies()
	rt.ReloadRules()
	return rt, nil
}

// Settings returns the live settings snapshot.
//
// The pointed-to value is immutable: readers must never write through it,
// and ApplySettings swaps in a whole new one rather than mutating in place.
// A pointer rather than a value because GlobalSettings is a large struct
// with four nested configs and six slices, and this is on the per-request
// path.
func (rt *Runtime) Settings() *models.GlobalSettings {
	if s := rt.settings.Load(); s != nil {
		return s
	}
	// A zero-value Runtime built as a struct literal (tests do this) has no
	// snapshot. Returning documented defaults beats a nil dereference on a
	// per-request path; New always stores one before anything can read it.
	return &defaultSettings
}

// defaultSettings backs Settings() for a Runtime that never had one stored.
// Shared, so it must never be written through - the same rule that applies
// to every pointer Settings() returns.
var defaultSettings = models.NewGlobalSettings()

// SetSettings replaces the entire snapshot, restart-required fields
// included. This is the constructor's path and the one tests use to stand up
// a runtime with specific settings; hot-reload goes through ApplySettings
// instead, which deliberately leaves restart-required fields alone.
func (rt *Runtime) SetSettings(s models.GlobalSettings) {
	rt.settings.Store(&s)
}

// ApplySettings swaps in the hot fields of next, keeping every
// restart-required field at the value currently in effect
// (settingsvc.MergeHot). It returns the field names that changed but need a
// restart, so a caller can report them.
//
// Side effects are limited to stores that support being re-pointed at
// runtime; anything requiring a rebind or a reopened handle is
// restart-required by classification and is not touched here.
func (rt *Runtime) ApplySettings(next models.GlobalSettings) []string {
	live := rt.Settings()
	if live == nil {
		rt.settings.Store(&next)
		return nil
	}

	pending := settingsvc.RestartRequired(*live, next)
	merged := settingsvc.MergeHot(*live, next)
	rt.settings.Store(&merged)

	// categories_dir is classified hot precisely because the store can be
	// re-pointed; mgmtapi already does this per request.
	if rt.Categories != nil && merged.CategoriesDir != live.CategoriesDir {
		rt.Categories.Configure(merged.CategoriesDir)
	}
	return pending
}

// ReloadSettings re-reads settings.json from disk and applies it. Called by
// the settings watcher, and directly by front-ends whose platform makes
// fsnotify unreliable (Android) or whose writer is another process.
func (rt *Runtime) ReloadSettings() {
	next, err := config.LoadSettings(rt.SettingsPath)
	if err != nil {
		slog.Warn("settings: reload failed, keeping current settings", "err", err)
		return
	}
	pending := rt.ApplySettings(next)
	if len(pending) > 0 {
		slog.Info("settings: reloaded; some changes need a restart",
			"restart_required", strings.Join(pending, ","))
		return
	}
	slog.Info("settings: reloaded")
}

// Start begins watching policies_dir and settings.json for changes,
// hot-reloading until ctx is cancelled.
//
// The settings watcher watches the file's *directory*, not the file:
// config.atomicWriteFile writes a temp file and renames it into place, so a
// watch on the file itself would follow the replaced inode and go deaf after
// the first save. Watching the directory is also what makes the split-process
// deployment work, where `webfilter mgmt` writes the file and `webfilter
// proxy` has to notice.
func (rt *Runtime) Start(ctx context.Context) {
	config.WatchDir(ctx, rt.policyStore.Dir, 300*time.Millisecond, rt.ReloadPolicies)

	if dir := filepath.Dir(rt.SettingsPath); dir != "" {
		// rules.json lives next to settings.json, so one watch covers both.
		config.WatchDir(ctx, dir, 300*time.Millisecond, func() {
			rt.ReloadSettings()
			rt.ReloadRules()
		})
	}
}

// ReloadRules re-reads rules.json (also invoked by the config-dir watcher).
func (rt *Runtime) ReloadRules() {
	f, err := rt.ruleStore.Load()
	if err != nil {
		slog.Warn("rules: failed to load rules.json", "err", err)
		return
	}
	rt.rules.Store(&f)
	rt.generation.Add(1)
	slog.Info("rules: loaded", "count", len(f.Rules), "devices", len(f.Devices), "path", rt.ruleStore.Path)
}

// Rules returns the current rules document (never nil).
func (rt *Runtime) Rules() *rules.File {
	if f := rt.rules.Load(); f != nil {
		return f
	}
	return &rules.File{Devices: map[string][]string{}}
}

// DefaultPolicy returns the policy a client with no match is treated as
// having: the one named "default" if present, else documented defaults.
// Used when rules apply to an unmatched client.
func (rt *Runtime) DefaultPolicy() models.Policy {
	for _, p := range rt.Policies() {
		if strings.EqualFold(p.Name, "default") {
			return p
		}
	}
	p := models.NewPolicy()
	p.Name = "default"
	return p
}

// RuleStore exposes the on-disk store for the management API.
func (rt *Runtime) RuleStore() *rules.Store { return rt.ruleStore }

// ReloadPolicies re-reads every policies/*.json file immediately (also
// invoked automatically by the fsnotify watcher Start begins).
func (rt *Runtime) ReloadPolicies() {
	policies, err := rt.policyStore.List()
	if err != nil {
		slog.Warn("policy_router: failed to load policies", "err", err)
		return
	}
	rt.policies.Store(&policies)
	rt.rebuildMitmBypass(policies)
	rt.generation.Add(1)
	slog.Info("policy_router: loaded policies", "count", len(policies), "dir", rt.policyStore.Dir)
}

// Generation counts how many times the policy set has been loaded. It exists
// so a caller can tell "the configuration changed" without diffing it.
//
// The ICAP service publishes it as the ISTag an ICAP client caches adapted
// objects against: without a tag that moves, a policy edit would never reach
// anything the upstream proxy already holds in its cache.
func (rt *Runtime) Generation() uint64 {
	return rt.generation.Load()
}

// Policies returns the current policy snapshot, in file-sort order
// (matches the tie-breaking PolicyStore.List documents).
func (rt *Runtime) Policies() []models.Policy {
	p := rt.policies.Load()
	if p == nil {
		return nil
	}
	return *p
}

func (rt *Runtime) rebuildMitmBypass(policies []models.Policy) {
	seen := make(map[string]struct{})
	domains := make([]string, 0)
	for _, p := range policies {
		if p.Mitm.Mode != models.MitmModeExclude {
			continue
		}
		for _, site := range p.Mitm.Sites {
			d := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(site), "*."))
			if d == "" {
				continue
			}
			if _, ok := seen[d]; !ok {
				seen[d] = struct{}{}
				domains = append(domains, d)
			}
		}
	}
	rt.mitmBypass.Store(&domains)
}

// ShouldBypassMitm reports whether host (or a parent domain) is in the
// aggregated MITM-exclude list from every loaded policy, mirroring
// policy_router.py's _sync_ignore_hosts/ctx.options.ignore_hosts. Unlike
// mitmproxy, this can't be scoped per source IP - a bypass here applies to
// every client, exactly matching the Python original's documented
// limitation ("Per-source-IP TLS bypass is architecturally impossible").
func (rt *Runtime) ShouldBypassMitm(host string) bool {
	p := rt.mitmBypass.Load()
	if p == nil {
		return false
	}
	host = strings.ToLower(host)
	for _, d := range *p {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// GetPolicy matches a client IP to a policy by specificity, most specific
// first: (0) MAC match, (1) exact single-IP match, (2) CIDR block match
// (narrowest/longest-prefix wins), (3) catch-all (empty source_ips).
// Within a tier, policies are considered in file-sort order (first wins).
// A policy is skipped if its schedule is not currently active. Ported from
// policy_router.py's get_policy. Detailed matching logic lives in
// MatchPolicy so the management API can simulate the same decision.
func (rt *Runtime) GetPolicy(clientIP string) *models.Policy {
	policies := rt.Policies()
	match := MatchPolicy(policies, clientIP, time.Now(), neighbors.Lookup)
	if match.PolicyIndex < 0 {
		return nil
	}
	return &policies[match.PolicyIndex]
}
