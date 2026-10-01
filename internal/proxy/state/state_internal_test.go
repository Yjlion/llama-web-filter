package state

import (
	"testing"
	"time"

	"github.com/yjlion/llama-web-filter/internal/models"
)

func policyNamed(name string, sourceIPs ...string) models.Policy {
	p := models.NewPolicy()
	p.Name = name
	p.SourceIPs = sourceIPs
	return p
}

func TestGetPolicyExactIPWinsOverCIDR(t *testing.T) {
	rt := &Runtime{}
	policies := []models.Policy{
		policyNamed("cidr", "192.168.1.0/24"),
		policyNamed("exact", "192.168.1.5"),
	}
	rt.policies.Store(&policies)

	got := rt.GetPolicy("192.168.1.5")
	if got == nil || got.Name != "exact" {
		t.Fatalf("GetPolicy = %+v, want exact-IP policy", got)
	}
}

func TestGetPolicyNarrowestCIDRWins(t *testing.T) {
	rt := &Runtime{}
	policies := []models.Policy{
		policyNamed("wide", "192.168.0.0/16"),
		policyNamed("narrow", "192.168.1.0/24"),
	}
	rt.policies.Store(&policies)

	got := rt.GetPolicy("192.168.1.5")
	if got == nil || got.Name != "narrow" {
		t.Fatalf("GetPolicy = %+v, want narrow CIDR policy", got)
	}
}

func TestGetPolicyCatchAll(t *testing.T) {
	rt := &Runtime{}
	policies := []models.Policy{
		policyNamed("specific", "10.0.0.0/8"),
		policyNamed("catchall"),
	}
	rt.policies.Store(&policies)

	got := rt.GetPolicy("203.0.113.9")
	if got == nil || got.Name != "catchall" {
		t.Fatalf("GetPolicy = %+v, want catchall policy", got)
	}
}

func TestGetPolicyNoMatchReturnsNil(t *testing.T) {
	rt := &Runtime{}
	policies := []models.Policy{policyNamed("specific", "10.0.0.0/8")}
	rt.policies.Store(&policies)

	if got := rt.GetPolicy("203.0.113.9"); got != nil {
		t.Fatalf("GetPolicy = %+v, want nil", got)
	}
}

func TestGetPolicySkipsInactiveSchedule(t *testing.T) {
	rt := &Runtime{}
	inactive := policyNamed("inactive", "192.168.1.5")
	inactive.Schedule = models.ScheduleConfig{
		Enabled: true,
		ActiveWindows: []models.TimeWindow{
			{Days: []int{}, Start: "00:00", End: "00:00"},
		},
	}
	fallback := policyNamed("fallback")
	policies := []models.Policy{inactive, fallback}
	rt.policies.Store(&policies)

	got := rt.GetPolicy("192.168.1.5")
	if got == nil || got.Name != "fallback" {
		t.Fatalf("GetPolicy = %+v, want fallback (inactive policy skipped)", got)
	}
}

func TestGetPolicyIPv4MappedIPv6Matches(t *testing.T) {
	rt := &Runtime{}
	policies := []models.Policy{policyNamed("v4", "192.168.1.5")}
	rt.policies.Store(&policies)

	got := rt.GetPolicy("::ffff:192.168.1.5")
	if got == nil || got.Name != "v4" {
		t.Fatalf("GetPolicy = %+v, want v4 policy to match its IPv4-mapped IPv6 form", got)
	}
}

func TestMatchPolicyExplainsCIDRMatch(t *testing.T) {
	policies := []models.Policy{
		policyNamed("lan", "192.168.1.0/24"),
		policyNamed("default"),
	}
	match := MatchPolicy(policies, "192.168.1.20", time.Now(), nil)
	if match.PolicyName != "lan" || match.Tier != PolicyMatchCIDR || match.Source != "192.168.1.0/24" {
		t.Fatalf("match = %+v, want lan CIDR", match)
	}
}

func TestMatchPolicyReportsInactivePolicies(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.Local)
	inactive := policyNamed("bedtime", "192.168.1.20")
	inactive.Schedule = models.ScheduleConfig{
		Enabled: true,
		ActiveWindows: []models.TimeWindow{
			{Days: []int{0}, Start: "00:00", End: "01:00"},
		},
	}
	active := policyNamed("default")

	match := MatchPolicy([]models.Policy{inactive, active}, "192.168.1.20", now, nil)
	if match.PolicyName != "default" || len(match.InactivePolicies) != 1 || match.InactivePolicies[0] != "bedtime" {
		t.Fatalf("match = %+v, want default with inactive bedtime", match)
	}
}

func mondayMorning() time.Time { return time.Date(2026, 7, 6, 10, 0, 0, 0, time.Local) } // Monday
func mondayEvening() time.Time { return time.Date(2026, 7, 6, 20, 0, 0, 0, time.Local) } // Monday, outside 09:00-17:00

func weekdaySchedule() models.ScheduleConfig {
	return models.ScheduleConfig{
		Enabled: true,
		ActiveWindows: []models.TimeWindow{
			{Days: []int{0}, Start: "09:00", End: "17:00"},
		},
	}
}

func TestMatchPolicyScheduledExactIPWinsOverFallback(t *testing.T) {
	scheduled := policyNamed("bedtime", "192.168.1.5")
	scheduled.Schedule = weekdaySchedule()
	fallback := policyNamed("default", "192.168.1.5")
	policies := []models.Policy{fallback, scheduled}

	inWindow := MatchPolicy(policies, "192.168.1.5", mondayMorning(), nil)
	if inWindow.PolicyName != "bedtime" {
		t.Fatalf("during window: match = %+v, want scheduled policy to win", inWindow)
	}

	outOfWindow := MatchPolicy(policies, "192.168.1.5", mondayEvening(), nil)
	if outOfWindow.PolicyName != "default" {
		t.Fatalf("outside window: match = %+v, want fallback policy to win", outOfWindow)
	}
}

func TestMatchPolicyScheduledCIDRWinsOverFallbackRegardlessOfPrefix(t *testing.T) {
	// The fallback policy has the narrower/more specific CIDR, but the
	// scheduled policy must still win while its window is active.
	scheduled := policyNamed("bedtime", "192.168.1.0/24")
	scheduled.Schedule = weekdaySchedule()
	fallback := policyNamed("default", "192.168.1.0/28")
	policies := []models.Policy{fallback, scheduled}

	inWindow := MatchPolicy(policies, "192.168.1.5", mondayMorning(), nil)
	if inWindow.PolicyName != "bedtime" {
		t.Fatalf("during window: match = %+v, want scheduled policy to win over narrower fallback CIDR", inWindow)
	}

	outOfWindow := MatchPolicy(policies, "192.168.1.5", mondayEvening(), nil)
	if outOfWindow.PolicyName != "default" {
		t.Fatalf("outside window: match = %+v, want fallback policy to win", outOfWindow)
	}
}

func TestMatchPolicyInactiveFlagSkipsPolicyEntirely(t *testing.T) {
	inactive := policyNamed("kids", "192.168.1.5")
	inactive.Inactive = true
	fallback := policyNamed("default")
	policies := []models.Policy{inactive, fallback}

	match := MatchPolicy(policies, "192.168.1.5", time.Now(), nil)
	if match.PolicyName != "default" {
		t.Fatalf("match = %+v, want fallback (inactive policy must never match)", match)
	}
	found := false
	for _, n := range match.InactivePolicies {
		if n == "kids" {
			found = true
		}
	}
	if !found {
		t.Fatalf("InactivePolicies = %v, want to include administratively-inactive 'kids'", match.InactivePolicies)
	}
}

func TestShouldBypassMitm(t *testing.T) {
	rt := &Runtime{}
	excluded := models.NewPolicy()
	excluded.Name = "excluded"
	excluded.Mitm = models.MitmConfig{Mode: models.MitmModeExclude, Sites: []string{"*.example.com"}}
	included := models.NewPolicy()
	included.Name = "included"
	included.Mitm = models.MitmConfig{Mode: models.MitmModeInclude, Sites: []string{"other.com"}}
	policies := []models.Policy{excluded, included}
	rt.policies.Store(&policies)
	rt.rebuildMitmBypass(policies)

	if !rt.ShouldBypassMitm("example.com") {
		t.Error("ShouldBypassMitm(example.com) = false, want true (exact domain from *.example.com)")
	}
	if !rt.ShouldBypassMitm("sub.example.com") {
		t.Error("ShouldBypassMitm(sub.example.com) = false, want true (subdomain)")
	}
	if rt.ShouldBypassMitm("other.com") {
		t.Error("ShouldBypassMitm(other.com) = true, want false (only listed under include-mode policy)")
	}
	if rt.ShouldBypassMitm("notexample.com") {
		t.Error("ShouldBypassMitm(notexample.com) = true, want false (must not match as a bare suffix)")
	}
}
