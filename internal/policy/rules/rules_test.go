package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yjlion/llama-web-filter/internal/models"
)

func at(day time.Weekday, hhmm string) time.Time {
	// 2026-10-05 is a Monday.
	base := time.Date(2026, 10, 5, 0, 0, 0, 0, time.Local)
	for base.Weekday() != day {
		base = base.AddDate(0, 0, 1)
	}
	var h, m int
	_, _ = fmt.Sscanf(hhmm, "%d:%d", &h, &m)
	return base.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute)
}

func TestValidateNormalisesAndRejects(t *testing.T) {
	devices := map[string][]string{"kids-tablet": {"10.0.0.7"}}
	r := Rule{Target: TargetAdultImages, Action: ActionBlur, Match: Match{Sources: []string{" 10.10.10.10 ", "Kids-Tablet", "LAN", "aa-bb-cc-dd-ee-ff"}, Time: &TimeWindow{Start: "9:5", End: "17:00", Days: []string{"Monday", "fri"}}}}
	if err := Validate(&r, devices); err != nil {
		t.Fatal(err)
	}
	if r.Match.Time.Start != "09:05" || r.Match.Time.Days[0] != "mon" || r.Match.Sources[1] != "kids-tablet" || r.Match.Sources[2] != "lan" {
		t.Fatalf("normalised = %+v", r.Match)
	}
	bad := Rule{Target: TargetAds, Action: ActionBlur}
	if err := Validate(&bad, nil); err == nil {
		t.Fatal("blur must be rejected for ads")
	}
	bad = Rule{Target: TargetSite, Action: ActionBlock}
	if err := Validate(&bad, nil); err == nil {
		t.Fatal("site rule without value must be rejected")
	}
	bad = Rule{Target: TargetAds, Action: ActionBlock, Match: Match{Sources: []string{"nonsense"}}}
	if err := Validate(&bad, nil); err == nil {
		t.Fatal("unknown source must be rejected")
	}
}

func TestAppliesSourcesTimeAndSites(t *testing.T) {
	r := Rule{ID: "r1", Enabled: true, Target: TargetAdultImages, Action: ActionBlur,
		Match: Match{Sources: []string{"10.10.10.10"}, Time: &TimeWindow{Start: "10:00", End: "17:00"}}}
	c := Client{IP: "10.10.10.10", Host: "x.example", URL: "https://x.example/", Now: at(time.Monday, "12:00")}
	if !r.Applies(c, nil, urlInList) {
		t.Fatal("should apply at noon for the named IP")
	}
	c.Now = at(time.Monday, "18:00")
	if r.Applies(c, nil, urlInList) {
		t.Fatal("should not apply after 17:00")
	}
	c.Now = at(time.Monday, "12:00")
	c.IP = "10.10.10.11"
	if r.Applies(c, nil, urlInList) {
		t.Fatal("should not apply to another IP")
	}

	lan := Rule{ID: "r2", Enabled: true, Target: TargetAds, Action: ActionBlock,
		Match: Match{Sources: []string{"lan"}, Sites: Sites{Exclude: []string{"www.cnn.com"}}}}
	c = Client{IP: "192.168.1.5", Host: "www.cnn.com", URL: "https://www.cnn.com/", Now: time.Now()}
	if lan.Applies(c, nil, urlInList) {
		t.Fatal("excluded site must not match")
	}
	c.Host, c.URL = "news.example", "https://news.example/"
	if !lan.Applies(c, nil, urlInList) {
		t.Fatal("LAN client on another site must match")
	}
	c.IP = "8.8.8.8"
	if lan.Applies(c, nil, urlInList) {
		t.Fatal("public IP is not LAN")
	}

	overnight := TimeWindow{Start: "22:00", End: "06:00", Days: []string{"mon"}}
	if !overnight.Active(at(time.Monday, "23:00")) || !overnight.Active(at(time.Tuesday, "05:00")) || overnight.Active(at(time.Tuesday, "07:00")) || overnight.Active(at(time.Wednesday, "05:00")) {
		t.Fatal("overnight window handling is wrong")
	}

	dev := Rule{ID: "r3", Enabled: true, Target: TargetInternet, Action: ActionBlock, Match: Match{Sources: []string{"kids-tablet"}}}
	devices := map[string][]string{"kids-tablet": {"aa:bb:cc:dd:ee:ff", "10.0.0.0/24"}}
	if !dev.Applies(Client{IP: "10.0.0.9", Now: time.Now()}, devices, urlInList) {
		t.Fatal("device alias by CIDR member should match")
	}
	if !dev.Applies(Client{IP: "1.2.3.4", MAC: "AA-BB-CC-DD-EE-FF", Now: time.Now()}, devices, urlInList) {
		t.Fatal("device alias by MAC member should match")
	}
}

func TestApplyOverlaysPolicy(t *testing.T) {
	base := models.NewPolicy()
	base.Name = "default"
	all := []Rule{
		{ID: "a", Enabled: true, Target: TargetAdultImages, Action: ActionBlur, Match: Match{Sources: []string{"10.10.10.10"}}},
		{ID: "b", Enabled: true, Target: TargetAds, Action: ActionBlock, Match: Match{Sources: []string{"lan"}, Sites: Sites{Exclude: []string{"www.cnn.com"}}}},
		{ID: "c", Enabled: true, Target: TargetSite, Action: ActionBlock, Value: []string{"bad.example"}},
		{ID: "d", Enabled: false, Target: TargetInternet, Action: ActionBlock},
	}
	c := Client{IP: "10.10.10.10", Policy: "default", Host: "x.example", URL: "https://x.example/", Now: time.Now()}
	eff, used := Apply(base, all, c, nil, urlInList)
	if !eff.ImageClassifier.Enabled || eff.ImageClassifier.Action != models.ImageActionBlur {
		t.Fatalf("image classifier not applied: %+v", eff.ImageClassifier)
	}
	if !eff.AdBlock.Enabled || !eff.UrlFilter.Enabled || eff.UrlFilter.Block[0] != "bad.example" {
		t.Fatalf("ads/site rules not applied: %+v %+v", eff.AdBlock, eff.UrlFilter)
	}
	if len(used) != 3 || used[2] != "c" {
		t.Fatalf("used = %v", used)
	}
	if len(base.UrlFilter.Block) != 0 || base.AdBlock.Enabled {
		t.Fatal("base policy must not be mutated")
	}
	// On cnn.com the ads rule is excluded.
	c.Host, c.URL = "www.cnn.com", "https://www.cnn.com/"
	eff, _ = Apply(base, all, c, nil, urlInList)
	if eff.AdBlock.Enabled {
		t.Fatal("ads must stay allowed on the excluded site")
	}
}

func TestDescribe(t *testing.T) {
	r := Rule{Target: TargetAdultImages, Action: ActionBlur, Match: Match{Sources: []string{"10.10.10.10"}, Time: &TimeWindow{Start: "10:00", End: "17:00"}}}
	if got := Describe(r); got != "Blur adult images for 10.10.10.10 between 10:00 and 17:00." {
		t.Fatalf("Describe = %q", got)
	}
	r = Rule{Target: TargetAds, Action: ActionBlock, Match: Match{Sources: []string{"lan"}, Sites: Sites{Exclude: []string{"www.cnn.com"}}}}
	if got := Describe(r); got != "Block ads for every device on the LAN, except on www.cnn.com." {
		t.Fatalf("Describe = %q", got)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	st := NewStore(t.TempDir() + "/rules.json")
	if err := st.SetDevices(map[string][]string{"Kids-Tablet": {"10.0.0.7"}}); err != nil {
		t.Fatal(err)
	}
	r, err := st.Add(Rule{Enabled: true, Text: "x", Target: TargetAds, Action: ActionBlock, Match: Match{Sources: []string{"kids-tablet"}}})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID == "" || r.Created.IsZero() {
		t.Fatalf("Add should assign id and time: %+v", r)
	}
	f, _ := st.Load()
	if len(f.Rules) != 1 || f.Devices["kids-tablet"][0] != "10.0.0.7" {
		t.Fatalf("Load = %+v", f)
	}
	if _, err := st.SetEnabled(r.ID, false); err != nil {
		t.Fatal(err)
	}
	r.Action = ActionAllow
	r.Enabled = false
	if _, err := st.Update(r); err != nil {
		t.Fatal(err)
	}
	f, _ = st.Load()
	if f.Rules[0].Enabled || f.Rules[0].Action != ActionAllow {
		t.Fatalf("after update = %+v", f.Rules[0])
	}
	if err := st.Delete(r.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(r.ID); err != ErrNotFound {
		t.Fatalf("second delete = %v", err)
	}
}

// urlInList is a minimal stand-in for proxy.UrlInList (which cannot be
// imported here without a cycle): exact host or subdomain match.
func urlInList(host, _ string, patterns []string) bool {
	for _, p := range patterns {
		p = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(p)), "*.")
		if p != "" && (host == p || strings.HasSuffix(host, "."+p)) {
			return true
		}
	}
	return false
}
