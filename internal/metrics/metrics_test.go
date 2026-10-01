package metrics

import (
	"strings"
	"sync"
	"testing"
)

// render is WriteText into a string, for assertions.
func render(t *testing.T, r *Registry) string {
	t.Helper()
	var b strings.Builder
	if err := r.WriteText(&b); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	return b.String()
}

func TestCounterAndGaugeExposition(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("wf_things_total", "Things that happened.")
	g := r.NewGauge("wf_things_active", "Things in flight.")

	c.Inc()
	c.Add(4)
	g.Set(3)
	g.Dec()

	got := render(t, r)
	want := `# HELP wf_things_active Things in flight.
# TYPE wf_things_active gauge
wf_things_active 2
# HELP wf_things_total Things that happened.
# TYPE wf_things_total counter
wf_things_total 5
`
	if got != want {
		t.Errorf("exposition mismatch:\n got:\n%s\nwant:\n%s", got, want)
	}
}

// Families must come out in name order regardless of registration order, so
// a scrape diff is stable and golden assertions do not depend on init order.
func TestFamiliesSortedByName(t *testing.T) {
	r := NewRegistry()
	r.NewCounter("wf_zebra_total", "z")
	r.NewCounter("wf_alpha_total", "a")
	r.NewCounter("wf_middle_total", "m")

	got := render(t, r)
	iAlpha := strings.Index(got, "wf_alpha_total")
	iMiddle := strings.Index(got, "wf_middle_total")
	iZebra := strings.Index(got, "wf_zebra_total")
	if !(iAlpha < iMiddle && iMiddle < iZebra) {
		t.Errorf("families not name-sorted: alpha=%d middle=%d zebra=%d\n%s", iAlpha, iMiddle, iZebra, got)
	}
}

func TestCounterVecLabels(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounterVec("wf_requests_total", "Requests.", []string{"action", "policy"})

	c.Inc("ok", "default")
	c.Inc("ok", "default")
	c.Inc("blocked", "kids")

	if got := c.Value("ok", "default"); got != 2 {
		t.Errorf("Value(ok,default) = %d, want 2", got)
	}
	if got := c.Value("blocked", "kids"); got != 1 {
		t.Errorf("Value(blocked,kids) = %d, want 1", got)
	}
	if got := c.Value("nope", "nope"); got != 0 {
		t.Errorf("Value of unseen series = %d, want 0", got)
	}

	got := render(t, r)
	// Series are sorted by their joined key, so "blocked" precedes "ok".
	want := `# HELP wf_requests_total Requests.
# TYPE wf_requests_total counter
wf_requests_total{action="blocked",policy="kids"} 1
wf_requests_total{action="ok",policy="default"} 2
`
	if got != want {
		t.Errorf("exposition mismatch:\n got:\n%s\nwant:\n%s", got, want)
	}
}

// A wrong-arity call must be ignored rather than panicking or, worse,
// silently creating a series under a truncated key: a metrics bug should
// never be able to take down a filtering proxy.
func TestCounterVecIgnoresArityMismatch(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounterVec("wf_x_total", "x", []string{"a", "b"})

	c.Inc("only-one")
	c.Inc("one", "two", "three")

	if got := render(t, r); strings.Contains(got, "wf_x_total{") {
		t.Errorf("arity-mismatched calls created a series:\n%s", got)
	}
}

// Label values reach the exposition format from policy names, which are
// user-chosen filenames. Without escaping, a quote or backslash produces
// output no scraper can parse.
func TestLabelValueEscaping(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounterVec("wf_esc_total", "Escaping.", []string{"policy"})
	c.Inc(`we"ird\name` + "\n" + "second")

	got := render(t, r)
	want := `wf_esc_total{policy="we\"ird\\name\nsecond"} 1`
	if !strings.Contains(got, want) {
		t.Errorf("label not escaped:\n got:\n%s\nwant line:\n%s", got, want)
	}
}

func TestHelpEscaping(t *testing.T) {
	r := NewRegistry()
	// A quote is literal in HELP; a backslash and newline are not.
	r.NewCounter("wf_help_total", "A \"quoted\" help\nwith a break and a \\ backslash.")

	got := render(t, r)
	want := `# HELP wf_help_total A "quoted" help\nwith a break and a \\ backslash.`
	if !strings.Contains(got, want) {
		t.Errorf("help not escaped:\n got:\n%s\nwant line:\n%s", got, want)
	}
	// The HELP line must stay on one physical line.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "# HELP") && strings.Count(line, "\n") > 0 {
			t.Errorf("HELP line contains a raw newline: %q", line)
		}
	}
}

func TestHistogramCumulativeBuckets(t *testing.T) {
	r := NewRegistry()
	h := r.NewHistogramVec("wf_dur_seconds", "Durations.", []string{"kind"}, []float64{0.1, 1})

	h.Observe(0.05, "text") // <= 0.1, <= 1
	h.Observe(0.5, "text")  //         <= 1
	h.Observe(5, "text")    //                only +Inf

	got := render(t, r)
	for _, want := range []string{
		`wf_dur_seconds_bucket{kind="text",le="0.1"} 1`,
		`wf_dur_seconds_bucket{kind="text",le="1"} 2`,
		`wf_dur_seconds_bucket{kind="text",le="+Inf"} 3`,
		`wf_dur_seconds_count{kind="text"} 3`,
		`wf_dur_seconds_sum{kind="text"} 5.55`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if h.Count("text") != 3 {
		t.Errorf("Count = %d, want 3", h.Count("text"))
	}
}

// The +Inf bucket must always equal _count, which is what makes a histogram
// well-formed; getting this wrong makes rate() silently wrong rather than
// obviously broken.
func TestHistogramInfBucketEqualsCount(t *testing.T) {
	r := NewRegistry()
	h := r.NewHistogramVec("wf_h_seconds", "h", []string{"k"}, []float64{0.01})
	for i := 0; i < 7; i++ {
		h.Observe(float64(i), "a")
	}

	got := render(t, r)
	if !strings.Contains(got, `wf_h_seconds_bucket{k="a",le="+Inf"} 7`) {
		t.Errorf("+Inf bucket wrong:\n%s", got)
	}
	if !strings.Contains(got, `wf_h_seconds_count{k="a"} 7`) {
		t.Errorf("_count wrong:\n%s", got)
	}
}

func TestDuplicateRegistrationPanics(t *testing.T) {
	r := NewRegistry()
	r.NewCounter("wf_dup_total", "one")
	defer func() {
		if recover() == nil {
			t.Error("registering a duplicate name did not panic")
		}
	}()
	r.NewCounter("wf_dup_total", "two")
}

// Every metric type is written from many goroutines while being scraped.
// Run with -race; this is the test that justifies the atomics.
func TestConcurrentUpdatesAndScrape(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("wf_c_total", "c")
	g := r.NewGauge("wf_g", "g")
	cv := r.NewCounterVec("wf_cv_total", "cv", []string{"label"})
	h := r.NewHistogramVec("wf_h_seconds", "h", []string{"label"}, nil)

	const workers, iters = 8, 200
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				c.Inc()
				g.Inc()
				g.Dec()
				// Two distinct label values, so the lazy series-creation
				// path is exercised concurrently as well.
				cv.Inc([]string{"a", "b"}[i%2])
				h.Observe(float64(i)/1000, "a")
			}
		}(w)
	}
	// Scrape concurrently with the writers.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			var b strings.Builder
			_ = r.WriteText(&b)
		}
	}()
	wg.Wait()

	if got := c.Value(); got != workers*iters {
		t.Errorf("counter = %d, want %d", got, workers*iters)
	}
	if got := g.Value(); got != 0 {
		t.Errorf("gauge = %v, want 0 after balanced Inc/Dec", got)
	}
	if got := cv.Value("a") + cv.Value("b"); got != workers*iters {
		t.Errorf("counter vec total = %d, want %d", got, workers*iters)
	}
	if got := h.Count("a"); got != workers*iters {
		t.Errorf("histogram count = %d, want %d", got, workers*iters)
	}
}

// The default registry is what /metrics actually serves, so its output must
// parse as a valid exposition document: every sample line preceded by HELP
// and TYPE for its family, and no stray blank lines.
func TestDefaultRegistryIsWellFormed(t *testing.T) {
	got := render(t, Default)
	if !strings.Contains(got, "webfilter_build_info{") {
		t.Errorf("build info missing from default registry:\n%s", got)
	}
	if !strings.Contains(got, "webfilter_start_time_seconds ") {
		t.Errorf("start time missing from default registry:\n%s", got)
	}

	seenType := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		switch {
		case line == "":
			t.Error("blank line in exposition output")
		case strings.HasPrefix(line, "# TYPE "):
			seenType[strings.Fields(line)[2]] = true
		case strings.HasPrefix(line, "# HELP "):
		default:
			// A sample line: its family must already have had a TYPE line.
			family := line
			if i := strings.IndexAny(family, "{ "); i >= 0 {
				family = family[:i]
			}
			base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(family, "_bucket"), "_sum"), "_count")
			if !seenType[family] && !seenType[base] {
				t.Errorf("sample %q has no preceding # TYPE line", line)
			}
		}
	}
}
