// Package metrics is a dependency-free Prometheus metrics registry: atomic
// counters, gauges and fixed-bucket histograms, rendered in the text
// exposition format at /metrics by internal/mgmtapi.
//
// It is hand-rolled rather than built on prometheus/client_golang because
// this project keeps a deliberately short direct-dependency list and builds
// CGO-free for android/arm64 as well as the desktop targets; the client
// library would pull in protobuf, procfs and four more modules to emit the
// same handful of counters. The trade-off is that there are no Go runtime
// or process collectors here, and no native histograms - if those are ever
// wanted, swapping the registry for the real client is a contained change,
// because nothing outside this package knows how a sample is encoded.
//
// Everything a caller touches is safe for concurrent use. Metric instances
// are created once (at package init, via the Default registry) and then only
// incremented/observed, so the hot path never allocates or takes a lock
// except on the first use of a new label combination.
//
// IMPORTANT: these are in-process counters. Under standalone `webfilter
// mgmt` the proxy engine runs in a different process, so every engine-side
// counter a scrape sees there reads zero. A scrape target has to be a
// process that actually serves traffic (`run`, or `proxy` alongside its own
// mgmt server). See docs/metrics.md.
package metrics

import (
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// metricType is the Prometheus type reported in the # TYPE line.
type metricType string

const (
	typeCounter   metricType = "counter"
	typeGauge     metricType = "gauge"
	typeHistogram metricType = "histogram"
)

// collector is implemented by every metric family the registry can render.
type collector interface {
	name() string
	help() string
	typ() metricType
	// writeSamples appends this family's sample lines to b.
	writeSamples(b *strings.Builder)
}

// Registry holds a set of metric families and renders them on demand.
//
// Families are registered at construction time (package init) and never
// removed, so rendering only needs a read lock.
type Registry struct {
	mu         sync.RWMutex
	collectors []collector
	names      map[string]bool
}

// NewRegistry returns an empty registry. Most callers want Default.
func NewRegistry() *Registry {
	return &Registry{names: map[string]bool{}}
}

// register adds c, panicking on a duplicate name. Registration happens at
// init time, so a panic here is a build-time-ish programming error that
// surfaces on the first run rather than a runtime failure mode in
// production.
func (r *Registry) register(c collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.names[c.name()] {
		panic("metrics: duplicate metric registered: " + c.name())
	}
	r.names[c.name()] = true
	r.collectors = append(r.collectors, c)
}

// WriteText renders every registered family in the Prometheus text
// exposition format (version 0.0.4). Families are emitted in name order so
// the output is stable and diffable in tests.
func (r *Registry) WriteText(w io.Writer) error {
	r.mu.RLock()
	cs := make([]collector, len(r.collectors))
	copy(cs, r.collectors)
	r.mu.RUnlock()

	sort.Slice(cs, func(i, j int) bool { return cs[i].name() < cs[j].name() })

	var b strings.Builder
	for _, c := range cs {
		b.WriteString("# HELP ")
		b.WriteString(c.name())
		b.WriteByte(' ')
		b.WriteString(escapeHelp(c.help()))
		b.WriteByte('\n')
		b.WriteString("# TYPE ")
		b.WriteString(c.name())
		b.WriteByte(' ')
		b.WriteString(string(c.typ()))
		b.WriteByte('\n')
		c.writeSamples(&b)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// ---------------------------------------------------------------------------
// Counter / Gauge
// ---------------------------------------------------------------------------

// Counter is a monotonically increasing value with no labels.
type Counter struct {
	metricName string
	metricHelp string
	v          atomic.Uint64
}

// NewCounter registers and returns an unlabelled counter.
func (r *Registry) NewCounter(name, help string) *Counter {
	c := &Counter{metricName: name, metricHelp: help}
	r.register(c)
	return c
}

// Inc adds one.
func (c *Counter) Inc() { c.v.Add(1) }

// Add adds n (n must be >= 0; counters never decrease).
func (c *Counter) Add(n uint64) { c.v.Add(n) }

// Value returns the current count, for tests.
func (c *Counter) Value() uint64 { return c.v.Load() }

func (c *Counter) name() string    { return c.metricName }
func (c *Counter) help() string    { return c.metricHelp }
func (c *Counter) typ() metricType { return typeCounter }
func (c *Counter) writeSamples(b *strings.Builder) {
	b.WriteString(c.metricName)
	b.WriteByte(' ')
	b.WriteString(strconv.FormatUint(c.v.Load(), 10))
	b.WriteByte('\n')
}

// Gauge is a value that can go up and down. It stores a float64 in its IEEE
// bit pattern so updates stay atomic without a mutex.
type Gauge struct {
	metricName string
	metricHelp string
	bits       atomic.Uint64
}

// NewGauge registers and returns an unlabelled gauge.
func (r *Registry) NewGauge(name, help string) *Gauge {
	g := &Gauge{metricName: name, metricHelp: help}
	r.register(g)
	return g
}

// Set replaces the current value.
func (g *Gauge) Set(v float64) { g.bits.Store(math.Float64bits(v)) }

// Inc adds one.
func (g *Gauge) Inc() { g.Add(1) }

// Dec subtracts one.
func (g *Gauge) Dec() { g.Add(-1) }

// Add adds delta, retrying on a concurrent update.
func (g *Gauge) Add(delta float64) {
	for {
		old := g.bits.Load()
		next := math.Float64bits(math.Float64frombits(old) + delta)
		if g.bits.CompareAndSwap(old, next) {
			return
		}
	}
}

// Value returns the current value, for tests.
func (g *Gauge) Value() float64 { return math.Float64frombits(g.bits.Load()) }

func (g *Gauge) name() string    { return g.metricName }
func (g *Gauge) help() string    { return g.metricHelp }
func (g *Gauge) typ() metricType { return typeGauge }
func (g *Gauge) writeSamples(b *strings.Builder) {
	b.WriteString(g.metricName)
	b.WriteByte(' ')
	writeFloat(b, g.Value())
	b.WriteByte('\n')
}

// ---------------------------------------------------------------------------
// CounterVec
// ---------------------------------------------------------------------------

// CounterVec is a counter family partitioned by a fixed set of label names.
//
// The label names are declared once at registration so the cardinality of a
// family is visible at its declaration site. Keep label values bounded by
// configuration (actions, addon names, policy names) - never put a hostname,
// URL path, client IP or user agent in one, or a scrape turns into a
// per-request dump and the series count grows without limit.
type CounterVec struct {
	metricName string
	metricHelp string
	labels     []string

	mu     sync.RWMutex
	values map[string]*atomic.Uint64
}

// NewCounterVec registers and returns a labelled counter family.
func (r *Registry) NewCounterVec(name, help string, labels []string) *CounterVec {
	c := &CounterVec{
		metricName: name,
		metricHelp: help,
		labels:     labels,
		values:     map[string]*atomic.Uint64{},
	}
	r.register(c)
	return c
}

// Inc adds one to the series identified by values, which must have the same
// length and order as the label names given at registration. A mismatched
// call is ignored rather than panicking: a metric is never worth taking down
// a filtering proxy for.
func (c *CounterVec) Inc(values ...string) { c.Add(1, values...) }

// Add adds n to the series identified by values.
func (c *CounterVec) Add(n uint64, values ...string) {
	if len(values) != len(c.labels) {
		return
	}
	key := joinKey(values)

	c.mu.RLock()
	v, ok := c.values[key]
	c.mu.RUnlock()
	if ok {
		v.Add(n)
		return
	}

	c.mu.Lock()
	if v, ok = c.values[key]; !ok {
		v = &atomic.Uint64{}
		c.values[key] = v
	}
	c.mu.Unlock()
	v.Add(n)
}

// Value returns the count for one series, for tests.
func (c *CounterVec) Value(values ...string) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if v, ok := c.values[joinKey(values)]; ok {
		return v.Load()
	}
	return 0
}

func (c *CounterVec) name() string    { return c.metricName }
func (c *CounterVec) help() string    { return c.metricHelp }
func (c *CounterVec) typ() metricType { return typeCounter }

func (c *CounterVec) writeSamples(b *strings.Builder) {
	c.mu.RLock()
	keys := make([]string, 0, len(c.values))
	for k := range c.values {
		keys = append(keys, k)
	}
	samples := make(map[string]uint64, len(c.values))
	for k, v := range c.values {
		samples[k] = v.Load()
	}
	c.mu.RUnlock()

	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(c.metricName)
		writeLabels(b, c.labels, splitKey(k), "", "")
		b.WriteByte(' ')
		b.WriteString(strconv.FormatUint(samples[k], 10))
		b.WriteByte('\n')
	}
}

// ---------------------------------------------------------------------------
// Histogram
// ---------------------------------------------------------------------------

// DefaultLatencyBuckets covers sub-millisecond work through several seconds,
// which is the range both classifiers span: the Bayesian text scorer is
// microseconds, the MobileNetV2 image pass is tens to hundreds of
// milliseconds on a desktop CPU and can reach seconds on a phone.
var DefaultLatencyBuckets = []float64{
	0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

// HistogramVec is a histogram family partitioned by label names, with
// cumulative ("le") buckets, a sum and a count per series.
type HistogramVec struct {
	metricName string
	metricHelp string
	labels     []string
	buckets    []float64 // sorted upper bounds, +Inf implied

	mu     sync.RWMutex
	series map[string]*histSeries
}

type histSeries struct {
	counts []atomic.Uint64 // one per bucket, plus one for +Inf
	sum    atomic.Uint64   // float64 bits
	count  atomic.Uint64
}

// NewHistogramVec registers and returns a labelled histogram family. buckets
// must be sorted ascending; nil means DefaultLatencyBuckets.
func (r *Registry) NewHistogramVec(name, help string, labels []string, buckets []float64) *HistogramVec {
	if buckets == nil {
		buckets = DefaultLatencyBuckets
	}
	h := &HistogramVec{
		metricName: name,
		metricHelp: help,
		labels:     labels,
		buckets:    buckets,
		series:     map[string]*histSeries{},
	}
	r.register(h)
	return h
}

// Observe records one value (seconds, for latency) in the series identified
// by values.
func (h *HistogramVec) Observe(v float64, values ...string) {
	if len(values) != len(h.labels) {
		return
	}
	key := joinKey(values)

	h.mu.RLock()
	s, ok := h.series[key]
	h.mu.RUnlock()
	if !ok {
		h.mu.Lock()
		if s, ok = h.series[key]; !ok {
			s = &histSeries{counts: make([]atomic.Uint64, len(h.buckets)+1)}
			h.series[key] = s
		}
		h.mu.Unlock()
	}

	// Cumulative buckets: a value counts in its own bucket and every wider
	// one, which is what "le" means in the exposition format.
	for i, ub := range h.buckets {
		if v <= ub {
			s.counts[i].Add(1)
		}
	}
	s.counts[len(h.buckets)].Add(1) // +Inf
	s.count.Add(1)
	for {
		old := s.sum.Load()
		next := math.Float64bits(math.Float64frombits(old) + v)
		if s.sum.CompareAndSwap(old, next) {
			break
		}
	}
}

// Count returns the observation count for one series, for tests.
func (h *HistogramVec) Count(values ...string) uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if s, ok := h.series[joinKey(values)]; ok {
		return s.count.Load()
	}
	return 0
}

func (h *HistogramVec) name() string    { return h.metricName }
func (h *HistogramVec) help() string    { return h.metricHelp }
func (h *HistogramVec) typ() metricType { return typeHistogram }

func (h *HistogramVec) writeSamples(b *strings.Builder) {
	h.mu.RLock()
	keys := make([]string, 0, len(h.series))
	for k := range h.series {
		keys = append(keys, k)
	}
	series := make(map[string]*histSeries, len(h.series))
	for k, v := range h.series {
		series[k] = v
	}
	h.mu.RUnlock()

	sort.Strings(keys)
	for _, k := range keys {
		s := series[k]
		vals := splitKey(k)
		for i, ub := range h.buckets {
			b.WriteString(h.metricName)
			b.WriteString("_bucket")
			writeLabels(b, h.labels, vals, "le", formatBucket(ub))
			b.WriteByte(' ')
			b.WriteString(strconv.FormatUint(s.counts[i].Load(), 10))
			b.WriteByte('\n')
		}
		b.WriteString(h.metricName)
		b.WriteString("_bucket")
		writeLabels(b, h.labels, vals, "le", "+Inf")
		b.WriteByte(' ')
		b.WriteString(strconv.FormatUint(s.counts[len(h.buckets)].Load(), 10))
		b.WriteByte('\n')

		b.WriteString(h.metricName)
		b.WriteString("_sum")
		writeLabels(b, h.labels, vals, "", "")
		b.WriteByte(' ')
		writeFloat(b, math.Float64frombits(s.sum.Load()))
		b.WriteByte('\n')

		b.WriteString(h.metricName)
		b.WriteString("_count")
		writeLabels(b, h.labels, vals, "", "")
		b.WriteByte(' ')
		b.WriteString(strconv.FormatUint(s.count.Load(), 10))
		b.WriteByte('\n')
	}
}

// ---------------------------------------------------------------------------
// encoding helpers
// ---------------------------------------------------------------------------

// keySep separates label values in a map key. \x00 cannot appear in a label
// value that survives escapeLabel, so it cannot be forged to collide two
// different label sets into one series.
const keySep = "\x00"

func joinKey(values []string) string { return strings.Join(values, keySep) }
func splitKey(key string) []string   { return strings.Split(key, keySep) }

// writeLabels renders {a="1",b="2"}, optionally appending one extra label
// (used for a histogram's le). Emits nothing when there are no labels at all.
func writeLabels(b *strings.Builder, names, values []string, extraName, extraValue string) {
	if len(names) == 0 && extraName == "" {
		return
	}
	b.WriteByte('{')
	first := true
	for i, n := range names {
		if i >= len(values) {
			break
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.WriteString(n)
		b.WriteString(`="`)
		b.WriteString(escapeLabel(values[i]))
		b.WriteByte('"')
	}
	if extraName != "" {
		if !first {
			b.WriteByte(',')
		}
		b.WriteString(extraName)
		b.WriteString(`="`)
		b.WriteString(extraValue) // bucket bounds are generated, never user input
		b.WriteByte('"')
	}
	b.WriteByte('}')
}

// escapeLabel applies the exposition format's label-value escaping:
// backslash, double quote and line feed. Label values here can come from
// policy names, which are user-chosen filenames, so this is not optional.
func escapeLabel(v string) string {
	if !strings.ContainsAny(v, "\\\"\n") {
		return v
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}

// escapeHelp escapes a HELP line: backslash and line feed only (a double
// quote is literal in HELP).
func escapeHelp(v string) string {
	if !strings.ContainsAny(v, "\\\n") {
		return v
	}
	r := strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	return r.Replace(v)
}

// writeFloat renders a float the way the exposition format expects, with
// Inf/NaN spelled out rather than Go's "+Inf"-adjacent formatting drifting.
func writeFloat(b *strings.Builder, v float64) {
	switch {
	case math.IsNaN(v):
		b.WriteString("NaN")
	case math.IsInf(v, 1):
		b.WriteString("+Inf")
	case math.IsInf(v, -1):
		b.WriteString("-Inf")
	default:
		b.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
	}
}

// formatBucket renders a bucket upper bound. Prometheus compares these as
// strings when merging series across scrapes, so the formatting has to be
// stable - 'g' with -1 precision gives the shortest round-trippable form.
func formatBucket(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}
