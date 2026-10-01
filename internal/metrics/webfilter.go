package metrics

import (
	"time"

	"github.com/yjlion/llama-web-filter/internal/version"
)

// Default is the process-wide registry every producer writes into.
//
// A package-level registry rather than one threaded through BuildProxyEngine:
// the producers (internal/proxy and its addons) and the consumer
// (internal/mgmtapi) share no wiring today, and plumbing a registry into
// every addon struct would be a large mechanical change whose only benefit -
// multiple independent registries - nothing here wants. The cost is that
// tests observing counters must account for other tests' increments, which
// the helpers below (Value/Count) make easy enough by diffing.
var Default = NewRegistry()

// The metric set is deliberately small and its label values are all bounded
// by configuration. Nothing here is labelled by hostname, URL path, client
// IP or user agent: those are per-request values, and a counter labelled
// with one stops being a counter and becomes an unbounded log.
var (
	// Requests counts every request the pipeline completed, labelled with
	// the final action (ok/modified/blocked), the addon that set it, and the
	// policy that applied. Recorded by the RequestLogger addon, which runs
	// last and so observes the final decision exactly once.
	Requests = Default.NewCounterVec(
		"webfilter_requests_total",
		"Requests processed by the filtering pipeline, by final action, deciding component and policy.",
		[]string{"action", "component", "policy"},
	)

	// Blocks counts block decisions by the component that made them. This is
	// not simply Requests{action="blocked"}: the connection-level gate
	// (hostgate) and the SOCKS5 UDP relay refuse traffic before any
	// FlowContext exists, so those blocks are counted here and nowhere else.
	Blocks = Default.NewCounterVec(
		"webfilter_blocks_total",
		"Block decisions by the component that made them, including connection-level refusals that never reach the request pipeline.",
		[]string{"component"},
	)

	// ClassifierDuration measures wall time inside an NSFW classifier.
	ClassifierDuration = Default.NewHistogramVec(
		"webfilter_classifier_duration_seconds",
		"Time spent scoring content in an NSFW classifier.",
		[]string{"classifier"},
		nil,
	)

	// ClassifierResults counts classifier outcomes. "error" means the
	// content could not be scored at all (an undecodable image, a corrupt
	// model); it is worth alerting on, because unscoreable content is passed
	// through rather than blocked.
	ClassifierResults = Default.NewCounterVec(
		"webfilter_classifier_results_total",
		"Classifier outcomes: nsfw (over threshold), clean (under), or error (could not score, content passed through).",
		[]string{"classifier", "result"},
	)

	// LLMRequests counts calls to the edge model by kind (image/text/host/
	// compile) and outcome (ok/error/timeout/unavailable).
	LLMRequests = Default.NewCounterVec(
		"webfilter_llm_requests_total",
		"Edge-LLM classification calls, by kind and outcome.",
		[]string{"kind", "result"},
	)

	// LLMDuration measures wall time of one model call, by kind.
	LLMDuration = Default.NewHistogramVec(
		"webfilter_llm_request_duration_seconds",
		"Wall time of one edge-LLM call, by kind.",
		[]string{"kind"},
		nil,
	)

	// UpstreamErrors counts failed upstream fetches (DNS failure, refused
	// connection, TLS failure, timeout). A rising rate here is the proxy
	// failing to reach the internet, not the proxy filtering anything.
	UpstreamErrors = Default.NewCounter(
		"webfilter_upstream_errors_total",
		"Upstream fetches that failed before a response was received.",
	)

	// Connections counts accepted client connections by listener mode
	// (regular/socks5/socks4/transparent/icap).
	Connections = Default.NewCounterVec(
		"webfilter_connections_total",
		"Client connections accepted, by listener mode.",
		[]string{"mode"},
	)

	// ConnectionsActive tracks connections currently being served. It is a
	// gauge rather than a derived rate because a stuck tunnel shows up here
	// and nowhere else.
	ConnectionsActive = Default.NewGauge(
		"webfilter_connections_active",
		"Client connections currently being served.",
	)

	// BuildInfo is the conventional always-1 gauge carrying build metadata
	// in its labels, so a dashboard can group by version without a separate
	// data source.
	BuildInfo = Default.NewCounterVec(
		"webfilter_build_info",
		"Build metadata. Always 1; the version and commit are in the labels.",
		[]string{"version", "commit"},
	)

	// StartTime is the process start as a Unix timestamp, which is how
	// Prometheus expects uptime to be exposed (uptime is then
	// `time() - webfilter_start_time_seconds`, correct across scrapes and
	// restarts in a way a self-reported duration is not).
	StartTime = Default.NewGauge(
		"webfilter_start_time_seconds",
		"Process start time as a Unix timestamp.",
	)
)

func init() {
	BuildInfo.Inc(version.Version, version.Commit)
	StartTime.Set(float64(time.Now().Unix()))
}

// ObserveClassifier records one classifier run: its duration and its
// outcome. Kept here rather than inlined at the two call sites so the
// duration and the result can never be recorded with disagreeing labels.
func ObserveClassifier(classifier string, started time.Time, result string) {
	ClassifierDuration.Observe(time.Since(started).Seconds(), classifier)
	ClassifierResults.Inc(classifier, result)
}

// Classifier result label values.
const (
	ResultNSFW  = "nsfw"
	ResultClean = "clean"
	ResultError = "error"
)
