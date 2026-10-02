package addons

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
)

// ContentClassifier is the backend the text and image classifier addons
// ask for verdicts. In llama-web-filter it is the verdict service in front
// of the edge LLM (internal/classify/verdict); tests use stubs. Every call
// carries a wait budget: the backend answers from its cache instantly, or
// waits on the model for at most that long and reports TimedOut, in which
// case the addon applies the policy's on_timeout action.
type ContentClassifier interface {
	ClassifyText(ctx context.Context, req TextRequest) Verdict
	ClassifyImage(ctx context.Context, req ImageRequest) Verdict
	// ClassifyHost says whether a hostname serves ads/trackers; Adult is
	// overloaded to mean "block it".
	ClassifyHost(ctx context.Context, req HostRequest) Verdict
}

// HostRequest is a hostname the filter lists do not know.
type HostRequest struct {
	Host        string
	SamplePaths []string
	Budget      time.Duration
}

// TextRequest is a page's extracted text.
type TextRequest struct {
	URL    string
	Title  string
	Text   string
	Budget time.Duration
}

// ImageRequest is one encoded image.
type ImageRequest struct {
	URL    string
	Data   []byte
	Budget time.Duration
}

// Verdict is a classifier answer.
type Verdict struct {
	// Known is true when a real decision exists; Score/Adult are then
	// meaningful. When false, exactly one of TimedOut or Unavailable is set.
	Known       bool
	Score       float64
	Adult       bool
	Source      string
	Detail      string
	TimedOut    bool
	Unavailable bool
}

// ImagePrefetcher scores a page's images ahead of the browser's requests.
// Optional; nil disables speculative pre-scoring.
type ImagePrefetcher interface {
	Prefetch(page *url.URL, srcs []string, limit int, headers http.Header)
}

// budgetFor resolves the wait budget for a classifier: the policy's own
// budget_ms when set, else the global llm.budget value for the kind.
func budgetFor(fc *proxy.FlowContext, policyMs int, kind string) time.Duration {
	if policyMs > 0 {
		return time.Duration(policyMs) * time.Millisecond
	}
	var ms int
	if fc.Runtime != nil {
		b := fc.Runtime.Settings().LLM.Budget
		switch kind {
		case "image":
			ms = b.ImageMs
		case "text":
			ms = b.TextMs
		case "host":
			ms = b.HostMs
		case "category":
			ms = b.CategoryMs
		}
	}
	if ms <= 0 {
		d := models.NewLLMConfig().Budget
		switch kind {
		case "image":
			ms = d.ImageMs
		case "text":
			ms = d.TextMs
		case "category":
			ms = d.CategoryMs
		default:
			ms = d.HostMs
		}
	}
	return time.Duration(ms) * time.Millisecond
}
