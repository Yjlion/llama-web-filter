package addons

import (
	"time"

	"github.com/yjlion/llama-web-filter/internal/logstore"
	"github.com/yjlion/llama-web-filter/internal/metrics"
	"github.com/yjlion/llama-web-filter/internal/proxy"
)

// RequestLogger logs every request to the rolling request log. Registered
// last so it observes the final action set by upstream filters
// (blocked/modified/ok), ported from proxy/addons/request_logger.py.
type RequestLogger struct{}

func (RequestLogger) Name() string { return "request_logger" }

func (RequestLogger) HandleResponse(fc *proxy.FlowContext) {
	status := 0
	if fc.Response != nil {
		status = fc.Response.StatusCode
	}
	record(fc, status)
}

func (RequestLogger) HandleError(fc *proxy.FlowContext) {
	// Connection/upstream errors never reach the response hook.
	if !fc.WFLogged {
		record(fc, 0)
	}
}

func record(fc *proxy.FlowContext, status int) {
	fc.WFLogged = true
	action := fc.WFAction
	if action == "" {
		action = "ok"
	}
	policyName := ""
	if fc.Policy != nil {
		policyName = fc.Policy.Name
	}
	path := fc.Request.URL.Path
	if len(path) > 200 {
		path = path[:200]
	}
	// This addon runs last in the pipeline, so it observes the final action
	// exactly once per request - the one place a request counter can live
	// without double-counting or missing modified/blocked outcomes. Only
	// config-bounded values are used as labels; host, path, client IP and
	// user agent are deliberately left out of the metric.
	metrics.Requests.Inc(action, fc.WFComponent, policyName)
	_ = fc.Runtime.Logs.LogRequest(logstore.RequestEntry{
		TS:        time.Now().Unix(),
		Method:    fc.Request.Method,
		Host:      fc.Request.URL.Hostname(),
		Path:      path,
		Status:    status,
		Action:    action,
		Component: fc.WFComponent,
		Policy:    policyName,
		ClientIP:  fc.ClientIP,
		UserAgent: fc.Request.Header.Get("User-Agent"),
	})
}
