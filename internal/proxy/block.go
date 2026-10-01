package proxy

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"
	"time"

	"github.com/yjlion/llama-web-filter/internal/logstore"
	"github.com/yjlion/llama-web-filter/internal/metrics"
)

//go:embed block_template.html
var blockTemplateSource string

var blockTemplate = template.Must(template.New("block").Parse(blockTemplateSource))

// rtlLangs are languages that render the block page right-to-left.
var rtlLangs = map[string]bool{"he": true, "yi": true}

type blockLabels struct {
	Title, Reason, Filter, Policy string
}

// blockI18N mirrors block_page.py's _BP_I18N: block-page chrome labels per
// UI language. The dynamic reason/component text is produced by the
// addons themselves (English); only these static labels are localized.
var blockI18N = map[string]blockLabels{
	"en": {Title: "Access Blocked", Reason: "Reason:", Filter: "Filter:", Policy: "Policy:"},
	"he": {Title: "הגישה נחסמה", Reason: "סיבה:", Filter: "מסנן:", Policy: "מדיניות:"},
	"yi": {Title: "צוטריט געשפּאַרט", Reason: "סיבה:", Filter: "פֿילטער:", Policy: "פּאָליסי:"},
	"es": {Title: "Acceso bloqueado", Reason: "Motivo:", Filter: "Filtro:", Policy: "Política:"},
	"fr": {Title: "Accès bloqué", Reason: "Motif :", Filter: "Filtre :", Policy: "Politique :"},
	"de": {Title: "Zugriff blockiert", Reason: "Grund:", Filter: "Filter:", Policy: "Richtlinie:"},
	"zh": {Title: "访问已被拦截", Reason: "原因：", Filter: "过滤器：", Policy: "策略："},
}

func labelsFor(lang string) blockLabels {
	if l, ok := blockI18N[lang]; ok {
		return l
	}
	return blockI18N["en"]
}

// LogBlock records a block event without necessarily replacing the
// response body (used by components like youtube_filter that mutate JSON
// in place rather than returning the HTML block page). Mirrors
// block_page.py's log_block: marks fc.WFAction/WFComponent and inserts a
// blocks-table row.
func (fc *FlowContext) LogBlock(reason, component string) {
	fc.WFAction = "blocked"
	fc.WFComponent = component
	metrics.Blocks.Inc(component)

	policyName := "unknown"
	if fc.Policy != nil {
		policyName = fc.Policy.Name
	}
	_ = fc.Runtime.Logs.LogBlock(logstore.BlockEntry{
		TS:        time.Now().Unix(),
		Domain:    fc.Request.URL.Hostname(),
		URL:       fc.Request.URL.String(),
		Reason:    reason,
		Component: component,
		Policy:    policyName,
		ClientIP:  fc.ClientIP,
	})
}

// Block renders the HTML block page and sets it as fc's response,
// mirroring block_page.py's make_block_response (which also calls
// log_block internally).
func (fc *FlowContext) Block(reason, component string) {
	fc.LogBlock(reason, component)

	policyName := "unknown"
	customMessage := ""
	if fc.Policy != nil {
		policyName = fc.Policy.Name
		customMessage = fc.Policy.BlockPage.Message
	}

	lang := fc.Runtime.Settings().UILanguage
	if _, ok := blockI18N[lang]; !ok {
		lang = "en"
	}
	dir := "ltr"
	if rtlLangs[lang] {
		dir = "rtl"
	}

	data := struct {
		Domain        string
		Reason        string
		Component     string
		PolicyName    string
		CustomMessage string
		Lang          string
		Dir           string
		Labels        blockLabels
	}{
		Domain:        fc.Request.URL.Hostname(),
		Reason:        reason,
		Component:     component,
		PolicyName:    policyName,
		CustomMessage: customMessage,
		Lang:          lang,
		Dir:           dir,
		Labels:        labelsFor(lang),
	}

	var buf bytes.Buffer
	if err := blockTemplate.Execute(&buf, data); err != nil {
		// Should never happen (template is embedded/validated at init) -
		// fail safe with a minimal plain-text block notice.
		buf.Reset()
		buf.WriteString("Access Blocked: " + reason)
	}

	fc.Response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
	}
	fc.ResponseBody = buf.Bytes()
}
