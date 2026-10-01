package models

import (
	"encoding/json"
	"path/filepath"
)

// GlobalSettings mirrors config/settings.json (shared/models.py's
// GlobalSettings). WireGuard listen mode is intentionally out of scope for
// this port (see project plan); proxy_listen parsing still tolerates a
// "wireguard@" prefix without erroring so an old settings.json with a
// leftover wireguard entry doesn't fail to load - that entry is simply
// skipped when starting listeners.
type GlobalSettings struct {
	ProxyListen []string `json:"proxy_listen"`
	MgmtHost    string   `json:"mgmt_host"`
	MgmtPort    int      `json:"mgmt_port"`

	// MgmtTLS serves the management UI and API over HTTPS instead of plain
	// HTTP. Defaults off. The certificate comes from MgmtCertFile/MgmtKeyFile
	// when both are set, and is otherwise minted on demand by the runtime CA
	// - the same issuer the proxy uses for TLS-wrapped listeners.
	//
	// The CA-minted case has a bootstrapping consequence worth knowing:
	// /api/ca-cert is then served over HTTPS signed by the very CA the client
	// has not installed yet, so the first fetch shows a certificate warning,
	// and WPAD clients will not fetch /proxy.pac from an untrusted endpoint.
	// Install the CA out of band (certs/ca.crt) or point Mgmt{Cert,Key}File
	// at a publicly trusted certificate.
	MgmtTLS      bool   `json:"mgmt_tls"`
	MgmtCertFile string `json:"mgmt_cert_file"`
	MgmtKeyFile  string `json:"mgmt_key_file"`

	CertDir       string `json:"cert_dir"`
	PoliciesDir   string `json:"policies_dir"`
	CategoriesDir string `json:"categories_dir"`
	UILanguage    string `json:"ui_language"`
	LogsDir       string `json:"logs_dir"`

	LogBlocks        bool `json:"log_blocks"`
	LogRequests      bool `json:"log_requests"`
	LogRetentionDays int  `json:"log_retention_days"`

	DefaultPolicy *string `json:"default_policy"`

	AuthEnabled  bool   `json:"auth_enabled"`
	PasswordHash string `json:"password_hash"`
	SecretKey    string `json:"secret_key"`

	PacProxyHost   string   `json:"pac_proxy_host"`
	PacDirectHosts []string `json:"pac_direct_hosts"`
	PacDirectIPs   []string `json:"pac_direct_ips"`

	MgmtHostname   string `json:"mgmt_hostname"`
	MgmtHostnameIP string `json:"mgmt_hostname_ip"`

	UpstreamProxy string `json:"upstream_proxy"`
	UpstreamAuth  string `json:"upstream_auth"`

	ProxyAuthEnabled      bool   `json:"proxy_auth_enabled"`
	ProxyAuthUsername     string `json:"proxy_auth_username"`
	ProxyAuthPasswordHash string `json:"proxy_auth_password_hash"`

	// MetricsEnabled exposes GET /metrics on the management server in the
	// Prometheus text exposition format. Defaults on: the endpoint carries
	// only aggregate counters (no hostnames, paths or client addresses) and
	// sits behind the same auth as the rest of the management API.
	MetricsEnabled bool `json:"metrics_enabled"`

	// MetricsToken, when set, additionally accepts
	// `Authorization: Bearer <token>` on /metrics, because a Prometheus
	// scraper cannot log in and carry a session cookie. Deliberately NOT
	// treated as a secret by settingsvc: it has to be readable to be copied
	// into a scrape config, and it grants read access to counters only -
	// never to the UI or any mutation.
	MetricsToken string `json:"metrics_token"`

	Icap IcapConfig `json:"icap"`

	// LLM configures the local edge model runtime; see LLMConfig.
	LLM LLMConfig `json:"llm"`

	// OuiPath is a Go-port-only optional field (documented deviation): path
	// to an optional IEEE OUI vendor lookup table override. When empty, the
	// app uses the embedded lookup table; `webfilter oui update` can still
	// refresh an override at internal/neighbors.DefaultOuiPath
	// ("./data/oui.txt"). The Python original hardcodes shared/data/oui.txt
	// instead of making it configurable; round-trips harmlessly through it
	// since unrecognized settings.json fields aren't validated against there.
	OuiPath string `json:"oui_path,omitempty"`

	// TextClassifierModelPath is deprecated and ignored. It remains only so
	// older settings.json files round-trip without losing an unknown field;
	// the text classifier now uses an embedded pure-Go Bayesian scorer.
	TextClassifierModelPath string `json:"text_classifier_model_path,omitempty"`

	// DisableTray is a Go-port-only, Windows-only field: on Windows, `webfilter
	// run` launched interactively (not dispatched to us by the Service
	// Control Manager) always has a desktop session available, so it shows
	// the system tray icon by default. Set this to opt out and get a plain
	// foreground run instead - matching Linux/macOS, which never auto-show
	// it. Has no effect outside `webfilter run` on Windows.
	DisableTray bool `json:"disable_tray"`
}

// IcapConfig tunes the ICAP adaptation service (RFC 3507), which lets an
// existing proxy - Squid, typically - hand its requests and responses to this
// filter instead of being replaced by it. The same policies, category lists,
// SafeSearch rewriting and classifiers apply either way.
//
// There is deliberately no "enabled" field and no listen address here: an
// "icap@host:port" (or "icaps@host:port") entry in proxy_listen is what turns
// the service on, exactly like every other listener mode. These are only the
// knobs that have no sensible per-listener meaning.
type IcapConfig struct {
	// PreviewSize is how many leading body bytes the service asks for before
	// deciding whether it wants the rest. A preview is what makes it cheap to
	// wave through a video or an installer without streaming it through the
	// filter first.
	PreviewSize int `json:"preview_size"`

	// MaxBodyBytes caps how much of one body is buffered for inspection.
	// Anything larger passes unfiltered rather than being held in memory -
	// the classifiers cannot say anything useful about a partial file, and an
	// ICAP server that buffers whole downloads is a memory bomb.
	MaxBodyBytes int `json:"max_body_bytes"`

	// NormalizeAcceptEncoding rewrites the client's Accept-Encoding to gzip
	// on the way out, so response bodies come back in a coding this filter
	// can actually decode. Without it a browser advertising br/zstd gets
	// bodies no content-inspecting addon can read, and they pass unfiltered.
	// The engine's own MITM path does the same thing for the same reason.
	NormalizeAcceptEncoding bool `json:"normalize_accept_encoding"`

	// TrustClientIPHeader makes the service believe the ICAP client's
	// X-Client-IP header. That header is the *only* way the end user's
	// address survives the hop through Squid, and without it every client
	// collapses into one and per-client policy tiers stop working. Turn it
	// off only when the ICAP port is reachable by something you do not trust
	// to tell the truth about its users.
	TrustClientIPHeader bool `json:"trust_client_ip_header"`
}

// NewIcapConfig returns the documented ICAP defaults.
func NewIcapConfig() IcapConfig {
	return IcapConfig{
		PreviewSize:             4096,
		MaxBodyBytes:            8 << 20,
		NormalizeAcceptEncoding: true,
		TrustClientIPHeader:     true,
	}
}

type icapConfigAlias IcapConfig

func (c *IcapConfig) UnmarshalJSON(data []byte) error {
	*c = NewIcapConfig()
	if err := json.Unmarshal(data, (*icapConfigAlias)(c)); err != nil {
		return err
	}
	if c.PreviewSize < 0 {
		c.PreviewSize = 0
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 8 << 20
	}
	return nil
}

// NewGlobalSettings returns GlobalSettings with every field at its
// documented Python default.
func NewGlobalSettings() GlobalSettings {
	return GlobalSettings{
		ProxyListen:      []string{"0.0.0.0:8080", "socks5@127.0.0.1:1080"},
		MgmtHost:         "0.0.0.0",
		MgmtPort:         8000,
		CertDir:          "./certs",
		PoliciesDir:      "./policies",
		CategoriesDir:    "./categories",
		UILanguage:       "en",
		LogsDir:          "./logs",
		LogBlocks:        true,
		LogRequests:      true,
		LogRetentionDays: 30,
		MetricsEnabled:   true,
		PacDirectHosts:   []string{},
		PacDirectIPs:     []string{},
		MgmtHostname:     "web.filter",
		Icap:             NewIcapConfig(),
		LLM:              NewLLMConfig(),
	}
}

type globalSettingsAlias GlobalSettings

func (s *GlobalSettings) UnmarshalJSON(data []byte) error {
	*s = NewGlobalSettings()
	if err := json.Unmarshal(data, (*globalSettingsAlias)(s)); err != nil {
		return err
	}
	s.migrateLegacy(data)
	if len(s.ProxyListen) == 0 {
		s.ProxyListen = []string{"0.0.0.0:8080", "socks5@127.0.0.1:1080"}
	} else {
		cleaned := make([]string, 0, len(s.ProxyListen))
		for _, v := range s.ProxyListen {
			if t := trimSpace(v); t != "" {
				cleaned = append(cleaned, t)
			}
		}
		if len(cleaned) == 0 {
			cleaned = []string{"0.0.0.0:8080", "socks5@127.0.0.1:1080"}
		}
		s.ProxyListen = cleaned
	}
	return nil
}

func cleanStringSlice(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if t := trimSpace(v); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// legacySettingsFields captures the pre-proxy_listen flat schema
// (proxy_port + listen_host) and the renamed blocks_log_path field, so an
// old settings.json (from before these fields existed) still loads.
type legacySettingsFields struct {
	ProxyPort     *int    `json:"proxy_port"`
	ListenHost    *string `json:"listen_host"`
	BlocksLogPath *string `json:"blocks_log_path"`
}

func (s *GlobalSettings) migrateLegacy(data []byte) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil {
		return
	}
	var legacy legacySettingsFields
	_ = json.Unmarshal(data, &legacy)

	if _, hasProxyListen := raw["proxy_listen"]; !hasProxyListen && legacy.ProxyPort != nil {
		host := "0.0.0.0"
		if legacy.ListenHost != nil {
			host = *legacy.ListenHost
		}
		s.ProxyListen = []string{host + ":" + itoa(*legacy.ProxyPort)}
	}
	if _, hasMgmtHost := raw["mgmt_host"]; !hasMgmtHost && legacy.ListenHost != nil {
		s.MgmtHost = *legacy.ListenHost
	}
	if _, hasLogsDir := raw["logs_dir"]; !hasLogsDir && legacy.BlocksLogPath != nil {
		s.LogsDir = filepath.Dir(*legacy.BlocksLogPath)
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// DBPath returns the SQLite log database path derived from LogsDir.
func (s GlobalSettings) DBPath() string {
	return filepath.Join(s.LogsDir, "webfilter.db")
}

// PrimaryProxyPort extracts the first proxy_listen port whose mode is a
// plaintext "regular" or "socks5" listener (the two modes that bind a TCP
// port a client connects a browser/OS proxy setting to, and which the
// plaintext-assuming tun2socks target logic can dial). TLS-wrapped variants
// are skipped. Returns 8080 if none found.
func (s GlobalSettings) PrimaryProxyPort() int {
	for _, entry := range s.ProxyListen {
		spec := ParseListenSpec(entry)
		if !spec.TLS && (spec.Mode == "regular" || spec.Mode == "socks5") && spec.Port != 0 {
			return spec.Port
		}
	}
	return 8080
}

// PrimaryRegularProxyPort extracts the first proxy_listen port whose mode
// is a plaintext "regular" listener — an HTTP proxy a browser or PAC file
// can point at (PAC's PROXY directive cannot name a SOCKS listener, nor a
// TLS-wrapped proxy). Returns 8080 if none found, matching the port
// EnsureLocalHTTPProxyListener injects.
func (s GlobalSettings) PrimaryRegularProxyPort() int {
	for _, entry := range s.ProxyListen {
		spec := ParseListenSpec(entry)
		if spec.Mode == "regular" && !spec.TLS && spec.Port != 0 {
			return spec.Port
		}
	}
	return 8080
}

func (s GlobalSettings) PrimarySocks5Port() int {
	for _, entry := range s.ProxyListen {
		spec := ParseListenSpec(entry)
		if spec.Mode == "socks5" && !spec.TLS && spec.Port != 0 {
			return spec.Port
		}
	}
	return 0
}
