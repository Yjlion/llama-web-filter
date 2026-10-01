// Package version holds build-time version information, set via -ldflags at release build time.
package version

var (
	// Version is the semantic version, overridden at build time with
	// -ldflags "-X github.com/yjlion/llama-web-filter/internal/version.Version=v1.2.3".
	Version = "dev"
	// Commit is the git commit hash, overridden at build time.
	Commit = "unknown"
	// BuildDate is the build timestamp, overridden at build time.
	BuildDate = "unknown"
)

// String returns a human-readable version string.
func String() string {
	return Version + " (commit " + Commit + ", built " + BuildDate + ")"
}
