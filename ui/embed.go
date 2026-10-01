// Package ui embeds the management web UI (Tailwind + Alpine.js, copied
// verbatim from the Python original's management/ui/*) into the Go binary.
// These files are reused as-is per the project plan - the Go management
// API is built to match their expected endpoint paths/JSON shapes exactly,
// rather than the UI being modified to fit the backend.
package ui

import "embed"

//go:embed *.html *.js *.css
var Files embed.FS
