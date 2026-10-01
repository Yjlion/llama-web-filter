package mgmtapi

import (
	"bytes"
	"mime"
	"net/http"
	"path"
	"time"

	"github.com/yjlion/llama-web-filter/ui"
)

// staticHandler serves the embedded UI files directly via fs.ReadFile +
// http.ServeContent, deliberately NOT http.FileServer/http.FileServerFS:
// FileServer canonicalizes "/index.html" by redirecting it to "/", which
// creates an infinite redirect loop against the root-path rewrite below
// (and would also break the UI's own `location.href = 'index.html'`
// navigations, which the live Python original serves as a plain 200 - Go's
// redirect-index.html-to-slash behavior has no FastAPI/Starlette
// equivalent). ServeContent has no such special-casing.
//
// Verified empirically against the live Python original: it is a plain
// multi-page app where every internal link already carries an explicit
// ".html" suffix (e.g. href="policies.html") - no extension-less path
// resolution is needed. "/" serves index.html; any other unmatched path
// 404s with the same {"detail":"Not Found"} JSON body FastAPI returns.
func staticHandler() http.Handler {
	// Content-Type by extension needs to be pinned explicitly: Go's
	// mime.TypeByExtension falls back to the OS mime registry, which
	// differs between Windows and Linux and can return the legacy
	// "application/javascript" instead of "text/javascript" - observed on
	// the live Python server to be "text/javascript; charset=utf-8".
	mime.AddExtensionType(".js", "text/javascript; charset=utf-8")
	mime.AddExtensionType(".css", "text/css; charset=utf-8")
	mime.AddExtensionType(".html", "text/html; charset=utf-8")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "/" {
			p = "/index.html"
		}
		// embed.FS paths never have a leading slash.
		data, err := ui.Files.ReadFile(p[1:])
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "Not Found")
			return
		}
		if ct := mime.TypeByExtension(path.Ext(p)); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		http.ServeContent(w, r, p, time.Time{}, bytes.NewReader(data))
	})
}
