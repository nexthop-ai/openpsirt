package httpapi

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// Interface serves the built web interface.
//
// Embedded into the binary by whoever builds it and handed in here, rather
// than embedded in this package: a build that has not run the frontend still
// has to compile and serve the API, and //go:embed of a missing directory is a
// compile error rather than an empty filesystem.
type Interface struct {
	// Files is the built output — index.html at its root. Nil serves nothing,
	// which is what a development build or an API-only deployment gets.
	Files fs.FS
}

// reserved reports whether a path belongs to this server rather than to the
// page, whether or not anything is currently routed there.
//
// A list rather than a rule, and deliberately including paths nothing serves
// today: the framework's documentation route is disabled by configuration, so
// it is unrouted — and "unrouted" is exactly what marks a path as the page's.
// Without this, turning that route back on would be shadowed by the interface,
// and the interface would have quietly claimed a name the server means to own.
func reserved(path string) bool {
	if path == "/v1" || strings.HasPrefix(path, "/v1/") {
		return true
	}
	switch path {
	case "/docs", "/openapi.json", "/openapi.yaml",
		"/openapi-3.0.json", "/openapi-3.0.yaml":
		return true
	}
	return strings.HasPrefix(path, "/schemas/")
}

// mountInterface serves the interface under everything the API does not claim.
//
// A single-page application owns its own routing, so a path this server does
// not recognize is not a 404 — it is a route the page knows and this process
// does not. Anything under /v1 is the API's and is left alone, so a mistyped
// endpoint still answers as an endpoint rather than as a page.
func mountInterface(router interface {
	NotFound(http.HandlerFunc)
}, ui Interface) {
	if ui.Files == nil {
		return
	}
	files := http.FileServer(http.FS(ui.Files))

	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		// The API answers for itself, including for paths it does not have.
		// Serving a page here would answer a bad endpoint with HTML, which a
		// client parsing JSON reports as a parse failure rather than as the
		// 404 it is.
		if reserved(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}

		// A real file is served as itself. Anything else is a route belonging
		// to the page, which is index.html — the page then reads the path and
		// decides what to draw.
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name != "" && name != "." {
			if f, err := ui.Files.Open(name); err == nil {
				_ = f.Close()
				files.ServeHTTP(w, r)
				return
			}
		}
		serveIndex(w, r, ui.Files)
	})
}

// serveIndex hands back the page itself.
//
// Never cached. The built assets beside it carry a content hash in their names
// and may be cached forever; index.html is the one file that names them, so a
// cached copy pins a browser to the previous deployment's assets — which are
// gone.
func serveIndex(w http.ResponseWriter, r *http.Request, files fs.FS) {
	page, err := fs.ReadFile(files, "index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(page)
}
