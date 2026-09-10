// Package webui carries the built web interface into the binary.
//
// A package of its own so that the embed directive names a directory that is
// always present. //go:embed fails to compile when its target is missing, and
// the built output is not in the repository — so what is embedded is this
// package's own placeholder directory, which the frontend build fills.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var built embed.FS

// Files is the built interface, or nil where nothing was built into it.
//
// Nil rather than an empty filesystem, because the two mean different things
// to whatever serves this: an API-only binary should serve no page at all,
// where an empty directory would answer every path with a 404 that looks like
// a broken deployment.
func Files() fs.FS {
	inner, err := fs.Sub(built, "dist")
	if err != nil {
		return nil
	}
	// A build that never ran the frontend leaves only the placeholder, and
	// there is no page to serve.
	if _, err := fs.Stat(inner, "index.html"); err != nil {
		return nil
	}
	return inner
}
