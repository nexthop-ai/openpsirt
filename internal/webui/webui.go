// Package webui carries the built web interface into the binary.
//
// A package of its own so that the embed directive names a directory that is
// always present. //go:embed fails to compile when its target is missing, and
// the built output is not in the repository — so what is embedded is this
// package's own placeholder directory, which the frontend build fills.
package webui

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
)

//go:embed all:dist
var built embed.FS

// ErrNoInterface says no interface was built into this binary.
//
// An expected state rather than a fault: an API-only build is a thing
// somebody chooses, and it serves no page at all. Distinguished from a fault
// because the two used to be one answer — nil, written nowhere — so the whole
// interface disappearing and nobody having asked for one were indistinguishable
// to the caller and silent to everybody.
var ErrNoInterface = errors.New("no web interface was built into this binary")

// Files is the built interface.
//
// It answers ErrNoInterface where the frontend build never ran, and a wrapped
// error where the embedded directory cannot be read at all — which is a broken
// binary rather than a choice.
func Files() (fs.FS, error) {
	inner, err := fs.Sub(built, "dist")
	if err != nil {
		return nil, fmt.Errorf("read the interface embedded in this binary: %w", err)
	}
	// A build that never ran the frontend leaves only the placeholder, and
	// there is no page to serve.
	if _, err := fs.Stat(inner, "index.html"); err != nil {
		return nil, ErrNoInterface
	}
	return inner, nil
}
