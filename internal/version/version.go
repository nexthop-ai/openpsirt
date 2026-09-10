// Package version reports what this build is.
package version

import "runtime"

// Set at link time. See the Makefile.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// Info describes a build.
type Info struct {
	Version string `json:"version" doc:"Release version, or \"dev\" for an unreleased build"`
	Commit  string `json:"commit" doc:"Git commit the binary was built from"`
	Date    string `json:"date" doc:"Build timestamp, RFC 3339"`
	Go      string `json:"go" doc:"Go toolchain that produced the binary"`
}

// Get returns this build's identity.
func Get() Info {
	return Info{Version: version, Commit: commit, Date: date, Go: runtime.Version()}
}
