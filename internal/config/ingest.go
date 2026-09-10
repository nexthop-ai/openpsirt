package config

import "github.com/nexthop-ai/openpsirt/internal/sbom"

// Limits is what a scan file is read within.
//
// Each bound left unset here stays at the reader's own default rather than
// becoming zero, which is what "all of them configurable" has to mean for a
// deployment that wants one of them changed. The whole surface existed with no
// way to reach it: the process passed an empty set and the reader filled every
// field from its defaults, so a deployment could not lower any of them.
func (c Config) Limits() sbom.Limits {
	return sbom.Limits{
		MaxBytes:      int64(c.IngestMaxBytes),
		MaxComponents: c.IngestMaxComponents,
		MaxEdges:      c.IngestMaxEdges,
		MaxStatements: c.IngestMaxStatements,
		MaxDepth:      c.IngestMaxDepth,
	}
}
