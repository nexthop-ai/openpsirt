package config

import "github.com/nexthop-ai/openpsirt/internal/sbom"

// Limits is what a scan file is read within.
//
// Each bound left unset here stays at the reader's own default rather than
// becoming zero, which is what "all of them configurable" has to mean for a
// deployment that wants one of them changed. Passing an empty set instead
// leaves the reader filling every field from its defaults, and the whole
// surface unreachable: nothing a deployment sets can lower any of them.
func (c Config) Limits() sbom.Limits {
	return sbom.Limits{
		MaxBytes:      int64(c.IngestMaxBytes),
		MaxComponents: c.IngestMaxComponents,
		MaxEdges:      c.IngestMaxEdges,
		MaxFiles:      c.IngestMaxFiles,
		MaxStatements: c.IngestMaxStatements,
		MaxDepth:      c.IngestMaxDepth,
		MaxDocuments:  c.IngestMaxDocuments,
	}
}
