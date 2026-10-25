// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"github.com/nexthop-ai/openpsirt/internal/sarif"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

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

// AnalysisLimits is what an analyzer's results are read within, with each
// bound left unset at the reader's own default.
func (c Config) AnalysisLimits() sarif.Limits {
	return sarif.Limits{
		MaxBytes:      int64(c.AnalysisMaxBytes),
		MaxDepth:      c.AnalysisMaxDepth,
		MaxRuns:       c.AnalysisMaxRuns,
		MaxResults:    c.AnalysisMaxResults,
		MaxRules:      c.AnalysisMaxRules,
		MaxLocations:  c.AnalysisMaxLocations,
		MaxSteps:      c.AnalysisMaxSteps,
		MaxModules:    c.AnalysisMaxModules,
		MaxBases:      c.AnalysisMaxBases,
		MaxChain:      c.AnalysisMaxChain,
		MaxProperties: c.AnalysisMaxProperties,
		MaxText:       c.AnalysisMaxText,
		MaxHeld:       c.AnalysisMaxHeld,
	}.OrDefault()
}

// AnalysisDocuments is how many documents one analyzer upload may carry.
func (c Config) AnalysisDocuments() int {
	if c.AnalysisMaxDocuments > 0 {
		return c.AnalysisMaxDocuments
	}
	return sarif.DefaultDocuments
}
