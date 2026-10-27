// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package triageapi holds the operations over decisions and their occurrences: the
// review queue, proposing, approving, re-affirmation, comments, exploitation
// here and obligation windows.
package triageapi

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// Register adds the operations over decisions and their occurrences: the review queue,
// proposing, approving, re-affirming, comments, and what is exploited here.
func Register(api huma.API, in core.Deps) {
	registerScrutiny(api, in)
	registerReadiness(api, in)
	registerTriage(api, in)
	registerFindingDecision(api, in)
	registerAssessment(api, in)
	registerExploitedHere(api, in)
	registerObligations(api, in)
	registerFixes(api, in)
	registerTriageReading(api, in)
	registerComments(api, in)
	registerDecisions(api, in)
	registerReaffirmDecision(api, in)
	registerReaffirmMany(api, in)
	registerProposing(api, in)
	registerLeadDecisions(api, in)
	registerLeadFixed(api, in)
	registerLeadRules(api, in)
	registerOccurrenceDecisions(api, in)
	registerElsewhere(api, in)
	registerReachAcross(api, in)
	// The place a decision's work is happening, stored and never sent to.
	registerDecisionLink(api, in)
}
