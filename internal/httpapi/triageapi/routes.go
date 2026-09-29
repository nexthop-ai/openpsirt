// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package triageapi holds the operations over claims and decisions: the
// review queue, proposing, approving, re-affirmation, comments, exploitation
// here and obligation windows.
package triageapi

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// Register adds the operations over claims and decisions: the review queue,
// proposing, approving, re-affirming, comments, and what is exploited here.
func Register(api huma.API, in core.Deps) {
	registerScrutiny(api, in)
	registerReadiness(api, in)
	registerTriage(api, in)
	registerFindingDecision(api, in)
	registerAssessment(api, in)
	registerExploitedHere(api, in)
	registerObligations(api, in)
	registerTriageReading(api, in)
	registerComments(api, in)
	registerClaims(api, in)
	registerReaffirmClaim(api, in)
	registerReaffirmMany(api, in)
	registerProposing(api, in)
	registerPlaceDecisions(api, in)
	registerElsewhere(api, in)
	registerReachAcross(api, in)
	// The place a claim's work is happening, stored and never sent to.
	registerClaimLink(api, in)
}
