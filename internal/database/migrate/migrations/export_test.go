// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import "github.com/nexthop-ai/openpsirt/internal/database"

// StatementsV030 is v0.3.0's declaration of each table it changes, every
// statement of it, as it reads on one engine.
func StatementsV030(engine database.Engine) map[string][]string {
	t := typesFor(engine)
	return map[string][]string{
		"finding":     findingV030(t),
		"flaw_report": reportV030(t),
		"component":   componentV030(t),
	}
}

// StatementsV050 is v0.5.0's declaration of each table it creates or changes.
func StatementsV050(engine database.Engine) map[string][]string {
	t := typesFor(engine)
	merge := mergeV050(t)
	return map[string][]string{
		"admin_change":        trailV050(t),
		"graph_node":          graphNodeV050(t),
		"vulnerability_alias": aliasV050(t),
		"vulnerability":       vulnerabilityV050(t),
		"vulnerability_merge": merge[:2],
		"decision_superseded": merge[2:],
		"assessment":          assessmentV050(t),
		"notification":        notificationV050(t),
		"outbound":            outboundV050(t),
		"chat_preference":     {chatV050(t)[0]},
		"chat_delivery":       {chatV050(t)[1]},
		"suppression":         suppressionV050(t),
		"disclosure_movement": disclosureMovementV050(t),
		"saved_filter":        savedFilterV050(t),

		// What an advisory marks and what an agreement to one saw.
		"advisory_override":      advisoryV050(t)[:1],
		"advisory_agreed_status": advisoryV050(t)[1:],

		// The builds a claim was made on.
		"claim_build": claimBuildV050(t),
	}
}

// StatementsV060 is the untagged release's declaration of each table it
// creates or changes.
func StatementsV060(engine database.Engine) map[string][]string {
	obligation := obligationV060(typesFor(engine))
	groups := groupRoleV060(typesFor(engine))
	return map[string][]string{
		"obligation_window": obligation[:1],
		"told_outside":      obligation[1:3],
		"told_place":        obligation[3:4],
		"exploited_fix":     obligation[4:],
		"group_role":        groups[:1],
		"group_role_all":    groups[1:],
		"api_key":           credentialV060(typesFor(engine))[:2],
		"personal_token":    credentialV060(typesFor(engine))[2:],
	}
}

// Respelled is one kept findings-list query in v0.5.0's words.
var Respelled = respelled

// Unscoped is one kept findings-list query without its scope, as v0.5.0's
// upgrade leaves it.
var Unscoped = unscopedV050
