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
	}
}

// Respelled is one kept findings-list query in v0.5.0's words.
var Respelled = respelled

// Unscoped is one kept findings-list query without its scope, as v0.5.0's
// upgrade leaves it.
var Unscoped = unscopedV050
