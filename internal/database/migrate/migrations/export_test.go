// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import "github.com/nexthop-ai/openpsirt/internal/database"

// StatementsV060 is v0.6.0's declaration of each table it
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

// StatementsV070 is the untagged release's declaration of each table it
// changes.
func StatementsV070(engine database.Engine) map[string][]string {
	t := typesFor(engine)
	return map[string][]string{
		"finding":       findingV070(t),
		"scan_run":      scanRunV070(t),
		"vex_statement": vexStatementsV070(t),
		"vex_issuance":  vexIssuanceV070(t),
		"suppression":   suppressionV070(t),
	}
}
