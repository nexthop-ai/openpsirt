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
