// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import "github.com/nexthop-ai/openpsirt/internal/database"

// DeclaredV030 is each table v0.3.0 declares, and the columns its statement
// names, as the statements read on one engine.
func DeclaredV030(engine database.Engine) (map[string][]string, error) {
	t := typesFor(engine)
	out := map[string][]string{}
	for _, statements := range [][]string{findingV030(t), reportV030(t), componentV030(t)} {
		for _, stmt := range statements {
			m := createsTable.FindStringSubmatch(stmt)
			if m == nil {
				continue
			}
			d, err := declared(stmt)
			if err != nil {
				return nil, err
			}
			out[m[1]] = d.columns
		}
	}
	return out, nil
}
