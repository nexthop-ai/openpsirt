// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"regexp"

	"github.com/uptrace/bun"
)

// roleTablesV0110 is each table v0.11.0 declares a role's name in. A table a
// later release adds is declared at its own width.
var roleTablesV0110 = []string{"role_grant", "role_grant_all", "group_role", "group_role_all"}

// roleV0110 is v0.11.0's declaration of the tables holding a role's name:
// v0.7.0's, with the name declared at a short identifier's width. A kind's
// width holds sixteen characters, and security-testing-triage is twenty-three.
// Derived from v0.7.0's declaration; no release between changed it.
func roleV0110(t *columnTypes) []string {
	baseline := accessBaseline(t)
	role := regexp.MustCompile(`("role"\s+)` + regexp.QuoteMeta(t.kind))
	var out []string
	for _, table := range roleTablesV0110 {
		made, indexes, err := pick(baseline, table)
		if err != nil {
			panic(err)
		}
		out = append(out, role.ReplaceAllString(made, "${1}"+t.name))
		out = append(out, indexes...)
	}
	return out
}

// roleWidthV0110 widens the role column of each table holding one. Every row
// keeps its value.
func roleWidthV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	declared := roleV0110(u.t)
	for _, table := range roleTablesV0110 {
		if err := u.widen(declared, table, "role"); err != nil {
			return err
		}
	}
	return nil
}
