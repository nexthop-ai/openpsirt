// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"strings"

	"github.com/uptrace/bun"
)

// MayApproveWhere is the condition that the person in personColumn may agree
// today to a decision about the product productColumn names, at the
// visibility visibilityColumn holds: MayApprove asked of the grants in force,
// on the product or across every product.
//
// Built from MayApprove and the reading and triage rules, so a statement
// asking who may still approve answers as a signed-in subject is answered. A test holds the two to one answer for every
// role on every visibility, granted either way.
//
// The columns are written at the call site and never supplied by anybody: a
// column name cannot be bound by a placeholder (REQ-66).
func MayApproveWhere(personColumn, productColumn, visibilityColumn string) (string, []any) {
	var parts []string
	var args []any
	for _, v := range Visibilities() {
		var either []string
		var eitherArgs []any
		if MayApprove(v, true, true, false) {
			held, heldArgs := holdingOn(personColumn, productColumn, []Role{Approver})
			either, eitherArgs = append(either, held), append(eitherArgs, heldArgs...)
		}
		if MayApprove(v, false, true, true) {
			held, heldArgs := holdingOn(personColumn, productColumn, rolesTriaging(v))
			either, eitherArgs = append(either, held), append(eitherArgs, heldArgs...)
		}
		if len(either) == 0 {
			continue
		}
		reads, readArgs := holdingOn(personColumn, productColumn, rolesReading(0, v))
		parts = append(parts, `(`+visibilityColumn+` = ? AND `+reads+` AND (`+strings.Join(either, " OR ")+`))`)
		args = append(args, string(v))
		args = append(args, readArgs...)
		args = append(args, eitherArgs...)
	}
	if len(parts) == 0 {
		return `1 = 0`, nil
	}
	return `(` + strings.Join(parts, " OR ") + `)`, args
}

// holdingOn is the condition that the person in personColumn holds one of
// these roles on the product productColumn names, granted there or across every
// product, in force: holdingAny with the product a column of the caller's
// query rather than a bound value.
func holdingOn(personColumn, productColumn string, enough []Role) (string, []any) {
	return `(EXISTS (SELECT 1 FROM "role_grant" AS "g"
			WHERE "g"."person_id" = ` + personColumn + ` AND "g"."active" = ?
			  AND "g"."product_id" = ` + productColumn + ` AND "g"."role" IN (?))
		OR EXISTS (SELECT 1 FROM "role_grant_all" AS "ga"
			WHERE "ga"."person_id" = ` + personColumn + ` AND "ga"."active" = ?
			  AND "ga"."role" IN (?)))`,
		[]any{true, bun.List(enough), true, bun.List(enough)}
}

// rolesTriaging is which roles are enough to triage at a visibility, asked of
// the rule a signed-in subject is asked by.
func rolesTriaging(visibility Visibility) []Role {
	var enough []Role
	for _, role := range Roles() {
		if NewPerson(0, "", false, map[int64][]Role{0: {role}}, 0).Triages(visibility, 0) {
			enough = append(enough, role)
		}
	}
	return enough
}
