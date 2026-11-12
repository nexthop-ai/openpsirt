// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import "strings"

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
			held, heldArgs := holdingOn(personColumn, productColumn, nil, []Role{Approver})
			either, eitherArgs = append(either, held), append(eitherArgs, heldArgs...)
		}
		if MayApprove(v, false, true, true) {
			held, heldArgs := holdingOn(personColumn, productColumn, nil, rolesTriaging(v))
			either, eitherArgs = append(either, held), append(eitherArgs, heldArgs...)
		}
		if len(either) == 0 {
			continue
		}
		reads, readArgs := holdingOn(personColumn, productColumn, nil, rolesReading(0, v))
		parts = append(parts, `(`+visibilityColumn+` = ? AND `+reads+` AND (`+strings.Join(either, " OR ")+`))`)
		args = append(args, string(v))
		args = append(args, readArgs...)
		args = append(args, eitherArgs...)
	}
	if len(parts) == 0 {
		return `1 = 0`, nil
	}
	// A deactivated account keeps its grant rows and is refused at sign-in.
	return `(EXISTS (SELECT 1 FROM "person" AS "pa" WHERE "pa"."id" = ` + personColumn +
		` AND "pa"."deactivated_at" IS NULL) AND (` + strings.Join(parts, " OR ") + `))`, args
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
