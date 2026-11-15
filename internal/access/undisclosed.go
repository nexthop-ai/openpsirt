// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import "regexp"

// VisibilityColumn is a column holding a visibility, as a statement names it.
//
// A column is spliced into the statement, so the set is
// closed and named here: its one field is unexported, so no other package
// builds one from a string it was handed or from a literal. The empty value
// names no column, and an aggregate asked of it panics.
type VisibilityColumn struct{ name string }

// spliced is the column as the statement names it.
func (c VisibilityColumn) spliced() string {
	if c.name == "" {
		panic("access: a visibility column names no column")
	}
	return c.name
}

// The columns a statement counts undisclosed rows of, each by the alias its
// table takes in the statements that ask. Functions rather than variables, so
// no other package can reassign one.

// FindingVisibility is a finding's visibility.
func FindingVisibility() VisibilityColumn { return VisibilityColumn{`"f"."visibility"`} }

// DecisionOccurrenceVisibility is a decision occurrence's visibility.
func DecisionOccurrenceVisibility() VisibilityColumn {
	return VisibilityColumn{`"de"."visibility"`}
}

// PrivateCount is an aggregate counting the rows of a group whose visibility
// is undisclosed, with the argument it binds.
//
// The one spelling of the question. The visibility words are compared for
// equality and never ordered, because an ordering answers "is any of this
// undisclosed" only while the words sort that way. A count, so a group with
// no undisclosed rows is zero on every engine rather than a null.
func PrivateCount(column VisibilityColumn) (string, any) {
	return "COUNT(CASE WHEN " + column.spliced() + " = ? THEN 1 END)", string(Private)
}

// AnyPrivate is a condition over a group that holds where any of its rows is
// undisclosed, with the argument it binds.
func AnyPrivate(column VisibilityColumn) (string, any) {
	count, arg := PrivateCount(column)
	return "(" + count + " > 0)", arg
}

// WithheldCount is an aggregate counting the rows of a group whose detail
// stays inside the deployment, with the argument it binds: every visibility
// but public.
//
// Undisclosed and security testing rows both. Disclosure applies to private work
// alone, and PrivateCount is the question it asks; what a message leaving
// the deployment may say about a row is asked of this one.
func WithheldCount(column VisibilityColumn) (string, any) {
	return "COUNT(CASE WHEN " + column.spliced() + " <> ? THEN 1 END)", string(Public)
}

// AnyWithheld is a condition over a group that holds where the detail of any
// of its rows stays inside the deployment, with the argument it binds.
func AnyWithheld(column VisibilityColumn) (string, any) {
	count, arg := WithheldCount(column)
	return "(" + count + " > 0)", arg
}

// alias is the shape of a name a column list selects a count under. The name
// is placed in the statement inside quotes, so a quote in it would close them.
var alias = regexp.MustCompile(`^[a-z_]+$`)

// as quotes name as a column alias, refusing one that is not a plain word.
func as(caller, name string) string {
	if !alias.MatchString(name) {
		panic("access." + caller + ": " + name + " is not an alias")
	}
	return ` AS "` + name + `"`
}

// PrivateCountAs is PrivateCount selected under a name, for a column list.
func PrivateCountAs(column VisibilityColumn, name string) (string, any) {
	count, arg := PrivateCount(column)
	return count + as("PrivateCountAs", name), arg
}

// WithheldCountAs is WithheldCount selected under a name, for a column list.
func WithheldCountAs(column VisibilityColumn, name string) (string, any) {
	count, arg := WithheldCount(column)
	return count + as("WithheldCountAs", name), arg
}

// SecurityTestingCountAs is an aggregate counting the rows of a group that are
// security testing work, selected under a name, with the argument it binds. A reader
// of undisclosed work reads none of them, so an audience is asked about them
// apart.
func SecurityTestingCountAs(column VisibilityColumn, name string) (string, any) {
	return "COUNT(CASE WHEN " + column.spliced() + " = ? THEN 1 END)" + as("SecurityTestingCountAs", name), string(SecurityTesting)
}

// AnyPrivateAs is AnyPrivate selected under a name, for a column list.
func AnyPrivateAs(column VisibilityColumn, name string) (string, any) {
	cond, arg := AnyPrivate(column)
	return cond + as("AnyPrivateAs", name), arg
}
