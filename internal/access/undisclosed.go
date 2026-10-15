// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import "regexp"

// visibilityColumns are the qualified columns a statement may count
// undisclosed rows of. A column is placed in the statement as written, so it
// comes from this set rather than from a caller.
var visibilityColumns = map[string]bool{
	`"f"."visibility"`:  true,
	`"de"."visibility"`: true,
	`"q"."visibility"`:  true,
}

// PrivateCount is an aggregate counting the rows of a group whose visibility
// is undisclosed, with the argument it binds.
//
// The one spelling of the question. The visibility words are compared for
// equality and never ordered, because an ordering answers "is any of this
// undisclosed" only while the words sort that way. A count, so a group with
// no undisclosed rows is zero on every engine rather than a null.
func PrivateCount(column string) (string, any) {
	if !visibilityColumns[column] {
		panic("access.PrivateCount: " + column + " is not a visibility column")
	}
	return "COUNT(CASE WHEN " + column + " = ? THEN 1 END)", string(Private)
}

// AnyPrivate is a condition over a group that holds where any of its rows is
// undisclosed, with the argument it binds.
func AnyPrivate(column string) (string, any) {
	count, arg := PrivateCount(column)
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
func PrivateCountAs(column, name string) (string, any) {
	count, arg := PrivateCount(column)
	return count + as("PrivateCountAs", name), arg
}

// AnyPrivateAs is AnyPrivate selected under a name, for a column list.
func AnyPrivateAs(column, name string) (string, any) {
	cond, arg := AnyPrivate(column)
	return cond + as("AnyPrivateAs", name), arg
}
