// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

// visibilityColumns are the qualified columns a statement may count
// undisclosed rows of. A column is placed in the statement as written, so it
// comes from this set rather than from a caller.
var visibilityColumns = map[string]bool{
	"f.visibility":  true,
	"de.visibility": true,
	"q.visibility":  true,
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

// PrivateCountAs is PrivateCount selected under a name, for a column list.
func PrivateCountAs(column, name string) (string, any) {
	count, arg := PrivateCount(column)
	return count + ` AS "` + name + `"`, arg
}

// AnyPrivateAs is AnyPrivate selected under a name, for a column list.
func AnyPrivateAs(column, name string) (string, any) {
	cond, arg := AnyPrivate(column)
	return cond + ` AS "` + name + `"`, arg
}
