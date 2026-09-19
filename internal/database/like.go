package database

import "strings"

// LikeEscape is the escape character every LIKE predicate here states.
//
// A backslash is what it must not be. MySQL and MariaDB treat a backslash
// as an escape inside a string literal, so `ESCAPE '\'` is an unterminated
// string: a syntax error on two engines and parsed happily by the other two.
// SQLite has no default escape character at all, so leaving the clause out
// makes a backslash mean one thing on three engines and another on the fourth.
//
// Here rather than in each package that searches, because it is an engine
// difference and this package is where those live. Written out per package it
// is unexported in one and copied into the next, and the package after that
// escapes nothing at all.
const LikeEscape = "#"

// LikeClause is the clause every predicate using these helpers carries.
//
// Stated as a constant so a predicate cannot be written with the escaping and
// without the clause, which escapes the term and then asks the engine to
// interpret the escape character as an ordinary one.
const LikeClause = ` ESCAPE '` + LikeEscape + `'`

// LikeEscaped makes a value match itself under LIKE and nothing else.
//
// A search box is not a pattern language. Typing "50%" means a name containing
// "50%", not every name containing "50" — and "a_b" means what it says rather
// than "a, anything, b".
//
// What it cost where it was missing: the picker that decides who may be named
// on an embargoed case answered a term of "%" with every eligible person in
// the deployment, in one request.
func LikeEscaped(value string) string {
	return strings.NewReplacer(
		LikeEscape, LikeEscape+LikeEscape,
		"%", LikeEscape+"%",
		"_", LikeEscape+"_",
	).Replace(value)
}

// LikeContains wraps an escaped term so it matches anywhere in a value.
//
// Folded here as well, because every caller compares against a lowered column
// or a folded copy. Folding in Go is Unicode-aware and LOWER() on SQLite is
// ASCII-only, so a term folded once here and once by the engine is found on
// three engines and missed on the fourth wherever the column has no folded
// copy — which is written down beside the callers it still applies to.
func LikeContains(term string) string {
	return "%" + LikeEscaped(strings.ToLower(term)) + "%"
}
