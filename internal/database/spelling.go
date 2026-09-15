package database

import (
	"fmt"
	"strings"

	"github.com/uptrace/bun"
)

// Expr is a piece of SQL a caller composed and owns.
//
// A named type rather than a string, so that the places where text reaches a
// statement are the places this type appears. What a caller may build one from
// is its own to answer; what this package refuses to do is take a column name
// as an ordinary parameter and splice it in.
type Expr string

// Column quotes a possibly qualified column reference for every engine.
//
// The quoting the package that owns engine-specific SQL is supposed to own and
// did not, so every caller hand-wrote its identifiers.
//
// The character is the engine's own answer rather than the standard quote the
// schema is written in. Two of the four name the backtick and take both, so
// either would work today — asking makes it true of an engine that does not.
func Column(db bun.IDB, name string) Expr {
	quote := string([]byte{db.Dialect().IdentQuote()})
	parts := strings.Split(name, ".")
	for i, part := range parts {
		// A quote inside a name is doubled, which is how every one of the four
		// escapes one. Nothing in the schema carries one; a name arriving from
		// somewhere else might, and this is the one function that decides.
		parts[i] = quote + strings.ReplaceAll(part, quote, quote+quote) + quote
	}
	return Expr(strings.Join(parts, "."))
}

// Composed is an expression the caller built and stands behind — a CASE, a
// function call, anything that is not one name.
//
// Separate from Column so that a grep for it finds every place a fragment is
// composed rather than quoted, which is the list somebody reviewing REQ-66
// wants.
func Composed(sql string) Expr { return Expr(sql) }

// SecondsBetween is the gap between two moments, in seconds, in the spelling
// each engine understands.
//
// There is no portable way to subtract two timestamps and get a number: one
// returns an interval, one a number of days, and the others something else
// again. So this is one of the few places an engine has to be asked directly,
// and it lives here — in the package that already owns every other such
// answer — rather than in whichever caller needed it first.
//
// It was written twice, in two packages, each under a comment calling itself
// one of the few places an engine is asked, and neither knew the other
// existed. That is what the rule confining engine-specific SQL exists to stop,
// and the second copy is exactly how a rule stated as "three places" stops
// describing the code.
//
// MariaDB takes the MySQL spelling because it takes the MySQL dialect: the two
// share a driver and one dialect covers both, so the name reported here is
// "mysql" for either. Nothing below depends on telling them apart, and if that
// ever changes this is where it changes.
//
// Both ends are Expr rather than string. A placeholder cannot bind a column
// name, so what is passed here reaches the statement text — and a function
// taking a bare string leaves nothing between it and a name arriving from a
// query parameter except that today's callers all pass literals. Naming the
// type is what makes that structural rather than a habit (REQ-66).
func SecondsBetween(db bun.IDB, from, to Expr) string {
	switch db.Dialect().Name().String() {
	case "pg":
		return fmt.Sprintf("EXTRACT(EPOCH FROM (%s - %s))", to, from)
	case "mysql":
		return fmt.Sprintf("TIMESTAMPDIFF(SECOND, %s, %s)", from, to)
	default:
		// SQLite keeps these as text and compares them as text, which is why
		// the stored format is fixed; julianday is its way of getting a number
		// out, and the result is in days.
		return fmt.Sprintf("((julianday(%s) - julianday(%s)) * 86400)", to, from)
	}
}

// AsTimestamp is an expression typed as a moment, in the spelling each engine
// understands.
//
// A value bound into a statement arrives untyped, and an expression built out
// of several of them — a CASE choosing between moments — is a string as far as
// the engine can tell. One of the four then refuses to write it into a
// timestamp column, and the other three take it; so this is one of the few
// places an engine has to be asked directly, and it lives here with the rest.
//
// The target is the type the schema declares for a moment on that engine, so a
// change there is a change here.
func AsTimestamp(db bun.IDB, expr string) string {
	switch db.Dialect().Name().String() {
	case "pg":
		return fmt.Sprintf("CAST(%s AS TIMESTAMPTZ)", expr)
	case "mysql":
		// MariaDB takes the MySQL spelling because it takes the MySQL
		// dialect. Neither accepts TIMESTAMP as a cast target.
		return fmt.Sprintf("CAST(%s AS DATETIME(6))", expr)
	default:
		// SQLite stores a moment as text in a fixed format and compares it as
		// text, so there is nothing to cast it to.
		return expr
	}
}
