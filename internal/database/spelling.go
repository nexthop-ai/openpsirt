package database

import (
	"fmt"

	"github.com/uptrace/bun"
)

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
func SecondsBetween(db bun.IDB, from, to string) string {
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
