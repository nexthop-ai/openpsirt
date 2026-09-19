package currency

import (
	"testing"
	"time"
)

// The lease length taken inside a pass, for a test that has
// to make one lapse part way through.
//
// Set by Run in production, where the caller states the interval. A test that
// drives Once directly has never set it, and a lease of no length is one that
// has already lapsed.
func Asking(r *Refresher, interval time.Duration) { r.interval = interval }

// RenewEvery is how many components a pass gets through before it asks for the
// lease again.
//
// Exported for the test alone: a second spelling of the number there would
// pass while the pass used a different one.
const RenewEvery = renewEvery

// Examining lowers the ceiling on how many components one read of the report
// classifies, and puts it back when the test ends.
//
// Exported for the test alone. The arm past the ceiling reports the count as a
// floor rather than as the answer, and reaching it honestly would mean seeding
// twenty thousand components on four engines.
func Examining(t *testing.T, most int) {
	t.Helper()
	was := mostExamined
	mostExamined = most
	t.Cleanup(func() { mostExamined = was })
}
