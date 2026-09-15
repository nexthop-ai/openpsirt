package currency

import "time"

// Asking is how long a lease is taken for inside a pass, for a test that has
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
