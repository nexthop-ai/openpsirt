package notify

// SweepBatch is how many notifications one sweep carries.
//
// Exported for the test alone, which has to build a backlog of exactly that
// size to show that the sweep reaches past one: a second spelling of the
// number in the test would pass while the sweep used a different one.
const SweepBatch = sweepBatch
