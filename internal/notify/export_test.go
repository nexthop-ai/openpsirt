package notify

import "context"

// SweepBatch is how many notifications one sweep carries.
//
// Exported for the test alone, which has to build a backlog of exactly that
// size to show that the sweep reaches past one: a second spelling of the
// number in the test would pass while the sweep used a different one.
const SweepBatch = sweepBatch

// StillToTell is how many notifications one destination's window holds.
//
// Exported so a test can ask the predicate directly. What wedges a sweep is a
// row that can never leave the window, and the window is bounded — so with
// only a handful of rows the sweep still reaches past them and a test that
// watches what was sent cannot tell a settled row from an unsettleable one.
func StillToTell(s *Signal, ctx context.Context, name string) (int, error) {
	var to Outbound
	if err := s.db.NewSelect().Model(&to).Where("name = ?", name).Scan(ctx); err != nil {
		return 0, err
	}
	rows, err := s.window(ctx, to)
	return len(rows), err
}
