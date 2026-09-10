// Package scanner runs a vulnerability scan over an inventory.
//
// The scanner sits behind an interface with one implementation, the same shape
// the notification channels and the identity providers use. A second scanner
// should be an adapter rather than a rewrite, and the choice of which to run
// should be an operator's rather than ours.
package scanner

import (
	"context"
	"io"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Scanner reads an inventory and reports what it knows about.
type Scanner interface {
	// Name identifies the implementation, and is recorded against everything
	// it finds. Counts are only comparable between products measured the same
	// way.
	Name() string
	// Scan reads an inventory and reports what is affected.
	Scan(ctx context.Context, inventory io.Reader) (Result, error)
}

// Result is one execution's output.
type Result struct {
	// Version is the scanner's own version and DatabaseVersion identifies the
	// vulnerability data it matched against. Both are recorded because a
	// change in either changes what is found, and a finding that appeared or
	// vanished for that reason is otherwise unexplainable.
	Version         string
	DatabaseVersion string
	Reported        []finding.Reported
	// Caution is what the scanner said while succeeding.
	//
	// Read only on failure before this, which discarded the case that
	// matters: a run that answers and warns that its answer is coarse. Told
	// to match Go binaries carrying no function symbols it says so and falls
	// back to module granularity, which can report a component as affected
	// when the vulnerable function is not linked in. That qualifies every
	// finding the run produced and reached nobody.
	Caution string
}
