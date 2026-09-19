package finding

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// ErrNotOursToClose says a scanner's finding is not something a person closes.
var ErrNotOursToClose = errors.New(
	"a scan is the authority on what it found, so only a flaw somebody recorded is closed by hand")

// ErrNoReason says a closure arrived without one.
var ErrNoReason = errors.New("say what fixed it")

// ErrNothingOpenThere says the build holds nothing open under that issue.
var ErrNothingOpenThere = errors.New("nothing is open there")

// Resolved is what a closure did.
type Resolved struct {
	// Closed is how many places of the issue in this build were closed. An
	// issue sits at many places and a fix reaches all of them, so this is the
	// number of rows written rather than the number of things somebody
	// decided about.
	Closed int
	At     time.Time
}

// Resolve closes a flaw somebody recorded, in one build, because somebody says
// it is fixed there.
//
// Resolution is computed from scans everywhere else, and that is
// the right rule: it removes the gap between marking work done and the work
// being done, and nobody can close an issue while a release they committed to
// still carries it. What it needs is evidence, and for this one class there is
// none and never will be — a run is the authority on what it found and it
// never found this, so the computation has no input and the finding stays open
// forever.
//
// So the exception is exactly as wide as the gap: a finding a person recorded,
// closed by a person, with who, when and why on the record. A scanner's
// finding is refused here, because for that one the evidence exists and
// letting somebody overrule it is precisely what resolution computed, not
// declared was written against.
func (s *Store) Resolve(ctx context.Context, subject access.Subject,
	targetID, vulnerabilityID int64, because string) (*Resolved, error) {

	because = strings.TrimSpace(because)
	if because == "" {
		return nil, ErrNoReason
	}
	// The submission policy, before the note is stored. A closure by a person
	// is the one thing here nothing else evidences, so what it says is kept
	// forever and read back on every screen that asks why.
	if err := markdown.Check(because); err != nil {
		return nil, err
	}
	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	if subject.Kind != access.Person || subject.ID == 0 {
		return nil, access.Denied(fmt.Sprintf("close a finding in product %d", productID))
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	out := &Resolved{At: now}
	err = database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		out.Closed = 0

		// Read inside the transaction, because a retry re-runs this against a
		// database that has moved: what is open there, and what visibility it
		// carries, are both read here rather than handed in.
		var rows []Finding
		err := tx.NewSelect().Model(&rows).
			Where("target_id = ?", targetID).
			Where("vulnerability_id = ?", vulnerabilityID).
			Where("closed_at IS NULL").
			Scan(ctx)
		if err != nil {
			return fmt.Errorf("read what is open there: %w", err)
		}
		if len(rows) == 0 {
			return ErrNothingOpenThere
		}

		// Only what a person recorded. The read spans every component
		// the issue sits at in this build, because that is how a
		// finding is addressed here — but a scanner's row at another
		// component is not evidence about this one, and refusing on it
		// made a recorded flaw permanently unclosable the moment a
		// scan reported the same identifier anywhere in the build.
		// That is the state a recorded flaw closed by a person exists
		// to prevent, reached by the ordinary path: the flaw stayed
		// open forever, every screen looked right, and the wrongness
		// was only that it never left.
		//
		// A scanner's rows are left alone rather than refused, because
		// they close when the scan stops reporting them and nothing
		// anybody types makes that true.
		ids := make([]int64, 0, len(rows))
		reported := false
		for _, row := range rows {
			if row.Kind != Entered {
				reported = true
				continue
			}
			// The same right recording it asked for, checked against what
			// each row actually is rather than against the issue: somebody
			// who may argue about disclosed findings has not been handed the
			// undisclosed ones, here any more than there.
			if !subject.Triages(row.Visibility, productID) {
				return access.Denied(
					fmt.Sprintf("close a finding in product %d", productID))
			}
			ids = append(ids, row.ID)
		}
		if len(ids) == 0 {
			// Nothing here is ours. Said as that rather than as "nothing is
			// open", because something is: a scanner reported it, and what
			// closes it is a scan that stops.
			if reported {
				return ErrNotOursToClose
			}
			return ErrNothingOpenThere
		}

		return database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
			result, err := tx.NewUpdate().Model((*Finding)(nil)).
				Set("closed_at = ?", now).
				Set("closed_by = ?", subject.ID).
				Set("closed_note = ?", because).
				Set("closed_because = ?", Fixed).
				Where("id IN (?)", bun.List(batch)).
				// Still open, checked as the write happens. Two people closing
				// the same thing at once is ordinary, and the second must not
				// overwrite the first's reason with its own.
				Where("closed_at IS NULL").
				Exec(ctx)
			if err != nil {
				return fmt.Errorf("close %d findings: %w", len(batch), err)
			}
			affected, err := database.Affected(result)
			if err != nil {
				return fmt.Errorf("close %d findings: %w", len(batch), err)
			}
			out.Closed += int(affected)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
