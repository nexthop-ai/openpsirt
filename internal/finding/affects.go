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

// ErrNotOursToSay is what an issue a scanner reported answers.
//
// Which builds hold one of those is a fact the scans establish, and editing it
// here would be overwriting what was found with what somebody thinks. A flaw
// recorded by hand has no scan behind it, which is exactly why its build set
// is ours to correct.
var ErrNotOursToSay = errors.New(
	"which builds hold a scanned issue is what the scans found, not something to set here")

// Reset is what setting the builds did.
type Reset struct {
	Added  int
	Closed int
}

// Affects makes the builds a recorded flaw is filed against exactly these.
//
// **Research narrows and widens what somebody first believed**, and the first
// belief is written down before the analysis is finished — that is the point of
// being able to record one early. So the set is editable, declaratively: this
// is the list, work out what changed.
//
// **Widening opens findings; narrowing closes them as `invalid`** — because a
// build taken out of the set was never affected, rather than having stopped
// being affected. The record of it stays, with the reason, so that the history
// says what was believed and when it was corrected.
//
// **A reason is required whenever anything is closed.** Taking a build back out
// of an advisory's affected list with no explanation is the state a history
// exists to prevent.
func (s *Store) Affects(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64, targets []int64, because string) (*Reset, error) {

	if len(targets) == 0 {
		return nil, ErrNoBuild
	}
	if subject.Kind != access.Person || subject.ID == 0 {
		return nil, access.Denied(fmt.Sprintf("say what is affected in product %d", productID))
	}
	because = strings.TrimSpace(because)
	// The submission policy, before the note is stored. It is the same column
	// a person's closure writes, and both writers have to hold to it or the
	// column is only as bounded as the laxer of the two.
	if err := markdown.Check(because); err != nil {
		return nil, err
	}

	wanted := make(map[int64]bool, len(targets))
	for _, target := range targets {
		other, err := productOf(ctx, s.db, target)
		if err != nil {
			return nil, err
		}
		if other != productID {
			return nil, ErrSeveralProducts
		}
		wanted[target] = true
	}

	// What is filed now, and what the flaw is in. Read before the transaction
	// because resolving a component is a walk of a build's graph, and because
	// a build that does not hold it has to be refused before anything is
	// written — which is what recording already does for the same reason. The
	// transaction reads the set again and writes against that.
	standing, err := s.filedAgainst(ctx, productID, vulnerabilityID)
	if err != nil {
		return nil, err
	}
	if len(standing) == 0 {
		return nil, ErrNothingOpenThere
	}
	component, err := s.ComponentName(ctx, standing[0].ComponentID)
	if err != nil {
		return nil, err
	}
	// Resolved in every build being added, so a name one of them does not hold
	// is a refusal naming it rather than a build listed as affected with
	// nothing there.
	opening := map[int64]int64{}
	names := map[int64]string{}
	for target := range wanted {
		if standingAt(standing, target) {
			continue
		}
		componentID, name, err := carrying(ctx, s.db, target, Entering{Component: component})
		if err != nil {
			return nil, err
		}
		opening[target] = componentID
		names[target] = name
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	out := &Reset{}
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		out.Added, out.Closed = 0, 0

		// What is open now, read inside the transaction: a retry
		// re-runs this against a database somebody else may have
		// moved.
		// Ordered, because the first row is what a filing against another
		// build is copied from. Unordered, which row that is depends on the
		// plan an engine happened to pick, so the same request could produce
		// a different row on a different engine or after an index changed.
		// The earliest filing is the one to copy: it is the record of what was
		// first known about this issue here.
		var rows []Finding
		err := tx.NewSelect().Model(&rows).
			Join(`JOIN target AS "tg" ON tg.id = f.target_id`).
			Join(`JOIN stream AS "st" ON st.id = tg.stream_id`).
			Where("st.product_id = ?", productID).
			Where("f.vulnerability_id = ?", vulnerabilityID).
			Where("f.closed_at IS NULL").
			Order("f.opened_at ASC", "f.id ASC").
			Scan(ctx)
		if err != nil {
			return fmt.Errorf("read which builds hold it: %w", err)
		}
		if len(rows) == 0 {
			return ErrNothingOpenThere
		}

		here := map[int64]bool{}
		var closing []int64
		// Which builds are being taken out, as against how many rows that
		// is: a build holding the component in two places is one build.
		out.Closed = 0
		leaving := map[int64]bool{}
		for i := range rows {
			row := &rows[i]
			// Only a flaw somebody recorded. A scanned issue's build set is
			// what the scans found.
			if row.Kind != Entered {
				return ErrNotOursToSay
			}
			// The same right recording it asked for, checked against what each
			// row actually is: somebody who may argue about disclosed findings
			// has not been handed the undisclosed ones.
			if !subject.Triages(row.Visibility, productID) {
				return access.Denied(
					fmt.Sprintf("say what is affected in product %d", productID))
			}
			here[row.TargetID] = true
			if !wanted[row.TargetID] {
				closing = append(closing, row.ID)
				leaving[row.TargetID] = true
			}
		}
		if len(closing) > 0 && because == "" {
			return ErrNoReason
		}

		// Widening first. A build added and then immediately closed by the
		// same call is not something to guard against — the two sets are
		// disjoint by construction — and doing the opening first means a
		// failure leaves the set larger rather than smaller, which is the
		// safer direction for a list of what is affected.
		for target := range wanted {
			if here[target] {
				continue
			}
			componentID, held := opening[target]
			if !held {
				// Resolved before the transaction and not found now: the set
				// moved under a retry. Reported rather than guessed at.
				return fmt.Errorf("the builds changed while this was being written; try again")
			}
			// One row per place, as recording it did: where the component
			// sits comes from the build's own graph, so a flaw filed against
			// another build is keyed the way a scan of that build would key
			// it.
			sittings, err := sittingsOf(ctx, tx, target, componentID)
			if err != nil {
				return err
			}
			for _, sitting := range sittings {
				row := openIn(target, vulnerabilityID, componentID, names[target],
					sitting, &rows[0], now)
				if _, err := tx.NewInsert().Model(row).Exec(ctx); err != nil {
					return fmt.Errorf("record it against another build: %w", err)
				}
			}
			// Builds, not rows. A build holding the component in two places
			// is one build added, and what this reports is the set somebody
			// just stated.
			out.Added++
		}

		out.Closed = len(leaving)
		if len(closing) == 0 {
			return nil
		}
		return database.IDsInBatches(ctx, closing, func(ctx context.Context, batch []int64) error {
			result, err := tx.NewUpdate().Model((*Finding)(nil)).
				Set("closed_at = ?", now).
				Set("closed_by = ?", subject.ID).
				Set("closed_note = ?", because).
				Set("closed_because = ?", Invalid).
				Where("id IN (?)", bun.List(batch)).
				// Still open, checked as the write happens: two people editing
				// the set at once is ordinary, and the second must not
				// overwrite the first's reason.
				Where("closed_at IS NULL").
				Exec(ctx)
			if err != nil {
				return fmt.Errorf("take %d builds back out: %w", len(batch), err)
			}
			if _, err := database.Affected(result); err != nil {
				return fmt.Errorf("take %d builds back out: %w", len(batch), err)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// openIn is the finding this flaw makes in a build that has just been added to
// its set.
//
// Everything but the place is copied from a row that already exists, so a build
// added later is on the same clock and at the same rating as the ones recorded
// first. Working it out again from today's settings would give the newest build
// a later deadline for the same flaw.
func openIn(targetID, vulnerabilityID, componentID int64, name string,
	where sits, like *Finding, now time.Time) *Finding {

	return &Finding{
		TargetID: targetID, Kind: Entered, Visibility: like.Visibility,
		VulnerabilityID: vulnerabilityID,
		ComponentID:     componentID,
		ConsumerID:      optional(where.consumerID),
		PlaceIdentity:   PlaceIdentity(name, where.consumer),
		LastChangedAt:   now,
		OpenedAt:        now,
		Urgency:         like.Urgency,
		DiscloseAt:      like.DiscloseAt,
		DueAt:           like.DueAt,
	}
}

// filedAgainst is every open finding for one issue in one product.
func (s *Store) filedAgainst(ctx context.Context, productID, vulnerabilityID int64) ([]Finding, error) {
	var rows []Finding
	err := s.db.NewSelect().Model(&rows).
		Join(`JOIN target AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN stream AS "st" ON st.id = tg.stream_id`).
		Where("st.product_id = ?", productID).
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where("f.closed_at IS NULL").
		Order("f.opened_at ASC", "f.id ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read which builds hold it: %w", err)
	}
	return rows, nil
}

// standingAt reports whether one of these findings is in that build.
func standingAt(rows []Finding, targetID int64) bool {
	for i := range rows {
		if rows[i].TargetID == targetID {
			return true
		}
	}
	return false
}
