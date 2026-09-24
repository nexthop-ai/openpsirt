// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// ErrDisclosed says the issue is already public in this product.
var ErrDisclosed = errors.New("that issue is already disclosed in this product")

// ErrDisclosureWaiting says a disclosure of this issue is already waiting for
// a second person. A second request would put two entries on the queue for
// one act.
var ErrDisclosureWaiting = errors.New("a disclosure of that issue is already waiting for a second person")

// Disclose makes one issue public in one product, and reports whether it took
// effect or is waiting for somebody to agree.
//
// Recorded as a movement of the embargo whose act is disclosure, because it is
// the last one: the end of the embargo brought to today. The rules shortening
// has apply to it unchanged.
//
// | Where the embargo stands | Second person |
// |---|---|
// | Its date has arrived | Never: disclosing is what everybody was told would happen |
// | Its date is ahead | Past the threshold, counting how far the end has already been carried plus the days given up |
// | It has no date | Always: a flaw found here has no end anybody agreed to, so the whole decision is this one |
//
// One way. Nothing makes a disclosed issue undisclosed again, because what was
// read while it was public cannot be unread.
func (s *Store) Disclose(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64, reason string) (*Movement, error) {

	if !subject.Triages(access.Private, productID) {
		return nil, access.Denied(fmt.Sprintf("disclose an issue in product %d", productID))
	}
	if subject.ID == 0 {
		return nil, access.Denied("disclose an issue without being anybody")
	}
	if strings.TrimSpace(reason) == "" {
		return nil, Unreasoned{Said: "say why the issue is being disclosed"}
	}
	// The submission policy, run before the text is stored. The row is
	// append-only and becomes public with the rest of the record.
	if err := markdown.Check(reason); err != nil {
		return nil, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)

	var out *Movement
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		ends, err := undisclosedHere(ctx, tx, productID, vulnerabilityID)
		if err != nil {
			return err
		}
		asked := &Movement{
			VulnerabilityID: vulnerabilityID, ProductID: productID,
			Act: Disclosure, Was: now, Until: now, Reason: reason,
			AskedBy: subject.ID, AskedAt: now,
		}
		switch {
		case ends == nil:
			// Recorded with no distance: there was no end to bring in.
			asked.NeedsApproval = true
		case !ends.After(now):
			asked.Was = *ends
		default:
			asked.Was = *ends
			threshold, err := setting.NewStore(tx).Duration(ctx,
				setting.MovementThreshold, setting.DefaultMovementThreshold)
			if err != nil {
				return err
			}
			already, err := movedBy(ctx, tx, productID, vulnerabilityID)
			if err != nil {
				return err
			}
			asked.NeedsApproval = threshold <= 0 || already+asked.Distance() >= threshold
		}
		if asked.NeedsApproval {
			// Refused only where this one would wait too. One that takes
			// effect at once ends the embargo whatever is waiting, and what
			// was waiting leaves the queue with nothing left to disclose.
			waiting, err := tx.NewSelect().Model((*Movement)(nil)).
				Where("product_id = ?", productID).
				Where("vulnerability_id = ?", vulnerabilityID).
				Where("act = ?", Disclosure).
				Where("needs_approval = ?", true).
				Where("approved_at IS NULL").
				Exists(ctx)
			if err != nil {
				return fmt.Errorf("read whether a disclosure is waiting: %w", err)
			}
			if waiting {
				return ErrDisclosureWaiting
			}
		}
		out = asked
		if _, err := tx.NewInsert().Model(out).Exec(ctx); err != nil {
			return fmt.Errorf("record the disclosure: %w", err)
		}
		if out.NeedsApproval {
			return nil
		}
		return makePublic(ctx, tx, productID, vulnerabilityID, now)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// undisclosedHere reads whether anything of this issue in this product is
// undisclosed, and where its embargo ends.
//
// Closed places count. A place that closed while undisclosed still carries a
// record — comments, decisions, who did what — and disclosing the issue is
// disclosing that record too (REQ-40). The end is read from the open places,
// which are the ones a movement reads and moves, and from the closed ones only
// where nothing is open; it is nil where none carries a date.
func undisclosedHere(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64) (*time.Time, error) {
	var held struct {
		Places int        `bun:"places"`
		Public int        `bun:"public"`
		Ends   *time.Time `bun:"ends"`
	}
	err := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`COUNT(CASE WHEN f.visibility = ? THEN 1 END) AS "places"`, access.Private).
		ColumnExpr(`COUNT(CASE WHEN f.visibility = ? THEN 1 END) AS "public"`, access.Public).
		ColumnExpr(`COALESCE(MAX(CASE WHEN f.visibility = ? AND f.closed_at IS NULL THEN f.disclose_at END), `+
			`MAX(CASE WHEN f.visibility = ? THEN f.disclose_at END)) AS "ends"`,
			access.Private, access.Private).
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where(inThisProductAs("f.target_id"), productID).
		Scan(ctx, &held)
	if err != nil {
		return nil, fmt.Errorf("read whether this issue is undisclosed: %w", err)
	}
	switch {
	case held.Places > 0:
		return held.Ends, nil
	case held.Public > 0:
		return nil, ErrDisclosed
	default:
		return nil, ErrNotEmbargoed
	}
}

// makePublic turns every place of one issue in one product public, open and
// closed, along with every decision made about it there.
//
// A decision carries the visibility of the finding it was made about, so that
// who may reach it is answered by the row. Left behind, the decisions of a
// disclosed issue would stay readable only to the people who could read it
// before, which is the opposite of what disclosing says.
//
// The disclosure date goes with it. A public finding carries none, and one
// left behind is read back as the date an embargo ends that has already
// ended. The movement just recorded keeps where it stood.
func makePublic(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64,
	now time.Time) error {

	if _, err := db.NewUpdate().Model((*Finding)(nil)).
		Set("visibility = ?", access.Public).
		Set("disclose_at = NULL").
		Set("last_changed_at = ?", now).
		Where("vulnerability_id = ?", vulnerabilityID).
		Where("visibility = ?", access.Private).
		Where(inThisProduct, productID).
		Exec(ctx); err != nil {
		return fmt.Errorf("disclose the findings: %w", err)
	}
	if _, err := db.NewUpdate().TableExpr(`"decision"`).
		Set(`"visibility" = ?`, access.Public).
		Where(`"product_id" = ?`, productID).
		Where(`"vulnerability_id" = ?`, vulnerabilityID).
		Where(`"visibility" = ?`, access.Private).
		Exec(ctx); err != nil {
		return fmt.Errorf("disclose the decisions: %w", err)
	}
	return nil
}

// Audience is who to tell that an issue was disclosed, and the names to tell them
// in.
type Audience struct {
	Product       string
	Vulnerability string
	// People is every person holding a place of the issue in the product,
	// open or closed. People only: a place in a team's queue has nobody to
	// tell, and the queue itself shows the change.
	People []int64
}

// ToTell reads who holds an issue in a product, for the person who has just
// disclosed it there.
func (s *Store) ToTell(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64) (*Audience, error) {

	if !subject.Triages(access.Private, productID) {
		return nil, access.Denied(fmt.Sprintf("read who holds an issue in product %d", productID))
	}
	out := &Audience{}
	err := s.db.NewSelect().
		TableExpr(`"product" AS "p"`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = ?`, vulnerabilityID).
		ColumnExpr("p.name").
		ColumnExpr("v.identifier").
		Where("p.id = ?", productID).
		Scan(ctx, &out.Product, &out.Vulnerability)
	if err != nil {
		return nil, fmt.Errorf("read what was disclosed: %w", err)
	}
	err = s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "person" AS "ps" ON ps.party_id = f.assigned_to`).
		ColumnExpr("DISTINCT ps.id").
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where(inThisProductAs("f.target_id"), productID).
		OrderExpr("ps.id").
		Scan(ctx, &out.People)
	if err != nil {
		return nil, fmt.Errorf("read who holds this issue: %w", err)
	}
	return out, nil
}
