// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// ErrNoSuchRelease says the issue is in no release by that name in that
// product.
var ErrNoSuchRelease = refusal.New("that issue is in no release by that name in that product")

// Placed is one release of one issue an advisory covers, as the advisory
// screen reads it.
type Placed struct {
	Covered Covered
	Release
	// Status is what the document states about the release.
	Status string
	// Changed says the status differs from what an agreement standing on what
	// the advisory says now saw. A decision approved or lapsing after the
	// agreement moves a release's status, and the agreement stands.
	Changed bool
}

// agreedStatus is what one release stood at when one agreement was given.
type agreedStatus struct {
	bun.BaseModel `bun:"table:advisory_agreed_status,alias:ag"`

	ID              int64  `bun:"id,pk,autoincrement"`
	ApprovalID      int64  `bun:"approval_id,notnull"`
	ProductID       int64  `bun:"product_id,notnull"`
	VulnerabilityID int64  `bun:"vulnerability_id,notnull"`
	StreamID        int64  `bun:"stream_id,notnull"`
	VariantID       int64  `bun:"variant_id,notnull"`
	Status          string `bun:"status,notnull"`
}

// releaseKey names one release of one issue in one product.
type releaseKey struct{ product, issue, stream, variant int64 }

// placed is every release of every issue the advisory covers, with its status,
// read through the handle given.
func placed(ctx context.Context, db bun.IDB, subject access.Subject,
	advisoryID int64) ([]Placed, error) {

	held, err := coveredBy(ctx, db, advisoryID)
	if err != nil {
		return nil, err
	}
	var out []Placed
	for _, one := range held {
		rows, err := releases(ctx, db, subject, advisoryID, one.ProductID, one.IssueID)
		if err != nil {
			return nil, err
		}
		for _, release := range rows {
			out = append(out, Placed{Covered: one, Release: release, Status: release.Status()})
		}
	}
	return out, nil
}

// Releases is every release of every issue the advisory covers, with what the
// document states about it, the decision it stands under, and whether that
// moved since an agreement standing on what the advisory says now.
func (s *Store) Releases(ctx context.Context, subject access.Subject,
	identifier string) ([]Placed, error) {

	row, err := s.byName(ctx, subject, identifier)
	if err != nil {
		return nil, err
	}
	out, err := placed(ctx, s.db, subject, row.ID)
	if err != nil {
		return nil, err
	}
	agreed, err := s.agreed(ctx, row)
	if err != nil || len(agreed) == 0 {
		return out, err
	}
	ids := make([]int64, 0, len(agreed))
	for _, one := range agreed {
		ids = append(ids, one.ID)
	}
	// Read as the issue each recorded row stands for, so an issue that
	// merged into another after the agreement is compared as the one it
	// merged into.
	var saw []struct {
		ApprovalID int64  `bun:"approval_id"`
		ProductID  int64  `bun:"product_id"`
		IssueID    int64  `bun:"issue_id"`
		StreamID   int64  `bun:"stream_id"`
		VariantID  int64  `bun:"variant_id"`
		Status     string `bun:"status"`
	}
	where, args := database.InAnyOf("ag.approval_id", ids)
	if err := s.db.NewSelect().
		TableExpr(`"advisory_agreed_status" AS "ag"`).
		Join(`JOIN "vulnerability" AS "sv" ON sv.id = ag.vulnerability_id`).
		ColumnExpr(`ag.approval_id AS "approval_id"`).
		ColumnExpr(`ag.product_id AS "product_id"`).
		ColumnExpr(`sv.issue_id AS "issue_id"`).
		ColumnExpr(`ag.stream_id AS "stream_id"`).
		ColumnExpr(`ag.variant_id AS "variant_id"`).
		ColumnExpr(`ag.status AS "status"`).
		Where(where, args...).Scan(ctx, &saw); err != nil {
		return nil, fmt.Errorf("read what the agreements saw: %w", err)
	}
	seen := make(map[int64]map[releaseKey]string, len(ids))
	for _, one := range saw {
		if seen[one.ApprovalID] == nil {
			seen[one.ApprovalID] = map[releaseKey]string{}
		}
		seen[one.ApprovalID][releaseKey{one.ProductID, one.IssueID,
			one.StreamID, one.VariantID}] = one.Status
	}
	// Against every agreement standing rather than the first: two people
	// agreeing a day apart can have seen two different documents, and either
	// of them is owed the difference.
	//
	// An agreement that recorded nothing was given before statuses were
	// recorded, and says nothing about what it saw. Compared, every release
	// of every advisory agreed to before the upgrade reads as changed.
	for i := range out {
		key := releaseKey{out[i].Covered.ProductID, out[i].Covered.IssueID,
			out[i].StreamID, out[i].VariantID}
		for _, id := range ids {
			if seen[id] != nil && seen[id][key] != out[i].Status {
				out[i].Changed = true
			}
		}
	}
	return out, nil
}

// recordSeen writes what every release stood at as one agreement is given,
// inside the transaction that gives it.
func recordSeen(ctx context.Context, tx bun.Tx, subject access.Subject,
	advisoryID, approvalID int64) error {

	now, err := placed(ctx, tx, subject, advisoryID)
	if err != nil {
		return err
	}
	rows := make([]agreedStatus, 0, len(now))
	for _, one := range now {
		rows = append(rows, agreedStatus{
			ApprovalID: approvalID, ProductID: one.Covered.ProductID, VulnerabilityID: one.Covered.IssueID,
			StreamID: one.StreamID, VariantID: one.VariantID, Status: one.Status,
		})
	}
	if len(rows) == 0 {
		return nil
	}
	return database.InBatches(ctx, tx, rows)
}

// MarkAffected marks one release of one issue the advisory covers as affected
// whatever its decisions say, or clears the mark.
//
// A decision reaches every build whose versions match, so one made about a
// variant where the code is compiled out also covers a variant where it is
// compiled in. The person preparing the advisory is the one who sees which
// variant it was made on beside the release it reaches, and says so here.
//
// Part of what the advisory says, so a change opens an edition and takes back
// every agreement standing, as retitling does. Asking for what already stands
// changes nothing and opens nothing.
func (s *Store) MarkAffected(ctx context.Context, subject access.Subject,
	advisory, product, identifier, stream, variant string, affected bool) error {

	row, err := s.byName(ctx, subject, advisory)
	if err != nil {
		return err
	}
	if err := s.mayWrite(ctx, subject, row, "mark a release affected"); err != nil {
		return err
	}
	named, err := catalog.NewStore(s.db).ProductByName(ctx, product)
	if err != nil {
		return err
	}
	if !triages(subject, named.ID) {
		return ErrNoSuchIssue
	}
	issue, _, err := s.ours(ctx, subject, named.ID, identifier)
	if err != nil {
		return err
	}
	held, err := s.covers(ctx, row)
	if err != nil {
		return err
	}
	covered := false
	for _, one := range held {
		covered = covered || (one.ProductID == named.ID && one.IssueID == issue.ID)
	}
	if !covered {
		return ErrNoSuchIssue
	}
	// The release resolved by the names the document gives it. A stream and a
	// variant are declared once and never renamed, so resolving them outside
	// the transaction reads nothing that moves.
	among, err := releases(ctx, s.db, subject, row.ID, named.ID, issue.ID)
	if err != nil {
		return err
	}
	var at *Release
	for i := range among {
		if catalog.Matching(among[i].Stream) == catalog.Matching(stream) &&
			catalog.Matching(among[i].Variant) == catalog.Matching(variant) {
			at = &among[i]
		}
	}
	if at == nil {
		return ErrNoSuchRelease
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		// Every mark on this release filed under any name of the issue, the
		// way the document reads them: a mark set before the issue merged
		// into another is the other's.
		const marks = `"advisory_id" = ? AND "product_id" = ?
			AND "vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "issue_id" = ?)
			AND "stream_id" = ? AND "variant_id" = ?`
		on := []any{row.ID, named.ID, issue.ID, at.StreamID, at.VariantID}
		var held []Override
		if err := tx.NewSelect().Model(&held).Where(marks, on...).
			OrderExpr("ao.id").Scan(ctx); err != nil {
			return err
		}
		standing := false
		var revive *Override
		for i := range held {
			if held[i].RemovedAt == nil {
				standing = true
			} else if revive == nil {
				revive = &held[i]
			}
		}
		switch {
		case standing == affected:
			return nil
		case affected && revive != nil:
			// Matched on still being cleared, and counted: two people
			// marking at once both read it cleared, and the second must not
			// open an edition for a change the first already made.
			result, err := tx.NewUpdate().Model((*Override)(nil)).
				Set("removed_at = NULL").Set("removed_by = NULL").
				Set("set_at = ?", now).Set("set_by = ?", subject.ID).
				Where("id = ?", revive.ID).
				Where("removed_at IS NOT NULL").Exec(ctx)
			if err != nil {
				return err
			}
			if n, err := database.Affected(result); err != nil || n == 0 {
				return err
			}
		case affected:
			if _, err := tx.NewInsert().Model(&Override{
				AdvisoryID: row.ID, ProductID: named.ID, VulnerabilityID: issue.ID,
				StreamID: at.StreamID, VariantID: at.VariantID,
				SetAt: now, SetBy: subject.ID,
			}).Exec(ctx); err != nil {
				// Two people marking one release at once both read nothing,
				// and the constraint is what refuses the second. Run again,
				// it finds the first one's mark standing and changes nothing.
				if database.IsDuplicate(err) {
					return database.ErrGoAgain
				}
				return err
			}
		default:
			// Counted for the reason reviving one is.
			result, err := tx.NewUpdate().Model((*Override)(nil)).
				Set("removed_at = ?", now).Set("removed_by = ?", subject.ID).
				Where(marks, on...).
				Where("removed_at IS NULL").Exec(ctx)
			if err != nil {
				return err
			}
			if n, err := database.Affected(result); err != nil || n == 0 {
				return err
			}
		}
		return reopen(ctx, tx, row, subject.ID, now)
	})
	switch {
	case errors.Is(err, ErrNoSuchRelease):
		return err
	case err != nil:
		return fmt.Errorf("mark a release affected: %w", err)
	}
	return nil
}
