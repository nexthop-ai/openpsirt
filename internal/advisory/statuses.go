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
	var saw []agreedStatus
	where, args := database.InAnyOf("ag.approval_id", ids)
	if err := s.db.NewSelect().Model(&saw).Where(where, args...).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what the agreements saw: %w", err)
	}
	seen := make(map[int64]map[releaseKey]string, len(ids))
	for _, id := range ids {
		seen[id] = map[releaseKey]string{}
	}
	for _, one := range saw {
		seen[one.ApprovalID][releaseKey{one.ProductID, one.VulnerabilityID,
			one.StreamID, one.VariantID}] = one.Status
	}
	// Against every agreement standing rather than the first: two people
	// agreeing a day apart can have seen two different documents, and either
	// of them is owed the difference.
	for i := range out {
		key := releaseKey{out[i].Covered.ProductID, out[i].Covered.IssueID, out[i].StreamID, out[i].VariantID}
		for _, id := range ids {
			if seen[id][key] != out[i].Status {
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
		var mark Override
		err := tx.NewSelect().Model(&mark).
			Where("advisory_id = ?", row.ID).
			Where("product_id = ?", named.ID).
			Where("vulnerability_id = ?", issue.ID).
			Where("stream_id = ?", at.StreamID).
			Where("variant_id = ?", at.VariantID).
			Limit(1).Scan(ctx)
		found := err == nil
		if err != nil && !database.IsNoRows(err) {
			return err
		}
		standing := found && mark.RemovedAt == nil
		switch {
		case standing == affected:
			return nil
		case affected && found:
			if _, err := tx.NewUpdate().Model((*Override)(nil)).
				Set("removed_at = NULL").Set("removed_by = NULL").
				Set("set_at = ?", now).Set("set_by = ?", subject.ID).
				Where("id = ?", mark.ID).Exec(ctx); err != nil {
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
			if _, err := tx.NewUpdate().Model((*Override)(nil)).
				Set("removed_at = ?", now).Set("removed_by = ?", subject.ID).
				Where("id = ?", mark.ID).
				Where("removed_at IS NULL").Exec(ctx); err != nil {
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
