package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Record is how much of the triage record one person is responsible for.
//
// Counted rather than listed. What a person page answers is the shape of
// somebody's part in the record — whether they propose and never approve,
// whether a withdrawn agreement of theirs is still standing behind others —
// and the lists behind each number are the record's own screens, narrowed the
// way that screen narrows.
type Record struct {
	// Proposed is how many claims they argued.
	Proposed int
	// Approved is how many claims they agreed to that still stand, and
	// Withdrawn how many they agreed to and later took back. Two numbers
	// rather than one: an agreement taken back is not somebody who agrees,
	// and the record's own file already says so.
	Approved  int
	Withdrawn int
	// LastProposedAt and LastApprovedAt are when they last did either, or
	// absent where they never have. What separates somebody who has stopped
	// from somebody who never started, which a count of zero cannot.
	LastProposedAt *time.Time
	LastApprovedAt *time.Time
}

// RecordOf reads one person's part in the triage record.
//
// **For an administrator alone.** It counts across every product without
// narrowing, which is the only way the question is answerable — a
// concentration signal computed over the products the reader happens to hold
// is not the signal. Enforced here, where the rest of this store's rules are
// (REQ-42).
func (s *Store) RecordOf(ctx context.Context, subject access.Subject, personID int64) (Record, error) {
	if !subject.Admin || subject.Kind != access.Person {
		return Record{}, access.Denied("read somebody else's part in the record")
	}
	var out Record

	proposed, err := s.db.NewSelect().Model((*Claim)(nil)).
		Where("proposed_by = ?", personID).Count(ctx)
	if err != nil {
		return Record{}, fmt.Errorf("count what they proposed: %w", err)
	}
	out.Proposed = proposed
	if proposed > 0 {
		var at time.Time
		if err := s.db.NewSelect().Model((*Claim)(nil)).
			ColumnExpr("MAX(proposed_at)").
			Where("proposed_by = ?", personID).Scan(ctx, &at); err != nil {
			return Record{}, fmt.Errorf("read when they last proposed: %w", err)
		}
		out.LastProposedAt = &at
	}

	approved, err := s.db.NewSelect().Model((*Approval)(nil)).
		Where("approved_by = ?", personID).Where("withdrawn_at IS NULL").Count(ctx)
	if err != nil {
		return Record{}, fmt.Errorf("count what they agreed to: %w", err)
	}
	out.Approved = approved

	withdrawn, err := s.db.NewSelect().Model((*Approval)(nil)).
		Where("approved_by = ?", personID).Where("withdrawn_at IS NOT NULL").Count(ctx)
	if err != nil {
		return Record{}, fmt.Errorf("count what they took back: %w", err)
	}
	out.Withdrawn = withdrawn

	if approved+withdrawn > 0 {
		var at time.Time
		if err := s.db.NewSelect().Model((*Approval)(nil)).
			ColumnExpr("MAX(approved_at)").
			Where("approved_by = ?", personID).Scan(ctx, &at); err != nil {
			return Record{}, fmt.Errorf("read when they last agreed: %w", err)
		}
		out.LastApprovedAt = &at
	}
	return out, nil
}
