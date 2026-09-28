// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/filed"
)

// sameCase is the condition that a grant's issue column names the issue bound
// in its one placeholder: the same issue, or one merged into it.
func sameCase(column string) string { return filed.Under(column) }

// Collaborator is one person brought into one undisclosed case.
//
// The grant is on the pair of product and issue rather than on the product:
// they see that issue everywhere it sits in that product and nothing else —
// not the rest of the embargo list, and not a count of it. The case it exists
// for is the engineer who normally sees only public findings and is needed on
// one embargoed flaw in their own component.
//
// It grants reading and arguing, never approving. Two collaborators could
// otherwise satisfy the two people a dismissal on an embargoed finding asks
// for, with nobody accountable for the product involved — the rule met in form
// and defeated in substance.
type Collaborator struct {
	bun.BaseModel `bun:"table:case_collaborator,alias:cc"`

	ID              int64 `bun:"id,pk,autoincrement"`
	ProductID       int64 `bun:"product_id,notnull"`
	VulnerabilityID int64 `bun:"vulnerability_id,notnull"`
	PersonID        int64 `bun:"person_id,notnull"`
	AddedBy         int64 `bun:"added_by,notnull"`
	AddedAt         time.Time
	RemovedBy       *int64     `bun:"removed_by"`
	RemovedAt       *time.Time `bun:"removed_at"`
	// LivePerson carries the person again while the grant stands and is null
	// once it is withdrawn, which is how "one live grant per person per case"
	// is enforced by the database rather than by a check somebody remembers.
	LivePerson *int64 `bun:"live_person_id"`
}

// AddToCase brings somebody into one case, and reports whether it did.
//
// Adding somebody who is already on it is not a failure: the unique index
// refuses the second row, and the state the caller asked for is the state that
// holds. It reports false, because nothing changed, so the caller neither
// records nor announces a grant that already stood.
func (s *Store) AddToCase(ctx context.Context, productID, vulnerabilityID, personID,
	by int64) (bool, error) {

	row := &Collaborator{
		ProductID: productID, VulnerabilityID: vulnerabilityID, PersonID: personID,
		AddedBy: by, AddedAt: s.now().Truncate(time.Microsecond),
		LivePerson: &personID,
	}
	return s.insertOnce(ctx, "bring them into that case", row,
		func(ctx context.Context) (bool, error) {
			// A live grant, which is what the index holds one of per person per
			// case: a withdrawn row keeps the record and grants nothing, so it
			// is not a reason to report success.
			return s.onCase(ctx, productID, vulnerabilityID, personID)
		})
}

// RemoveFromCase withdraws the grant, keeping the row.
//
// Withdrawn rather than deleted, like every other grant: who could see an
// embargoed case, and when, is exactly the question asked afterwards.
func (s *Store) RemoveFromCase(ctx context.Context, productID, vulnerabilityID, personID,
	by int64) error {

	now := s.now().Truncate(time.Microsecond)
	result, err := s.db.NewUpdate().Model((*Collaborator)(nil)).
		Set("removed_at = ?", now).
		Set("removed_by = ?", by).
		Set("live_person_id = ?", nil).
		Where("product_id = ?", productID).
		Where(sameCase("vulnerability_id"), vulnerabilityID).
		Where("person_id = ?", personID).
		Where("live_person_id IS NOT NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("take them off that case: %w", err)
	}
	return matched(result, "take them off that case", "they are not on that case")
}

// OnCase lists who is on one case, as person identifiers, oldest first.
func (s *Store) OnCase(ctx context.Context, productID, vulnerabilityID int64) ([]int64, error) {
	var people []int64
	err := s.db.NewSelect().Model((*Collaborator)(nil)).
		ColumnExpr("cc.person_id").
		Where("cc.product_id = ?", productID).
		Where(sameCase("cc.vulnerability_id"), vulnerabilityID).
		Where("cc.live_person_id IS NOT NULL").
		OrderExpr("cc.added_at, cc.id").
		Scan(ctx, &people)
	if err != nil {
		return nil, fmt.Errorf("read who is on that case: %w", err)
	}
	return people, nil
}

// CasesOf is every case one person is on, as issues per product.
//
// Read where a person becomes a subject, beside their roles and their teams,
// because "may they reach this issue" is asked by the finding, its decisions,
// its comments and its attachments — and a lookup at each of those is four
// answers that can disagree.
func (s *Store) CasesOf(ctx context.Context, personID int64) (map[int64][]int64, error) {
	var rows []Collaborator
	// Every issue read as the one the grant names: the issue that stands and
	// every issue merged into it. A finding is filed under the issue that
	// stands, and a decision, note or attachment under whichever issue it was
	// made against, so the grant reaches each of them by the issue it states.
	err := s.db.NewSelect().Model(&rows).
		Column("cc.product_id").
		ColumnExpr(`"mv"."id" AS "vulnerability_id"`).
		Join(`JOIN "vulnerability" AS "ci" ON "ci"."id" = "cc"."vulnerability_id"`).
		Join(`JOIN "vulnerability" AS "mv" ON "mv"."issue_id" = "ci"."issue_id"`).
		Where("cc.person_id = ?", personID).
		Where("cc.live_person_id IS NOT NULL").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read which cases they are on: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	cases := map[int64][]int64{}
	seen := map[[2]int64]bool{}
	for _, row := range rows {
		key := [2]int64{row.ProductID, row.VulnerabilityID}
		if seen[key] {
			continue
		}
		seen[key] = true
		cases[row.ProductID] = append(cases[row.ProductID], row.VulnerabilityID)
	}
	return cases, nil
}

// onCase says whether one person's grant on one case stands.
func (s *Store) onCase(ctx context.Context, productID, vulnerabilityID,
	personID int64) (bool, error) {

	on, err := s.db.NewSelect().Model((*Collaborator)(nil)).
		Column("cc.id").
		Where("cc.product_id = ?", productID).
		Where(sameCase("cc.vulnerability_id"), vulnerabilityID).
		Where("cc.person_id = ?", personID).
		Where("cc.live_person_id IS NOT NULL").
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether they are on that case: %w", err)
	}
	return on, nil
}

// CaseRows is the standing grants on one case, for a screen that needs who
// brought each person in and when.
func (s *Store) CaseRows(ctx context.Context, productID,
	vulnerabilityID int64) ([]Collaborator, error) {

	var rows []Collaborator
	err := s.db.NewSelect().Model(&rows).
		Where("product_id = ?", productID).
		Where(sameCase("vulnerability_id"), vulnerabilityID).
		Where("live_person_id IS NOT NULL").
		Order("added_at", "id").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read who is on that case: %w", err)
	}
	return rows, nil
}
