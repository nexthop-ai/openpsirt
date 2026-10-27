// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// CodeFindingCollaborator is one person granted one code finding recorded as a flaw in one product.
//
// The grant is on the pair of product and occurrence, as a case collaborator's is
// on the pair of product and issue. It reads the code finding's evidence and nothing
// else of the product, at the internal and private visibilities, and only
// while the code finding's flaw is undisclosed: disclosure ends it, whether or not the
// code finding was included. An included code finding goes public with its flaw
// and an internal-only one stays internal.
type CodeFindingCollaborator struct {
	bun.BaseModel `bun:"table:code_finding_collaborator,alias:lc"`

	ID                 int64  `bun:"id,pk,autoincrement"`
	ProductID          int64  `bun:"product_id,notnull"`
	OccurrenceIdentity string `bun:"occurrence_identity,notnull"`
	PersonID           int64  `bun:"person_id,notnull"`
	AddedBy            int64  `bun:"added_by,notnull"`
	AddedAt            time.Time
	RemovedBy          *int64     `bun:"removed_by"`
	RemovedAt          *time.Time `bun:"removed_at"`
	// LivePerson carries the person again while the grant stands and is null
	// once it is withdrawn, so the database holds one live grant per person
	// per code finding.
	LivePerson *int64 `bun:"live_person_id"`
}

// codeFindingVisibilities is what a code finding grant reaches while the code finding's flaw is
// undisclosed. A code finding recorded as a flaw is internal until its flaw is disclosed,
// internal only or included in disclosure.
var codeFindingVisibilities = []Visibility{Internal}

// CodeFindingGrantVisibilities is what a code finding grant reaches, for a condition over
// findings.
func CodeFindingGrantVisibilities() []Visibility {
	return append([]Visibility(nil), codeFindingVisibilities...)
}

// AddToCodeFinding brings somebody onto one code finding, and reports whether it did. Adding
// somebody already on it reports false and changes nothing.
func (s *Store) AddToCodeFinding(ctx context.Context, productID int64, occurrenceIdentity string, personID,
	by int64) (bool, error) {

	row := &CodeFindingCollaborator{
		ProductID: productID, OccurrenceIdentity: occurrenceIdentity, PersonID: personID,
		AddedBy: by, AddedAt: s.now().Truncate(time.Microsecond),
		LivePerson: &personID,
	}
	return s.insertOnce(ctx, "bring them onto that code finding", row,
		func(ctx context.Context) (bool, error) {
			return s.onCodeFinding(ctx, productID, occurrenceIdentity, personID)
		})
}

// RemoveFromCodeFinding withdraws a code finding grant, keeping the row.
func (s *Store) RemoveFromCodeFinding(ctx context.Context, productID int64, occurrenceIdentity string,
	personID, by int64) error {

	now := s.now().Truncate(time.Microsecond)
	result, err := s.db.NewUpdate().Model((*CodeFindingCollaborator)(nil)).
		Set(`"removed_at" = ?`, now).
		Set(`"removed_by" = ?`, by).
		Set(`"live_person_id" = ?`, nil).
		Where(`"product_id" = ?`, productID).
		Where(`"occurrence_identity" = ?`, occurrenceIdentity).
		Where(`"person_id" = ?`, personID).
		Where(`"live_person_id" IS NOT NULL`).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("take them off that code finding: %w", err)
	}
	return matched(result, "take them off that code finding", "they are not on that code finding")
}

// CodeFindingRows is the standing grants on one code finding, oldest first.
func (s *Store) CodeFindingRows(ctx context.Context, productID int64, occurrenceIdentity string) ([]CodeFindingCollaborator, error) {
	var rows []CodeFindingCollaborator
	err := s.db.NewSelect().Model(&rows).
		Where(`"lc"."product_id" = ?`, productID).
		Where(`"lc"."occurrence_identity" = ?`, occurrenceIdentity).
		Where(`"lc"."live_person_id" IS NOT NULL`).
		OrderExpr(`"lc"."added_at", "lc"."id"`).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read who is on that code finding: %w", err)
	}
	return rows, nil
}

// CodeFindingsOf is every code finding one person is granted, as occurrences per product. Read
// where a person becomes a subject, beside their cases.
func (s *Store) CodeFindingsOf(ctx context.Context, personID int64) (map[int64][]string, error) {
	var rows []CodeFindingCollaborator
	err := s.db.NewSelect().Model(&rows).
		Column("lc.product_id", "lc.occurrence_identity").
		Where(`"lc"."person_id" = ?`, personID).
		Where(`"lc"."live_person_id" IS NOT NULL`).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read which code findings they are on: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	codeFindings := map[int64][]string{}
	for _, row := range rows {
		codeFindings[row.ProductID] = append(codeFindings[row.ProductID], row.OccurrenceIdentity)
	}
	return codeFindings, nil
}

// onCodeFinding says whether one person's grant on one code finding stands.
func (s *Store) onCodeFinding(ctx context.Context, productID int64, occurrenceIdentity string,
	personID int64) (bool, error) {

	on, err := s.db.NewSelect().Model((*CodeFindingCollaborator)(nil)).
		Column("lc.id").
		Where(`"lc"."product_id" = ?`, productID).
		Where(`"lc"."occurrence_identity" = ?`, occurrenceIdentity).
		Where(`"lc"."person_id" = ?`, personID).
		Where(`"lc"."live_person_id" IS NOT NULL`).
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether they are on that code finding: %w", err)
	}
	return on, nil
}
