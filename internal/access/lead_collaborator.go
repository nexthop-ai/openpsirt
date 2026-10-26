// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// LeadCollaborator is one person granted one handed-off lead in one product.
//
// The grant is on the pair of product and place, as a case collaborator's is
// on the pair of product and issue. It reads the lead's evidence and nothing
// else of the product, at the internal and private visibilities, and only
// while the lead's flaw is undisclosed: disclosure ends it, kept lead or
// moved. A moved lead goes public with its flaw and a kept one stays
// internal.
type LeadCollaborator struct {
	bun.BaseModel `bun:"table:lead_collaborator,alias:lc"`

	ID            int64  `bun:"id,pk,autoincrement"`
	ProductID     int64  `bun:"product_id,notnull"`
	PlaceIdentity string `bun:"place_identity,notnull"`
	PersonID      int64  `bun:"person_id,notnull"`
	AddedBy       int64  `bun:"added_by,notnull"`
	AddedAt       time.Time
	RemovedBy     *int64     `bun:"removed_by"`
	RemovedAt     *time.Time `bun:"removed_at"`
	// LivePerson carries the person again while the grant stands and is null
	// once it is withdrawn, so the database holds one live grant per person
	// per lead.
	LivePerson *int64 `bun:"live_person_id"`
}

// leadVisibilities is what a lead grant reaches while the lead's flaw is
// undisclosed: a kept lead and a moved one.
var leadVisibilities = []Visibility{Internal, Private}

// LeadGrantVisibilities is what a lead grant reaches, for a condition over
// findings.
func LeadGrantVisibilities() []Visibility { return append([]Visibility(nil), leadVisibilities...) }

// AddToLead brings somebody onto one lead, and reports whether it did. Adding
// somebody already on it reports false and changes nothing.
func (s *Store) AddToLead(ctx context.Context, productID int64, placeIdentity string, personID,
	by int64) (bool, error) {

	row := &LeadCollaborator{
		ProductID: productID, PlaceIdentity: placeIdentity, PersonID: personID,
		AddedBy: by, AddedAt: s.now().Truncate(time.Microsecond),
		LivePerson: &personID,
	}
	return s.insertOnce(ctx, "bring them onto that lead", row,
		func(ctx context.Context) (bool, error) {
			return s.onLead(ctx, productID, placeIdentity, personID)
		})
}

// RemoveFromLead withdraws a lead grant, keeping the row.
func (s *Store) RemoveFromLead(ctx context.Context, productID int64, placeIdentity string,
	personID, by int64) error {

	now := s.now().Truncate(time.Microsecond)
	result, err := s.db.NewUpdate().Model((*LeadCollaborator)(nil)).
		Set(`"removed_at" = ?`, now).
		Set(`"removed_by" = ?`, by).
		Set(`"live_person_id" = ?`, nil).
		Where(`"product_id" = ?`, productID).
		Where(`"place_identity" = ?`, placeIdentity).
		Where(`"person_id" = ?`, personID).
		Where(`"live_person_id" IS NOT NULL`).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("take them off that lead: %w", err)
	}
	return matched(result, "take them off that lead", "they are not on that lead")
}

// LeadRows is the standing grants on one lead, oldest first.
func (s *Store) LeadRows(ctx context.Context, productID int64, placeIdentity string) ([]LeadCollaborator, error) {
	var rows []LeadCollaborator
	err := s.db.NewSelect().Model(&rows).
		Where(`"lc"."product_id" = ?`, productID).
		Where(`"lc"."place_identity" = ?`, placeIdentity).
		Where(`"lc"."live_person_id" IS NOT NULL`).
		OrderExpr(`"lc"."added_at", "lc"."id"`).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read who is on that lead: %w", err)
	}
	return rows, nil
}

// LeadsOf is every lead one person is granted, as places per product. Read
// where a person becomes a subject, beside their cases.
func (s *Store) LeadsOf(ctx context.Context, personID int64) (map[int64][]string, error) {
	var rows []LeadCollaborator
	err := s.db.NewSelect().Model(&rows).
		Column("lc.product_id", "lc.place_identity").
		Where(`"lc"."person_id" = ?`, personID).
		Where(`"lc"."live_person_id" IS NOT NULL`).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read which leads they are on: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	leads := map[int64][]string{}
	for _, row := range rows {
		leads[row.ProductID] = append(leads[row.ProductID], row.PlaceIdentity)
	}
	return leads, nil
}

// onLead says whether one person's grant on one lead stands.
func (s *Store) onLead(ctx context.Context, productID int64, placeIdentity string,
	personID int64) (bool, error) {

	on, err := s.db.NewSelect().Model((*LeadCollaborator)(nil)).
		Column("lc.id").
		Where(`"lc"."product_id" = ?`, productID).
		Where(`"lc"."place_identity" = ?`, placeIdentity).
		Where(`"lc"."person_id" = ?`, personID).
		Where(`"lc"."live_person_id" IS NOT NULL`).
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether they are on that lead: %w", err)
	}
	return on, nil
}
