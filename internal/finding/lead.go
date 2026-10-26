// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// LeadAt is the finding a lead is on one build, where the subject may read
// it: the open one, or the newest where none is open. A lead nobody may read
// here and a lead that is not here are both ErrNoOpenFinding.
func (s *Store) LeadAt(ctx context.Context, subject access.Subject, targetID int64, placeIdentity string) (*Finding, error) {
	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	reach := LeadReach(subject, productID)
	return s.leadWhere(ctx, targetID, placeIdentity, reach.Full, reach.FullArgs)
}

// LeadOrStubAt is LeadAt for a read of the lead's evidence, and reports
// whether the subject reads it only as a stub: the lead without the case
// (LeadReading).
func (s *Store) LeadOrStubAt(ctx context.Context, subject access.Subject, targetID int64,
	placeIdentity string) (*Finding, bool, error) {

	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, false, err
	}
	reach := LeadReach(subject, productID)
	lead, err := s.leadWhere(ctx, targetID, placeIdentity, reach.Full, reach.FullArgs)
	if !errors.Is(err, ErrNoOpenFinding) {
		return lead, false, err
	}
	lead, err = s.leadWhere(ctx, targetID, placeIdentity, reach.Stub, reach.StubArgs)
	return lead, err == nil, err
}

// leadWhere is the lead at a place on one build that a condition admits.
func (s *Store) leadWhere(ctx context.Context, targetID int64, placeIdentity string,
	reads string, readArgs []any) (*Finding, error) {

	kinds, kindArgs := kind.Evidence.Where(`"f"."kind"`)
	var lead Finding
	err := s.db.NewSelect().Model(&lead).
		Where(`"f"."target_id" = ?`, targetID).
		Where(`"f"."place_identity" = ?`, placeIdentity).
		Where(reads, readArgs...).
		Where(kinds, kindArgs...).
		OrderExpr(`CASE WHEN "f"."closed_at" IS NULL THEN 0 ELSE 1 END ASC, "f"."id" DESC`).
		Limit(1).Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrNoOpenFinding
	case err != nil:
		return nil, fmt.Errorf("read the lead at that place: %w", err)
	}
	return &lead, nil
}

// ErrStillSeen says a lead a run still sees is not stated fixed.
var ErrStillSeen = refusal.New("the newest comparable run still sees this lead, so it is not fixed here")

// FixLead closes a lead on one build because somebody states it is fixed
// there. The lead has to be one a comparable run no longer sees: that absence
// is the evidence the statement is made with, and a run still reporting the
// result is the authority on what it found. A lead seen again opens anew at
// the same place.
func (s *Store) FixLead(ctx context.Context, subject access.Subject, targetID int64,
	placeIdentity, because string) (*Resolved, error) {

	because = strings.TrimSpace(because)
	if because == "" {
		return nil, ErrNoReason
	}
	if err := markdown.Check(because); err != nil {
		return nil, err
	}
	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	out := &Resolved{}
	err = database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		now := s.now().UTC().Truncate(time.Microsecond)
		out.At, out.Closed = now, 0
		kinds, kindArgs := kind.Evidence.Where(`"f"."kind"`)
		var lead struct {
			ID         int64             `bun:"id"`
			Visibility access.Visibility `bun:"visibility"`
			Absent     *int64            `bun:"absent_run_id"`
		}
		err := tx.NewSelect().TableExpr(`"finding" AS "f"`).
			Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
			ColumnExpr(`"f"."id", "f"."visibility", "si"."absent_run_id"`).
			Where(`"f"."target_id" = ?`, targetID).
			Where(`"f"."place_identity" = ?`, placeIdentity).
			Where(`"f"."closed_at" IS NULL`).
			Where(kinds, kindArgs...).
			Limit(1).Scan(ctx, &lead)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return ErrNothingOpenThere
		case err != nil:
			return fmt.Errorf("read the lead at that place: %w", err)
		}
		// A lead somebody may not read is one they are not told of.
		if !subject.Reads(lead.Visibility, productID) {
			return ErrNothingOpenThere
		}
		if !subject.Triages(lead.Visibility, productID) {
			return access.Denied(fmt.Sprintf("close a lead in product %d", productID))
		}
		if lead.Absent == nil {
			return ErrStillSeen
		}
		if err := LeadEnded(ctx, tx, productID, placeIdentity, now); err != nil {
			return err
		}
		result, err := tx.NewUpdate().Model((*Finding)(nil)).
			Set(`"closed_at" = ?`, now).
			Set(`"closed_by" = ?`, subject.ID).
			Set(`"closed_note" = ?`, because).
			Set(`"closed_because" = ?`, Fixed).
			Where(`"id" = ?`, lead.ID).
			Where(`"closed_at" IS NULL`).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("close lead %d: %w", lead.ID, err)
		}
		affected, err := database.Affected(result)
		if err != nil {
			return fmt.Errorf("close lead %d: %w", lead.ID, err)
		}
		out.Closed = int(affected)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ErrLeadPastEndOfLife refuses a change to a lead every release it was seen
// in is past its end of life. It is kept as it stands.
var ErrLeadPastEndOfLife = refusal.New("every release this lead was seen in is past its end of life, so it is kept as it stands")

// LeadEnded refuses, with ErrLeadPastEndOfLife, a change to the lead at a
// place in a product where every release it was seen in is past its end of
// life at now. A lead seen nowhere is left to the caller's own answer.
func LeadEnded(ctx context.Context, db bun.IDB, productID int64, placeIdentity string, now time.Time) error {
	kinds, kindArgs := kind.Leads.Where(`"f"."kind"`)
	var streams []int64
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "t" ON "t"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
		ColumnExpr(`DISTINCT "t"."stream_id"`).
		Where(`"s"."product_id" = ?`, productID).
		Where(`"f"."place_identity" = ?`, placeIdentity).
		Where(kinds, kindArgs...).
		Scan(ctx, &streams); err != nil {
		return fmt.Errorf("read the releases a lead was seen in: %w", err)
	}
	if len(streams) == 0 {
		return nil
	}
	ended, err := catalog.NewStore(db).StreamsPastEndOfLife(ctx, now)
	if err != nil {
		return err
	}
	for _, id := range streams {
		if !slices.Contains(ended, id) {
			return nil
		}
	}
	return ErrLeadPastEndOfLife
}
