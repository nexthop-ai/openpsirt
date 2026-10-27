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
	"github.com/nexthop-ai/openpsirt/internal/series"
)

// CodeFindingAt is the finding a code finding is on one build, where the subject may read
// it: the open one, or the newest where none is open. A code finding nobody may read
// here and a code finding that is not here are both ErrNoOpenFinding.
func (s *Store) CodeFindingAt(ctx context.Context, subject access.Subject, targetID int64, occurrenceIdentity string) (*Finding, error) {
	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	reach := CodeFindingReach(subject, productID)
	return s.codeFindingWhere(ctx, targetID, occurrenceIdentity, reach.Full, reach.FullArgs)
}

// codeFindingWhere is the code finding at an occurrence on one build that a condition admits.
func (s *Store) codeFindingWhere(ctx context.Context, targetID int64, occurrenceIdentity string,
	reads string, readArgs []any) (*Finding, error) {

	kinds, kindArgs := kind.Evidence.Where(`"f"."kind"`)
	var codeFinding Finding
	err := s.db.NewSelect().Model(&codeFinding).
		Where(`"f"."target_id" = ?`, targetID).
		Where(`"f"."occurrence_identity" = ?`, occurrenceIdentity).
		Where(reads, readArgs...).
		Where(kinds, kindArgs...).
		OrderExpr(`CASE WHEN "f"."closed_at" IS NULL THEN 0 ELSE 1 END ASC, "f"."id" DESC`).
		Limit(1).Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrNoOpenFinding
	case err != nil:
		return nil, fmt.Errorf("read the code finding at that occurrence: %w", err)
	}
	return &codeFinding, nil
}

// ErrStillSeen says a code finding a run still sees is not stated fixed.
var ErrStillSeen = refusal.New("the newest comparable run still sees this code finding, so it is not fixed here")

// ErrNotAFixingRun refuses a statement that a code finding was fixed in a build no
// run of its series on that build left it out of.
var ErrNotAFixingRun = refusal.New("name the run whose build fixed it: a comparable run of the code finding's series " +
	"on this build, at or after the first that did not see it")

// FixCodeFinding closes a code finding on one build because somebody states it is fixed
// there, naming the run whose build fixed it. The code finding has to be one a
// comparable run no longer sees: that absence is the evidence the statement is
// made with, and a run still reporting the result is the authority on what it
// found. The run named is one of the code finding's series on the build, applied and
// comparable, built at or after the first run that did not see it. A code finding seen
// again opens anew at the same occurrence.
func (s *Store) FixCodeFinding(ctx context.Context, subject access.Subject, targetID int64,
	occurrenceIdentity, because string, fixedIn int64) (*Resolved, error) {

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
		var codeFinding struct {
			ID         int64             `bun:"id"`
			Visibility access.Visibility `bun:"visibility"`
			Absent     *int64            `bun:"absent_run_id"`
			Series     int64             `bun:"series_id"`
		}
		err := tx.NewSelect().TableExpr(`"finding" AS "f"`).
			Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
			ColumnExpr(`"f"."id", "f"."visibility", "si"."absent_run_id", "si"."series_id"`).
			Where(`"f"."target_id" = ?`, targetID).
			Where(`"f"."occurrence_identity" = ?`, occurrenceIdentity).
			Where(`"f"."closed_at" IS NULL`).
			Where(kinds, kindArgs...).
			Limit(1).Scan(ctx, &codeFinding)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return ErrNothingOpenThere
		case err != nil:
			return fmt.Errorf("read the code finding at that occurrence: %w", err)
		}
		// A code finding somebody may not read is one they are not told of.
		if !subject.Reads(codeFinding.Visibility, productID) {
			return ErrNothingOpenThere
		}
		if !subject.Triages(codeFinding.Visibility, productID) {
			return access.Denied(fmt.Sprintf("close a code finding in product %d", productID))
		}
		if codeFinding.Absent == nil {
			return ErrStillSeen
		}
		fixing, err := tx.NewSelect().TableExpr(`"series_run" AS "sr"`).
			Join(`JOIN "series_run" AS "ab" ON "ab"."id" = ?`, *codeFinding.Absent).
			Where(`"sr"."id" = ?`, fixedIn).
			Where(`"sr"."series_id" = ?`, codeFinding.Series).
			Where(`"sr"."target_id" = ?`, targetID).
			Where(`"sr"."status" = ?`, series.Applied).
			Where(`"sr"."comparable" = ?`, true).
			Where(`"sr"."built_at" >= "ab"."built_at"`).
			Exists(ctx)
		if err != nil {
			return fmt.Errorf("read the run the code finding was fixed in: %w", err)
		}
		if !fixing {
			return ErrNotAFixingRun
		}
		if err := CodeFindingEnded(ctx, tx, productID, occurrenceIdentity, now); err != nil {
			return err
		}
		result, err := tx.NewUpdate().Model((*Finding)(nil)).
			Set(`"closed_at" = ?`, now).
			Set(`"closed_by" = ?`, subject.ID).
			Set(`"closed_note" = ?`, because).
			Set(`"closed_because" = ?`, Fixed).
			Where(`"id" = ?`, codeFinding.ID).
			Where(`"closed_at" IS NULL`).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("close code finding %d: %w", codeFinding.ID, err)
		}
		affected, err := database.Affected(result)
		if err != nil {
			return fmt.Errorf("close code finding %d: %w", codeFinding.ID, err)
		}
		out.Closed = int(affected)
		if _, err := tx.NewUpdate().Model((*series.Sighting)(nil)).
			Set(`"fixed_run_id" = ?`, fixedIn).
			Where(`"finding_id" = ?`, codeFinding.ID).
			Exec(ctx); err != nil {
			return fmt.Errorf("record the build code finding %d was fixed in: %w", codeFinding.ID, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ErrCodeFindingPastEndOfLife refuses a change to a code finding every release it was seen
// in is past its end of life. It is kept as it stands.
var ErrCodeFindingPastEndOfLife = refusal.New("every release this code finding was seen in is past its end of life, so it is kept as it stands")

// CodeFindingInSupport is the condition, as SQL, under which CodeFindingEnded accepts a
// change to the code finding at an occurrence in a product at a moment: the occurrence
// holds no code finding, or a code finding of it is in a release not past its end of life. The
// product and the occurrence are columns of the caller's query, quoted as it
// names them.
func CodeFindingInSupport(product, occurrence string, at time.Time) (string, []any) {
	kinds, kindArgs := kind.CodeFindings.Where(`"lsf"."kind"`)
	past, pastArgs := catalog.PastEndOfLife("lss", "lsp", at)
	seen := `SELECT 1 FROM "finding" AS "lsf"
		JOIN "target" AS "lst" ON "lst"."id" = "lsf"."target_id"
		JOIN "stream" AS "lss" ON "lss"."id" = "lst"."stream_id"
		JOIN "product" AS "lsp" ON "lsp"."id" = "lss"."product_id"
		WHERE "lss"."product_id" = ` + product + ` AND "lsf"."occurrence_identity" = ` + occurrence + ` AND ` + kinds
	args := append(slices.Clone(kindArgs), kindArgs...)
	args = append(args, pastArgs...)
	return `(NOT EXISTS (` + seen + `) OR EXISTS (` + seen + ` AND NOT ` + past + `))`, args
}

// CodeFindingEnded refuses, with ErrCodeFindingPastEndOfLife, a change to the code finding at an
// occurrence in a product where every release it was seen in is past its end of
// life at now. A code finding seen nowhere is left to the caller's own answer.
func CodeFindingEnded(ctx context.Context, db bun.IDB, productID int64, occurrenceIdentity string, now time.Time) error {
	kinds, kindArgs := kind.CodeFindings.Where(`"f"."kind"`)
	var streams []int64
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "t" ON "t"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
		ColumnExpr(`DISTINCT "t"."stream_id"`).
		Where(`"s"."product_id" = ?`, productID).
		Where(`"f"."occurrence_identity" = ?`, occurrenceIdentity).
		Where(kinds, kindArgs...).
		Scan(ctx, &streams); err != nil {
		return fmt.Errorf("read the releases a code finding was seen in: %w", err)
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
	return ErrCodeFindingPastEndOfLife
}

// ErrCodeFindingRecordedAsFlaw refuses a change to who holds a code finding recorded as a flaw.
// It is closed work for its holder: its flaw is held as itself.
var ErrCodeFindingRecordedAsFlaw = refusal.New("that code finding was recorded as a flaw, so its flaw is assigned instead")

// AssignCodeFinding records who is dealing with a code finding, across every build of the
// product it is seen on, or hands it back to nobody where to is nil. Admits
// is asked whether the party may hold work of every visibility open at the
// code finding, in the transaction that moves it. Nil admits any party.
//
// The grain is the code finding, which is its occurrence in the product: a decision
// about it covers every stream and variant it is seen on, and so does whoever
// works it. The write is the one every finding is handed over through, under
// the same rule about who may move what: taking a code finding nobody holds and handing
// back your own is triage at the code finding's visibility, and giving it to somebody
// else or taking it from them asks for assigner beside it.
//
// The visibilities other than public among what moved come back, each once,
// which decides what may be said about the act outside the application.
func (s *Store) AssignCodeFinding(ctx context.Context, subject access.Subject, targetID int64,
	occurrenceIdentity string, to *int64, admits Admits) (moved int64, withheld []access.Visibility, err error) {

	err = database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		moved, withheld = 0, nil
		inner := &Store{db: tx, now: s.now, reach: s.reach}
		var err error
		moved, withheld, err = inner.assignCodeFinding(ctx, subject, targetID, occurrenceIdentity, to, admits)
		return err
	})
	return moved, withheld, err
}

// assignCodeFinding is AssignCodeFinding inside the transaction it opened.
func (s *Store) assignCodeFinding(ctx context.Context, subject access.Subject, targetID int64,
	occurrenceIdentity string, to *int64, admits Admits) (int64, []access.Visibility, error) {

	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return 0, nil, err
	}
	visible := access.Visible(subject, productID)
	if !subject.Sees(productID) || len(visible) == 0 {
		return 0, nil, ErrNothingOpenThere
	}
	naming := oneCodeFinding(productID, occurrenceIdentity)
	var open []access.Visibility
	if err := naming(s.db.NewSelect().Model((*Finding)(nil)).ColumnExpr(`DISTINCT "visibility"`)).
		Where(`"closed_at" IS NULL`).
		Where(`"visibility" IN (?)`, bun.List(visible)).
		Scan(ctx, &open); err != nil {
		return 0, nil, fmt.Errorf("read the code finding at that occurrence: %w", err)
	}
	// A code finding somebody may not read is one they are not told of.
	if len(open) == 0 {
		return 0, nil, ErrNothingOpenThere
	}
	for _, v := range open {
		if !subject.Triages(v, productID) {
			return 0, nil, access.Denied(fmt.Sprintf(
				"decide who deals with a code finding in product %d", productID))
		}
	}
	if err := CodeFindingEnded(ctx, s.db, productID, occurrenceIdentity, s.now().UTC()); err != nil {
		return 0, nil, err
	}
	recordedAsFlaw, err := s.db.NewSelect().Model((*CodeFindingFlaw)(nil)).
		Where(`"product_id" = ?`, productID).Where(`"occurrence_identity" = ?`, occurrenceIdentity).Exists(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("read whether that code finding was recorded as a flaw: %w", err)
	}
	if recordedAsFlaw {
		return 0, nil, ErrCodeFindingRecordedAsFlaw
	}
	dispatches := subject.Holds(access.Assigner, productID)
	if err := mayMove(subject, productID, to, dispatches); err != nil {
		return 0, nil, err
	}
	if to != nil && admits != nil {
		held, err := withheldAmong(ctx, s.db, visible, naming)
		if err != nil {
			return 0, nil, fmt.Errorf("read how far this code finding is disclosed: %w", err)
		}
		if err := admits(ctx, s.db, held); err != nil {
			return 0, nil, err
		}
	}

	moved, err := s.moveWhere(ctx, s.db, subject, productID, to, dispatches,
		func(q *bun.UpdateQuery) *bun.UpdateQuery {
			kinds, kindArgs := kind.CodeFindings.Where(`"kind"`)
			return q.Where(kinds, kindArgs...).Where(`"occurrence_identity" = ?`, occurrenceIdentity)
		})
	if err != nil {
		return 0, nil, err
	}
	if moved == 0 {
		// Nothing moved: nothing open, or somebody else holds it and this
		// caller may not take it. Asked on the failing path only, over what
		// the caller may read.
		if !dispatches {
			held, err := naming(s.db.NewSelect().Model((*Finding)(nil)).Column("id")).
				Where(`"closed_at" IS NULL`).
				Where(`"visibility" IN (?)`, bun.List(visible)).
				Where(`"assigned_to" IS NOT NULL`).
				Where(`"assigned_to" NOT IN (?)`, bun.List(subject.Mine())).
				Exists(ctx)
			if err != nil {
				return 0, nil, fmt.Errorf("read who is dealing with this code finding: %w", err)
			}
			if held {
				return 0, nil, heldElsewhere(productID)
			}
		}
		return 0, nil, nil
	}
	// Asked of every visibility rather than of what the caller may read: what
	// moved carries its visibility to whoever now holds it.
	withheld, err := withheldAmong(ctx, s.db, access.Visibilities(), naming)
	if err != nil {
		return moved, nil, fmt.Errorf("read whether that code finding is disclosed: %w", err)
	}
	return moved, withheld, nil
}

// oneCodeFinding names one code finding across a product's builds.
func oneCodeFinding(productID int64, occurrenceIdentity string) func(*bun.SelectQuery) *bun.SelectQuery {
	kinds, kindArgs := kind.CodeFindings.Where(`"kind"`)
	return func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.Where(inThisProduct, productID).
			Where(kinds, kindArgs...).
			Where(`"occurrence_identity" = ?`, occurrenceIdentity)
	}
}
