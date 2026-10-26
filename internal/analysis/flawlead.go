// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// ErrNoUndoReason refuses an undone hand-off that says nothing about why: it
// takes the flaw back out of every build it was recorded against.
var ErrNoUndoReason = refusal.New("say why the hand-off is undone: the flaw is taken back out of every build")

// flawLead is the lead a flaw was recorded from, with what its hand-off was
// offered. It stays with the flaw once the hand-off is undone.
type flawLead struct {
	bun.BaseModel `bun:"table:flaw_lead,alias:fl"`

	ID                 int64      `bun:"id,pk,autoincrement"`
	ProductID          int64      `bun:"product_id,notnull"`
	VulnerabilityID    int64      `bun:"vulnerability_id,notnull"`
	PlaceIdentity      string     `bun:"occurrence_identity,notnull"`
	SuggestedComponent string     `bun:"suggested_component,nullzero"`
	SuggestedEcosystem string     `bun:"suggested_ecosystem,nullzero"`
	SuggestedNamespace string     `bun:"suggested_namespace,nullzero"`
	SuggestedFrom      Source     `bun:"suggested_from,notnull"`
	HandedBy           int64      `bun:"handed_by,notnull"`
	HandedAt           time.Time  `bun:"handed_at,notnull"`
	UndoneBy           *int64     `bun:"undone_by"`
	UndoneAt           *time.Time `bun:"undone_at"`
	UndoneNote         string     `bun:"undone_note,nullzero"`
}

// flawLeadBuild is one build of the set a hand-off proposed a flaw against.
type flawLeadBuild struct {
	bun.BaseModel `bun:"table:flaw_lead_build,alias:flb"`

	ID         int64 `bun:"id,pk,autoincrement"`
	FlawLeadID int64 `bun:"flaw_lead_id,notnull"`
	TargetID   int64 `bun:"target_id,notnull"`
	Seen       bool  `bun:"seen,notnull"`
}

// recordOrigin writes, with the flaw, the lead it was recorded from, the
// component the offer ranked first and the builds it proposed: every build
// the lead was seen in, and the builds holding the chosen component that the
// lead's series never analyzed.
func recordOrigin(ctx context.Context, tx bun.IDB, productID int64, placeIdentity string,
	vulnerabilityID int64, offer *Offer, chosen finding.Entering, by int64, now time.Time) error {

	row := &flawLead{
		ProductID: productID, VulnerabilityID: vulnerabilityID, PlaceIdentity: placeIdentity,
		SuggestedFrom: FromBuild, HandedBy: by, HandedAt: now,
	}
	if len(offer.Suggestions) > 0 {
		first := offer.Suggestions[0]
		row.SuggestedComponent, row.SuggestedEcosystem, row.SuggestedNamespace = first.Component,
			first.Ecosystem, first.Namespace
		row.SuggestedFrom = first.From
	}
	if _, err := tx.NewInsert().Model(row).Exec(ctx); err != nil {
		return fmt.Errorf("record the lead the flaw was recorded from: %w", err)
	}
	proposed := map[int64]bool{}
	var order []int64
	for _, b := range offer.Seen {
		if _, ok := proposed[b.TargetID]; !ok {
			order = append(order, b.TargetID)
		}
		proposed[b.TargetID] = true
	}
	if picked := strings.TrimSpace(chosen.Component); picked != "" {
		for _, s := range offer.Suggestions {
			if graph.Folded(s.Component) != graph.Folded(picked) ||
				!sameOrUnstated(s.Ecosystem, chosen.Ecosystem) || !sameOrUnstated(s.Namespace, chosen.Namespace) {
				continue
			}
			for _, b := range s.Unanalyzed {
				if _, ok := proposed[b.TargetID]; !ok {
					order = append(order, b.TargetID)
					proposed[b.TargetID] = false
				}
			}
			break
		}
	}
	for _, target := range order {
		if _, err := tx.NewInsert().Model(&flawLeadBuild{
			FlawLeadID: row.ID, TargetID: target, Seen: proposed[target],
		}).Exec(ctx); err != nil {
			return fmt.Errorf("record the builds the flaw was proposed against: %w", err)
		}
	}
	return nil
}

// sameOrUnstated reports whether a value a suggestion states is the one a
// person chose, where they chose one.
func sameOrUnstated(offered, chosen string) bool {
	chosen = strings.TrimSpace(chosen)
	return chosen == "" || chosen == offered
}

// UndoHandOff undoes the hand-off of the lead at a place in a product while
// its flaw is undisclosed, with every lead handed off as the flaw: each is
// confirmed again and internal, its collaborators' grants end, and the flaw is
// taken back out of every build it was recorded against, closed as invalid
// for the reason given. The flaw keeps the record of the lead it was recorded
// from, marked undone.
func UndoHandOff(ctx context.Context, db bun.IDB, subject access.Subject, productID int64, placeIdentity,
	because string, now time.Time) error {

	if err := MayHandOff(subject, productID); err != nil {
		return err
	}
	because = strings.TrimSpace(because)
	if because == "" {
		return ErrNoUndoReason
	}
	if err := markdown.Check(because); err != nil {
		return err
	}
	return database.Within(ctx, db, func(ctx context.Context, tx bun.IDB) error {
		at := now.UTC().Truncate(time.Microsecond)
		h, err := handedFor(ctx, tx, subject, productID, placeIdentity)
		if err != nil {
			return err
		}
		if h.Disclosed() {
			return ErrFlawDisclosed
		}
		with, err := handedWith(ctx, tx, h)
		if err != nil {
			return err
		}
		was, became := "handed off", "hand-off undone"
		for i := range with {
			one := &with[i]
			name, err := LeadName(ctx, tx, one)
			if err != nil {
				return err
			}
			if err := one.Unlink(ctx, tx); err != nil {
				return err
			}
			if err := endLeadGrants(ctx, tx, subject, productID, one.PlaceIdentity, name, at); err != nil {
				return err
			}
			if err := recordAccess(ctx, tx, subject, name, &was, &became); err != nil {
				return err
			}
		}
		if err := takeFlawBack(ctx, tx, subject, productID, h.VulnerabilityID, because, at); err != nil {
			return err
		}
		if _, err := tx.NewUpdate().Model((*flawLead)(nil)).
			Set(`"undone_by" = ?`, subject.ID).
			Set(`"undone_at" = ?`, at).
			Set(`"undone_note" = ?`, because).
			Where(`"vulnerability_id" = ?`, h.VulnerabilityID).
			Where(`"undone_at" IS NULL`).
			Exec(ctx); err != nil {
			return fmt.Errorf("record the hand-off as undone: %w", err)
		}
		return nil
	})
}

// endLeadGrants withdraws every standing grant of the lead at a place, each
// recorded in the administration trail as a withdrawal is. A grant reaches a
// lead its flaw is not disclosed for, and a lead no longer handed off has no
// case to be brought into.
func endLeadGrants(ctx context.Context, tx bun.IDB, subject access.Subject, productID int64,
	placeIdentity, name string, now time.Time) error {

	rights := access.NewStore(tx)
	rows, err := rights.LeadRows(ctx, productID, placeIdentity)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	people := make([]int64, 0, len(rows))
	for _, row := range rows {
		people = append(people, row.PersonID)
	}
	identity, err := rights.Handles(ctx, people)
	if err != nil {
		return err
	}
	records := trail.NewStore(tx)
	for _, row := range rows {
		if err := rights.RemoveFromLead(ctx, productID, placeIdentity, row.PersonID, subject.ID); err != nil {
			return err
		}
		if err := records.Record(ctx, subject, trail.Case, name+" · "+identity[row.PersonID],
			trail.Said("a lead collaborator", true), nil); err != nil {
			return err
		}
	}
	return nil
}

// takeFlawBack closes every open finding of a flaw recorded from a lead, in
// one product, as invalid for the reason given: a flaw recorded from a
// hand-off somebody undid should not have been recorded. Only the flaw's own
// findings close, and not those of an issue it merged with.
func takeFlawBack(ctx context.Context, tx bun.IDB, subject access.Subject, productID, vulnerabilityID int64,
	because string, now time.Time) error {

	kinds, kindArgs := kind.In(`"f"."kind"`, []kind.Kind{kind.Entered})
	var open []struct {
		ID         int64             `bun:"id"`
		Visibility access.Visibility `bun:"visibility"`
	}
	if err := tx.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "t" ON "t"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
		ColumnExpr(`"f"."id", "f"."visibility"`).
		Where(`"s"."product_id" = ?`, productID).
		Where(`"f"."vulnerability_id" = ?`, vulnerabilityID).
		Where(`"f"."closed_at" IS NULL`).
		Where(kinds, kindArgs...).
		Scan(ctx, &open); err != nil {
		return fmt.Errorf("read where the flaw is open: %w", err)
	}
	ids := make([]int64, 0, len(open))
	for _, row := range open {
		if !subject.Triages(row.Visibility, productID) {
			return access.Denied(fmt.Sprintf("take a flaw back in product %d", productID))
		}
		ids = append(ids, row.ID)
	}
	return database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		result, err := tx.NewUpdate().Model((*finding.Finding)(nil)).
			Set(`"closed_at" = ?`, now).
			Set(`"closed_by" = ?`, subject.ID).
			Set(`"closed_note" = ?`, because).
			Set(`"closed_because" = ?`, finding.Invalid).
			Where(`"id" IN (?)`, bun.List(batch)).
			Where(`"closed_at" IS NULL`).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("take the flaw back out of its builds: %w", err)
		}
		if n, err := database.Affected(result); err != nil {
			return fmt.Errorf("take the flaw back out of its builds: %w", err)
		} else if n != int64(len(batch)) {
			return fmt.Errorf("take the flaw back out of its builds: %w", database.ErrGoAgain)
		}
		return nil
	})
}

// FlawOrigin is the lead a flaw was recorded from, as its reader reads it.
type FlawOrigin struct {
	// Place is the lead's place identity, and Build the build its newest
	// finding the reader reads is on.
	Place string
	Build BuildName
	Rule  string
	Path  string
	Line  int
	State State
	// Suggested is the component the hand-off's offer ranked first, empty
	// for the build itself, and From where the offer took it from.
	Suggested Suggestion
	// Proposed is the builds the hand-off proposed, and whether the lead was
	// seen in each.
	Proposed []ProposedBuild
	HandedBy int64
	HandedAt time.Time
	// UndoneBy, UndoneAt and UndoneNote are who undid the hand-off, when and
	// why. UndoneAt is nil while it stands.
	UndoneBy   *int64
	UndoneAt   *time.Time
	UndoneNote string
	// FixedIn is each build the flaw is still open on where the lead is not
	// reproduced, with the first run that did not see it, and the build a
	// person stated fixed the lead in where they did.
	FixedIn []Unseen
}

// ProposedBuild is one build of a hand-off's proposed set.
type ProposedBuild struct {
	BuildName
	Seen bool
}

// Unseen is a build the flaw is open on whose lead a comparable run no
// longer sees: the evidence a person states the flaw fixed there with.
type Unseen struct {
	BuildName
	NotSeen RunAt
	Fixed   *RunAt
}

// OriginOf is the lead the flaw filed under an issue was recorded from in a
// product, where the subject reads the lead in full. Nil where the flaw was
// recorded from no lead, or the subject does not read it.
func OriginOf(ctx context.Context, db bun.IDB, subject access.Subject, productID, vulnerabilityID int64) (
	*FlawOrigin, error) {

	var row flawLead
	err := db.NewSelect().Model(&row).
		Where(`"fl"."product_id" = ?`, productID).
		Where(`"fl"."vulnerability_id" = ?`, vulnerabilityID).
		Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read the lead the flaw was recorded from: %w", err)
	}
	reach := finding.LeadReach(subject, productID)
	kinds, kindArgs := kind.Leads.Where(`"f"."kind"`)
	state, stateArgs := stateOf(productID)
	var lead struct {
		TargetID int64  `bun:"target_id"`
		Stream   string `bun:"stream"`
		Variant  string `bun:"variant"`
		Rule     string `bun:"rule"`
		Path     string `bun:"path"`
		Line     *int   `bun:"start_line"`
		State    State  `bun:"state"`
	}
	err = db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
		Join(`JOIN "vulnerability" AS "vu" ON "vu"."id" = "f"."vulnerability_id"`).
		Join(`JOIN "target" AS "t" ON "t"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "t"."variant_id"`).
		ColumnExpr(`"f"."target_id", "s"."name" AS "stream", "va"."name" AS "variant"`).
		ColumnExpr(`"vu"."identifier" AS "rule", "ar"."path", "ar"."start_line"`).
		ColumnExpr(state+` AS "state"`, stateArgs...).
		Where(`"s"."product_id" = ?`, productID).
		Where(`"f"."occurrence_identity" = ?`, row.PlaceIdentity).
		Where(reach.Full, reach.FullArgs...).
		Where(kinds, kindArgs...).
		OrderExpr(`CASE WHEN "f"."closed_at" IS NULL THEN 0 ELSE 1 END ASC, "f"."id" DESC`).
		Limit(1).Scan(ctx, &lead)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read the lead the flaw was recorded from: %w", err)
	}
	out := &FlawOrigin{
		Place: row.PlaceIdentity, Rule: lead.Rule, Path: lead.Path, Line: atLeast(lead.Line), State: lead.State,
		Build: BuildName{TargetID: lead.TargetID, Stream: lead.Stream, Variant: lead.Variant},
		Suggested: Suggestion{Component: row.SuggestedComponent, Ecosystem: row.SuggestedEcosystem,
			Namespace: row.SuggestedNamespace, From: row.SuggestedFrom},
		HandedBy: row.HandedBy, HandedAt: row.HandedAt,
		UndoneBy: row.UndoneBy, UndoneAt: row.UndoneAt, UndoneNote: row.UndoneNote,
	}
	if err := db.NewSelect().TableExpr(`"flaw_lead_build" AS "flb"`).
		Join(`JOIN "target" AS "t" ON "t"."id" = "flb"."target_id"`).
		Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "t"."variant_id"`).
		ColumnExpr(`"t"."id" AS "target_id", "s"."name" AS "stream", "va"."name" AS "variant", "flb"."seen"`).
		Where(`"flb"."flaw_lead_id" = ?`, row.ID).
		OrderExpr(`"flb"."seen" DESC, "s"."name" ASC, "va"."name" ASC`).
		Scan(ctx, &out.Proposed); err != nil {
		return nil, fmt.Errorf("read the builds the flaw was proposed against: %w", err)
	}
	if out.FixedIn, err = notReproducedFor(ctx, db, reach, productID, vulnerabilityID, row.PlaceIdentity); err != nil {
		return nil, err
	}
	return out, nil
}

// notReproducedFor is each build a flaw is open on in a product where the
// newest finding of the lead at a place that the reach admits is not
// reproduced, or closed as fixed, with the run that first did not see it.
func notReproducedFor(ctx context.Context, db bun.IDB, reach finding.LeadReading, productID,
	vulnerabilityID int64, placeIdentity string) ([]Unseen, error) {

	leads, leadArgs := kind.Leads.Where(`"f"."kind"`)
	entered, enteredArgs := kind.In(`"ef"."kind"`, []kind.Kind{kind.Entered})
	var rows []struct {
		BuildName
		AbsentRunID *int64 `bun:"absent_run_id"`
		FixedRunID  *int64 `bun:"fixed_run_id"`
	}
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
		Join(`JOIN "target" AS "t" ON "t"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "t"."variant_id"`).
		ColumnExpr(`"t"."id" AS "target_id", "s"."name" AS "stream", "va"."name" AS "variant"`).
		ColumnExpr(`"si"."absent_run_id", "si"."fixed_run_id"`).
		Where(`"s"."product_id" = ?`, productID).
		Where(`"f"."occurrence_identity" = ?`, placeIdentity).
		Where(leads, leadArgs...).
		Where(reach.Full, reach.FullArgs...).
		Where(`EXISTS (SELECT 1 FROM "finding" AS "ef" WHERE "ef"."target_id" = "f"."target_id"
			AND "ef"."vulnerability_id" = ? AND "ef"."closed_at" IS NULL AND `+entered+`)`,
			append([]any{vulnerabilityID}, enteredArgs...)...).
		OrderExpr(`"s"."name" ASC, "va"."name" ASC, "f"."id" DESC`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read where the flaw's lead is not reproduced: %w", err)
	}
	store := series.NewStore(db)
	out := make([]Unseen, 0, len(rows))
	// The newest finding of the lead on each build speaks: a lead seen again
	// after a fixed closure opens anew there.
	spoken := map[int64]bool{}
	for _, row := range rows {
		if spoken[row.TargetID] {
			continue
		}
		spoken[row.TargetID] = true
		if row.AbsentRunID == nil {
			continue
		}
		absent, err := store.ByID(ctx, *row.AbsentRunID)
		if err != nil {
			return nil, err
		}
		one := Unseen{BuildName: row.BuildName,
			NotSeen: RunAt{ID: absent.ID, BuiltAt: absent.BuiltAt, Commit: absent.SourceCommit}}
		if row.FixedRunID != nil {
			fixed, err := store.ByID(ctx, *row.FixedRunID)
			if err != nil {
				return nil, err
			}
			one.Fixed = &RunAt{ID: fixed.ID, BuiltAt: fixed.BuiltAt, Commit: fixed.SourceCommit}
		}
		out = append(out, one)
	}
	return out, nil
}
