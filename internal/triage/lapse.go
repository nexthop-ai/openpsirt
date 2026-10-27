// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

type Lapsed struct {
	// Rows is how many rows stopped applying.
	Rows int64
	// Told is who to tell, once each.
	Told []ForPerson
}

// Lapse marks the rows this target's contents have moved out from under.
//
// A row is stored against the upstream versions it was made about. When
// those versions move it stops applying, and that much is automatic, because
// what applies is matched on the versions. What is not automatic is anybody
// finding out. Without this the finding simply reappears as though nobody had
// ever looked at it, with the reasoning stranded on a row nothing points at —
// which is the outcome that keeping the old row exists to prevent.
//
// Run after a scan records what it found, because that is when the versions
// have just changed. It is one statement rather than one per occurrence: a real
// image holds tens of thousands of occurrences, and a sweep costing a write per
// occurrence is a sweep somebody turns off.
//
// A row covering nothing in the product is not lapsed. A component
// that is gone altogether closed its findings and there is nothing to ask
// anybody about, where a component still present at a different version is
// exactly the question somebody has to answer again.
//
// And covering is asked of the product, not of this build. A decision is a
// lookup shared by every build whose code matches it: one release stream
// moving to a new version while another still ships the old one leaves the
// decision covering the other, and a decision about code that is still there
// is not one anybody needs to make again. It lapses when the last build
// holding its versions moves — which the sweep of that build finds, because a
// sweep still asks only about the occurrences this build has open.
//
// Only this build's product is swept. An occurrence is a pair of names, and the same
// pair sits in other products; their decisions are theirs. Lapsed is what one
// sweep found the code had moved out from under, and who is waiting to hear
// about it.
//
// A lapse is the other outcome a proposer is told about: it hands the work
// back to them, having taken a decision they made out of force, and nothing
// they did caused it.
func (s *Store) Lapse(ctx context.Context, targetID int64) (Lapsed, error) {
	// Every open finding of this target at the row's occurrence, with the
	// versions it currently has — stated the same way the row was written
	// against them, from the same expression, so that a row cannot lapse
	// on one path and stand on the other.
	openHere := func(db bun.IDB) *bun.SelectQuery {
		return db.NewSelect().
			ColumnExpr("1").
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
			Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
			Where(`"f"."target_id" = ?`, targetID).
			Where(`"f"."closed_at" IS NULL`).
			Apply(ofKinds(kind.VersionCarry, "f")).
			Where(finding.DecisionOccurrenceOf("f"))
	}

	// Any open finding in the row's product, in any build, still at the
	// versions it was decided about.
	stillCovered := func(db bun.IDB) *bun.SelectQuery {
		return db.NewSelect().
			ColumnExpr("1").
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
			Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
			Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
			Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
			Where(`"st"."product_id" = "de"."product_id"`).
			Where(`"f"."closed_at" IS NULL`).
			Apply(ofKinds(kind.VersionCarry, "f")).
			Where(finding.DecisionOccurrenceOf("f")).
			Where(finding.VersionsMatch)
	}

	// Still found here, at versions that are not the ones this was decided
	// about, and no longer found at those versions anywhere in the product.
	// Absent and empty are the same answer on the finding's side, so a
	// row recorded against no version matches a component stating none.
	lapsable := func(db bun.IDB) *bun.SelectQuery {
		return db.NewSelect().Model((*DecisionOccurrence)(nil)).
			Join(finding.DecisionOccurrenceIssue).
			ColumnExpr(`"de"."id"`).
			Where(`"de"."state" IN (?, ?)`, Proposed, Approved).
			// A decision about the match rather than about the version does not
			// stop applying when the version moves. A bump does not make a
			// wrong match right, and lapsing one would hand the same wrong
			// match back at every point release.
			Where(`NOT EXISTS (SELECT 1 FROM "decision" AS "lc"`+
				` WHERE "lc"."id" = "de"."decision_id" AND "lc"."outcome" = ?)`, Mismatched).
			Where(`"de"."product_id" = (?)`, db.NewSelect().
				ColumnExpr(`"st"."product_id"`).
				TableExpr(`"target" AS "tg"`).
				Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
				Where(`"tg"."id" = ?`, targetID)).
			Where("EXISTS (?)", openHere(db).Where("NOT ("+finding.VersionsMatch+")")).
			Where("NOT EXISTS (?)", stillCovered(db)).
			OrderExpr(`"de"."id"`).
			Limit(int64(database.InBulk.Most))
	}

	db, err := s.pool()
	if err != nil {
		return Lapsed{}, err
	}

	// Marked and read back as one act, a bounded batch at a time, so a crash
	// between the update and the read cannot leave rows lapsed with nobody
	// told. Each pass identifies its rows by identifier, which is what keeps
	// two sweeps over targets of one product from reading each other's rows.
	// Batched because a sweep over a real image can lapse thousands at once.
	//
	// Who to tell is gathered once, over every row that lapsed, so a proposer
	// whose rows span batches hears once. A batch that fails leaves the ones
	// before it committed, and those are still reported alongside the error.
	// A row this sweep lapsed leaves the lapsable set unless somebody revises
	// it in between, so the sweep ends at the pass that marks none — or at a
	// pass that read fewer than a batch, which read every row lapsable at
	// that moment. Asking again then reads every row in the product
	// once more to find only what changed since, which the next sweep finds.
	out := Lapsed{}
	var all []int64
	var failed error
	for more := true; more; {
		var moved int64
		var lapsed []int64
		if err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
			moved, lapsed = 0, nil
			var ids []int64
			if err := lapsable(tx).Scan(ctx, &ids); err != nil {
				return fmt.Errorf("read what the code moved out from under: %w", err)
			}
			more = len(ids) == database.InBulk.Most
			if len(ids) == 0 {
				return nil
			}
			moment := s.now().Truncate(time.Microsecond)
			n, err := markLapsed(ctx, tx, ids, moment)
			if err != nil {
				return fmt.Errorf("mark what the code moved out from under: %w", err)
			}
			moved = n
			// The rows this pass lapsed, read back inside the same act. The
			// identifiers are this pass's own, so nothing another sweep marked
			// is in it.
			if err := tx.NewSelect().Model((*DecisionOccurrence)(nil)).
				ColumnExpr(`"de"."id"`).
				Where(`"de"."id" IN (?)`, bun.List(ids)).
				Where(`"de"."state" = ?`, LapsedState).
				Where(`"de"."ended_at" = ?`, moment).
				Scan(ctx, &lapsed); err != nil {
				return fmt.Errorf("read what lapsed: %w", err)
			}
			return nil
		}); err != nil {
			failed = err
			break
		}
		if moved == 0 {
			break
		}
		out.Rows += moved
		all = append(all, lapsed...)
	}
	told, err := s.proposersOfAll(ctx, all, database.InBulk.Most)
	out.Told = told
	if failed != nil {
		return out, failed
	}
	return out, err
}

// markLapsed marks these rows as lapsed at a moment and answers how many
// it matched.
//
// The live key is released for the same reason a withdrawal releases it: the
// decision no longer covers what is there, and somebody has to be able to
// decide about what is there now. Only a proposed or approved row is marked,
// so a row another sweep, a withdrawal or an approval moved in between is not
// counted here as well.
func markLapsed(ctx context.Context, tx bun.IDB, ids []int64, moment time.Time) (int64, error) {
	result, err := tx.NewUpdate().Model((*DecisionOccurrence)(nil)).
		Set(`"state" = ?`, LapsedState).
		Set(`"ended_at" = ?`, moment).
		Set(`"live_key" = ?`, nil).
		Where(`"de"."id" IN (?)`, bun.List(ids)).
		Where(`"de"."state" IN (?, ?)`, Proposed, Approved).
		Exec(ctx)
	if err != nil {
		return 0, err
	}
	return database.Affected(result)
}

// LapseLeads marks lapsed the decisions dismissing a lead at these occurrences of a
// product, because a run paired each lead only probably: on its function or
// its nearest line, rather than on its whole key. The decision was about the
// result as it was keyed, and a weaker pairing is a guess that the result is
// the same one, so somebody re-affirms it.
//
// A decision confirming a lead stands: it says the flaw is real, and a weaker
// pairing does not make it less so.
//
// Written inside the transaction that records the pairing, so a pairing is
// never recorded with the decision on it left standing. Who proposed each is
// returned for the caller to tell once the transaction commits.
func LapseLeads(ctx context.Context, tx bun.IDB, productID int64, occurrences []string, moment time.Time) (Lapsed, error) {
	var out Lapsed
	if len(occurrences) == 0 {
		return out, nil
	}
	var lapsed []int64
	for start := 0; start < len(occurrences); start += database.BatchSize {
		batch := occurrences[start:min(start+database.BatchSize, len(occurrences))]
		var ids []int64
		if err := tx.NewSelect().Model((*DecisionOccurrence)(nil)).
			Join(`JOIN "decision" AS "lc" ON "lc"."id" = "de"."decision_id"`).
			ColumnExpr(`"de"."id"`).
			Where(`"de"."product_id" = ?`, productID).
			Where(`"de"."occurrence_identity" IN (?)`, bun.List(batch)).
			Where(`"de"."state" IN (?, ?)`, Proposed, Approved).
			Where(`"lc"."outcome" IN (?, ?)`, Dismissed, NotSecurity).
			Scan(ctx, &ids); err != nil {
			return out, fmt.Errorf("read the decisions on leads paired probably: %w", err)
		}
		if len(ids) == 0 {
			continue
		}
		n, err := markLapsed(ctx, tx, ids, moment.Truncate(time.Microsecond))
		if err != nil {
			return out, fmt.Errorf("lapse the decisions on leads paired probably: %w", err)
		}
		out.Rows += n
		lapsed = append(lapsed, ids...)
	}
	if len(lapsed) == 0 {
		return out, nil
	}
	// Read in the transaction that lapsed them, so a retry reads who to tell
	// again rather than trusting a list from a world that is gone.
	told, err := NewStore(tx).proposersOfAll(ctx, lapsed, database.InBulk.Most)
	if err != nil {
		return out, err
	}
	for i := range told {
		told[i].Probable = true
	}
	out.Told = told
	return out, nil
}
