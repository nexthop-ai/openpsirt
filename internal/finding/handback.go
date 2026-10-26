// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// HandBack is HandBackUnread in the shape the access store calls, for the
// writes it makes itself: a sign-in rewriting derived grants, and a change of
// role mode.
func HandBack(ctx context.Context, db bun.IDB, narrowed access.Narrowed) error {
	_, err := NewStore(db).HandBackUnread(ctx, narrowed)
	return err
}

// HandBackUnread hands back the open work a holder no longer reads, for the
// people and teams a write narrowed, and reports how much moved.
//
// Run inside the write that took the right away, whatever that write was: a
// role withdrawn, a sign-in whose groups stopped granting one, a switch out of
// group-bound mode, somebody taken off a team, a team retired, or somebody
// deactivated.
// The people named are asked about, and so is every team they are on, because
// a team holds work only while a member reads it.
//
// Work goes back to nobody, exactly as when somebody leaves. No routing sweep
// is queued, because a full queue would then refuse the write that took the
// reading away; a rule places the work when one is next recorded.
func (s *Store) HandBackUnread(ctx context.Context, narrowed access.Narrowed) (int64, error) {
	var moved int64
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		var err error
		moved, err = handBackUnread(ctx, tx, narrowed, s.now().UTC().Truncate(time.Microsecond))
		return err
	})
	return moved, err
}

func handBackUnread(ctx context.Context, tx bun.IDB, narrowed access.Narrowed, now time.Time) (int64, error) {
	holders, err := holdersNarrowed(ctx, tx, narrowed)
	if err != nil || len(holders) == 0 {
		return 0, err
	}
	parties := make([]int64, 0, len(holders))
	for party := range holders {
		parties = append(parties, party)
	}
	held, err := heldByParty(ctx, tx, parties)
	if err != nil {
		return 0, err
	}
	rights := access.NewStore(tx)
	var moved int64
	for _, one := range held {
		kept, err := holders[one.party].reads(ctx, rights, one.product)
		if err != nil {
			return 0, err
		}
		if len(one.visibilities) > 0 && !containsAll(kept, one.visibilities) {
			n, err := releaseUnread(ctx, tx, one.party, one.product, kept)
			if err != nil {
				return 0, err
			}
			moved += n
		}
		if one.reports && !slices.Contains(kept, access.Private) {
			n, err := moveReportsOf(ctx, tx, one.party, nil, one.product, now)
			if err != nil {
				return 0, err
			}
			moved += n
		}
	}
	return moved, nil
}

// narrowedHolder is one party asked about: a person or a team, by its own identifier.
type narrowedHolder struct {
	person int64
	team   int64
}

// reads is every visibility this holder may keep work at in one product.
//
// A person keeps undisclosed and internal work where they read it, and
// disclosed work while they hold any role there, because disclosed work
// travels with the assignment. A team keeps what one member reads, and
// disclosed work while one member reads the product at any visibility: the
// rule a hand assignment to the team asks. A report is kept where undisclosed
// work is.
func (h narrowedHolder) reads(ctx context.Context, rights *access.Store, productID int64) ([]access.Visibility, error) {
	var kept []access.Visibility
	if h.person != 0 {
		holds, err := rights.HoldsAnythingIn(ctx, h.person, productID)
		if err != nil || !holds {
			return nil, err
		}
		kept = append(kept, access.Public)
		for _, v := range []access.Visibility{access.Private, access.Internal} {
			reads, err := rights.PersonReads(ctx, h.person, productID, v)
			if err != nil {
				return nil, err
			}
			if reads {
				kept = append(kept, v)
			}
		}
		return kept, nil
	}
	for _, v := range []access.Visibility{access.Private, access.Internal} {
		reads, err := rights.AnyMemberReads(ctx, h.team, productID, v)
		if err != nil {
			return nil, err
		}
		if reads {
			kept = append(kept, v)
		}
	}
	if len(kept) == 0 {
		reads, err := rights.AnyMemberReads(ctx, h.team, productID, access.Public)
		if err != nil || !reads {
			return nil, err
		}
	}
	return append(kept, access.Public), nil
}

func containsAll(kept, held []access.Visibility) bool {
	for _, v := range held {
		if !slices.Contains(kept, v) {
			return false
		}
	}
	return true
}

// holdersNarrowed resolves what a write narrowed to the parties holding work,
// keyed by party: the people named, every team named or that one of them is
// on, or everybody holding anything.
func holdersNarrowed(ctx context.Context, db bun.IDB, narrowed access.Narrowed) (map[int64]narrowedHolder, error) {
	var people, teams []struct {
		ID      int64 `bun:"id"`
		PartyID int64 `bun:"party_id"`
	}
	personQ := db.NewSelect().Model((*access.Account)(nil)).Column("id", "party_id")
	teamQ := db.NewSelect().Model((*access.Team)(nil)).Column("id", "party_id")
	if narrowed.Everybody {
		kinds, kindArgs := kind.Assignment.Where(`"f"."kind"`)
		holding := `("party_id" IN (SELECT "f"."assigned_to" FROM "finding" AS "f"
			WHERE "f"."assigned_to" IS NOT NULL AND "f"."closed_at" IS NULL AND ` + kinds + `)
			OR "party_id" IN (SELECT "fr"."assigned_to" FROM "flaw_report" AS "fr"
			WHERE "fr"."assigned_to" IS NOT NULL AND "fr"."evaluated_at" IS NULL))`
		personQ = personQ.Where(holding, kindArgs...)
		teamQ = teamQ.Where(holding, kindArgs...)
	} else {
		if len(narrowed.People) == 0 && len(narrowed.Teams) == 0 {
			return nil, nil
		}
		personQ = personQ.Where(`"id" IN (?)`, bun.List(append([]int64{0}, narrowed.People...)))
		teamQ = teamQ.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.WhereOr(`"id" IN (?)`, bun.List(append([]int64{0}, narrowed.Teams...))).
				WhereOr(`"id" IN (SELECT "tmm"."team_id" FROM "team_member" AS "tmm"
					WHERE "tmm"."person_id" IN (?))`, bun.List(append([]int64{0}, narrowed.People...)))
		})
	}
	if err := personQ.Scan(ctx, &people); err != nil {
		return nil, fmt.Errorf("read whose reading changed: %w", err)
	}
	if err := teamQ.Scan(ctx, &teams); err != nil {
		return nil, fmt.Errorf("read which teams that reaches: %w", err)
	}
	out := make(map[int64]narrowedHolder, len(people)+len(teams))
	for _, p := range people {
		out[p.PartyID] = narrowedHolder{person: p.ID}
	}
	for _, t := range teams {
		out[t.PartyID] = narrowedHolder{team: t.ID}
	}
	return out, nil
}

// heldIn is what one party holds open in one product: findings and leads at
// these visibilities, and whether any report.
type heldIn struct {
	party        int64
	product      int64
	visibilities []access.Visibility
	reports      bool
}

// heldByParty reads what these parties hold open, per product.
func heldByParty(ctx context.Context, db bun.IDB, parties []int64) ([]heldIn, error) {
	var rows []struct {
		Party      int64             `bun:"party"`
		Product    int64             `bun:"product"`
		Visibility access.Visibility `bun:"visibility"`
	}
	kinds, kindArgs := kind.Assignment.Where(`"f"."kind"`)
	if err := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
		ColumnExpr(`DISTINCT "f"."assigned_to" AS "party", "st"."product_id" AS "product", `+
			`"f"."visibility" AS "visibility"`).
		Where(`"f"."assigned_to" IN (?)`, bun.List(parties)).
		Where(`"f"."closed_at" IS NULL`).
		Where(kinds, kindArgs...).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what they hold: %w", err)
	}
	var reports []struct {
		Party   int64 `bun:"party"`
		Product int64 `bun:"product"`
	}
	if err := db.NewSelect().
		TableExpr(`"flaw_report" AS "fr"`).
		ColumnExpr(`DISTINCT "fr"."assigned_to" AS "party", "fr"."product_id" AS "product"`).
		Where(`"fr"."assigned_to" IN (?)`, bun.List(parties)).
		Where(`"fr"."evaluated_at" IS NULL`).
		Scan(ctx, &reports); err != nil {
		return nil, fmt.Errorf("read which reports they hold: %w", err)
	}
	index := map[[2]int64]int{}
	var out []heldIn
	at := func(party, product int64) *heldIn {
		key := [2]int64{party, product}
		i, ok := index[key]
		if !ok {
			i = len(out)
			index[key] = i
			out = append(out, heldIn{party: party, product: product})
		}
		return &out[i]
	}
	for _, r := range rows {
		one := at(r.Party, r.Product)
		one.visibilities = append(one.visibilities, r.Visibility)
	}
	for _, r := range reports {
		at(r.Party, r.Product).reports = true
	}
	return out, nil
}

// releaseUnread hands back one party's open findings and leads in one product
// at every visibility outside kept, and all of them where kept is empty.
func releaseUnread(ctx context.Context, db bun.IDB, party, productID int64,
	kept []access.Visibility) (int64, error) {

	kinds, kindArgs := kind.Assignment.Where(`"kind"`)
	update := db.NewUpdate().Model((*Finding)(nil)).
		Set(`"assigned_to" = ?`, nil).Set(`"assigned_at" = ?`, nil).
		Where(kinds, kindArgs...).
		Where(`"assigned_to" = ?`, party).
		Where(`"closed_at" IS NULL`).
		Where(inThisProduct, productID)
	if len(kept) > 0 {
		update = update.Where(`"visibility" NOT IN (?)`, bun.List(kept))
	}
	result, err := update.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("hand back what they may no longer read: %w", err)
	}
	moved, err := database.Affected(result)
	if err != nil {
		return 0, fmt.Errorf("hand back what they may no longer read: %w", err)
	}
	return moved, nil
}
