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
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// ErrSamePerson says work was handed from somebody to themselves.
//
// A sentinel because it is the one refusal here that is about what was asked
// rather than about what went wrong. Everything else this returns is a
// database that could not answer, and reporting those to a caller as though
// they were its fault is how a driver's error text ends up on a screen.
var ErrSamePerson = refusal.New("that would hand their work to themselves")

// ErrRecipientMayNotRead says work was handed to somebody not cleared to read
// all of it: some of it is undisclosed or security testing in a product where they may
// not read work of that visibility. The hand-over would show it to them.
var ErrRecipientMayNotRead = refusal.New("some of this is undisclosed or security testing and they may " +
	"not read work of that visibility there, so handing it to them would show it to them")

// ErrRecipientHoldsNothing says work was handed to somebody who holds no role in
// a product some of it is in, or has left: they could never open it, so it
// would sit in no list.
var ErrRecipientHoldsNothing = refusal.New("they hold no role in a product some of this is in, " +
	"or have left, so the work would sit with somebody who cannot open it")

// moveWork is the write itself, apart from the answering: which rows move, and
// what they move to.
//
// Taken out of Assign so that an act which hands over several pieces of work at
// once — planning an upgrade, which promises the whole component — can do it
// inside the transaction that records the promise, under the same rule and
// with the same narrowing. A second copy of this update would be a second
// place for the dispatch rule to be forgotten.
func (s *Store) moveWork(ctx context.Context, db bun.IDB, subject access.Subject,
	productID, vulnerabilityID, componentID int64, to *int64, dispatches bool) (int64, error) {

	return s.moveWhere(ctx, db, subject, productID, to, dispatches,
		func(q *bun.UpdateQuery) *bun.UpdateQuery {
			return asPieces(q).Where(`"vulnerability_id" = ?`, vulnerabilityID).
				Where(`"component_id" = ?`, componentID)
		})
}

// asPieces keeps a write to the kinds whose work is an issue at a component:
// the findings list's kinds. A code finding is one occurrence, named by includeCodeFinding, and an
// analyzer rule at a component is many code findings rather than one piece of work.
func asPieces(q *bun.UpdateQuery) *bun.UpdateQuery {
	kinds, kindArgs := kind.Triage.Where(`"kind"`)
	return q.Where(kinds, kindArgs...)
}

// moveWhere is moveWork over whichever work the caller names: one issue at one
// component, several issues at every binary of one fold, or one code finding.
//
// The naming is the only part a caller supplies. The product, the open rows and
// who may move which of them are this function's, so an act that hands over
// many pieces at once is held to exactly the rule that hands over one.
func (s *Store) moveWhere(ctx context.Context, db bun.IDB, subject access.Subject,
	productID int64, to *int64, dispatches bool,
	naming func(*bun.UpdateQuery) *bun.UpdateQuery) (int64, error) {

	// Refused here, where the rows are chosen: with neither way in, the group
	// below would be empty, and an empty group narrows nothing.
	if err := mayMove(subject, productID, to, dispatches); err != nil {
		return 0, err
	}
	selfward := to == nil || *to == subject.Party()

	now := s.now().UTC().Truncate(time.Microsecond)
	kinds, kindArgs := kind.Assignment.Where(`"kind"`)
	update := naming(db.NewUpdate().Model((*Finding)(nil)).
		Where(kinds, kindArgs...).
		// Across the product's builds, not one of them. The same code
		// built as several variants is one piece of work — a decision
		// carries no variant, so somebody taking this on has taken on
		// every build of the product holding the same component.
		// Assigning one build left the identical work unassigned
		// beside it, which is how a person ends up holding half of
		// what they think they hold.
		Where(inThisProduct, productID).
		Where(`"closed_at" IS NULL`))

	// Which rows this caller may move, asked here rather than beforehand so
	// that the engine answers it at the moment of the write: there is no
	// window for a colleague's assignment to land in, and a row that stopped
	// qualifying is simply not matched.
	//
	// Two ways in, and a row qualifies by either.
	//
	// Dispatching — putting work on somebody else, or taking what they hold —
	// is an act on the finding, so it reaches the visibilities this caller
	// triages.
	//
	// Taking work nobody holds and handing back their own is part of
	// triaging and needs no dispatch right: work nobody holds, work already
	// theirs, and work sitting in a queue of a team they are on. That last is
	// not taking work off a colleague, which is the act the dispatch right
	// names: work assigned to a team is unheld until somebody takes it. It
	// reaches what they read, and a disclosed row of their own whatever they
	// read, because an assignment carries it to them and disclosure does not
	// strand it there.
	mine := bun.List(subject.Mine())
	triaged := bun.List(triagedIn(subject, productID))
	read := bun.List(access.Visible(subject, productID))
	update = update.WhereGroup(" AND ", func(q *bun.UpdateQuery) *bun.UpdateQuery {
		if dispatches {
			q = q.WhereOr(`"visibility" IN (?)`, triaged)
		}
		if selfward {
			q = q.WhereOr(`(("assigned_to" IS NULL OR "assigned_to" IN (?))
				AND ("visibility" IN (?) OR ("visibility" = ? AND "assigned_to" IN (?))))`,
				mine, read, access.Public, mine)
		}
		return q
	})

	if to == nil {
		update = update.Set(`"assigned_to" = ?`, nil).Set(`"assigned_at" = ?`, nil)
	} else {
		update = update.Set(`"assigned_to" = ?`, *to).Set(`"assigned_at" = ?`, now)
	}

	result, err := update.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("record who is dealing with this: %w", err)
	}
	moved, err := database.Affected(result)
	if err != nil {
		return 0, fmt.Errorf("record who is dealing with this: %w", err)
	}
	return moved, nil
}

// mayMove refuses giving work to somebody else, or taking what they hold, to a
// subject without the right that names it.
func mayMove(subject access.Subject, productID int64, to *int64, dispatches bool) error {
	if !dispatches && to != nil && *to != subject.Party() {
		return access.Denied(fmt.Sprintf(
			"give work to somebody else in product %d — you may take what nobody owns, "+
				"and hand back your own", productID))
	}
	return nil
}

// mayHandOver refuses deciding who deals with findings in a product to a
// subject who does not triage there, and answers whether they may dispatch:
// put work on somebody else, or take what somebody else holds.
func mayHandOver(subject access.Subject, productID int64) (dispatches bool, err error) {
	if !subject.TriagesIn(productID) {
		return false, access.Denied(fmt.Sprintf(
			"decide who deals with findings in product %d", productID))
	}
	return subject.Holds(access.Assigner, productID), nil
}

// triagedIn is the visibilities this subject triages in one product.
func triagedIn(subject access.Subject, productID int64) []access.Visibility {
	var triaged []access.Visibility
	for _, v := range access.Visibilities() {
		if subject.Triages(v, productID) {
			triaged = append(triaged, v)
		}
	}
	return triaged
}

// HandOverWithin gives several pieces of work to one party inside a
// transaction somebody else opened, under the rule Assign holds.
//
// It exists for this: planning an upgrade is one act that answers a whole
// component, and saying who is carrying it is part of that act rather than a
// second one somebody might forget. Recorded in the same transaction, so a
// promise nobody is carrying and a holder with no promise are both impossible.
//
// Product-wide, like every other assignment: the promise is per build, and who
// is carrying the work is not — somebody moving the package on one release is
// who moves it on the next.
func (s *Store) HandOverWithin(ctx context.Context, tx bun.IDB, subject access.Subject,
	productID int64, work [][2]int64, to *int64) (int64, error) {

	dispatches, err := mayHandOver(subject, productID)
	if err != nil {
		return 0, err
	}
	// Refused before any work is read, as Assign and AssignMatching refuse,
	// so a hand-over of nothing to somebody else is refused rather than
	// answered as zero moved.
	if err := mayMove(subject, productID, to, dispatches); err != nil {
		return 0, err
	}
	var moved int64
	for _, each := range work {
		n, err := s.moveWork(ctx, tx, subject, productID, each[0], each[1], to,
			dispatches)
		if err != nil {
			return 0, err
		}
		moved += n
	}
	return moved, nil
}

// Assign records who is dealing with an issue in a component, across every
// build of one product that holds it.
//
// Set for the whole group at once rather than per occurrence: assigning one
// occurrence of an issue and not another is not something anybody means to do,
// and the occurrences of a group are the same problem seen from several
// parents. Across builds for the same reason — the same code built as several
// variants is one piece of work, and it is answered by one decision.
//
// Assigning to nobody is how something is handed back, and is deliberately the
// same operation — taking work back is not a different kind of act from giving
// it out, and making it one produces two paths that drift. The build is named
// rather than the product, and the product is resolved from it here. Both are
// int64, so a caller passing the wrong one is invisible to the compiler — and
// it is invisible on SQLite too, where a fresh database makes the first
// product and the first build both 1. Taking the build keeps every call site
// saying what it is looking at and leaves one place that knows the grain.
//
// The party work lands on is a person or a team, in the column that already
// holds one. Nothing here asks which it is: the whole point of one
// column is that every filter, count and handover asks "who holds this" once.
//
// Admits is asked whether the party may hold work of every visibility open
// there, in the transaction that moves it. Nil admits any party.
//
// The visibilities other than public among what moved come back, each once,
// which decides what may be said about the act outside the application.
func (s *Store) Assign(ctx context.Context, subject access.Subject, buildID, vulnerabilityID,
	componentID int64, to *int64, admits Admits) (moved int64, withheld []access.Visibility, err error) {

	err = database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		moved, withheld = 0, nil
		inner := &Store{db: tx, now: s.now, reach: s.reach}
		var err error
		moved, withheld, err = inner.assign(ctx, subject, buildID, vulnerabilityID,
			componentID, to, admits)
		return err
	})
	return moved, withheld, err
}

// assign is Assign inside the transaction it opened.
//
// One transaction, because whether the recipient may hold the work depends on
// what is open there, and a scan recording an undisclosed occurrence between a
// read of that and the write would hand the new row over unasked.
func (s *Store) assign(ctx context.Context, subject access.Subject, buildID, vulnerabilityID,
	componentID int64, to *int64, admits Admits) (int64, []access.Visibility, error) {

	productID, err := productOf(ctx, s.db, buildID)
	if err != nil {
		return 0, nil, err
	}
	// Deciding who deals with something is a write, so it asks for a
	// right. Being able to *see* a finding is not being able to hand it
	// around, and narrowing by visibility is not an authorization check —
	// it stops somebody assigning what they cannot see, not somebody
	// assigning.
	//
	// The right needed depends on who it lands on. Taking work nobody owns, and
	// handing back your own, are part of triaging: the constant stream of
	// unowned findings assigning what is there now produces would
	// otherwise need somebody's attention before anybody could start.
	// Putting work on somebody else, or taking what they are holding, is a
	// different act and asks for the right that names it.
	//
	// Where the caller may not dispatch, the rule is carried into the write
	// below rather than checked before it: a check and a write that are two
	// statements are two moments, and a colleague's assignment landing
	// between them is all it takes to reassign what the rule just refused.
	dispatches, err := mayHandOver(subject, productID)
	if err != nil {
		return 0, nil, err
	}
	if err := mayMove(subject, productID, to, dispatches); err != nil {
		return 0, nil, err
	}
	visible, err := access.Readable(subject, productID)
	if err != nil {
		return 0, nil, err
	}

	// An assignment carries visibility of what was assigned, so the
	// recipient is asked about every visibility open here rather than
	// about their present sight of the row — which, before the
	// assignment, they do not have.
	if to != nil && admits != nil {
		withheld, err := withheldAmong(ctx, s.db, visible,
			oneFinding(productID, vulnerabilityID, componentID))
		if err != nil {
			return 0, nil, fmt.Errorf("read how far this is disclosed: %w", err)
		}
		if err := admits(ctx, s.db, withheld); err != nil {
			return 0, nil, err
		}
	}

	moved, err := s.moveWork(ctx, s.db, subject, productID, vulnerabilityID, componentID,
		to, dispatches)
	if err != nil {
		return 0, nil, err
	}
	if moved == 0 {
		// Nothing moved. For a caller who may not dispatch, that is either
		// "there is nothing there" or "somebody else is holding it", and the
		// two deserve different answers — so the question is asked once, on
		// the failing path only, and narrowed by what this person may see so
		// that the answer cannot describe a row they may not read.
		if !dispatches {
			kinds, kindArgs := kind.Triage.Where(`"kind"`)
			held, err := s.db.NewSelect().Model((*Finding)(nil)).
				Column("id").
				Where(kinds, kindArgs...).
				Where(inThisProduct, productID).
				Where(`"vulnerability_id" = ?`, vulnerabilityID).
				Where(`"component_id" = ?`, componentID).
				Where(`"closed_at" IS NULL`).
				Where(`"visibility" IN (?)`, bun.List(visible)).
				Where(`"assigned_to" IS NOT NULL`).
				Where(`"assigned_to" NOT IN (?)`, bun.List(subject.Mine())).
				Exists(ctx)
			if err != nil {
				return 0, nil, fmt.Errorf("read who is dealing with this: %w", err)
			}
			if held {
				return 0, nil, heldElsewhere(productID)
			}
		}
		return 0, nil, nil
	}

	// The disclosure of what was just handed over.
	//
	// Answered here because the caller has to know it to decide what may
	// be said about it outside the application and cannot see the rows
	// from where it stands. Asked after the write and narrowed the same
	// way, so it describes what actually moved. Any one row answers: they
	// are one issue at one component in one build, and visibility belongs
	// to the finding rather than to the occurrence.
	//
	// Asked of every visibility rather than of what the caller may read: what
	// moved carries its visibility to whoever now holds it, whether or not the
	// caller can see every row of it.
	withheld, err := withheldAmong(ctx, s.db, access.Visibilities(),
		oneFinding(productID, vulnerabilityID, componentID))
	if err != nil {
		return moved, nil, fmt.Errorf("read whether that finding is disclosed: %w", err)
	}
	return moved, withheld, nil
}

// heldElsewhere refuses taking work somebody else holds to a caller who may
// not dispatch.
func heldElsewhere(productID int64) error {
	return access.Denied(fmt.Sprintf(
		"take work somebody else is dealing with in product %d — you may take "+
			"what nobody owns, and hand back your own", productID))
}

// withheldAmong is every visibility other than public that an open finding
// naming selects holds, among the visibilities given, each once and in the
// order access.Visibilities names them.
//
// A set rather than the strictest of them: undisclosed and security testing work are
// read under separate grants, so neither is stricter than the other, and a
// recipient is asked about each one present. Work where this is empty is
// disclosed throughout, and travels with an assignment to whoever holds it.
func withheldAmong(ctx context.Context, db bun.IDB, visible []access.Visibility,
	naming func(*bun.SelectQuery) *bun.SelectQuery) ([]access.Visibility, error) {

	kinds, kindArgs := kind.Assignment.Where(`"kind"`)
	var held []access.Visibility
	if err := naming(db.NewSelect().Model((*Finding)(nil)).ColumnExpr(`DISTINCT "visibility"`)).
		Where(kinds, kindArgs...).
		Where(`"closed_at" IS NULL`).
		Where(`"visibility" IN (?)`, bun.List(visible)).
		Where(`"visibility" <> ?`, access.Public).
		Scan(ctx, &held); err != nil {
		return nil, err
	}
	return inOrder(held), nil
}

// inOrder is a set of visibilities in the order access.Visibilities names
// them, each once, so two reads of one set compare equal.
func inOrder(held []access.Visibility) []access.Visibility {
	var out []access.Visibility
	for _, v := range access.Visibilities() {
		if slices.Contains(held, v) {
			out = append(out, v)
		}
	}
	return out
}

// oneFinding names one issue at one component across a product's builds.
func oneFinding(productID, vulnerabilityID, componentID int64) func(*bun.SelectQuery) *bun.SelectQuery {
	kinds, kindArgs := kind.Triage.Where(`"kind"`)
	return func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.Where(inThisProduct, productID).
			Where(kinds, kindArgs...).
			Where(`"vulnerability_id" = ?`, vulnerabilityID).
			Where(`"component_id" = ?`, componentID)
	}
}

// WithheldOnComponent is every visibility other than public open against a
// component in these builds.
//
// The question an assignment asks about one finding, asked about everything
// an upgrade covers. Handing a promise to somebody is handing them what it
// covers, and one embargoed finding among fifty is enough to make the handover
// the disclosure — so what matters is every visibility in the set rather than
// that of whichever row somebody happened to be looking at.
func (s *Store) WithheldOnComponent(ctx context.Context, subject access.Subject,
	productID int64, buildIDs []int64, component, version string) ([]access.Visibility, error) {

	visible, err := access.Readable(subject, productID)
	if err != nil {
		return nil, err
	}
	if len(buildIDs) == 0 {
		return nil, nil
	}
	folds, err := OneFoldNamed(ctx, s.db, buildIDs, component, version)
	if err != nil {
		return nil, err
	}
	if len(folds) == 0 {
		return nil, nil
	}
	// Matched on the fold, the way the upgrade itself resolves what it covers:
	// naming any binary of a source package reaches all of them, so asking
	// about the binary alone would miss the embargo sitting on its sibling.
	kinds, kindArgs := kind.Triage.Where(`"kind"`)
	withheld, err := withheldAmong(ctx, s.db, visible, func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.Where(`"build_id" IN (?)`, bun.List(buildIDs)).
			Where(kinds, kindArgs...).
			Where(`"component_id" IN (SELECT "c"."id" FROM "component" AS "c"
			WHERE `+FoldedOn+` IN (?))`, bun.List(folds))
	})
	if err != nil {
		return nil, fmt.Errorf("read how far this is disclosed: %w", err)
	}
	return withheld, nil
}

// Release hands everything one person holds back to nobody.
//
// The case this exists for is somebody leaving. Their work is then invisible
// twice over — not in the shared list because it is assigned, and not in
// anybody's own list because they are not here — so it is in no view at all
// rather than visibly orphaned.
//
// Nothing tells us somebody has left. Membership is read at sign-in, and
// somebody who has gone never signs in again, so this is an action an
// administrator takes rather than something the software discovers.
func (s *Store) Release(ctx context.Context, subject access.Subject, party int64) (int64, error) {
	return s.handOver(ctx, subject, party, nil)
}

// HandOver moves everything one person holds to somebody else.
//
// Kept apart from Release because they answer different questions. Handing
// over says who is dealing with it now; releasing says nobody is, and puts it
// back where it can be picked up — which is the honest answer when whoever
// takes it on has not been decided.
func (s *Store) HandOver(ctx context.Context, subject access.Subject, from, to int64) (int64, error) {
	if from == to {
		return 0, ErrSamePerson
	}
	return s.handOver(ctx, subject, from, &to)
}

func (s *Store) handOver(ctx context.Context, subject access.Subject, from int64, to *int64) (int64, error) {
	if !subject.Admin {
		// Moving work somebody else was given is an administrative act. A
		// person hands back their own by assigning it to nobody.
		return 0, access.Denied("move work assigned to somebody else")
	}

	var moved int64
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		now := s.now().UTC().Truncate(time.Microsecond)
		if to != nil {
			if err := mayReadAllOf(ctx, tx, from, *to); err != nil {
				return err
			}
		}
		kinds, kindArgs := kind.Assignment.Where(`"kind"`)
		update := tx.NewUpdate().Model((*Finding)(nil)).
			Where(kinds, kindArgs...).
			Where(`"assigned_to" = ?`, from).
			Where(`"closed_at" IS NULL`)
		if to == nil {
			update = update.Set(`"assigned_to" = ?`, nil).Set(`"assigned_at" = ?`, nil)
		} else {
			// A code finding recorded as a flaw is closed work for its holder, and stays
			// with them: it is listed to nobody, so moving it hands over
			// nothing. Released, it is held by nobody.
			update = update.Set(`"assigned_to" = ?`, *to).Set(`"assigned_at" = ?`, now).
				Where(notRecordedAsFlawIn)
		}
		result, err := update.Exec(ctx)
		if err != nil {
			return fmt.Errorf("move what they were dealing with: %w", err)
		}
		moved, err = database.Affected(result)
		if err != nil {
			return fmt.Errorf("move what they were dealing with: %w", err)
		}
		// The open reports they hold go the same way, under the same rule:
		// the recipient reads undisclosed work wherever one is held.
		reports, err := moveReportsOf(ctx, tx, from, to, 0, now)
		moved += reports
		return err
	})
	return moved, err
}

// mayReadAllOf refuses a hand-over whose recipient could not open what it
// moves.
//
// Asked per product of everything being moved, disclosed work included, and
// inside the transaction that moves it: a recipient who holds no role in a
// product, or has left, is refused there whatever the work's visibility, the
// rule a hand-back keeps disclosed work by. Each visibility other than public
// is then asked about on its own, because each is its own grant. A party no
// person holds is refused.
func mayReadAllOf(ctx context.Context, tx bun.IDB, from, to int64) error {
	var held []struct {
		ProductID  int64             `bun:"product_id"`
		Visibility access.Visibility `bun:"visibility"`
	}
	kinds, kindArgs := kind.Assignment.Where(`"f"."kind"`)
	if err := tx.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "build" AS "b" ON "b"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "b"."branch_or_tag_id"`).
		ColumnExpr(`DISTINCT "st"."product_id" AS "product_id", "f"."visibility" AS "visibility"`).
		Where(`"f"."assigned_to" = ?`, from).
		Where(`"f"."closed_at" IS NULL`).
		Where(notRecordedAsFlaw).
		Where(kinds, kindArgs...).
		Scan(ctx, &held); err != nil {
		return fmt.Errorf("read where their work is: %w", err)
	}
	reported, err := reportProductsHeld(ctx, tx, from)
	if err != nil {
		return err
	}
	for _, productID := range reported {
		held = append(held, struct {
			ProductID  int64             `bun:"product_id"`
			Visibility access.Visibility `bun:"visibility"`
		}{productID, access.Private})
	}
	if len(held) == 0 {
		return nil
	}
	var people []int64
	if err := tx.NewSelect().Model((*access.Account)(nil)).
		Column("id").
		Where(`"party_id" = ?`, to).
		Limit(1).
		Scan(ctx, &people); err != nil {
		return fmt.Errorf("read who is taking the work on: %w", err)
	}
	if len(people) == 0 {
		return ErrRecipientHoldsNothing
	}
	rights := access.NewStore(tx)
	asked := map[int64][]access.Visibility{}
	for _, one := range held {
		holds, ok := asked[one.ProductID]
		if !ok {
			var err error
			if holds, err = rights.PersonHolds(ctx, people[0], one.ProductID); err != nil {
				return err
			}
			asked[one.ProductID] = holds
		}
		if len(holds) == 0 {
			return ErrRecipientHoldsNothing
		}
		if !slices.Contains(holds, one.Visibility) {
			return ErrRecipientMayNotRead
		}
	}
	return nil
}

// codeFindingOccurrence is the occurrence of the finding under "f" where it is a code finding,
// and the empty string for any other kind.
const codeFindingOccurrence = `CASE WHEN "f"."kind" = '` + string(kind.Analysis) + `' THEN "f"."occurrence_identity" ELSE '' END`

// notRecordedAsFlaw is whether the finding under "f", in the product of the
// branch or tag under "st", is no code finding recorded as a flaw. A code finding recorded as a flaw is
// closed work for its holder: its flaw is held and listed as itself.
const notRecordedAsFlaw = `NOT EXISTS (SELECT 1 FROM "code_finding_flaw" AS "cff"
	WHERE "cff"."product_id" = "st"."product_id" AND "cff"."occurrence_identity" = "f"."occurrence_identity")`

// notRecordedAsFlawIn is notRecordedAsFlaw over the finding under "f" alone, in the
// product its build is in, for a statement that joins no branch or tag.
const notRecordedAsFlawIn = `NOT EXISTS (SELECT 1 FROM "code_finding_flaw" AS "cff"
	JOIN "branch_or_tag" AS "hs" ON "hs"."product_id" = "cff"."product_id"
	JOIN "build" AS "ht" ON "ht"."branch_or_tag_id" = "hs"."id"
	WHERE "ht"."id" = "f"."build_id" AND "cff"."occurrence_identity" = "f"."occurrence_identity")`

// pieceOfWork is what one piece of work held is grouped by, over the finding
// under "f" and its branch or tag under "st": an issue in a component in a product,
// or one code finding in a product. A code finding's builds may name different versions of
// its component, and it is still one occurrence to judge.
const pieceOfWork = `"f"."vulnerability_id", "st"."product_id", ` + pieceComponent + `, ` + codeFindingOccurrence

// pieceComponent is the component a piece of work under "f" is keyed on: none
// for a code finding.
const pieceComponent = `CASE WHEN "f"."kind" = '` + string(kind.Analysis) + `' THEN 0 ELSE "f"."component_id" END`

// pieceInProductColumns is pieceOfWork within one product, with every column
// named, so a derived table can select it.
const pieceInProductColumns = `"f"."vulnerability_id", ` + pieceComponent + ` AS "piece_component", ` +
	codeFindingOccurrence + ` AS "code_finding_place"`
