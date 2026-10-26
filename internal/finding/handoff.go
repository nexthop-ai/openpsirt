// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

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
	"github.com/nexthop-ai/openpsirt/internal/filed"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
)

// Handoff is a confirmed lead recorded as a flaw here, by its place in a
// product.
type Handoff struct {
	bun.BaseModel `bun:"table:lead_handoff,alias:lh"`

	ID              int64  `bun:"id,pk,autoincrement"`
	ProductID       int64  `bun:"product_id,notnull"`
	PlaceIdentity   string `bun:"place_identity,notnull"`
	VulnerabilityID int64  `bun:"vulnerability_id,notnull"`
	// Visibility is what the lead's findings hold, and what a sighting
	// opening later opens at: internal where the lead was kept, private once
	// it was moved into the case, public once its flaw was disclosed.
	Visibility access.Visibility `bun:"visibility,notnull"`
	HandedBy   int64             `bun:"handed_by,notnull"`
	HandedAt   time.Time         `bun:"handed_at,notnull"`
	MovedBy    *int64            `bun:"moved_by"`
	MovedAt    *time.Time        `bun:"moved_at"`
	// DisclosedAt is when its flaw was disclosed, kept or moved. A kept lead
	// stays internal past it, so the visibility alone does not say so.
	DisclosedAt *time.Time `bun:"disclosed_at"`
	// LastRunID is the last analysis run to describe the lead, written before
	// the run writes anything about it. A write matched on it finds a run that
	// landed since it was read.
	LastRunID *int64 `bun:"last_run_id"`
}

// matchedOn narrows an update of one hand-off to the run it was read after,
// for a write that a run describing the lead since has to send round again.
func (h Handoff) matchedOn(q *bun.UpdateQuery) *bun.UpdateQuery {
	if h.LastRunID == nil {
		return q.Where(`"last_run_id" IS NULL`)
	}
	return q.Where(`"last_run_id" = ?`, *h.LastRunID)
}

// AsRead narrows an update of one hand-off to the row as it was read: its
// visibility, its flaw undisclosed, and the last run to describe it. A move,
// an undo, a disclosure or a run landing since is a lost race, which the
// retry reads again.
func (h Handoff) AsRead(q *bun.UpdateQuery) *bun.UpdateQuery {
	return h.matchedOn(q.Where(`"id" = ?`, h.ID).Where(`"visibility" = ?`, h.Visibility).
		Where(`"disclosed_at" IS NULL`))
}

// Unlink deletes the hand-off as it was read: its visibility, its flaw
// undisclosed, and the last run to describe it. A move, a disclosure or a run
// landing since is a lost race, answered with database.ErrGoAgain.
func (h Handoff) Unlink(ctx context.Context, db bun.IDB) error {
	q := db.NewDelete().Model((*Handoff)(nil)).
		Where(`"id" = ?`, h.ID).Where(`"visibility" = ?`, h.Visibility).Where(`"disclosed_at" IS NULL`)
	if h.LastRunID == nil {
		q = q.Where(`"last_run_id" IS NULL`)
	} else {
		q = q.Where(`"last_run_id" = ?`, *h.LastRunID)
	}
	result, err := q.Exec(ctx)
	if err != nil {
		return fmt.Errorf("undo the hand-off: %w", err)
	}
	if n, err := database.Affected(result); err != nil {
		return fmt.Errorf("undo the hand-off: %w", err)
	} else if n != 1 {
		return fmt.Errorf("undo the hand-off: %w", database.ErrGoAgain)
	}
	return nil
}

// Describing writes a run onto the hand-offs of the leads it is about to
// describe in one product: those at the places given, and those of the
// findings given. Written before the run reads a hand-off or writes a lead's
// source, so a disclosure or a move of one of them either waits for the run
// or finds the hand-off changed and reads again.
func Describing(ctx context.Context, db bun.IDB, productID, runID int64, places []string, findingIDs []int64) error {
	for start := 0; start < len(places); start += database.BatchSize {
		batch := places[start:min(start+database.BatchSize, len(places))]
		if _, err := db.NewUpdate().Model((*Handoff)(nil)).
			Set(`"last_run_id" = ?`, runID).
			Where(`"product_id" = ?`, productID).
			Where(`"place_identity" IN (?)`, bun.List(batch)).
			Exec(ctx); err != nil {
			return fmt.Errorf("mark the leads the run opens at: %w", err)
		}
	}
	if err := database.IDsInBatches(ctx, findingIDs, func(ctx context.Context, batch []int64) error {
		_, err := db.NewUpdate().Model((*Handoff)(nil)).
			Set(`"last_run_id" = ?`, runID).
			Where(`"product_id" = ?`, productID).
			Where(`"place_identity" IN (SELECT "df"."place_identity" FROM "finding" AS "df" WHERE "df"."id" IN (?))`,
				bun.List(batch)).
			Exec(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("mark the leads the run describes again: %w", err)
	}
	return nil
}

// Moved reports whether the lead was moved into its flaw's case.
func (h Handoff) Moved() bool { return h.MovedAt != nil }

// Disclosed reports whether the lead's flaw is disclosed.
func (h Handoff) Disclosed() bool { return h.DisclosedAt != nil }

// Undisclosed is the visibility the lead holds while its flaw is undisclosed:
// internal where it was kept, private where it was moved. Who manages a lead
// is asked at it, before and after disclosure alike.
func (h Handoff) Undisclosed() access.Visibility {
	if h.Moved() {
		return access.Private
	}
	return access.Internal
}

// HandoffAt is the hand-off of the lead at a place in a product, or nil where
// it was not handed off.
func HandoffAt(ctx context.Context, db bun.IDB, productID int64, placeIdentity string) (*Handoff, error) {
	var h Handoff
	err := db.NewSelect().Model(&h).
		Where(`"lh"."product_id" = ?`, productID).
		Where(`"lh"."place_identity" = ?`, placeIdentity).
		Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read whether that lead was handed off: %w", err)
	}
	return &h, nil
}

// movedLead is the condition that the lead finding under "f", in the product
// bound, was moved into its flaw's case.
const movedLead = `EXISTS (SELECT 1 FROM "lead_handoff" AS "lh"
	WHERE "lh"."product_id" = ? AND "lh"."place_identity" = "f"."place_identity" AND "lh"."moved_at" IS NOT NULL)`

// movedInto is movedLead narrowed to the flaws bound in its second
// placeholder, and every issue merged into them.
const movedInto = `EXISTS (SELECT 1 FROM "lead_handoff" AS "lh"
	WHERE "lh"."product_id" = ? AND "lh"."place_identity" = "f"."place_identity" AND "lh"."moved_at" IS NOT NULL
	  AND ` + `"lh"."vulnerability_id" IN (SELECT "mv"."id" FROM "vulnerability" AS "mv"
	    JOIN "vulnerability" AS "mi" ON "mi"."issue_id" = "mv"."issue_id" WHERE "mi"."id" IN (?)))`

// undisclosedLead is the condition that the lead finding under "f", in the
// product bound, has a flaw nobody disclosed: a lead grant reaches it only
// then.
const undisclosedLead = `NOT EXISTS (SELECT 1 FROM "lead_handoff" AS "lh"
	WHERE "lh"."product_id" = ? AND "lh"."place_identity" = "f"."place_identity" AND "lh"."disclosed_at" IS NOT NULL)`

// caseVisibilities is what a moved lead holds while its flaw is a case and
// once it is disclosed.
var caseVisibilities = []access.Visibility{access.Private, access.Public}

// LeadReading is who may read the lead finding under "f" in one product, as
// two conditions with what each binds.
//
// Full is the lead itself. It is read at the visibilities the subject reads
// in the product, on the leads they were granted while their flaw is
// undisclosed, and on a lead moved into a case they were brought into.
//
// Stub is the lead without the case: state, rule, location and sightings, and
// never what the analyzer said. It is a lead moved into a case, to somebody
// reading internal work in the product who reads it no other way. Asked only
// where Full is not met.
type LeadReading struct {
	Full     string
	FullArgs []any
	Stub     string
	StubArgs []any
}

// LeadReach is who may read a product's leads. The anonymous subject reads
// none: a lead is not one of the security documents a product publishes.
func LeadReach(s access.Subject, productID int64) LeadReading {
	none := LeadReading{Full: "1 = 0", Stub: "1 = 0"}
	if s.Kind == access.Anonymous {
		return none
	}
	var clauses []string
	var args []any
	if s.Sees(productID) {
		if visible := access.Visible(s, productID); len(visible) > 0 {
			clauses = append(clauses, `"f"."visibility" IN (?)`)
			args = append(args, bun.List(visible))
		}
	}
	if places := s.Leads(productID); len(places) > 0 {
		clauses = append(clauses, `("f"."visibility" IN (?) AND "f"."place_identity" IN (?) AND `+undisclosedLead+`)`)
		args = append(args, bun.List(access.LeadGrantVisibilities()), bun.List(places), productID)
	}
	if cases := s.Cases(productID); len(cases) > 0 && s.Kind == access.Person {
		clauses = append(clauses, `("f"."visibility" IN (?) AND `+movedInto+`)`)
		args = append(args, bun.List(caseVisibilities), productID, bun.List(cases))
	}
	out := none
	if len(clauses) > 0 {
		out.Full, out.FullArgs = "("+strings.Join(clauses, " OR ")+")", args
	}
	if s.Sees(productID) && s.Reads(access.Internal, productID) {
		out.Stub = `("f"."visibility" IN (?) AND ` + movedLead + `)`
		out.StubArgs = []any{bun.List(caseVisibilities), productID}
	}
	return out
}

// LeadVisible is the visibilities at which a subject reads a product's leads
// in a list, a count or a group: the product's own, refused where it reads
// none. The anonymous subject reads none, whatever it reads of the product: a
// disclosed lead is public, and a lead is not one of the security documents a
// product publishes.
func LeadVisible(s access.Subject, productID int64) ([]access.Visibility, error) {
	if s.Kind == access.Anonymous {
		return nil, access.Denied(fmt.Sprintf("read the leads of product %d", productID))
	}
	return access.Readable(s, productID)
}

// Either is the condition that the lead is read in full or as a stub.
func (r LeadReading) Either() (string, []any) {
	return "(" + r.Full + " OR " + r.Stub + ")", append(append([]any{}, r.FullArgs...), r.StubArgs...)
}

// leadsFollow carries the leads moved into one issue's case in one product to
// public with it: their findings, the claims about them and their hand-off.
// The snippets under a path the product does not disclose snippets for are
// stripped first. Every lead handed off as the issue, kept or moved, is marked
// disclosed. Run inside the disclosure's transaction.
func leadsFollow(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64, now time.Time) error {
	var handed []Handoff
	if err := db.NewSelect().Model(&handed).
		Where(`"lh"."product_id" = ?`, productID).
		Where(filed.Under(filed.HandoffIssue), vulnerabilityID).
		Where(`"lh"."disclosed_at" IS NULL`).
		Scan(ctx); err != nil {
		return fmt.Errorf("read the leads handed off as this flaw: %w", err)
	}
	var moved []Handoff
	for _, h := range handed {
		// Matched on the run it was read after: a run describing the lead
		// since wrote source this transaction cannot see, and the retry
		// strips it.
		result, err := h.matchedOn(db.NewUpdate().Model((*Handoff)(nil)).
			Set(`"disclosed_at" = ?`, now).
			Where(`"id" = ?`, h.ID).
			Where(`"disclosed_at" IS NULL`)).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("record the leads handed off as this flaw as disclosed: %w", err)
		}
		if n, err := database.Affected(result); err != nil {
			return fmt.Errorf("record the leads handed off as this flaw as disclosed: %w", err)
		} else if n != 1 {
			return fmt.Errorf("record the leads handed off as this flaw as disclosed: %w", database.ErrGoAgain)
		}
		if h.Moved() && h.Visibility == access.Private {
			moved = append(moved, h)
		}
	}
	if len(moved) == 0 {
		return nil
	}
	places := make([]string, 0, len(moved))
	ids := make([]int64, 0, len(moved))
	for _, h := range moved {
		places = append(places, h.PlaceIdentity)
		ids = append(ids, h.ID)
	}
	if err := stripUndisclosedSnippets(ctx, db, productID, places); err != nil {
		return err
	}
	if err := SetLeadVisibility(ctx, db, productID, places, access.Private, access.Public); err != nil {
		return err
	}
	// Matched on what was read: a lead taken out of the case since is a
	// lost race, which the retry reads again.
	result, err := db.NewUpdate().Model((*Handoff)(nil)).
		Set(`"visibility" = ?`, access.Public).
		Where(`"id" IN (?)`, bun.List(ids)).
		Where(`"visibility" = ?`, access.Private).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("record the leads disclosed with their flaw: %w", err)
	}
	if n, err := database.Affected(result); err != nil {
		return fmt.Errorf("record the leads disclosed with their flaw: %w", err)
	} else if n != int64(len(ids)) {
		return fmt.Errorf("record the leads disclosed with their flaw: %w", database.ErrGoAgain)
	}
	return nil
}

// StripDisclosedLeads strips the source a run kept beside these lead findings
// in one product where the lead went public with its flaw, under every path the
// product does not disclose snippets for. A run describing a disclosed lead
// again writes what the analyzer sent, so it is asked after every run.
func StripDisclosedLeads(ctx context.Context, db bun.IDB, productID int64, findingIDs []int64) error {
	var public []string
	if err := database.IDsInBatches(ctx, findingIDs, func(ctx context.Context, batch []int64) error {
		var some []string
		if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
			Join(`JOIN "lead_handoff" AS "lh" ON "lh"."place_identity" = "f"."place_identity"`).
			ColumnExpr(`DISTINCT "f"."place_identity"`).
			Where(`"lh"."product_id" = ?`, productID).
			Where(`"lh"."visibility" = ?`, access.Public).
			Where(`"f"."id" IN (?)`, bun.List(batch)).
			Scan(ctx, &some); err != nil {
			return err
		}
		public = append(public, some...)
		return nil
	}); err != nil {
		return fmt.Errorf("read which of the leads were disclosed: %w", err)
	}
	if len(public) == 0 {
		return nil
	}
	return stripUndisclosedSnippets(ctx, db, productID, public)
}

// SetLeadVisibility moves the lead findings at these places in one product,
// and the claims about them, from one visibility to another.
func SetLeadVisibility(ctx context.Context, db bun.IDB, productID int64, places []string,
	from, to access.Visibility) error {

	kinds, kindArgs := kind.Leads.Where(`"kind"`)
	if _, err := db.NewUpdate().Model((*Finding)(nil)).
		Set(`"visibility" = ?`, to).
		Where(kinds, kindArgs...).
		Where(`"place_identity" IN (?)`, bun.List(places)).
		Where(`"visibility" = ?`, from).
		Where(inThisProduct, productID).
		Exec(ctx); err != nil {
		return fmt.Errorf("move the lead's findings: %w", err)
	}
	// The claims about a lead are filed under its analyzer's rule, and a
	// claim follows the finding it was made about.
	if _, err := db.NewUpdate().TableExpr(`"decision"`).
		Set(`"visibility" = ?`, to).
		Where(`"product_id" = ?`, productID).
		Where(`"place_identity" IN (?)`, bun.List(places)).
		Where(`"visibility" = ?`, from).
		Where(`"vulnerability_id" IN (SELECT "rv"."id" FROM "vulnerability" AS "rv" WHERE "rv"."kind" = ?)`,
			string(kind.Rule)).
		Exec(ctx); err != nil {
		return fmt.Errorf("move the claims about the lead: %w", err)
	}
	return nil
}

// stripUndisclosedSnippets removes the source kept beside the leads at these
// places in one product, under every path the product does not disclose
// snippets for.
func stripUndisclosedSnippets(ctx context.Context, db bun.IDB, productID int64, places []string) error {
	config, err := sourcelink.NewStore(db).Config(ctx, productID)
	if err != nil {
		return err
	}
	kinds, kindArgs := kind.Leads.Where(`"f"."kind"`)
	var kept []struct {
		ID   int64  `bun:"id"`
		Path string `bun:"path"`
	}
	if err := db.NewSelect().TableExpr(`"analysis_result" AS "ar"`).
		Join(`JOIN "finding" AS "f" ON "f"."id" = "ar"."finding_id"`).
		ColumnExpr(`"ar"."finding_id" AS "id", "ar"."path"`).
		Where(kinds, kindArgs...).
		Where(`"f"."place_identity" IN (?)`, bun.List(places)).
		Where(inThisProductAs(`"f"."target_id"`), productID).
		Where(`"ar"."snippet" IS NOT NULL`).
		Scan(ctx, &kept); err != nil {
		return fmt.Errorf("read the snippets kept beside the leads: %w", err)
	}
	var results []int64
	for _, k := range kept {
		if !config.DisclosesSnippets(k.Path) {
			results = append(results, k.ID)
		}
	}
	if err := database.IDsInBatches(ctx, results, func(ctx context.Context, batch []int64) error {
		_, err := db.NewUpdate().TableExpr(`"analysis_result"`).
			Set(`"snippet" = NULL`).Set(`"snippet_line" = NULL`).
			Where(`"finding_id" IN (?)`, bun.List(batch)).Exec(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("strip the snippets of the leads: %w", err)
	}

	var spots []struct {
		ID   int64  `bun:"id"`
		Path string `bun:"path"`
	}
	if err := db.NewSelect().TableExpr(`"analysis_location" AS "al"`).
		Join(`JOIN "finding" AS "f" ON "f"."id" = "al"."finding_id"`).
		ColumnExpr(`"al"."id", "al"."path"`).
		Where(kinds, kindArgs...).
		Where(`"f"."place_identity" IN (?)`, bun.List(places)).
		Where(inThisProductAs(`"f"."target_id"`), productID).
		Where(`"al"."snippet" IS NOT NULL`).
		Scan(ctx, &spots); err != nil {
		return fmt.Errorf("read the snippets kept beside the leads' places: %w", err)
	}
	var locations []int64
	for _, k := range spots {
		// A step outside the checkout has no path, and no prefix discloses it.
		if k.Path == "" || !config.DisclosesSnippets(k.Path) {
			locations = append(locations, k.ID)
		}
	}
	if err := database.IDsInBatches(ctx, locations, func(ctx context.Context, batch []int64) error {
		_, err := db.NewUpdate().TableExpr(`"analysis_location"`).
			Set(`"snippet" = NULL`).Set(`"snippet_line" = NULL`).
			Where(`"id" IN (?)`, bun.List(batch)).Exec(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("strip the snippets of the leads' places: %w", err)
	}
	return nil
}
