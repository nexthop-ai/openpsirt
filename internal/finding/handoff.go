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
}

// Moved reports whether the lead was moved into its flaw's case.
func (h Handoff) Moved() bool { return h.MovedAt != nil }

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

// caseVisibilities is what a moved lead holds while its flaw is a case and
// once it is disclosed.
var caseVisibilities = []access.Visibility{access.Private, access.Public}

// LeadReading is who may read the lead finding under "f" in one product, as
// two conditions with what each binds.
//
// Full is the lead itself. It is read at the visibilities the subject reads
// in the product, on the leads they were granted while those are internal or
// private, and on a lead moved into a case they were brought into.
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
		clauses = append(clauses, `("f"."visibility" IN (?) AND "f"."place_identity" IN (?))`)
		args = append(args, bun.List(access.LeadGrantVisibilities()), bun.List(places))
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

// Either is the condition that the lead is read in full or as a stub.
func (r LeadReading) Either() (string, []any) {
	return "(" + r.Full + " OR " + r.Stub + ")", append(append([]any{}, r.FullArgs...), r.StubArgs...)
}

// leadsFollow carries the leads moved into one issue's case in one product to
// public with it: their findings, the claims about them and their hand-off.
// The snippets under a path the product does not disclose snippets for are
// stripped first. Run inside the disclosure's transaction.
func leadsFollow(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64) error {
	var moved []Handoff
	if err := db.NewSelect().Model(&moved).
		Where(`"lh"."product_id" = ?`, productID).
		Where(filed.Under(filed.HandoffIssue), vulnerabilityID).
		Where(`"lh"."moved_at" IS NOT NULL`).
		Where(`"lh"."visibility" = ?`, access.Private).
		Scan(ctx); err != nil {
		return fmt.Errorf("read the leads moved into this case: %w", err)
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
	if _, err := db.NewUpdate().Model((*Handoff)(nil)).
		Set(`"visibility" = ?`, access.Public).
		Where(`"id" IN (?)`, bun.List(ids)).
		Exec(ctx); err != nil {
		return fmt.Errorf("record the leads disclosed with their flaw: %w", err)
	}
	return nil
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
