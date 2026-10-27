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

// Flaw record is a confirmed code finding recorded as a flaw here, by its occurrence in a
// product.
type CodeFindingFlaw struct {
	bun.BaseModel `bun:"table:code_finding_flaw,alias:lh"`

	ID                 int64  `bun:"id,pk,autoincrement"`
	ProductID          int64  `bun:"product_id,notnull"`
	OccurrenceIdentity string `bun:"occurrence_identity,notnull"`
	VulnerabilityID    int64  `bun:"vulnerability_id,notnull"`
	// Visibility is what the code finding's findings hold, and what a sighting
	// opening later opens at: internal while its flaw is undisclosed, whether or
	// not it is included in disclosure, and public once an included code finding was disclosed with its flaw.
	Visibility access.Visibility `bun:"visibility,notnull"`
	RecordedBy int64             `bun:"recorded_by,notnull"`
	RecordedAt time.Time         `bun:"recorded_at,notnull"`
	IncludedBy *int64            `bun:"included_by"`
	IncludedAt *time.Time        `bun:"included_at"`
	// DisclosedAt is when its flaw was disclosed, whether or not the code finding was
	// included in disclosure. An internal-only code finding stays internal past it, so the visibility alone does not say so.
	DisclosedAt *time.Time `bun:"disclosed_at"`
	// LastRunID is the last analysis run to describe the code finding, written before
	// the run writes anything about it. A write matched on it finds a run that
	// landed since it was read.
	LastRunID *int64 `bun:"last_run_id"`
}

// matchedOn narrows an update of one flaw record to the run it was read after,
// for a write that a run describing the code finding since has to send round again.
func (h CodeFindingFlaw) matchedOn(q *bun.UpdateQuery) *bun.UpdateQuery {
	if h.LastRunID == nil {
		return q.Where(`"last_run_id" IS NULL`)
	}
	return q.Where(`"last_run_id" = ?`, *h.LastRunID)
}

// asPlaced narrows a write of one flaw record to whether it was included in its
// flaw's disclosure when it was read. An inclusion leaves the visibility alone, so the visibility
// does not say so.
func (h CodeFindingFlaw) asPlaced() string {
	if h.Included() {
		return `"included_at" IS NOT NULL`
	}
	return `"included_at" IS NULL`
}

// AsRead narrows an update of one flaw record to the row as it was read: its
// visibility, whether it was included in disclosure, its flaw undisclosed, and the last run to
// describe it. An inclusion, a removal, a disclosure or a run landing since is a lost
// race, which the retry reads again.
func (h CodeFindingFlaw) AsRead(q *bun.UpdateQuery) *bun.UpdateQuery {
	return h.matchedOn(q.Where(`"id" = ?`, h.ID).Where(`"visibility" = ?`, h.Visibility).
		Where(h.asPlaced()).Where(`"disclosed_at" IS NULL`))
}

// Unlink deletes the flaw record as it was read: its visibility, whether it was
// included in disclosure, its flaw undisclosed, and the last run to describe it.
// An inclusion, a removal, a disclosure or a run landing since is a lost race, answered with
// database.ErrGoAgain.
func (h CodeFindingFlaw) Unlink(ctx context.Context, db bun.IDB) error {
	q := db.NewDelete().Model((*CodeFindingFlaw)(nil)).
		Where(`"id" = ?`, h.ID).Where(`"visibility" = ?`, h.Visibility).Where(h.asPlaced()).
		Where(`"disclosed_at" IS NULL`)
	if h.LastRunID == nil {
		q = q.Where(`"last_run_id" IS NULL`)
	} else {
		q = q.Where(`"last_run_id" = ?`, *h.LastRunID)
	}
	result, err := q.Exec(ctx)
	if err != nil {
		return fmt.Errorf("undo the flaw record: %w", err)
	}
	if n, err := database.Affected(result); err != nil {
		return fmt.Errorf("undo the flaw record: %w", err)
	} else if n != 1 {
		return fmt.Errorf("undo the flaw record: %w", database.ErrGoAgain)
	}
	return nil
}

// Describing writes a run onto the flaw records of the code findings it is about to
// describe in one product: those at the occurrences given, and those of the
// findings given. Written before the run reads a flaw record or writes a code finding's
// source, so a disclosure or an inclusion of one of them either waits for the run
// or finds the flaw record changed and reads again.
func Describing(ctx context.Context, db bun.IDB, productID, runID int64, occurrences []string, findingIDs []int64) error {
	for start := 0; start < len(occurrences); start += database.BatchSize {
		batch := occurrences[start:min(start+database.BatchSize, len(occurrences))]
		if _, err := db.NewUpdate().Model((*CodeFindingFlaw)(nil)).
			Set(`"last_run_id" = ?`, runID).
			Where(`"product_id" = ?`, productID).
			Where(`"occurrence_identity" IN (?)`, bun.List(batch)).
			Exec(ctx); err != nil {
			return fmt.Errorf("mark the code findings the run opens at: %w", err)
		}
	}
	if err := database.IDsInBatches(ctx, findingIDs, func(ctx context.Context, batch []int64) error {
		_, err := db.NewUpdate().Model((*CodeFindingFlaw)(nil)).
			Set(`"last_run_id" = ?`, runID).
			Where(`"product_id" = ?`, productID).
			Where(`"occurrence_identity" IN (SELECT "df"."occurrence_identity" FROM "finding" AS "df" WHERE "df"."id" IN (?))`,
				bun.List(batch)).
			Exec(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("mark the code findings the run describes again: %w", err)
	}
	return nil
}

// Included reports whether the code finding was included in its flaw's disclosure.
func (h CodeFindingFlaw) Included() bool { return h.IncludedAt != nil }

// Disclosed reports whether the code finding's flaw is disclosed.
func (h CodeFindingFlaw) Disclosed() bool { return h.DisclosedAt != nil }

// CodeFindingFlawAt is the flaw record of the code finding at an occurrence in a product, or nil
// where it was not recorded as a flaw.
func CodeFindingFlawAt(ctx context.Context, db bun.IDB, productID int64, occurrenceIdentity string) (*CodeFindingFlaw, error) {
	var h CodeFindingFlaw
	err := db.NewSelect().Model(&h).
		Where(`"lh"."product_id" = ?`, productID).
		Where(`"lh"."occurrence_identity" = ?`, occurrenceIdentity).
		Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read whether that code finding was recorded as a flaw: %w", err)
	}
	return &h, nil
}

// includedCodeFinding is the condition that the code finding finding under "f", in the product
// bound, was included in its flaw's disclosure.
const includedCodeFinding = `EXISTS (SELECT 1 FROM "code_finding_flaw" AS "lh"
	WHERE "lh"."product_id" = ? AND "lh"."occurrence_identity" = "f"."occurrence_identity" AND "lh"."included_at" IS NOT NULL)`

// includedInto is includedCodeFinding narrowed to the flaws bound in its second
// placeholder, and every issue merged into them.
const includedInto = `EXISTS (SELECT 1 FROM "code_finding_flaw" AS "lh"
	WHERE "lh"."product_id" = ? AND "lh"."occurrence_identity" = "f"."occurrence_identity" AND "lh"."included_at" IS NOT NULL
	  AND ` + `"lh"."vulnerability_id" IN (SELECT "mv"."id" FROM "vulnerability" AS "mv"
	    JOIN "vulnerability" AS "mi" ON "mi"."issue_id" = "mv"."issue_id" WHERE "mi"."id" IN (?)))`

// undisclosedCodeFinding is the condition that the code finding finding under "f", in the
// product bound, has a flaw nobody disclosed: a code finding grant reaches it only
// then.
const undisclosedCodeFinding = `NOT EXISTS (SELECT 1 FROM "code_finding_flaw" AS "lh"
	WHERE "lh"."product_id" = ? AND "lh"."occurrence_identity" = "f"."occurrence_identity" AND "lh"."disclosed_at" IS NOT NULL)`

// caseVisibilities is what an included code finding holds while its flaw is a case and
// once it is disclosed.
var caseVisibilities = []access.Visibility{access.Internal, access.Public}

// CodeFindingReading is who may read the code finding finding under "f" in one product, as
// two conditions with what each binds.
//
// Full is every code finding the subject reads: at the visibilities the subject reads
// in the product, on the code findings they were granted while their flaw is
// undisclosed, on a code finding included in the disclosure of a flaw whose case they were brought into, and as
// Included.
//
// Included is a code finding included in its flaw's disclosure while the flaw is
// undisclosed, to somebody who reads private work in the product. The code finding
// stays internal, so its internal readers keep it, and the flaw's private
// readers read it as well. A list of the product's code findings carries it beside the
// product's own visibilities.
type CodeFindingReading struct {
	Full         string
	FullArgs     []any
	Included     string
	IncludedArgs []any
}

// CodeFindingReach is who may read a product's code findings. The anonymous subject reads
// none: a code finding is not one of the security documents a product publishes.
func CodeFindingReach(s access.Subject, productID int64) CodeFindingReading {
	none := CodeFindingReading{Full: "1 = 0", Included: "1 = 0"}
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
	if occurrences := s.CodeFindings(productID); len(occurrences) > 0 {
		clauses = append(clauses, `("f"."visibility" IN (?) AND "f"."occurrence_identity" IN (?) AND `+undisclosedCodeFinding+`)`)
		args = append(args, bun.List(access.CodeFindingGrantVisibilities()), bun.List(occurrences), productID)
	}
	if cases := s.Cases(productID); len(cases) > 0 && s.Kind == access.Person {
		clauses = append(clauses, `("f"."visibility" IN (?) AND `+includedInto+`)`)
		args = append(args, bun.List(caseVisibilities), productID, bun.List(cases))
	}
	out := none
	if s.Sees(productID) && s.Reads(access.Private, productID) && !s.Reads(access.Internal, productID) {
		out.Included = `("f"."visibility" = ? AND ` + includedCodeFinding + ` AND ` + undisclosedCodeFinding + `)`
		out.IncludedArgs = []any{access.Internal, productID, productID}
		clauses = append(clauses, out.Included)
		args = append(args, out.IncludedArgs...)
	}
	if len(clauses) > 0 {
		out.Full, out.FullArgs = "("+strings.Join(clauses, " OR ")+")", args
	}
	return out
}

// CodeFindingVisible is the visibilities at which a subject reads a product's code findings
// in a list, a count or a group: the product's own, refused where it reads
// none. The anonymous subject reads none, whatever it reads of the product: a
// disclosed code finding is public, and a code finding is not one of the security documents a
// product publishes.
func CodeFindingVisible(s access.Subject, productID int64) ([]access.Visibility, error) {
	if s.Kind == access.Anonymous {
		return nil, access.Denied(fmt.Sprintf("read the code findings of product %d", productID))
	}
	return access.Readable(s, productID)
}

// codeFindingsFollow carries the code findings included in one issue's disclosure in one product to
// public with it: their findings, the decisions about them and their flaw record.
// The snippets under a path the product does not disclose snippets for are
// stripped first. Every code finding recorded as the issue is marked disclosed, whether or
// not it was included. Run inside the disclosure's transaction.
func codeFindingsFollow(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64, now time.Time) error {
	var recorded []CodeFindingFlaw
	if err := db.NewSelect().Model(&recorded).
		Where(`"lh"."product_id" = ?`, productID).
		Where(filed.Under(filed.FlawIssue), vulnerabilityID).
		Where(`"lh"."disclosed_at" IS NULL`).
		Scan(ctx); err != nil {
		return fmt.Errorf("read the code findings recorded as this flaw: %w", err)
	}
	var included []CodeFindingFlaw
	for _, h := range recorded {
		// Matched on whether it was included and on the run it was read after:
		// a code finding taken out of disclosure since stays internal, and a run
		// describing the code finding since wrote source this transaction cannot
		// see. The retry reads both again.
		result, err := h.matchedOn(db.NewUpdate().Model((*CodeFindingFlaw)(nil)).
			Set(`"disclosed_at" = ?`, now).
			Where(`"id" = ?`, h.ID).
			Where(h.asPlaced()).
			Where(`"disclosed_at" IS NULL`)).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("record the code findings recorded as this flaw as disclosed: %w", err)
		}
		if n, err := database.Affected(result); err != nil {
			return fmt.Errorf("record the code findings recorded as this flaw as disclosed: %w", err)
		} else if n != 1 {
			return fmt.Errorf("record the code findings recorded as this flaw as disclosed: %w", database.ErrGoAgain)
		}
		if h.Included() && h.Visibility == access.Internal {
			included = append(included, h)
		}
	}
	if len(included) == 0 {
		return nil
	}
	occurrences := make([]string, 0, len(included))
	ids := make([]int64, 0, len(included))
	for _, h := range included {
		occurrences = append(occurrences, h.OccurrenceIdentity)
		ids = append(ids, h.ID)
	}
	if err := stripUndisclosedSnippets(ctx, db, productID, occurrences); err != nil {
		return err
	}
	if err := SetCodeFindingVisibility(ctx, db, productID, occurrences, access.Internal, access.Public); err != nil {
		return err
	}
	// Matched on what was read: a code finding taken out of disclosure since is a
	// lost race, which the retry reads again.
	result, err := db.NewUpdate().Model((*CodeFindingFlaw)(nil)).
		Set(`"visibility" = ?`, access.Public).
		Where(`"id" IN (?)`, bun.List(ids)).
		Where(`"visibility" = ?`, access.Internal).
		Where(`"included_at" IS NOT NULL`).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("record the code findings disclosed with their flaw: %w", err)
	}
	if n, err := database.Affected(result); err != nil {
		return fmt.Errorf("record the code findings disclosed with their flaw: %w", err)
	} else if n != int64(len(ids)) {
		return fmt.Errorf("record the code findings disclosed with their flaw: %w", database.ErrGoAgain)
	}
	return nil
}

// StripDisclosedCodeFindings strips the source a run kept beside these code finding findings
// in one product where the code finding went public with its flaw, under every path the
// product does not disclose snippets for. A run describing a disclosed code finding
// again writes what the analyzer sent, so it is asked after every run.
func StripDisclosedCodeFindings(ctx context.Context, db bun.IDB, productID int64, findingIDs []int64) error {
	var public []string
	if err := database.IDsInBatches(ctx, findingIDs, func(ctx context.Context, batch []int64) error {
		var some []string
		if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
			Join(`JOIN "code_finding_flaw" AS "lh" ON "lh"."occurrence_identity" = "f"."occurrence_identity"`).
			ColumnExpr(`DISTINCT "f"."occurrence_identity"`).
			Where(`"lh"."product_id" = ?`, productID).
			Where(`"lh"."visibility" = ?`, access.Public).
			Where(`"f"."id" IN (?)`, bun.List(batch)).
			Scan(ctx, &some); err != nil {
			return err
		}
		public = append(public, some...)
		return nil
	}); err != nil {
		return fmt.Errorf("read which of the code findings were disclosed: %w", err)
	}
	if len(public) == 0 {
		return nil
	}
	return stripUndisclosedSnippets(ctx, db, productID, public)
}

// SetCodeFindingVisibility moves the code finding findings at these occurrences in one
// product, and the decisions about them, from one visibility to another.
func SetCodeFindingVisibility(ctx context.Context, db bun.IDB, productID int64, occurrences []string,
	from, to access.Visibility) error {

	kinds, kindArgs := kind.CodeFindings.Where(`"kind"`)
	if _, err := db.NewUpdate().Model((*Finding)(nil)).
		Set(`"visibility" = ?`, to).
		Where(kinds, kindArgs...).
		Where(`"occurrence_identity" IN (?)`, bun.List(occurrences)).
		Where(`"visibility" = ?`, from).
		Where(inThisProduct, productID).
		Exec(ctx); err != nil {
		return fmt.Errorf("move the code finding's findings: %w", err)
	}
	// The decision occurrences about a code finding are filed under its analyzer's
	// rule, and each follows the finding it was made about.
	if _, err := db.NewUpdate().TableExpr(`"decision_occurrence"`).
		Set(`"visibility" = ?`, to).
		Where(`"product_id" = ?`, productID).
		Where(`"occurrence_identity" IN (?)`, bun.List(occurrences)).
		Where(`"visibility" = ?`, from).
		Where(`"vulnerability_id" IN (SELECT "rv"."id" FROM "vulnerability" AS "rv" WHERE "rv"."kind" = ?)`,
			string(kind.Rule)).
		Exec(ctx); err != nil {
		return fmt.Errorf("move the decisions about the code finding: %w", err)
	}
	return nil
}

// stripUndisclosedSnippets removes the source kept beside the code findings at these
// occurrences in one product, under every path the product does not disclose
// snippets for.
func stripUndisclosedSnippets(ctx context.Context, db bun.IDB, productID int64, occurrences []string) error {
	config, err := sourcelink.NewStore(db).Config(ctx, productID)
	if err != nil {
		return err
	}
	kinds, kindArgs := kind.CodeFindings.Where(`"f"."kind"`)
	var kept []struct {
		ID   int64  `bun:"id"`
		Path string `bun:"path"`
	}
	if err := db.NewSelect().TableExpr(`"analysis_result" AS "ar"`).
		Join(`JOIN "finding" AS "f" ON "f"."id" = "ar"."finding_id"`).
		ColumnExpr(`"ar"."finding_id" AS "id", "ar"."path"`).
		Where(kinds, kindArgs...).
		Where(`"f"."occurrence_identity" IN (?)`, bun.List(occurrences)).
		Where(inThisProductAs(`"f"."build_id"`), productID).
		Where(`"ar"."snippet" IS NOT NULL`).
		Scan(ctx, &kept); err != nil {
		return fmt.Errorf("read the snippets kept beside the code findings: %w", err)
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
		return fmt.Errorf("strip the snippets of the code findings: %w", err)
	}

	var spots []struct {
		ID   int64  `bun:"id"`
		Path string `bun:"path"`
	}
	if err := db.NewSelect().TableExpr(`"analysis_location" AS "al"`).
		Join(`JOIN "finding" AS "f" ON "f"."id" = "al"."finding_id"`).
		ColumnExpr(`"al"."id", "al"."path"`).
		Where(kinds, kindArgs...).
		Where(`"f"."occurrence_identity" IN (?)`, bun.List(occurrences)).
		Where(inThisProductAs(`"f"."build_id"`), productID).
		Where(`"al"."snippet" IS NOT NULL`).
		Scan(ctx, &spots); err != nil {
		return fmt.Errorf("read the snippets kept beside the code findings' occurrences: %w", err)
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
		return fmt.Errorf("strip the snippets of the code findings' occurrences: %w", err)
	}
	return nil
}
