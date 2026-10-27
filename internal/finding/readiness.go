// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// Standing is what one build holds now, split by severity band.
//
// Counted as issues at components, which is what the findings list counts —
// a component reached twenty ways carries the same issue twenty times, and
// counting rows would make a build look twenty times worse than the list
// somebody opens next.
type Standing struct {
	// BuildID is the build these are about.
	BuildID int64 `bun:"build_id"`
	// Branch or tag and Variant name it, and Kind says whether the release is a
	// branch or a tag. A screen asks because the comparison only means
	// something for a branch: a tag is one frozen point and was not cut into
	// anything.
	BranchOrTag     string `bun:"branch_or_tag"`
	BranchOrTagName string `bun:"branch_or_tag_name"`
	Variant         string `bun:"variant"`
	VariantName     string `bun:"variant_name"`
	Kind            string `bun:"kind"`
	// ByBand is critical, high, medium and low, folded the way the line folds
	// them, with nothing for a band holding nothing.
	ByBand map[string]int `bun:"-"`
	// Total is every band together.
	Total int `bun:"-"`
	// LastScanned is when the last run of this build finished, or nil where
	// none has. A count from a build nothing has scanned in a year is a
	// statement about last year.
	LastScanned *time.Time `bun:"-"`
}

// Readiness is a branch beside the last release cut from it.
//
// The pre-release question, and the reason a branch trend is worth having: is
// what we are about to ship better or worse than what we last shipped . Both
// halves come from data already collected — nightly scans on the branch, and
// the release's own scan — so this asks nothing new of a build pipeline.
type Readiness struct {
	Now Standing
	// Shipped is the release, or nil where there is nothing to compare
	// against: no release cut from this branch, none built the same way, or
	// one nothing has scanned. Absent rather than zeroed, because "we shipped
	// with none" and "we do not know what we shipped with" are answers a
	// person acts on differently.
	Shipped *Standing
	// Why is the missing part where Shipped is nil, in words a
	// screen can print. Empty where there is something to compare against.
	Why string
	// MinimumSeverity is the line these counts are at or above, so a screen can say
	// whose number it is showing.
	MinimumSeverity MinimumSeverity
}

// NothingScannedYet is what readiness says of a build declared and never
// built.
const NothingScannedYet = "nothing has been scanned here yet"

// ReadyFor compares a branch's current state against the last release cut from
// it, built the same way.
//
// The same variant on both sides. A branch built for one chip beside a
// release built for another compares two different pieces of software and
// reads as a regression somebody then goes looking for.
//
// The release is the latest one cut from this branch that we have scanned.
// A build nothing has scanned has no counts, and answering with zeroes would
// report a clean release that does not exist.
func (s *Store) ReadyFor(ctx context.Context, subject access.Subject,
	productID, branchOrTagID, variantID int64) (*Readiness, error) {

	if _, err := access.Readable(subject, productID); err != nil {
		return nil, err
	}
	floor, err := MinimumSeverityFor(ctx, s.db, productID)
	if err != nil {
		return nil, err
	}

	here, err := s.standing(ctx, subject, productID, branchOrTagID, variantID, floor)
	if err != nil {
		return nil, err
	}
	out := &Readiness{Now: *here, MinimumSeverity: floor}
	if here.BuildID == 0 || here.LastScanned == nil {
		// Declared and not scanned: never built, or built and every upload
		// refused. An answer rather than a refusal, and not zeroes alone,
		// which read as a build that was scanned and is clean.
		out.Why = NothingScannedYet
		return out, nil
	}
	if here.Kind != string(catalog.Branch) {
		// A tag is one frozen point and was not cut into anything, so there is
		// no "since we shipped" for it. Said rather than answered with an
		// empty comparison, which reads as a branch with nothing released.
		out.Why = "a tag is a fixed point, so nothing was cut from it"
		return out, nil
	}

	// The latest release cut from this branch, built the same way, that has
	// been scanned. Ordered by when the release was declared here: a tag is
	// cut at a moment and never moves again, so the newest declaration is the
	// last thing shipped.
	var release struct {
		BranchOrTagID int64 `bun:"branch_or_tag_id"`
	}
	err = s.db.NewSelect().
		TableExpr(`"branch_or_tag" AS "st"`).
		Join(`JOIN "build" AS "tg" ON "tg"."branch_or_tag_id" = "st"."id"`).
		ColumnExpr(`"st"."id" AS "branch_or_tag_id"`).
		Where(`"st"."parent_id" = ?`, branchOrTagID).
		Where(`"tg"."variant_id" = ?`, variantID).
		Where(`EXISTS (SELECT 1 FROM "scan_run" AS "sr"
			WHERE "sr"."build_id" = "tg"."id" AND "sr"."finished_at" IS NOT NULL)`).
		OrderExpr(`"st"."created_at" DESC, "st"."id" DESC`).
		Limit(1).
		Scan(ctx, &release)
	if err != nil && !database.IsNoRows(err) {
		return nil, fmt.Errorf("read the last release cut from this branch: %w", err)
	}
	if release.BranchOrTagID == 0 {
		out.Why = "no scanned release from this branch"
		return out, nil
	}

	shipped, err := s.standing(ctx, subject, productID, release.BranchOrTagID, variantID, floor)
	if err != nil {
		return nil, err
	}
	out.Shipped = shipped
	return out, nil
}

// standing counts what one build holds now, by band.
func (s *Store) standing(ctx context.Context, subject access.Subject,
	productID, branchOrTagID, variantID int64, floor MinimumSeverity) (*Standing, error) {

	_, all := subject.Products()

	// One row per issue at a component, then folded into bands. Distinct
	// first, because the fan-out is the point of the model and counting rows
	// measures how much the dependency graph shares rather than how much
	// there is to answer.
	//
	// Reduced on the finding alone, and the issue and its rating joined to
	// what is left: inside one product an issue has one band, so the pair
	// carries it without the band in the key, and joining first reads the
	// issue's row once per occurrence only to fold the copies away.
	kinds, args := kind.Statistics.Where(`"f"."kind"`)
	pairs := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"f"."component_id" AS "component_id"`).
		Where(`"f"."closed_at" IS NULL`).
		Where(`"st"."product_id" = ?`, productID).
		Where(`"tg"."branch_or_tag_id" = ?`, branchOrTagID).
		Where(`"tg"."variant_id" = ?`, variantID).
		Where(kinds, args...).
		GroupExpr(`"f"."vulnerability_id", "f"."component_id"`)
	pairs = floor.narrow(inOneProduct(pairs, subject, productID, all))
	inner := s.db.NewSelect().
		TableExpr(`(?) AS "grouped"`, pairs).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "grouped"."vulnerability_id"`).
		Join(rating.Here, productID).
		ColumnExpr(rating.BandExpr + ` AS "band"`)

	var rows []struct {
		Band string `bun:"band"`
		Open int    `bun:"open"`
	}
	if err := s.db.NewSelect().
		TableExpr(`(?) AS "counted"`, inner).
		ColumnExpr(`"counted"."band" AS "band"`).
		ColumnExpr(`COUNT(*) AS "open"`).
		GroupExpr(`"counted"."band"`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("count what this build holds: %w", err)
	}

	standing := &Standing{ByBand: map[string]int{}}
	for _, row := range rows {
		standing.ByBand[row.Band] = row.Open
		standing.Total += row.Open
	}

	// Named from the release and the variant rather than from the build, and
	// the build joined to them: a tag declared and not yet built has a name and
	// no build, which is the ordinary state of a tag between being cut and its
	// pipeline running.
	if err := s.db.NewSelect().
		TableExpr(`"branch_or_tag" AS "st"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = ?`, variantID).
		Join(`LEFT JOIN "build" AS "tg" ON "tg"."branch_or_tag_id" = "st"."id" AND "tg"."variant_id" = "va"."id"`).
		ColumnExpr(`COALESCE("tg"."id", 0) AS "build_id"`).
		ColumnExpr(`"st"."name" AS "branch_or_tag"`).
		ColumnExpr(catalog.ShownExpr("st")+` AS "branch_or_tag_name"`).
		ColumnExpr(`"st"."kind" AS "kind"`).
		ColumnExpr(`"va"."name" AS "variant"`).
		ColumnExpr(catalog.ShownExpr("va")+` AS "variant_name"`).
		Where(`"st"."id" = ?`, branchOrTagID).
		Limit(1).
		Scan(ctx, standing); err != nil {
		return nil, database.FromRead(err, catalog.ErrNotFound, "read what this build is called")
	}
	if standing.BuildID == 0 {
		return standing, nil
	}

	// The newest finished run, read as a row rather than as MAX(): an
	// aggregate over no rows answers NULL, which will not scan into a time,
	// and "never scanned" is an ordinary answer here rather than an error.
	var finished []time.Time
	if err := s.db.NewSelect().
		TableExpr(`"scan_run" AS "sr"`).
		ColumnExpr(`"sr"."finished_at"`).
		Where(`"sr"."build_id" = ?`, standing.BuildID).
		Where(`"sr"."finished_at" IS NOT NULL`).
		OrderExpr(`"sr"."finished_at" DESC`).
		Limit(1).
		Scan(ctx, &finished); err != nil {
		return nil, fmt.Errorf("read when this build was last scanned: %w", err)
	}
	if len(finished) == 1 {
		standing.LastScanned = &finished[0]
	}
	return standing, nil
}
