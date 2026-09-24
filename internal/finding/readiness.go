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
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// Standing is what one build holds now, split by severity band.
//
// Counted as issues at components, which is what the findings list counts —
// a component reached twenty ways carries the same issue twenty times, and
// counting rows would make a build look twenty times worse than the list
// somebody opens next.
type Standing struct {
	// TargetID is the build these are about.
	TargetID int64 `bun:"target_id"`
	// Stream and Variant name it, and Kind says whether the release is a
	// branch or a tag. A screen asks because the comparison only means
	// something for a branch: a tag is one frozen point and was not cut into
	// anything.
	Stream      string `bun:"stream"`
	StreamName  string `bun:"stream_name"`
	Variant     string `bun:"variant"`
	VariantName string `bun:"variant_name"`
	Kind        string `bun:"kind"`
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
	// Floor is the line these counts are at or above, so a screen can say
	// whose number it is showing.
	Floor Floor
}

// ReadyFor compares a branch's current state against the last release cut from
// it, built the same way.
//
// The same variant on both sides. A branch built for one chip beside a
// release built for another compares two different pieces of software and
// reads as a regression somebody then goes looking for.
//
// The release is the latest one cut from this branch that we have scanned.
// A tag declared and never built has no counts, and answering with zeroes
// would report a clean release that does not exist.
func (s *Store) ReadyFor(ctx context.Context, subject access.Subject,
	productID, streamID, variantID int64) (*Readiness, error) {

	if !subject.Sees(productID) {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	if len(access.Visible(subject, productID)) == 0 {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	floor, err := FloorFor(ctx, s.db, productID)
	if err != nil {
		return nil, err
	}

	here, err := s.standing(ctx, subject, productID, streamID, variantID, floor)
	if err != nil {
		return nil, err
	}
	out := &Readiness{Now: *here, Floor: floor}
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
		StreamID int64 `bun:"stream_id"`
	}
	err = s.db.NewSelect().
		TableExpr(`"stream" AS "st"`).
		Join(`JOIN "target" AS "tg" ON tg.stream_id = st.id`).
		ColumnExpr(`st.id AS "stream_id"`).
		Where("st.parent_id = ?", streamID).
		Where("tg.variant_id = ?", variantID).
		Where(`EXISTS (SELECT 1 FROM "scan_run" AS "sr"
			WHERE sr.target_id = tg.id AND sr.finished_at IS NOT NULL)`).
		OrderExpr("st.created_at DESC, st.id DESC").
		Limit(1).
		Scan(ctx, &release)
	if err != nil && !database.IsNoRows(err) {
		return nil, fmt.Errorf("read the last release cut from this branch: %w", err)
	}
	if release.StreamID == 0 {
		out.Why = "no scanned release from this branch"
		return out, nil
	}

	shipped, err := s.standing(ctx, subject, productID, release.StreamID, variantID, floor)
	if err != nil {
		return nil, err
	}
	out.Shipped = shipped
	return out, nil
}

// standing counts what one build holds now, by band.
func (s *Store) standing(ctx context.Context, subject access.Subject,
	productID, streamID, variantID int64, floor Floor) (*Standing, error) {

	_, all := subject.Products()

	// One row per issue at a component, then folded into bands. Distinct
	// first, because the fan-out is the point of the model and counting rows
	// measures how much the dependency graph shares rather than how much
	// there is to answer.
	inner := s.db.NewSelect().
		Distinct().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		Join(rating.Here, productID).
		ColumnExpr(rating.BandExpr+` AS "band"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		Where("f.closed_at IS NULL").
		Where("st.product_id = ?", productID).
		Where("tg.stream_id = ?", streamID).
		Where("tg.variant_id = ?", variantID)
	inner = floor.narrow(inOneProduct(inner, subject, productID, all))

	var rows []struct {
		Band string `bun:"band"`
		Open int    `bun:"open"`
	}
	if err := s.db.NewSelect().
		TableExpr(`(?) AS "counted"`, inner).
		ColumnExpr(`counted.band AS "band"`).
		ColumnExpr(`COUNT(*) AS "open"`).
		GroupExpr("counted.band").
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("count what this build holds: %w", err)
	}

	standing := &Standing{ByBand: map[string]int{}}
	for _, row := range rows {
		standing.ByBand[row.Band] = row.Open
		standing.Total += row.Open
	}

	if err := s.db.NewSelect().
		TableExpr(`"target" AS "tg"`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "variant" AS "va" ON va.id = tg.variant_id`).
		ColumnExpr(`tg.id AS "target_id"`).
		ColumnExpr(`st.name AS "stream"`).
		ColumnExpr(`st.display_name AS "stream_name"`).
		ColumnExpr(`st.kind AS "kind"`).
		ColumnExpr(`va.name AS "variant"`).
		ColumnExpr(`va.display_name AS "variant_name"`).
		Where("tg.stream_id = ?", streamID).
		Where("tg.variant_id = ?", variantID).
		Limit(1).
		Scan(ctx, standing); err != nil {
		return nil, fmt.Errorf("read what this build is called: %w", err)
	}

	// The newest finished run, read as a row rather than as MAX(): an
	// aggregate over no rows answers NULL, which will not scan into a time,
	// and "never scanned" is an ordinary answer here rather than an error.
	var finished []time.Time
	if err := s.db.NewSelect().
		TableExpr(`"scan_run" AS "sr"`).
		ColumnExpr("sr.finished_at").
		Where("sr.target_id = ?", standing.TargetID).
		Where("sr.finished_at IS NOT NULL").
		OrderExpr("sr.finished_at DESC").
		Limit(1).
		Scan(ctx, &finished); err != nil {
		return nil, fmt.Errorf("read when this build was last scanned: %w", err)
	}
	if len(finished) == 1 {
		standing.LastScanned = &finished[0]
	}
	return standing, nil
}
