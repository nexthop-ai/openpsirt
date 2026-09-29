// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// What a document states about one release, in the standard's words.
const (
	KnownAffected    = "known_affected"
	KnownNotAffected = "known_not_affected"
	Fixed            = "fixed"
)

// The outcomes a covering decision states, as the triage vocabulary spells
// them.
const (
	notApplicable = "not-applicable"
	alreadyFixed  = "already-fixed"
)

// Release is one build of the product and where it stands on the issue.
type Release struct {
	StreamID  int64
	VariantID int64
	Stream    string
	Variant   string
	// Holds says the issue is open there. False is a release that held it and
	// no longer does, which is the one that was fixed.
	Holds bool
	// Identifier is what this build's own inventory called the thing it is
	// about, and empty where that document named no component of its own.
	Identifier string
	// Grounds is the decision every open place of the issue in this release
	// stands under, where approved, live decisions with one outcome cover them
	// all, and nil otherwise.
	Grounds *Grounds
	// Overridden says the person preparing the advisory marked the release
	// affected whatever its decisions say.
	Overridden bool
}

// Grounds is the decision a release stands under, as the document and the
// advisory screen read it.
type Grounds struct {
	// Decision is the earliest decision among those covering the release.
	Decision int64
	Outcome  string
	// Reason is the decision's justification, in the vocabulary the CSAF
	// flag labels are.
	Reason string
	// Mitigation is what stops the flaw, where the decision named it. The
	// decision's reasoning is never read.
	Mitigation string
	// DecidedIn is the variants the decision's place was open in when it was
	// proposed. A decision reaches every build whose versions match, so a
	// release outside this list is one the decision reached rather than one
	// it was made about.
	DecidedIn []string
}

// Name is how the release is written in the document.
func (r Release) Name() string { return r.Stream + " (" + r.Variant + ")" }

// ProductID is the identifier statements refer to it by. A release is named by
// its stream and its variant together, never by one of them: the same branch
// built two ways is two builds, and naming only the branch would claim
// something about hardware nobody built for.
func (r Release) ProductID(product string) string {
	return product + ":" + r.Stream + ":" + r.Variant
}

// Decided is where the release's decisions put it, before any override: known
// not affected where they say the flaw does not apply and give a reason, fixed
// where they say it is already fixed, and known affected otherwise.
func (r Release) Decided() string {
	switch {
	case !r.Holds:
		return Fixed
	case r.Grounds == nil:
		return KnownAffected
	case (r.Grounds.Outcome == notApplicable || r.Grounds.Outcome == finding.Mismatched) &&
		r.Grounds.Reason != "":
		return KnownNotAffected
	case r.Grounds.Outcome == alreadyFixed:
		return Fixed
	}
	return KnownAffected
}

// Status is what the document states about the release: where its decisions
// put it, or known affected where the preparer marked it so.
func (r Release) Status() string {
	if r.Overridden && r.Holds {
		return KnownAffected
	}
	return r.Decided()
}

// releases reports every build of the product that holds this issue or once
// did, which is what an advisory states something about, with the decision
// each stands under and whether this advisory marks it affected anyway.
//
// A finding taken back as invalid is left out. Narrowing a flaw's affected
// builds closes a build's finding that way, and that build never shipped the
// flaw: named as fixed, it reads as a release somebody upgrades to.
//
// A superseded closure is never read as a fix. The version moved and the flaw
// came with it, so the row that superseded it speaks for the place. A release
// whose only closures are superseded, with nothing open, is stated as known
// affected: the last word on it says the flaw moved with the version, and
// nothing after it says the flaw left.
//
// The decisions are read at the visibilities the findings are, and through
// the one rule the VEX document of a build reads them by.
func releases(ctx context.Context, db bun.IDB, subject access.Subject,
	advisoryID, productID, issueID int64) ([]Release, error) {

	visible := access.Visible(subject, productID)
	var rows []struct {
		StreamID  int64  `bun:"stream_id"`
		VariantID int64  `bun:"variant_id"`
		Stream    string `bun:"stream"`
		Variant   string `bun:"variant"`
		Open      int    `bun:"open"`
		Settled   int    `bun:"settled"`
		Root      string `bun:"root_identifier"`
	}
	// One statement rather than one per build: a product with thirty tags
	// would otherwise be thirty round trips to write one document, and the
	// answer would be assembled from thirty moments rather than one.
	err := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "t" ON t.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = t.stream_id`).
		Join(`JOIN "variant" AS "va" ON va.id = t.variant_id`).
		// This build's own name for itself, from the scan that inventory
		// arrived on. Joined on the target's current scan, which is one row by
		// key, so it cannot multiply the findings counted below.
		Join(`LEFT JOIN "scan" AS "sc" ON sc.id = t.last_scan_id`).
		ColumnExpr(`st.id AS "stream_id"`).
		ColumnExpr(`va.id AS "variant_id"`).
		ColumnExpr(`st.name AS "stream"`).
		ColumnExpr(`va.name AS "variant"`).
		// Counted rather than filtered, so a release that held the flaw and no
		// longer does is still a row — that is the release somebody upgrades
		// to, and dropping it would leave finished work indistinguishable
		// from a release that never shipped the thing.
		ColumnExpr(`COUNT(CASE WHEN f.closed_at IS NULL THEN 1 END) AS "open"`).
		ColumnExpr(`COUNT(CASE WHEN f.closed_at IS NOT NULL
			AND COALESCE(f.closed_because, '') <> ? THEN 1 END) AS "settled"`, finding.Superseded).
		// One value per build, aggregated because the grouping is on the
		// build's names as well as its keys.
		ColumnExpr(`MIN(COALESCE(sc.root_identifier, '')) AS "root_identifier"`).
		Where("st.product_id = ?", productID).
		Where("f.vulnerability_id = ?", issueID).
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("COALESCE(f.closed_because, '') <> ?", finding.Invalid).
		GroupExpr("st.id, va.id, st.name, va.name").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which releases this is in: %w", err)
	}

	standing, err := standingIn(ctx, db, productID, issueID, visible)
	if err != nil {
		return nil, err
	}
	overridden, err := overridesOf(ctx, db, advisoryID, productID, issueID)
	if err != nil {
		return nil, err
	}

	out := make([]Release, 0, len(rows))
	for _, row := range rows {
		at := [2]int64{row.StreamID, row.VariantID}
		release := Release{
			StreamID: row.StreamID, VariantID: row.VariantID,
			Stream: row.Stream, Variant: row.Variant,
			Holds:      row.Open > 0 || row.Settled == 0,
			Identifier: row.Root, Overridden: overridden[at],
		}
		// Coverage is asked of open places, so a release holding the flaw
		// only through a superseded closure has none.
		if row.Open > 0 {
			release.Grounds = standing[at]
		}
		out = append(out, release)
	}
	// Ordered here rather than by the engine, so the document is byte-for-byte
	// the same whatever it was generated against — which is what lets somebody
	// diff two of them and see a real change.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Stream != out[j].Stream {
			return out[i].Stream < out[j].Stream
		}
		return out[i].Variant < out[j].Variant
	})
	return out, nil
}

// standingIn is the decision each build of the product stands under for this
// issue, keyed by its stream and variant, where one covers every open place.
func standingIn(ctx context.Context, db bun.IDB, productID, issueID int64,
	visible []access.Visibility) (map[[2]int64]*Grounds, error) {

	var rows []struct {
		StreamID  int64 `bun:"stream_id"`
		VariantID int64 `bun:"variant_id"`
		finding.Covering
	}
	q := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "t" ON t.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = t.stream_id`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		ColumnExpr(`t.stream_id AS "stream_id"`).
		ColumnExpr(`t.variant_id AS "variant_id"`).
		Where("st.product_id = ?", productID).
		Where("f.vulnerability_id = ?", issueID).
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr("t.stream_id, t.variant_id")
	if err := finding.WhollyCovered(q, productID, visible).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read which releases a decision covers: %w", err)
	}
	out := make(map[[2]int64]*Grounds, len(rows))
	if len(rows) == 0 {
		return out, nil
	}
	decided := make([]int64, 0, len(rows))
	for _, row := range rows {
		decided = append(decided, row.DecidedBy)
	}
	said, err := finding.StatedBy(ctx, db, decided)
	if err != nil {
		return nil, err
	}
	in, err := decidedIn(ctx, db, decided, visible)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[[2]int64{row.StreamID, row.VariantID}] = &Grounds{
			Decision: row.DecidedBy, Outcome: row.Outcome,
			Reason:     said[row.DecidedBy].Justification,
			Mitigation: said[row.DecidedBy].Mitigation,
			DecidedIn:  in[row.DecidedBy],
		}
	}
	return out, nil
}

// decidedIn is the variants each decision's place was open in when the
// decision was proposed, in name order.
//
// A decision records the product, the issue and the place, and no build: it
// reaches every build whose versions match. What the record does hold is when
// it was proposed and when each finding at its place opened and closed, which
// says where the place stood at that moment.
func decidedIn(ctx context.Context, db bun.IDB, decisions []int64,
	visible []access.Visibility) (map[int64][]string, error) {

	var rows []struct {
		ID      int64  `bun:"id"`
		Variant string `bun:"variant"`
	}
	where, args := database.InAnyOf("de.id", decisions)
	err := db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "vulnerability" AS "dv" ON dv.id = de.vulnerability_id`).
		Join(`JOIN "finding" AS "f" ON f.vulnerability_id = dv.issue_id
			AND f.place_identity = de.place_identity`).
		Join(`JOIN "target" AS "t" ON t.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = t.stream_id AND st.product_id = de.product_id`).
		Join(`JOIN "variant" AS "va" ON va.id = t.variant_id`).
		Distinct().
		ColumnExpr(`de.id AS "id"`).
		ColumnExpr(`va.name AS "variant"`).
		Where(where, args...).
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("f.opened_at <= de.proposed_at").
		Where("(f.closed_at IS NULL OR f.closed_at > de.proposed_at)").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read where these decisions were made: %w", err)
	}
	out := map[int64][]string{}
	for _, row := range rows {
		out[row.ID] = append(out[row.ID], row.Variant)
	}
	for id := range out {
		sort.Strings(out[id])
	}
	return out, nil
}

// Override is the person preparing an advisory marking one release affected
// whatever its decisions say.
//
// Part of what the advisory says, so setting one and clearing one each open an
// edition and take back every agreement standing. The row stays once cleared,
// as a cover does, so who marked a release and who cleared it are both on the
// record; marking it again revives the row.
type Override struct {
	bun.BaseModel `bun:"table:advisory_override,alias:ao"`

	ID              int64      `bun:"id,pk,autoincrement"`
	AdvisoryID      int64      `bun:"advisory_id,notnull"`
	ProductID       int64      `bun:"product_id,notnull"`
	VulnerabilityID int64      `bun:"vulnerability_id,notnull"`
	StreamID        int64      `bun:"stream_id,notnull"`
	VariantID       int64      `bun:"variant_id,notnull"`
	SetAt           time.Time  `bun:"set_at,notnull"`
	SetBy           int64      `bun:"set_by,notnull"`
	RemovedAt       *time.Time `bun:"removed_at"`
	RemovedBy       *int64     `bun:"removed_by"`
}

// overridesOf is the releases this advisory marks affected for one issue in
// one product, keyed by stream and variant.
//
// Read as the issue the marked row stands for, so a mark filed under an issue
// that merged into another marks the other.
func overridesOf(ctx context.Context, db bun.IDB, advisoryID, productID,
	issueID int64) (map[[2]int64]bool, error) {

	var rows []struct {
		StreamID  int64 `bun:"stream_id"`
		VariantID int64 `bun:"variant_id"`
	}
	err := db.NewSelect().
		TableExpr(`"advisory_override" AS "ao"`).
		Join(`JOIN "vulnerability" AS "ov" ON ov.id = ao.vulnerability_id`).
		ColumnExpr(`ao.stream_id AS "stream_id"`).
		ColumnExpr(`ao.variant_id AS "variant_id"`).
		Where("ao.advisory_id = ?", advisoryID).
		Where("ao.product_id = ?", productID).
		Where("ov.issue_id = ?", issueID).
		Where("ao.removed_at IS NULL").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which releases are marked affected: %w", err)
	}
	out := make(map[[2]int64]bool, len(rows))
	for _, row := range rows {
		out[[2]int64{row.StreamID, row.VariantID}] = true
	}
	return out, nil
}
