// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// The disclosure date a claim from outside starts on a flaw recorded here when
// it is ruled a duplicate of it.

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// duplicateStart is the date a duplicate ruling over these reports gives a
// flaw, the claim it counts from, and where the embargo ends before it.
type duplicateStart struct {
	at     time.Time
	report int64
	was    *time.Time
}

// startOf works out the date a duplicate ruling over these reports gives the
// flaw's undisclosed places in one product, or nothing where it gives none.
//
// Counted from when the earliest claim from outside arrived, or was recorded
// where it does not say, plus the disclosure window: the reporter publishes on
// their own clock, which started when they told us (REQ-37). A claim found here
// starts nothing. Nothing either where every place already ends on that date
// or earlier, because an earlier end is one somebody is already held to.
//
// Read on the handle it is given, so a ruling asks it inside the transaction
// that writes the ruling and a retry asks again.
func startOf(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64,
	reportIDs []int64) (*duplicateStart, error) {

	if len(reportIDs) == 0 {
		return nil, nil
	}
	var reports []FlawReport
	if err := db.NewSelect().Model(&reports).
		Column("fr.id", "fr.received_on", "fr.recorded_at").
		Where("fr.id IN (?)", bun.List(reportIDs)).
		Where("fr.found_here = ?", false).
		Order("fr.id").
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read when those claims arrived: %w", err)
	}
	var start *duplicateStart
	for _, report := range reports {
		arrived := report.RecordedAt
		if report.ReceivedOn != nil {
			arrived = *report.ReceivedOn
		}
		arrived = arrived.UTC()
		if start == nil || arrived.Before(start.at) {
			start = &duplicateStart{at: arrived, report: report.ID}
		}
	}
	if start == nil {
		return nil, nil
	}
	window, err := setting.NewStore(db).Duration(ctx,
		setting.DiscloseAfter, setting.DefaultDiscloseAfter)
	if err != nil {
		return nil, err
	}
	start.at = start.at.Add(window).Truncate(time.Microsecond)

	later, err := db.NewSelect().Model((*Finding)(nil)).
		Apply(flawPlaces(productID, vulnerabilityID)).
		Where("disclose_at IS NULL OR disclose_at > ?", start.at).
		Exists(ctx)
	if err != nil {
		return nil, fmt.Errorf("read whether the flaw ends later: %w", err)
	}
	if !later {
		return nil, nil
	}
	start.was, err = flawEnds(ctx, db, productID, vulnerabilityID)
	if err != nil {
		return nil, err
	}
	return start, nil
}

// flawPlaces narrows findings to a flaw's undisclosed open places in one
// product: the places a duplicate ruling dates.
//
// A flaw recorded here and nothing a scan found. A scanned issue is published
// by whoever published the advisory it matched, so no reporter is counting
// down to it here.
func flawPlaces(productID, vulnerabilityID int64) func(*bun.SelectQuery) *bun.SelectQuery {
	return func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.Where(HeldAs("vulnerability_id"), vulnerabilityID).
			Where("kind = ?", Entered).
			Where("visibility = ?", access.Private).
			Where("closed_at IS NULL").
			Where(inThisProduct, productID)
	}
}

// flawEnds is where a flaw's embargo ends in one product now, or nothing where
// no place has a date.
func flawEnds(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64) (*time.Time, error) {
	var dated []time.Time
	if err := db.NewSelect().Model((*Finding)(nil)).
		ColumnExpr("disclose_at").
		Apply(flawPlaces(productID, vulnerabilityID)).
		Where("disclose_at IS NOT NULL").
		OrderExpr("disclose_at DESC").
		Limit(1).
		Scan(ctx, &dated); err != nil {
		return nil, fmt.Errorf("read where the flaw's embargo ends: %w", err)
	}
	if len(dated) == 0 {
		return nil, nil
	}
	ends := dated[0].UTC()
	return &ends, nil
}

// dateFlaw writes an end onto a flaw's undisclosed places in one product,
// or clears it where there is none. Only places ending later than it, or not
// at all, where earlier says so: the rule a ruling dates by.
func dateFlaw(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64,
	until *time.Time, earlier bool, now time.Time) error {

	q := db.NewUpdate().Model((*Finding)(nil)).
		Set("last_changed_at = ?", now).
		Where(HeldAs("vulnerability_id"), vulnerabilityID).
		Where("kind = ?", Entered).
		Where("visibility = ?", access.Private).
		Where("closed_at IS NULL").
		Where(inThisProduct, productID)
	switch {
	case until == nil:
		q = q.Set("disclose_at = NULL")
	case earlier:
		q = q.Set("disclose_at = ?", *until).
			Where("disclose_at IS NULL OR disclose_at > ?", *until)
	default:
		q = q.Set("disclose_at = ?", *until)
	}
	if _, err := q.Exec(ctx); err != nil {
		return fmt.Errorf("date the flaw's embargo: %w", err)
	}
	return nil
}

// duplicateDated gives the flaw a duplicate ruling names the date the ruling
// starts, and records it as a movement of the embargo naming the ruling and
// the claim it counts from.
//
// Inside the ruling's transaction, so the ruling and the date are one act.
func duplicateDated(ctx context.Context, tx bun.IDB, ruling *ReportRuling,
	reportIDs []int64, now time.Time) error {

	if ruling.Disposition != Duplicate || ruling.DuplicateOf == nil {
		return nil
	}
	issue := *ruling.DuplicateOf
	start, err := startOf(ctx, tx, ruling.ProductID, issue, reportIDs)
	if err != nil || start == nil {
		return err
	}
	if err := dateFlaw(ctx, tx, ruling.ProductID, issue, &start.at, true, now); err != nil {
		return err
	}
	at, rulingID, report := start.at, ruling.ID, start.report
	moved := &Movement{
		VulnerabilityID: issue, ProductID: ruling.ProductID,
		Act: Duplicated, Was: start.was, Until: &at, Reason: ruling.Reasoning,
		AskedBy: ruling.ProposedBy, AskedAt: now,
		RulingID: &rulingID, FlawReportID: &report,
	}
	if _, err := tx.NewInsert().Model(moved).Exec(ctx); err != nil {
		return fmt.Errorf("record the date a duplicate started: %w", err)
	}
	return nil
}

// duplicateUndated puts a flaw's embargo back where the movements still
// standing leave it, once the duplicate ruling that dated it is withdrawn.
//
// The end is worked out again from the embargo's own record rather than taken
// from the ruling's movement alone. A person's extension or shortening sets an
// end, and a ruling moves it earlier only; replayed without every withdrawn
// ruling, the record says where the embargo would stand had those rulings
// never been made. Where that is where it stands now, the ruling set nothing
// that is still in force and nothing moves. Where it differs, the places take
// it, which may be no date at all, and the withdrawal is recorded as a
// movement naming the ruling.
func duplicateUndated(ctx context.Context, tx bun.IDB, ruling *ReportRuling,
	personID int64, now time.Time) error {

	if ruling.Disposition != Duplicate || ruling.DuplicateOf == nil {
		return nil
	}
	issue := *ruling.DuplicateOf
	var record []Movement
	if err := tx.NewSelect().Model(&record).
		Where("product_id = ?", ruling.ProductID).
		Where(FiledUnder("vulnerability_id"), issue).
		Order("asked_at", "id").
		Scan(ctx); err != nil {
		return fmt.Errorf("read how this embargo has been moved: %w", err)
	}
	dated := false
	var rulings []int64
	for _, row := range record {
		if row.Act == Duplicated && row.RulingID != nil {
			rulings = append(rulings, *row.RulingID)
			dated = dated || *row.RulingID == ruling.ID
		}
	}
	if !dated {
		return nil
	}
	var withdrawn []int64
	if err := tx.NewSelect().Model((*ReportRuling)(nil)).
		Column("rr.id").
		Where("rr.id IN (?)", bun.List(rulings)).
		Where("rr.withdrawn_at IS NOT NULL").
		Scan(ctx, &withdrawn); err != nil {
		return fmt.Errorf("read which rulings still stand: %w", err)
	}
	gone := make(map[int64]bool, len(withdrawn))
	for _, id := range withdrawn {
		gone[id] = true
	}

	standing := replayed(record, gone)
	placed, err := tx.NewSelect().Model((*Finding)(nil)).
		Apply(flawPlaces(ruling.ProductID, issue)).
		Exists(ctx)
	if err != nil {
		return fmt.Errorf("read whether the flaw is still undisclosed: %w", err)
	}
	if !placed {
		return nil
	}
	ends, err := flawEnds(ctx, tx, ruling.ProductID, issue)
	if err != nil {
		return err
	}
	if sameMoment(ends, standing) {
		return nil
	}
	if err := dateFlaw(ctx, tx, ruling.ProductID, issue, standing, false, now); err != nil {
		return err
	}
	rulingID := ruling.ID
	undone := &Movement{
		VulnerabilityID: issue, ProductID: ruling.ProductID,
		Act: Unduplicated, Was: ends, Until: standing,
		AskedBy: personID, AskedAt: now, RulingID: &rulingID,
	}
	if _, err := tx.NewInsert().Model(undone).Exec(ctx); err != nil {
		return fmt.Errorf("record the date a withdrawn duplicate put back: %w", err)
	}
	return nil
}

// replayed is where an embargo's record leaves its end once the rulings named
// are taken out of it.
//
// It starts where the first movement found the embargo. A person's extension or
// shortening in force sets the end to the date it asked for; a ruling brings it
// earlier or starts it. A movement still waiting moved nothing, and one
// recording a withdrawal is itself worked out from the others.
func replayed(record []Movement, withdrawn map[int64]bool) *time.Time {
	if len(record) == 0 {
		return nil
	}
	ends := record[0].Was
	for _, row := range record {
		if !row.InForce() {
			continue
		}
		switch row.Act {
		case Extension, Shortening:
			ends = row.Until
		case Duplicated:
			if row.RulingID != nil && withdrawn[*row.RulingID] {
				continue
			}
			if row.Until != nil && (ends == nil || row.Until.Before(*ends)) {
				ends = row.Until
			}
		}
	}
	return ends
}

// sameMoment reports whether two dates that may be absent are the same.
func sameMoment(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// DuplicateStarts is the disclosure date ruling these reports a duplicate of
// an issue would give it in this product, or nothing where it would give none.
//
// For the form a ruling is made on, which says what submitting it starts.
// Asked under the rule proposing the ruling is, and the issue under the rule
// naming it as the duplicate target is, so the answer says nothing somebody
// who could not submit the ruling would not be told.
func (s *Store) DuplicateStarts(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64, references []string) (*time.Time, error) {

	if err := mayHandle(subject, productID); err != nil {
		return nil, err
	}
	told, err := MayBeToldOfWithin(ctx, s.db, subject, productID, vulnerabilityID)
	if err != nil {
		return nil, err
	}
	if !told {
		return nil, ErrNoSuchIssueHere
	}
	named := distinctReferences(references)
	if len(named) == 0 {
		return nil, ErrNoReports
	}
	var found []FlawReport
	if err := s.db.NewSelect().Model(&found).
		Column("fr.id", "fr.reference").
		Where("fr.product_id = ?", productID).
		Where("fr.reference IN (?)", bun.List(named)).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the reports named: %w", err)
	}
	if len(found) != len(named) {
		here := map[string]bool{}
		for _, row := range found {
			here[row.Reference] = true
		}
		var missing []string
		for _, each := range named {
			if !here[each] {
				missing = append(missing, each)
			}
		}
		return nil, &NotHere{References: missing}
	}
	ids := make([]int64, 0, len(found))
	for _, row := range found {
		ids = append(ids, row.ID)
	}
	start, err := startOf(ctx, s.db, productID, vulnerabilityID, ids)
	if err != nil || start == nil {
		return nil, err
	}
	return &start.at, nil
}
