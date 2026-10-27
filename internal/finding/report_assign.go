// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// Who holds a report: a person, or a team whose queue it sits in, given by
// hand or placed by a standing rule, with every change kept for its history.

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// ErrReportJudged refuses holding a report that has been judged: its work goes
// on as the issue it became, or ended with the ruling that answered it.
var ErrReportJudged = refusal.New("that report has been judged, so there is nothing left to hold")

// ReportAssignment is one change of who holds a report.
type ReportAssignment struct {
	bun.BaseModel `bun:"table:report_assignment,alias:ra"`

	ID           int64 `bun:"id,pk,autoincrement"`
	FlawReportID int64 `bun:"flaw_report_id,notnull"`
	// AssignedTo is the party it went to. Absent is handed back to nobody.
	AssignedTo *int64 `bun:"assigned_to"`
	// AssignedBy is the person who did it. Absent where a standing rule
	// placed it, or an administrator's hand-over of everything somebody
	// held, which AssignedByRule and the act's own record tell apart.
	AssignedBy     *int64    `bun:"assigned_by"`
	AssignedByRule *int64    `bun:"assigned_by_rule"`
	AssignedAt     time.Time `bun:"assigned_at,notnull"`
}

// reportHeld is the visibility a report is held at, which is what a recipient
// is asked about: a report is undisclosed until it is an issue.
var reportHeld = []access.Visibility{access.Private}

// AssignReport records who is holding one open report, or hands it back.
//
// The rule a finding's assignment holds, at the visibility of a report.
// Taking a report nobody holds, one in a queue of a team the caller is on, and
// handing back their own are part of working reports. Giving one to somebody
// else, or taking one somebody else holds, needs the assigner right as well.
// Admits is asked whether the party may hold an undisclosed report, inside the
// transaction that moves it.
func (s *Store) AssignReport(ctx context.Context, subject access.Subject, productID int64,
	reference string, to *int64, admits Admits) (*FlawReport, error) {

	if err := mayWorkReference(subject, productID); err != nil {
		return nil, err
	}
	dispatches := subject.Holds(access.Assigner, productID)
	if err := mayMove(subject, productID, to, dispatches); err != nil {
		return nil, err
	}
	var row *FlawReport
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		var err error
		if row, err = reportIn(ctx, tx, productID, reference); err != nil {
			return err
		}
		if row.EvaluatedAt != nil {
			return ErrReportJudged
		}
		if to != nil && admits != nil {
			if err := admits(ctx, tx, reportHeld); err != nil {
				return err
			}
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		update := tx.NewUpdate().Model((*FlawReport)(nil)).
			Where(`"id" = ?`, row.ID).
			Where(`"evaluated_at" IS NULL`)
		if to == nil {
			update = update.Set(`"assigned_to" = ?`, nil).Set(`"assigned_at" = ?`, nil)
		} else {
			update = update.Set(`"assigned_to" = ?`, *to).Set(`"assigned_at" = ?`, now)
		}
		// Asked in the write, so an assignment landing between the read above
		// and here is not taken by somebody who may not take it.
		if !dispatches {
			update = update.Where(`("assigned_to" IS NULL OR "assigned_to" IN (?))`,
				bun.List(subject.Mine()))
		}
		res, err := update.Exec(ctx)
		if err != nil {
			return fmt.Errorf("record who holds the report: %w", err)
		}
		moved, err := database.Affected(res)
		if err != nil {
			return err
		}
		if moved == 0 {
			if !dispatches {
				return heldElsewhere(productID)
			}
			return ErrReportJudged
		}
		if sameHolder(row.AssignedTo, to) {
			return nil
		}
		by := subject.ID
		if err := recordHolder(ctx, tx, row.ID, to, &by, nil, now); err != nil {
			return err
		}
		row.AssignedTo = to
		if to == nil {
			row.AssignedAt = nil
		} else {
			row.AssignedAt = &now
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return row, nil
}

// sameHolder reports whether two holders are the same party, nobody included.
func sameHolder(a, b *int64) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

// recordHolder keeps one change of holder for a report's history.
func recordHolder(ctx context.Context, tx bun.IDB, reportID int64, to, by, rule *int64,
	at time.Time) error {

	if _, err := tx.NewInsert().Model(&ReportAssignment{
		FlawReportID: reportID, AssignedTo: to, AssignedBy: by, AssignedByRule: rule, AssignedAt: at,
	}).Exec(ctx); err != nil {
		return fmt.Errorf("keep who held the report: %w", err)
	}
	return nil
}

// HeldReport is one open report in a list of held work, with its product.
type HeldReport struct {
	FlawReport `bun:",extend"`

	// Product is the name the report is addressed under.
	Product string `bun:"product"`
}

// HeldReports is the open reports some set of parties holds, or nobody holds
// where none are named, across every product the subject reads reports in,
// oldest first. Open is not yet judged: a report with a ruling waiting for a
// second person still has somebody working it.
func (s *Store) HeldReports(ctx context.Context, subject access.Subject, productID int64,
	holders []int64, limit, offset int) ([]HeldReport, int, error) {

	if subject.Kind != access.Person {
		return nil, 0, access.Denied("read what is assigned")
	}
	var asked []int64
	if productID != 0 {
		asked = []int64{productID}
	}
	products := reportProducts(subject, asked)
	if len(products) == 0 {
		return nil, 0, nil
	}
	var rows []HeldReport
	q := s.db.NewSelect().Model(&rows).
		Join(`JOIN "product" AS "p" ON "p"."id" = "fr"."product_id"`).
		ColumnExpr(`"fr".*`).
		ColumnExpr(`"p"."name" AS "product"`).
		Where(`"fr"."evaluated_at" IS NULL`).
		Where(`"fr"."product_id" IN (?)`, bun.List(products))
	if len(holders) == 0 {
		q = q.Where(`"fr"."assigned_to" IS NULL`)
	} else {
		q = q.Where(`"fr"."assigned_to" IN (?)`, bun.List(holders))
	}
	total, err := q.Order("fr.recorded_at", "fr.id").
		Limit(int64(database.AList.Of(limit))).Offset(int64(offset)).
		ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("read which reports are held: %w", err)
	}
	return rows, int(total), nil
}

// ReportHoldings is how many open reports each party holds, across the
// products the subject reads reports in, or in one of them where productID is
// not zero.
func (s *Store) ReportHoldings(ctx context.Context, subject access.Subject,
	productID int64) (map[int64]int, error) {

	out := map[int64]int{}
	if subject.Kind != access.Person {
		return out, nil
	}
	var asked []int64
	if productID != 0 {
		asked = []int64{productID}
	}
	products := reportProducts(subject, asked)
	if len(products) == 0 {
		return out, nil
	}
	var rows []struct {
		Party int64 `bun:"party"`
		Open  int   `bun:"open"`
	}
	if err := s.db.NewSelect().TableExpr(`"flaw_report" AS "fr"`).
		ColumnExpr(`"fr"."assigned_to" AS "party"`).
		ColumnExpr(`COUNT(*) AS "open"`).
		Where(`"fr"."evaluated_at" IS NULL`).
		Where(`"fr"."product_id" IN (?)`, bun.List(products)).
		Where(`"fr"."assigned_to" IS NOT NULL`).
		GroupExpr(`"fr"."assigned_to"`).
		Limit(int64(database.InBulk.Most)).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read how many reports each holds: %w", err)
	}
	for _, row := range rows {
		out[row.Party] = row.Open
	}
	return out, nil
}

// moveReportsOf moves the open reports one party holds, in every product or
// in one, to another party or to nobody, keeping each change for its history.
// Asked inside the transaction of an administrator's hand-over.
func moveReportsOf(ctx context.Context, tx bun.IDB, from int64, to *int64, productID int64,
	now time.Time) (int64, error) {

	var ids []int64
	q := tx.NewSelect().Model((*FlawReport)(nil)).Column("id").
		Where(`"fr"."assigned_to" = ?`, from).
		Where(`"fr"."evaluated_at" IS NULL`)
	if productID != 0 {
		q = q.Where(`"fr"."product_id" = ?`, productID)
	}
	if err := q.Scan(ctx, &ids); err != nil {
		return 0, fmt.Errorf("read which reports they hold: %w", err)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	update := tx.NewUpdate().Model((*FlawReport)(nil)).Where(`"id" IN (?)`, bun.List(ids))
	if to == nil {
		update = update.Set(`"assigned_to" = ?`, nil).Set(`"assigned_at" = ?`, nil)
	} else {
		update = update.Set(`"assigned_to" = ?`, *to).Set(`"assigned_at" = ?`, now)
	}
	if _, err := update.Exec(ctx); err != nil {
		return 0, fmt.Errorf("move the reports they hold: %w", err)
	}
	for _, id := range ids {
		if err := recordHolder(ctx, tx, id, to, nil, nil, now); err != nil {
			return 0, err
		}
	}
	return int64(len(ids)), nil
}

// reportProductsHeld is the products where one party holds an open report,
// which a hand-over asks the recipient about.
func reportProductsHeld(ctx context.Context, tx bun.IDB, party int64) ([]int64, error) {
	var products []int64
	if err := tx.NewSelect().Model((*FlawReport)(nil)).
		ColumnExpr(`DISTINCT "fr"."product_id"`).
		Where(`"fr"."assigned_to" = ?`, party).
		Where(`"fr"."evaluated_at" IS NULL`).
		Scan(ctx, &products); err != nil {
		return nil, fmt.Errorf("read where they hold reports: %w", err)
	}
	return products, nil
}

// AddReportRule records a standing rule that places a product's reports
// nobody holds in a team's queue, and returns it. It names no package and no
// place: a report sits at neither.
func (s *Store) AddReportRule(ctx context.Context, by access.Subject, productID, teamID int64,
	name string) (*AssignmentRule, error) {

	if err := mayAssignByRule(by, productID); err != nil {
		return nil, err
	}
	return s.insertRule(ctx, by, productID, teamID, name, "", "", true)
}

// reportTeam is the first rule placing reports in a product whose team may
// hold a report, and that team's party: one member reads undisclosed work
// there. Zero where none does.
func reportTeam(ctx context.Context, db bun.IDB, productID int64) (rule, party int64, err error) {
	var rules []AssignmentRule
	if err := db.NewSelect().Model(&rules).
		Where(`"product_id" = ?`, productID).
		Where(`"retired_at" IS NULL`).
		Where(`"reports" = ?`, true).
		Order("ordinal", "id").Scan(ctx); err != nil {
		return 0, 0, fmt.Errorf("read the rules placing reports: %w", err)
	}
	if len(rules) == 0 {
		return 0, 0, nil
	}
	teams, err := (&Store{db: db}).partiesOf(ctx, rules)
	if err != nil {
		return 0, 0, err
	}
	rights := access.NewStore(db)
	for _, r := range rules {
		held, ok := teams[r.TeamID]
		if !ok {
			continue
		}
		reads, err := rights.AnyMemberReads(ctx, r.TeamID, productID, access.Private)
		if err != nil {
			return 0, 0, err
		}
		if reads {
			return r.ID, held, nil
		}
	}
	return 0, 0, nil
}

// routeReport places one report nobody holds with the first rule's team that
// may hold it, inside the transaction that recorded it.
func routeReport(ctx context.Context, tx bun.IDB, row *FlawReport, now time.Time) error {
	rule, party, err := reportTeam(ctx, tx, row.ProductID)
	if err != nil || party == 0 {
		return err
	}
	if _, err := tx.NewUpdate().Model((*FlawReport)(nil)).
		Set(`"assigned_to" = ?`, party).Set(`"assigned_at" = ?`, now).
		Where(`"id" = ?`, row.ID).Where(`"assigned_to" IS NULL`).Exec(ctx); err != nil {
		return fmt.Errorf("place the report: %w", err)
	}
	row.AssignedTo, row.AssignedAt = &party, &now
	return recordHolder(ctx, tx, row.ID, &party, nil, &rule, now)
}

// applyReportRule is one report rule's share of a sweep: the product's open
// reports nobody holds, placed in the rule's team's queue where a member reads
// undisclosed work there.
func (s *Store) applyReportRule(ctx context.Context, productID int64, rule AssignmentRule,
	party int64, room int) (read, placed int, err error) {

	reads, err := access.NewStore(s.db).AnyMemberReads(ctx, rule.TeamID, productID, access.Private)
	if err != nil || !reads {
		return 0, 0, err
	}
	err = database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		read, placed = 0, 0
		var ids []int64
		if err := tx.NewSelect().Model((*FlawReport)(nil)).Column("id").
			Where(`"fr"."product_id" = ?`, productID).
			Where(`"fr"."assigned_to" IS NULL`).
			Where(`"fr"."evaluated_at" IS NULL`).
			Order("fr.id").Limit(int64(room)).Scan(ctx, &ids); err != nil {
			return fmt.Errorf("read which reports that rule would place: %w", err)
		}
		read = len(ids)
		now := s.now().UTC().Truncate(time.Microsecond)
		for _, id := range ids {
			res, err := tx.NewUpdate().Model((*FlawReport)(nil)).
				Set(`"assigned_to" = ?`, party).Set(`"assigned_at" = ?`, now).
				Where(`"id" = ?`, id).Where(`"assigned_to" IS NULL`).
				Where(`"evaluated_at" IS NULL`).Exec(ctx)
			if err != nil {
				return fmt.Errorf("place a report: %w", err)
			}
			moved, err := database.Affected(res)
			if err != nil {
				return err
			}
			if moved == 0 {
				continue
			}
			ruleID := rule.ID
			if err := recordHolder(ctx, tx, id, &party, nil, &ruleID, now); err != nil {
				return err
			}
			placed++
		}
		return nil
	})
	return read, placed, err
}

// ReportCatches is what a rule placing reports would catch: the product's open
// reports, and how many of those nobody holds.
type ReportCatches struct {
	Open, Unheld int
}

// ReportsWouldMatch answers what a rule placing reports would catch, counted
// only for somebody who reads the product's reports.
func (s *Store) ReportsWouldMatch(ctx context.Context, subject access.Subject,
	productID int64) (ReportCatches, error) {

	if mayReadReports(subject, productID) != nil {
		return ReportCatches{}, nil
	}
	open := func() *bun.SelectQuery {
		return s.db.NewSelect().Model((*FlawReport)(nil)).
			Where(`"fr"."product_id" = ?`, productID).
			Where(`"fr"."evaluated_at" IS NULL`)
	}
	var found ReportCatches
	total, err := open().Count(ctx)
	if err != nil {
		return ReportCatches{}, fmt.Errorf("count the open reports: %w", err)
	}
	unheld, err := open().Where(`"fr"."assigned_to" IS NULL`).Count(ctx)
	if err != nil {
		return ReportCatches{}, fmt.Errorf("count the reports nobody holds: %w", err)
	}
	found.Open, found.Unheld = int(total), int(unheld)
	return found, nil
}
