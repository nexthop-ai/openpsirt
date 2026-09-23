// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// FlawReport is what somebody told us, and what became of it.
//
// It stands whether or not the claim turns out to be a flaw. A report nobody
// believes still has to be recorded, because the evidence that it arrived and
// was answered is the record itself — and a claim that can only be recorded by
// minting an issue for it either fills the findings with flaws nobody believes
// or goes unrecorded.
//
// Without it the coordinated-disclosure timeline cannot be evidenced at all —
// received, acknowledged, triaged, fixed, disclosed — and the advisory's
// acknowledgments section is empty, which is the part a researcher reads
// first.
//
// One row per issue rather than per finding: a flaw recorded against four
// builds is one report from one person, and four copies of their address is
// four places for it to be wrong.
type FlawReport struct {
	bun.BaseModel `bun:"table:flaw_report,alias:fr"`

	ID int64 `bun:"id,pk,autoincrement"`
	// Reference is the name this report is reached by, and the one somebody
	// quotes back to a reporter. Drawn rather than counted, for the reason a
	// recorded flaw's identifier is.
	Reference string `bun:"reference,notnull"`
	// ProductID is the product it was reported against, which is what decides
	// who may read it. An issue's identity spans its aliases, so the same
	// issue appears in other products as soon as a shared name is recorded,
	// and a report keyed on the issue alone was readable from every one of
	// them.
	ProductID int64 `bun:"product_id,notnull"`
	// VulnerabilityID is the issue it turned out to be, where it was accepted
	// as one. Absent is every other report: one nobody has judged, which is
	// the state every report arrives in, and one a ruling answers.
	VulnerabilityID *int64 `bun:"vulnerability_id"`
	// Summary is what was claimed, in the words it was claimed in. It carries
	// the substance of a report with no issue; once there is one, the issue's
	// own description is where the claim lives.
	Summary string `bun:"summary"`
	// ReportedBy and Contact are free text, because a reporter is somebody
	// outside this deployment with no account here — which is the whole shape
	// of the thing rather than an omission.
	ReportedBy string `bun:"reported_by"`
	Contact    string `bun:"contact"`
	// Credit is how they wish to be named in an advisory, which is not always
	// the name they reported under: "anonymous" is a real answer, and so is a
	// handle that is not the name on the mail.
	Credit string `bun:"credit"`
	// ReceivedOn is the day it arrived, which is what the embargo runs
	// from . A day rather than a moment: the reporter is counting in days
	// and so are we.
	ReceivedOn     *time.Time `bun:"received_on"`
	AcknowledgedAt *time.Time `bun:"acknowledged_at"`
	AcknowledgedBy *int64     `bun:"acknowledged_by"`
	// EvaluatedAt and EvaluatedBy are when somebody judged the claim, and
	// who. The person who transcribes a mail is not the person who decides
	// what it is worth, and a record that cannot tell them apart evidences
	// neither.
	EvaluatedAt *time.Time `bun:"evaluated_at"`
	EvaluatedBy *int64     `bun:"evaluated_by"`
	RecordedBy  int64      `bun:"recorded_by,notnull"`
	RecordedAt  time.Time  `bun:"recorded_at,notnull"`
	// RulingID is the ruling that answers it, waiting or in force. A report
	// under one is neither accepted nor ruled on again until it is
	// withdrawn.
	RulingID *int64 `bun:"ruling_id"`
}

// Told is what somebody types in when they record a flaw somebody sent them.
//
// Every field is optional. A flaw found by whoever is typing has no reporter,
// and a form that demanded one would be asking them to invent an answer —
// which is the failure mode of every required field that is not always true.
type Told struct {
	ReportedBy string
	Contact    string
	Credit     string
	// Received is the day it arrived, as a date. Empty is "we found it", and
	// the embargo then runs from when the record was made.
	Received string
}

// Stated reports whether anything was said about a reporter at all.
func (t Told) Stated() bool {
	return strings.TrimSpace(t.ReportedBy) != "" || strings.TrimSpace(t.Contact) != "" ||
		strings.TrimSpace(t.Credit) != "" || strings.TrimSpace(t.Received) != ""
}

// The day it arrived, where one was given and could be read.
//
// A date nobody can parse is treated as one nobody gave, for the reason a
// malformed setting is: the record is the point, and refusing the whole thing
// over a typo in an optional field loses the flaw to save the metadata.
func (t Told) When() *time.Time {
	day, err := time.Parse(time.DateOnly, strings.TrimSpace(t.Received))
	if err != nil {
		return nil
	}
	return &day
}

// ReportFor reads who told us about one issue, or nil where nobody did.
//
// Authorized here, against the product the report was made against. It was
// authorized by the caller instead, which resolved the issue in whatever
// product the request named — and an issue's identity spans its aliases, so
// the moment a shared name is recorded the same issue is open in other
// products. Somebody holding triage rights in any of those could read a
// reporter's name, address and received date for a report made about a
// product they hold nothing in.
//
// The same rule a report reached by its reference takes, because it is the
// same row. Asked as the issue's own visibility instead, judging a claim
// handed what a stranger wrote to everybody who triages announced work in
// that product — a widening by the act of filing, which is the one thing a
// report's visibility rule says does not happen.
//
// A report the subject may not reach and no report at all answer alike, so
// asking is not a way to find out that one exists.
func (s *Store) ReportFor(ctx context.Context, subject access.Subject,
	vulnerabilityID int64) (*FlawReport, error) {

	row := new(FlawReport)
	err := s.db.NewSelect().Model(row).
		Where("vulnerability_id = ?", vulnerabilityID).Scan(ctx)
	switch {
	case database.IsNoRows(err):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read who told us: %w", err)
	}
	if err := mayReadReports(subject, row.ProductID); err != nil {
		return nil, nil
	}
	return row, nil
}

// Acknowledge records that somebody answered the reporter.
//
// It records that it happened rather than doing it: what actually reaches a
// researcher is a mail somebody sends, from an address they already have.
// Recording it is what turns "somebody probably replied" into a date the
// timeline can be evidenced from, and what clears the condition an
// unacknowledged report opens.
//
// Acknowledging twice keeps the first date. When somebody was answered is a
// fact about the past, and the second person to press it did not change it.
func (s *Store) Acknowledge(ctx context.Context, subject access.Subject,
	vulnerabilityID int64) error {

	// Against the product it was reported against, like reading it. Clearing
	// the condition in one product's queue from another product's rights is
	// the same hole seen from the write side.
	told, err := s.ReportFor(ctx, subject, vulnerabilityID)
	if err != nil {
		return err
	}
	if told == nil {
		return nil
	}
	// Answering is working the report, which reading it does not grant.
	if err := mayHandle(subject, told.ProductID); err != nil {
		return err
	}
	return s.answered(ctx, subject, told.ID)
}

// answered writes the acknowledgment against one report.
func (s *Store) answered(ctx context.Context, subject access.Subject, reportID int64) error {
	now := s.now().UTC().Truncate(time.Microsecond)
	if _, err := s.db.NewUpdate().Model((*FlawReport)(nil)).
		Set("acknowledged_at = ?", now).
		Set("acknowledged_by = ?", subject.ID).
		Where("id = ?", reportID).
		Where("acknowledged_at IS NULL").
		Exec(ctx); err != nil {
		return fmt.Errorf("record that they were answered: %w", err)
	}
	return nil
}

// Unanswered is one report nobody has acknowledged, with where it sits.
type Unanswered struct {
	ReportID int64
	// Reference is the name the report is reached by, which is the only name
	// a report with no issue has.
	Reference string
	// VulnerabilityID and Identifier are the issue it was accepted as. Zero
	// and empty are a report with no issue: unjudged, or ruled something
	// other than an issue.
	VulnerabilityID int64
	Identifier      string
	ProductID       int64
	Product         string
	ReportedBy      string
	ReceivedOn      *time.Time
	Undisclosed     bool
}

// Unacknowledged is every report nobody has answered yet, across every product
// .
//
// Not narrowed here. The pass that reads this decides who hears about each
// one, and it has to see them all to do that — the same shape as every other
// condition the watch derives.
//
// Two queries, because the two populations differ in what makes them worth
// raising. A report that became an issue is worth raising only while that
// issue is open somewhere: one about something long closed is history rather
// than an unanswered letter, and a condition nobody can act on teaches people
// to ignore the list. A report with no issue has none to be open, and is
// still owed an answer whether or not a ruling says what it is — a ruling
// answers what the claim is, not the person who sent it.
func (s *Store) Unacknowledged(ctx context.Context) ([]Unanswered, error) {
	out, err := s.unacknowledgedOnIssues(ctx)
	if err != nil {
		return nil, err
	}
	unjudged, err := s.unacknowledgedWithoutIssue(ctx)
	if err != nil {
		return nil, err
	}
	return append(out, unjudged...), nil
}

// unacknowledgedOnIssues is every unanswered report about an issue still open
// somewhere.
func (s *Store) unacknowledgedOnIssues(ctx context.Context) ([]Unanswered, error) {
	var rows []struct {
		ReportID        int64      `bun:"report_id"`
		Reference       string     `bun:"reference"`
		VulnerabilityID int64      `bun:"vulnerability_id"`
		ProductID       int64      `bun:"product_id"`
		Product         string     `bun:"product"`
		Identifier      string     `bun:"identifier"`
		ReportedBy      string     `bun:"reported_by"`
		ReceivedOn      *time.Time `bun:"received_on"`
		Private         int        `bun:"private"`
	}
	err := s.db.NewSelect().
		TableExpr(`"flaw_report" AS "fr"`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = fr.vulnerability_id`).
		Join(`JOIN "finding" AS "f" ON f.vulnerability_id = fr.vulnerability_id`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "product" AS "p" ON p.id = st.product_id`).
		ColumnExpr(`fr.id AS "report_id"`).
		ColumnExpr(`MIN(fr.reference) AS "reference"`).
		ColumnExpr(`fr.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`st.product_id AS "product_id"`).
		ColumnExpr(`MIN(p.name) AS "product"`).
		ColumnExpr(`MIN(v.identifier) AS "identifier"`).
		ColumnExpr(`MIN(fr.reported_by) AS "reported_by"`).
		ColumnExpr(`MIN(fr.received_on) AS "received_on"`).
		ColumnExpr(`SUM(CASE WHEN f.visibility = ? THEN 1 ELSE 0 END) AS "private"`,
			access.Private).
		Where("fr.acknowledged_at IS NULL").
		Where("f.closed_at IS NULL").
		// The product it was reported against, not every product the issue
		// turns up in. One report is one letter to answer, and fanning it out
		// across the products a shared name reaches told each of them about a
		// reporter who wrote to one.
		Where("st.product_id = fr.product_id").
		GroupExpr("fr.id, fr.vulnerability_id, st.product_id").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which reports nobody has answered: %w", err)
	}
	out := make([]Unanswered, 0, len(rows))
	for _, row := range rows {
		out = append(out, Unanswered{
			ReportID: row.ReportID, Reference: row.Reference,
			VulnerabilityID: row.VulnerabilityID, ProductID: row.ProductID,
			Product: row.Product, Identifier: row.Identifier,
			ReportedBy: row.ReportedBy, ReceivedOn: row.ReceivedOn,
			Undisclosed: row.Private > 0,
		})
	}
	return out, nil
}

// unacknowledgedWithoutIssue is every unanswered report with no issue:
// unjudged, and ruled something other than an issue, which is still owed an
// answer.
//
// Undisclosed always. There is no issue to be public about, and nobody has
// decided that what a stranger sent is safe to repeat.
func (s *Store) unacknowledgedWithoutIssue(ctx context.Context) ([]Unanswered, error) {
	var rows []struct {
		ReportID   int64      `bun:"report_id"`
		Reference  string     `bun:"reference"`
		ProductID  int64      `bun:"product_id"`
		Product    string     `bun:"product"`
		ReportedBy string     `bun:"reported_by"`
		ReceivedOn *time.Time `bun:"received_on"`
	}
	err := s.db.NewSelect().
		TableExpr(`"flaw_report" AS "fr"`).
		Join(`JOIN "product" AS "p" ON p.id = fr.product_id`).
		ColumnExpr(`fr.id AS "report_id"`).
		ColumnExpr(`fr.reference AS "reference"`).
		ColumnExpr(`fr.product_id AS "product_id"`).
		ColumnExpr(`p.name AS "product"`).
		ColumnExpr(`fr.reported_by AS "reported_by"`).
		ColumnExpr(`fr.received_on AS "received_on"`).
		Where("fr.acknowledged_at IS NULL").
		Where("fr.vulnerability_id IS NULL").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which claims nobody has answered: %w", err)
	}
	out := make([]Unanswered, 0, len(rows))
	for _, row := range rows {
		out = append(out, Unanswered{
			ReportID: row.ReportID, Reference: row.Reference,
			ProductID: row.ProductID, Product: row.Product,
			ReportedBy: row.ReportedBy, ReceivedOn: row.ReceivedOn,
			Undisclosed: true,
		})
	}
	return out, nil
}
