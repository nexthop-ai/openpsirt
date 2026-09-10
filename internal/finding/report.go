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

// WhoTold is who told us about a flaw, and when.
//
// Without it the coordinated-disclosure timeline cannot be evidenced at all —
// received, acknowledged, triaged, fixed, disclosed — and the advisory's
// acknowledgments section is empty, which is the part a researcher reads
// first.
//
// One row per issue rather than per finding: a flaw recorded against four
// builds is one report from one person, and four copies of their address is
// four places for it to be wrong.
type WhoTold struct {
	bun.BaseModel `bun:"table:flaw_report,alias:fr"`

	ID              int64 `bun:"id,pk,autoincrement"`
	VulnerabilityID int64 `bun:"vulnerability_id,notnull"`
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
	RecordedBy     int64      `bun:"recorded_by,notnull"`
	RecordedAt     time.Time  `bun:"recorded_at,notnull"`
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

// When is the day it arrived, where one was given and could be read.
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
// Authorized by the caller, which has already resolved the issue in a product
// they may read: a report carries somebody's address, and the rule for who may
// see it is the rule for who may see the flaw.
func (s *Store) ReportFor(ctx context.Context, vulnerabilityID int64) (*WhoTold, error) {
	row := new(WhoTold)
	err := s.db.NewSelect().Model(row).
		Where("vulnerability_id = ?", vulnerabilityID).Scan(ctx)
	switch {
	case database.IsNoRows(err):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read who told us: %w", err)
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

	now := s.now().UTC().Truncate(time.Microsecond)
	if _, err := s.db.NewUpdate().Model((*WhoTold)(nil)).
		Set("acknowledged_at = ?", now).
		Set("acknowledged_by = ?", subject.ID).
		Where("vulnerability_id = ?", vulnerabilityID).
		Where("acknowledged_at IS NULL").
		Exec(ctx); err != nil {
		return fmt.Errorf("record that they were answered: %w", err)
	}
	return nil
}

// Unanswered is one report nobody has acknowledged, with where it sits.
type Unanswered struct {
	VulnerabilityID int64
	ProductID       int64
	Product         string
	Identifier      string
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
// **Only where the flaw is still open somewhere.** A report about something
// long closed is history rather than an unanswered letter, and a condition
// nobody can act on is one that teaches people to ignore the list.
func (s *Store) Unacknowledged(ctx context.Context) ([]Unanswered, error) {
	var rows []struct {
		VulnerabilityID int64      `bun:"vulnerability_id"`
		ProductID       int64      `bun:"product_id"`
		Product         string     `bun:"product"`
		Identifier      string     `bun:"identifier"`
		ReportedBy      string     `bun:"reported_by"`
		ReceivedOn      *time.Time `bun:"received_on"`
		Private         int        `bun:"private"`
	}
	err := s.db.NewSelect().
		TableExpr("flaw_report AS fr").
		Join(`JOIN "vulnerability" AS v ON v.id = fr.vulnerability_id`).
		Join(`JOIN "finding" AS f ON f.vulnerability_id = fr.vulnerability_id`).
		Join(`JOIN "target" AS tg ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS st ON st.id = tg.stream_id`).
		Join(`JOIN "product" AS p ON p.id = st.product_id`).
		ColumnExpr("fr.vulnerability_id AS vulnerability_id").
		ColumnExpr("st.product_id AS product_id").
		ColumnExpr("MIN(p.name) AS product").
		ColumnExpr("MIN(v.identifier) AS identifier").
		ColumnExpr("MIN(fr.reported_by) AS reported_by").
		ColumnExpr("MIN(fr.received_on) AS received_on").
		ColumnExpr("SUM(CASE WHEN f.visibility = ? THEN 1 ELSE 0 END) AS private",
			access.Private).
		Where("fr.acknowledged_at IS NULL").
		Where("f.closed_at IS NULL").
		GroupExpr("fr.vulnerability_id, st.product_id").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which reports nobody has answered: %w", err)
	}
	out := make([]Unanswered, 0, len(rows))
	for _, row := range rows {
		out = append(out, Unanswered{
			VulnerabilityID: row.VulnerabilityID, ProductID: row.ProductID,
			Product: row.Product, Identifier: row.Identifier,
			ReportedBy: row.ReportedBy, ReceivedOn: row.ReceivedOn,
			Undisclosed: row.Private > 0,
		})
	}
	return out, nil
}
