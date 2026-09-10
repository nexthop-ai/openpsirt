package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Disposed is one known vulnerability in one build, and what was decided about
// it — **including nothing**.
//
// The complement of the audit list rather than a variant of it. The audit list
// says what was decided; an auditor's first question is what was *known*,
// decided or not. Assembling that from the findings list means running it four
// times with different state filters and joining by hand, and the rows carry
// none of the who or the when.
type Disposed struct {
	Vulnerability string
	Severity      string
	Component     string
	Version       string
	Place         string
	// Consumer is what pulls the component in, empty where the build holds it
	// directly. The place identity is derived from content and is a hash, so
	// it correlates two rows and tells nobody where anything is; this is the
	// name an auditor reads.
	Consumer string
	// State is where this stands, in the four words the state filter uses.
	// "undecided" is the row an auditor is looking for and the one every other
	// report leaves out.
	State string
	// Outcome and Justification are what was claimed, where anything was.
	Outcome       string
	Justification string
	// ProposedBy and ProposedAt are who claimed it and when; ApprovedBy and
	// ApprovedAt are who agreed. Two different people is the whole of the
	// separation-of-duties control, so both are carried rather than a count.
	ProposedBy string
	ProposedAt *time.Time
	ApprovedBy string
	ApprovedAt *time.Time
	// AgreementCarried says the agreement was given for an earlier claim and
	// carried onto this one, which is what a re-affirmation stands on. The
	// person named read those words rather than these, and a register that
	// did not say so reported them as having agreed to reasoning they have
	// never seen.
	AgreementCarried bool
	// OpenedAt is when this was first seen here and ClosedAt when it stopped
	// being present. DueAt is the deadline it carried, and Met says whether
	// it was closed by then — answerable only for something that closed.
	OpenedAt time.Time
	ClosedAt *time.Time
	DueAt    *time.Time
	Met      *bool
}

// Register is every known vulnerability in one build with its disposition .
//
// **Current state, and no `as_of`.** Reconstructing the view as of a past date
// was asked for and refused: each row already carries the dates that evidence
// what is being checked, and a reconstruction would be a second answer about
// the past that has to be kept honest against the first.
//
// Closed rows are in it. What was known and dealt with is exactly what an
// auditor is asking about, and a register of only what is still open answers a
// different question.
func (s *Store) Register(ctx context.Context, subject access.Subject, targetID int64,
	limit, offset int) ([]Disposed, int, error) {

	rows, err := s.RegisterPage(ctx, subject, targetID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.registerSize(ctx, subject, targetID)
	if err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}

// registerSize counts what a build holds, for the page that says so.
//
// Its own statement because it is its own cost: a scan of every finding in
// the build, which is a quarter of a million rows on a real image.
func (s *Store) registerSize(ctx context.Context, subject access.Subject,
	targetID int64) (int, error) {

	_, narrow, err := s.registerNarrowing(ctx, subject, targetID)
	if err != nil {
		return 0, err
	}
	total, err := narrow(s.db.NewSelect()).ColumnExpr("f.id").Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count what this build holds: %w", err)
	}
	return total, nil
}

// registerNarrowing is the one place that says which of a build's findings a
// subject may read, so the page and the count cannot come to differ about it.
func (s *Store) registerNarrowing(ctx context.Context, subject access.Subject,
	targetID int64) (int64, func(*bun.SelectQuery) *bun.SelectQuery, error) {

	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return 0, nil, err
	}
	visible := access.Visible(subject, productID)
	if !subject.Sees(productID) || len(visible) == 0 {
		return 0, nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	return productID, func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.TableExpr("finding AS f").
			Where("f.target_id = ?", targetID).
			Where("f.visibility IN (?)", bun.List(visible))
	}, nil
}

// RegisterPage is a page of the register and nothing else.
//
// **The count is not free and an export does not carry it.** Counting is a
// scan of every finding in the build, and a file is written by asking for a
// page a thousand times — so the whole register was answering "how many are
// there altogether" a thousand times to fill in a number the file has no
// column for. The screen still asks, once, through Register.
func (s *Store) RegisterPage(ctx context.Context, subject access.Subject, targetID int64,
	limit, offset int) ([]Disposed, error) {

	productID, narrow, err := s.registerNarrowing(ctx, subject, targetID)
	if err != nil {
		return nil, err
	}
	limit = database.AWholeBuild.Of(limit)

	var rows []registerRow
	err = s.registerQuery(productID, narrow).
		Limit(limit).Offset(offset).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what was decided about this build: %w", err)
	}

	out := make([]Disposed, 0, len(rows))
	for _, row := range rows {
		out = append(out, disposedFrom(row))
	}
	return out, nil
}

// RegisterEach walks the whole register, handing over one row at a time.
//
// **An export does not page, and paging is what made it cost what it did.** A
// file was written by asking for a page a thousand times, and every page
// re-sorted the build's quarter of a million rows and then skipped past the
// ones already written — so the deeper the file got, the more each page cost.
// Measured on a real build: 52 minutes, and 0.69s for the first page against
// 3.41s for the last.
//
// One statement and one cursor instead. The sort happens once; nothing is
// skipped; **1.9 seconds** for the same 249,288 rows, in the same order. The
// reason the export paged in the first place — that no complete list ever
// exists in memory — is what a cursor already gives: this holds one row.
//
// The screen still pages, because a screen is a page.
func (s *Store) RegisterEach(ctx context.Context, subject access.Subject, targetID int64,
	each func(Disposed) error) error {

	productID, narrow, err := s.registerNarrowing(ctx, subject, targetID)
	if err != nil {
		return err
	}
	rows, err := s.registerQuery(productID, narrow).Rows(ctx)
	if err != nil {
		return fmt.Errorf("read what was decided about this build: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var row registerRow
		if err := s.db.ScanRow(ctx, rows, &row); err != nil {
			return fmt.Errorf("read what was decided about this build: %w", err)
		}
		if err := each(disposedFrom(row)); err != nil {
			return err
		}
	}
	// Asked separately, because a statement that fails partway through
	// leaves Next reporting only that there are no more rows — which is what
	// a complete answer looks like.
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read what was decided about this build: %w", err)
	}
	return nil
}

// registerRow is one row of the register as the statement returns it.
//
// Named rather than declared inside the reader, because two readers return it
// now: the screen's page, and the walk the export makes.
type registerRow struct {
	Vulnerability string     `bun:"vulnerability"`
	Severity      string     `bun:"severity"`
	Component     string     `bun:"component"`
	Version       string     `bun:"version"`
	Place         string     `bun:"place_identity"`
	Consumer      string     `bun:"consumer"`
	Outcome       string     `bun:"outcome"`
	Justification string     `bun:"justification"`
	DecisionState string     `bun:"decision_state"`
	ProposedBy    string     `bun:"proposed_by"`
	ProposedAt    *time.Time `bun:"proposed_at"`
	ApprovedBy    string     `bun:"approved_by"`
	ApprovedAt    *time.Time `bun:"approved_at"`
	Carried       bool       `bun:"agreement_carried"`
	OpenedAt      time.Time  `bun:"opened_at"`
	ClosedAt      *time.Time `bun:"closed_at"`
	DueAt         *time.Time `bun:"due_at"`
}

// registerQuery is the register, unbounded. What a caller adds is how much of
// it they want.
//
// The standing decision at each place, and the agreement it holds. Left joins
// throughout, because a place nobody has decided about is the row this exists
// to show — an inner join answers the question the audit list already answers.
func (s *Store) registerQuery(productID int64,
	narrow func(*bun.SelectQuery) *bun.SelectQuery) *bun.SelectQuery {

	return narrow(s.db.NewSelect()).
		Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
		Join("JOIN component AS c ON c.id = f.component_id").
		// What pulls the component in. Left, because a build holds some
		// components directly and those have no consumer at all.
		Join("LEFT JOIN component AS uc ON uc.id = f.consumer_id").
		Join(`LEFT JOIN decision AS de ON de.product_id = ?
			AND de.vulnerability_id = f.vulnerability_id
			AND de.place_identity = f.place_identity
			AND de.live_key IS NOT NULL`, productID).
		Join(`LEFT JOIN claim AS cl ON cl.id = de.claim_id`).
		Join(`LEFT JOIN person AS pp ON pp.id = de.proposed_by`).
		ColumnExpr("v.identifier AS vulnerability").
		ColumnExpr("COALESCE(v.assessed_severity, v.severity, '') AS severity").
		ColumnExpr("c.name AS component").
		ColumnExpr("c.version AS version").
		ColumnExpr("f.place_identity AS place_identity").
		ColumnExpr("COALESCE(uc.name, '') AS consumer").
		ColumnExpr("COALESCE(cl.outcome, '') AS outcome").
		ColumnExpr("COALESCE(cl.justification, '') AS justification").
		ColumnExpr("COALESCE(de.state, '') AS decision_state").
		ColumnExpr("COALESCE(pp.identity, '') AS proposed_by").
		ColumnExpr("de.proposed_at AS proposed_at").
		// The agreement that put it in force, asked as a scalar rather than
		// joined. Nothing makes an approval unique per decision — a second
		// approver adds a row — and joined, each extra one multiplied the
		// finding it belongs to into two rows on a page whose total counts
		// findings. The page then held one row fewer than it said, and every
		// later offset skipped one, so an auditor paging a register silently
		// never saw some of it.
		ColumnExpr(`COALESCE((SELECT p2.identity FROM "claim_approval" AS da2
			JOIN "person" AS p2 ON p2.id = da2.approved_by
			WHERE da2.claim_id = de.claim_id AND da2.withdrawn_at IS NULL
			ORDER BY da2.approved_at, da2.id LIMIT 1), '') AS approved_by`).
		ColumnExpr(`(SELECT MIN(da3.approved_at) FROM "claim_approval" AS da3
			WHERE da3.claim_id = de.claim_id AND da3.withdrawn_at IS NULL) AS approved_at`).
		// And whether that agreement was carried rather than given. The same
		// row the identity above comes from, ordered the same way, so the two
		// cannot describe different approvals.
		ColumnExpr(`COALESCE((SELECT CASE WHEN da4.carried_from IS NULL THEN 0 ELSE 1 END
			FROM "claim_approval" AS da4
			WHERE da4.claim_id = de.claim_id AND da4.withdrawn_at IS NULL
			ORDER BY da4.approved_at, da4.id LIMIT 1), 0) AS agreement_carried`).
		ColumnExpr("f.opened_at AS opened_at").
		ColumnExpr("f.closed_at AS closed_at").
		ColumnExpr("f.due_at AS due_at").
		OrderExpr("v.identifier, c.name, f.place_identity")
}

// disposedFrom is one row as the register states it.
func disposedFrom(row registerRow) Disposed {
	one := Disposed{
		Vulnerability: row.Vulnerability, Severity: row.Severity,
		Component: row.Component, Version: row.Version, Place: row.Place,
		Consumer: row.Consumer,
		Outcome:  row.Outcome, Justification: row.Justification,
		ProposedBy: row.ProposedBy, ProposedAt: row.ProposedAt,
		ApprovedBy: row.ApprovedBy, ApprovedAt: row.ApprovedAt,
		AgreementCarried: row.Carried,
		OpenedAt:         row.OpenedAt, ClosedAt: row.ClosedAt, DueAt: row.DueAt,
	}
	// The same four words the state filter uses, at the grain of one
	// place: a place has one standing decision or none, so there is no
	// aggregate to take here and no way for this to disagree with the
	// list.
	switch row.DecisionState {
	case "":
		one.State = "undecided"
	case "approved":
		one.State = "agreed"
	case "lapsed":
		one.State = "lapsed"
	default:
		one.State = "waiting"
	}
	// Whether the deadline was met, which is answerable only for
	// something that closed: an open row has not missed its deadline, it
	// has not reached the end of the question.
	//
	// Closed exactly at the deadline met it. The rate reads the boundary
	// that way — something open at its deadline instant is not yet
	// overdue — and two screens that disagree about the same second are
	// two screens that disagree.
	if row.ClosedAt != nil && row.DueAt != nil {
		met := !row.ClosedAt.After(*row.DueAt)
		one.Met = &met
	}
	return one
}
