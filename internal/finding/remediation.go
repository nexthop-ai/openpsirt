package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// Remediation is how fast things are being fixed, and what is aging.
//
// **Counted in issues, not in places.** One kernel flaw across sixty modules is
// one thing that was fixed, and a mean time to remediate weighted by how far a
// component fans out through an image is a measurement of the dependency graph
// rather than of anybody's work.
type Remediation struct {
	// Fixed and Opened are how many distinct issues closed and opened in the
	// window. Together they say whether the team is keeping pace; separately they
	// are two numbers people quote at each other.
	Fixed  int
	Opened int
	// TimeToFix is the average time an issue closed in this window was open
	// for, by the severity it was rated. Absent where nothing of that rating
	// closed — a zero would read as "fixed instantly".
	TimeToFix map[string]time.Duration
	// Aging is what is open now, by how long it has been open. The buckets are
	// the ones people ask in, and the last one is open-ended because "older
	// than ninety days" is the answer that matters and its shape does not.
	Aging []Bucket
}

// Bucket is how many issues have been open for a stretch of time.
type Bucket struct {
	// Label names the stretch, and Days is where it starts, so a caller can
	// order them without parsing the label.
	Label string
	Days  int
	Open  int
	// BySeverity is the same count cut by how the issues were rated. One
	// number for a bucket says a hundred things are over three months old and
	// not whether any of them matters, which is the question anybody asks
	// next — and a bucket of lows is a different place from a bucket with four
	// criticals in it.
	BySeverity map[string]int
	// Undecided is how many of them nobody has said anything about. The other
	// cut worth having: a hundred old findings that were all argued and
	// dismissed is a tidy record, and a hundred nobody has looked at is a
	// backlog, and the one number cannot tell them apart.
	Undecided int
}

// agingBuckets are the stretches what is open is counted into.
var agingBuckets = []struct {
	label string
	from  int
	to    int
}{
	{"under a week", 0, 7},
	{"one to four weeks", 7, 28},
	{"one to three months", 28, 90},
	{"over three months", 90, 0},
}

// resolved keeps only what counts as an issue actually going away.
//
// **A closure is not a fix unless the issue went with it.** A bump that
// carried the issue into the next version closed one row and opened another
// with the same issue in it, and a scanner that silently stopped reporting
// something closed a row and explained nothing. Counting either as a fix
// measures churn and reports it as progress, which is worse than reporting
// nothing: the number moves in the right direction while nothing improves.
//
// **`invalid` is not here either, and for a different reason from the other
// two.** A record taken back was never a finding, so it is not churn being
// counted as progress — it is nothing at all, and counting it would make the
// fix rate improve every time somebody corrected a filing mistake.
// Bound rather than spliced, and built from Resolving rather than retyped
// beside it: a value in a placeholder is the rule, and a literal here is the
// shape somebody copies to a place where it does matter.
func resolved(q *bun.SelectQuery) *bun.SelectQuery {
	return q.Where("f.closed_because IN (?)", bun.List(Resolving()))
}

// Remediation reports how fast issues are being closed and what is aging.
func (s *Store) Remediation(ctx context.Context, subject access.Subject, scope Scope,
	window time.Duration) (*Remediation, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are
	// different statements, and this is the second. A person holding
	// nothing is the first, and is answered below.
	if subject.Kind != access.Person {
		return nil, access.Denied("read what remediation is planned")
	}
	products, all := subject.Products()
	if !all && len(products) == 0 {
		return nil, nil
	}
	if window <= 0 {
		window = 30 * 24 * time.Hour
	}
	now := s.now().UTC()
	since := now.Add(-window)

	out := &Remediation{TimeToFix: map[string]time.Duration{}}

	// How long each issue took, averaged per severity band. Averaged over the
	// issue rather than over its rows: an issue is closed when the last of its
	// places is, and the places are what fans out.
	var spans []struct {
		Band    string  `bun:"band"`
		Seconds float64 `bun:"seconds"`
		Issues  int     `bun:"issues"`
	}
	closed := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		Join(rating.For(rating.OnStream)).
		ColumnExpr(rating.BandExpr+` AS "band"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`MAX(f.closed_at) AS "closed_at"`).
		ColumnExpr(`MIN(f.opened_at) AS "opened_at"`).
		Where("f.closed_at IS NOT NULL").
		Where("f.closed_at >= ?", since).
		GroupExpr("band, f.vulnerability_id")
	closed = resolved(scope.Narrow(onlyReadable(closed, subject, products, all)))

	// The averaging happens over the grouped issues, in a statement of its
	// own, because averaging inside the grouping would average the places.
	if err := s.db.NewSelect().
		TableExpr(`(?) AS "per_issue"`, closed).
		ColumnExpr(`per_issue.band AS "band"`).
		ColumnExpr(`COUNT(*) AS "issues"`).
		ColumnExpr(secondsBetween(s.db)+` AS "seconds"`).
		GroupExpr("per_issue.band").
		Scan(ctx, &spans); err != nil {
		return nil, fmt.Errorf("read how long fixes took: %w", err)
	}
	for _, row := range spans {
		out.Fixed += row.Issues
		if row.Issues > 0 {
			out.TimeToFix[row.Band] = time.Duration(row.Seconds) * time.Second
		}
	}

	// What opened in the same window, as distinct issues, so the two figures
	// are in the same unit and can be read against each other.
	opened := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr("f.vulnerability_id").
		Where("f.opened_at >= ?", since).
		GroupExpr("f.vulnerability_id")
	count, err := s.db.NewSelect().
		TableExpr(`(?) AS "grouped"`, scope.Narrow(onlyReadable(opened, subject, products, all))).Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("count what opened: %w", err)
	}
	out.Opened = count

	// What is open now, by how long it has been. One statement per bucket
	// rather than a case expression, because the boundaries are moments
	// computed here and a database that does its own date arithmetic does it
	// four different ways.
	for _, bucket := range agingBuckets {
		older := now.Add(-time.Duration(bucket.from) * 24 * time.Hour)
		q := s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
			Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
			ColumnExpr("f.vulnerability_id").
			Where("f.closed_at IS NULL").
			Where("f.opened_at <= ?", older).
			GroupExpr("f.vulnerability_id")
		if bucket.to > 0 {
			q = q.Where("f.opened_at > ?", now.Add(-time.Duration(bucket.to)*24*time.Hour))
		}
		n, err := s.db.NewSelect().
			TableExpr(`(?) AS "grouped"`, scope.Narrow(onlyReadable(q, subject, products, all))).Count(ctx)
		if err != nil {
			return nil, fmt.Errorf("count what is aging: %w", err)
		}
		one := Bucket{Label: bucket.label, Days: bucket.from, Open: n}

		// The same bucket cut by severity. Counted as distinct issues like the
		// bucket itself, so the parts sum to the whole rather than to the
		// number of places.
		var bands []struct {
			Band  string `bun:"band"`
			Count int    `bun:"number"`
		}
		byBand := q.NewSelect().
			TableExpr(`(?) AS "grouped"`, scope.Narrow(onlyReadable(
				byBandOf(q), subject, products, all))).
			ColumnExpr(`grouped.band AS "band"`).
			ColumnExpr(`COUNT(*) AS "number"`).
			GroupExpr("grouped.band")
		if err := byBand.Scan(ctx, &bands); err != nil {
			return nil, fmt.Errorf("count what is aging, by severity: %w", err)
		}
		one.BySeverity = make(map[string]int, len(bands))
		for _, band := range bands {
			one.BySeverity[BandOf(band.Band)] += band.Count
		}

		// And how many of them nobody has answered. The same test the deadline
		// list makes: a claim waiting for a second person is not standing, so
		// it answers nothing and the finding is still undecided.
		//
		// Matched on the live key rather than on both versions, because this
		// query does not join the components those versions live on — and for
		// a figure about a backlog "somebody has said something here" is the
		// question, not "which build of it".
		standing, held := InForce()
		unanswered := q.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
			Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
			ColumnExpr("f.vulnerability_id").
			Where("f.closed_at IS NULL").
			Where("f.opened_at <= ?", older).
			Where(`NOT EXISTS (SELECT 1 FROM "decision" AS "de"
				WHERE de.product_id = st.product_id
				  AND de.vulnerability_id = f.vulnerability_id
				  AND de.place_identity = f.place_identity
				  AND de.live_key IS NOT NULL
				  AND `+standing+`)`, held...).
			GroupExpr("f.vulnerability_id")
		if bucket.to > 0 {
			unanswered = unanswered.Where("f.opened_at > ?",
				now.Add(-time.Duration(bucket.to)*24*time.Hour))
		}
		one.Undecided, err = s.db.NewSelect().
			TableExpr(`(?) AS "grouped"`,
				scope.Narrow(onlyReadable(unanswered, subject, products, all))).Count(ctx)
		if err != nil {
			return nil, fmt.Errorf("count what is aging undecided: %w", err)
		}
		out.Aging = append(out.Aging, one)
	}
	return out, nil
}

// byBandOf is the same aging query carrying the severity each issue was rated
// at, so a bucket can be cut by it.
//
// The band is taken as the strictest across the rows an issue groups to, which
// is one value by construction: severity belongs to the issue rather than to
// the place, and MIN over one value is that value.
func byBandOf(from *bun.SelectQuery) *bun.SelectQuery {
	return from.Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		// Each row's own product rates it, read through the stream this query
		// already joins. Without it the plan reported the published rating
		// while the list it is a summary of reported the product's own.
		Join(rating.For(rating.OnStream)).
		ColumnExpr(`MIN(` + rating.EffectiveExpr + `) AS "band"`)
}

// secondsBetween averages how long an issue was open, through the one place an
// engine is asked how to subtract two moments.
func secondsBetween(db bun.IDB) string {
	return "AVG(" + database.SecondsBetween(db,
		database.Column(db, "per_issue.opened_at"),
		database.Column(db, "per_issue.closed_at")) + ")"
}
