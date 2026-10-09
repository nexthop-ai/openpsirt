// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// Remediation is how fast things are being fixed, and what is aging.
//
// Counted in issues, not in places. One kernel flaw across sixty modules is
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
	// Label names the stretch, Days is where it starts and Until where it
	// ends, so a caller can order them and ask for the same stretch without
	// parsing the label. Until is zero for the last, which has no end.
	Label string
	Days  int
	Until int
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

// agingBucket is one stretch what is open is counted into, in days before
// now: from is where it starts and to where it ends, zero for no end.
type agingBucket struct {
	label string
	from  int
	to    int
}

// agingBuckets are the stretches what is open is counted into.
var agingBuckets = []agingBucket{
	{"under a week", 0, 7},
	{"one to four weeks", 7, 28},
	{"one to three months", 28, 90},
	{"over three months", 90, 0},
}

// resolved keeps only what counts as an issue actually going away.
//
// A closure is not a fix unless the issue went with it. A bump that
// carried the issue into the next version closed one row and opened another
// with the same issue in it, and a scanner that silently stopped reporting
// something closed a row and explained nothing. Counting either as a fix
// measures churn and reports it as progress, which is worse than reporting
// nothing: the number moves in the right direction while nothing improves.
//
// `invalid` is not here either, and for a different reason from the other
// two. A record taken back was never a finding, so it is not churn being
// counted as progress — it is nothing at all, and counting it would make the
// fix rate improve every time somebody corrected a filing mistake.
// Bound rather than spliced, and built from Resolving rather than retyped
// beside it: a value in a placeholder is the rule, and a literal here is the
// shape somebody copies to a place where it does matter.
func resolved(q *bun.SelectQuery) *bun.SelectQuery {
	return q.Where("f.closed_because IN (?)", bun.List(Resolving()))
}

// Remediation reports how fast issues are being closed and what is aging.
// The period bounds what closed and what opened in it. What is *aging* is a
// statement about now whatever period was asked for: how long something has
// been open is answered by the clock, and reconstructing it as of a date gone
// by is the reconstruction the register refuses for the same reason.
func (s *Store) Remediation(ctx context.Context, subject access.Subject, scope Scope,
	since, until time.Time) (*Remediation, error) {

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
	now := s.now().UTC()
	if until.IsZero() {
		until = now
	}
	// An absent start is the beginning, which is what a zero side of a period
	// means and what the reports beside this one already do. Substituted with
	// a default here, a caller asking for an end alone got a window it never
	// asked for under a response saying the period ran from the beginning.

	out := &Remediation{TimeToFix: map[string]time.Duration{}}

	// spans is how long each issue took, averaged per severity band.
	// Averaged over the issue rather than over its rows: an issue is
	// closed when the last of its places is, and the places are what fans
	// out.
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
		Where(wasOpen).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			if !since.IsZero() {
				q = q.Where("f.closed_at >= ?", since)
			}
			return q.Where("f.closed_at < ?", until)
		}).
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

	// Everything opened in the same window, as distinct issues, so the two
	// figures are in the same unit and can be read against each other.
	opened := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr("f.vulnerability_id").
		Where(wasOpen).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			if !since.IsZero() {
				q = q.Where("f.opened_at >= ?", since)
			}
			return q.Where("f.opened_at < ?", until)
		}).
		GroupExpr("f.vulnerability_id")
	count, err := s.db.NewSelect().
		TableExpr(`(?) AS "grouped"`, scope.Narrow(onlyReadable(opened, subject, products, all))).Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("count what opened: %w", err)
	}
	out.Opened = count

	aging, err := s.aging(ctx, subject, products, all, scope, now)
	if err != nil {
		return nil, err
	}
	out.Aging = aging
	return out, nil
}

// aging counts what is open now into the buckets, each cut by severity and by
// whether anybody has answered it.
//
// One pass over the open findings rather than three per bucket. Each issue is
// reduced to a flag per bucket saying it has a place there, a flag per bucket
// saying one of those places is unanswered, and the rating it carries there;
// the issues are then counted by which flags and ratings they hold, which is
// a handful of rows however many issues there are. An issue with places in
// two buckets counts in both.
//
// The boundaries are moments computed here and bound, rather than date
// arithmetic in the statement, because a database that does its own date
// arithmetic does it four different ways.
func (s *Store) aging(ctx context.Context, subject access.Subject, products []int64, all bool,
	scope Scope, now time.Time) ([]Bucket, error) {

	// Answered is the same test the deadline list makes: a claim waiting for
	// a second person is not standing, so it answers nothing and the finding
	// is still undecided. Matched on the live key rather than on both
	// versions, because for a figure about a backlog "somebody has said
	// something here" is the question, not "which build of it".
	//
	// Built once from the decision side and joined on the finding, so the
	// question is asked of the decisions once rather than of every open
	// place in turn. The decision is outermost through CROSS JOIN ... WHERE,
	// for the reason the state filter gives: SQLite left to choose starts
	// from every open finding.
	standing, held := InForce()
	answered := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(DecisionIssue).
		Join(`CROSS JOIN "finding" AS "f2"`).
		Where("f2.vulnerability_id = dv.issue_id AND f2.place_identity = de.place_identity").
		Join(`JOIN "target" AS "tg2" ON tg2.id = f2.target_id`).
		Join(`JOIN "stream" AS "st2" ON st2.id = tg2.stream_id`).
		ColumnExpr(`f2.id AS "finding_id"`).
		Where("de.product_id = st2.product_id").
		Where("de.live_key IS NOT NULL").
		Where(standing, held...).
		Where("f2.closed_at IS NULL").
		GroupExpr("f2.id")

	// One row per issue and product, with the flags. Every narrowing is a
	// condition on a place, so each applies here, before the places are
	// reduced.
	places := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`LEFT JOIN (?) AS "answered" ON answered.finding_id = f.id`, answered).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`st.product_id AS "product_id"`).
		Where("f.closed_at IS NULL").
		Where("f.opened_at <= ?", now).
		GroupExpr("f.vulnerability_id, st.product_id")
	for i, bucket := range agingBuckets {
		in, args := bucket.holds(now)
		places = places.
			ColumnExpr(`MAX(CASE WHEN `+in+` THEN 1 ELSE 0 END) AS "open_`+bucketName(i)+`"`, args...).
			ColumnExpr(`MAX(CASE WHEN `+in+` AND answered.finding_id IS NULL THEN 1 ELSE 0 END)`+
				` AS "undecided_`+bucketName(i)+`"`, args...)
	}
	places = scope.Narrow(onlyReadable(places, subject, products, all))

	// One row per issue. The rating is joined to the reduced rows, each
	// product's own where it has stated one, and an issue's rating in a
	// bucket is the strictest across the products it is open in there:
	// the highest rank, with a word that ranks nothing below every band.
	issues := s.db.NewSelect().
		TableExpr(`(?) AS "grouped"`, places).
		Join(`JOIN "vulnerability" AS "v" ON v.id = grouped.vulnerability_id`).
		Join(rating.For(rating.OnGrouped)).
		GroupExpr("grouped.vulnerability_id")
	counted := s.db.NewSelect().
		TableExpr(`(?) AS "per_issue"`, issues).
		ColumnExpr(`COUNT(*) AS "issues"`)
	var keys []string
	for i := range agingBuckets {
		name := bucketName(i)
		issues = issues.
			ColumnExpr(`MAX(grouped.open_` + name + `) AS "open_` + name + `"`).
			ColumnExpr(`MAX(grouped.undecided_` + name + `) AS "undecided_` + name + `"`).
			ColumnExpr(`MAX(CASE WHEN grouped.open_` + name + ` = 1 THEN ` + rankCase(rating.EffectiveExpr, 0) +
				` END) AS "band_` + name + `"`)
		for _, column := range []string{"open_", "undecided_", "band_"} {
			counted = counted.ColumnExpr(`per_issue.` + column + name + ` AS "` + column + name + `"`)
			keys = append(keys, "per_issue."+column+name)
		}
	}
	counted = counted.GroupExpr(strings.Join(keys, ", "))

	// A row of flags is one shape an issue can have across the buckets, and
	// how many issues have it. Scanned by column name into one map per row,
	// because the columns are as many as the buckets.
	rows, err := counted.Rows(ctx)
	if err != nil {
		return nil, fmt.Errorf("count what is aging: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]Bucket, len(agingBuckets))
	for i, bucket := range agingBuckets {
		out[i] = Bucket{Label: bucket.label, Days: bucket.from, Until: bucket.to,
			BySeverity: map[string]int{}}
	}
	for rows.Next() {
		var (
			issueCount int
			open       = make([]int, len(agingBuckets))
			undecided  = make([]int, len(agingBuckets))
			band       = make([]sql.NullInt64, len(agingBuckets))
			into       = []any{&issueCount}
		)
		for i := range agingBuckets {
			into = append(into, &open[i], &undecided[i], &band[i])
		}
		if err := rows.Scan(into...); err != nil {
			return nil, fmt.Errorf("count what is aging: %w", err)
		}
		for i := range agingBuckets {
			if open[i] == 0 {
				continue
			}
			out[i].Open += issueCount
			out[i].BySeverity[BandOf(wordAt(int(band[i].Int64)))] += issueCount
			if undecided[i] != 0 {
				out[i].Undecided += issueCount
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("count what is aging: %w", err)
	}
	return out, nil
}

// holds is the condition that a finding opened within this bucket, with the
// moments it binds.
func (b agingBucket) holds(now time.Time) (string, []any) {
	older := now.Add(-time.Duration(b.from) * 24 * time.Hour)
	if b.to == 0 {
		return "f.opened_at <= ?", []any{older}
	}
	return "f.opened_at <= ? AND f.opened_at > ?",
		[]any{older, now.Add(-time.Duration(b.to) * 24 * time.Hour)}
}

// bucketName is the suffix of a bucket's columns.
func bucketName(i int) string {
	return strconv.Itoa(i)
}

// secondsBetween averages how long an issue was open, through the one place an
// engine is asked how to subtract two moments.
func secondsBetween(db bun.IDB) string {
	return "AVG(" + database.SecondsBetween(db,
		database.Column(db, "per_issue.opened_at"),
		database.Column(db, "per_issue.closed_at")) + ")"
}
