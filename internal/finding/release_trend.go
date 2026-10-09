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
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// ReleasePoint is one frozen point on a trend that follows releases.
//
// A tag never moves: what it shipped is what it shipped, and what is open
// against it is answered now against the vulnerability data of today rather
// than as of the day it was cut. That is the point of re-scanning a shipped
// release, and it is why this is a snapshot per release rather than a
// timeline.
type ReleasePoint struct {
	// Stream is the name a path addresses the release by, and StreamName the
	// spelling shown.
	Stream, StreamName string
	// Cut is when the release went out, where somebody said, and when it was
	// declared here otherwise. It is what orders them and it is not the axis:
	// the axis is the sequence, and the dates are labels.
	Cut time.Time
	// Open is the distinct issues open against it, and BySeverity the split.
	// Counted in issues like the calendar trend, so the two charts on one
	// screen cannot be quoting different units for the same word.
	Open       int
	BySeverity map[string]int
}

// ErrNoProductNamed is what a question about one product's line of releases
// answers where no product was named.
//
// Its own answer rather than an empty list, because an empty list is what a
// product with no releases looks like and the two are not the same statement.
var ErrNoProductNamed = refusal.New("release over release is a question about one product")

// ReleaseTrend reports what is open against each tagged release of a product.
//
// The axis follows what is being viewed. A branch is scanned
// nightly and has continuous data, so a calendar reads correctly on it. A tag
// is one frozen point that never moves again, and releases months apart make a
// calendar count read as slow drift rather than the step change it was — the
// gaps between them are the chart's whole shape, and they are gaps in nothing.
//
// Rates are not offered here. How many appeared and were resolved between
// two releases is a different question from what each shipped with, and the
// answer would be an artifact of how far apart somebody cut them. Rates always
// plot on calendar.
func (s *Store) ReleaseTrend(ctx context.Context, subject access.Subject, scope Scope,
	limit int) ([]ReleasePoint, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are
	// different statements, and this is the second. A person holding
	// nothing anywhere is the first, and is answered below.
	if subject.Kind != access.Person {
		return nil, access.Denied("read how a release is trending")
	}
	// A named product this subject reads nothing in is refused rather than
	// drawn as a chart with nothing on it.
	if scope.ProductID != nil {
		if _, err := access.Readable(subject, *scope.ProductID); err != nil {
			return nil, err
		}
	}
	products, all := subject.Products()
	if !all && len(products) == 0 {
		return nil, nil
	}
	if scope.ProductID == nil {
		// Release over release is a question about one product's line of
		// releases. Across products there is no sequence to plot: two
		// products' tags interleave by date and mean nothing side by side.
		//
		// Refused rather than answered empty. An empty list is what a product
		// with no releases looks like, so a request that named no product got
		// the same answer as one whose product has nothing to plot — and the
		// route's own description says a product must be named.
		return nil, ErrNoProductNamed
	}
	limit = database.APlot.Of(limit)

	var rows []struct {
		Stream     string    `bun:"stream"`
		StreamName string    `bun:"stream_name"`
		CreatedAt  time.Time `bun:"created_at"`
		Band       string    `bun:"band"`
		Open       int       `bun:"open"`
	}
	// The distinct issues per release, then the band of each, counted after.
	// The issues are reduced on the finding alone, before the issue or its
	// rating is joined: a release holds each issue at many places, and
	// joining first reads the issue's row once per place only to fold the
	// copies away. Inside one product an issue has one band, so the pair
	// is already distinct once it carries one.
	issues := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr(`tg.stream_id AS "stream_id"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		Where("st.kind = ?", "tag").
		Where("f.closed_at IS NULL").
		GroupExpr("tg.stream_id, f.vulnerability_id")
	issues = scope.Narrow(onlyReadable(issues, subject, products, all))

	inner := s.db.NewSelect().
		TableExpr(`(?) AS "grouped"`, issues).
		Join(`JOIN "stream" AS "st" ON st.id = grouped.stream_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = grouped.vulnerability_id`).
		Join(rating.For(rating.OnStream)).
		ColumnExpr(`st.name AS "stream"`).
		ColumnExpr(catalog.ShownExpr("st") + ` AS "stream_name"`).
		// The day it went out, where somebody said, and the day it was declared
		// here otherwise. Ordered by the declaration alone, the chart is an
		// accident of administration: a release recorded months after it
		// shipped sorts after ones that came out later, and a year
		// backfilled in an afternoon plots as a single day.
		ColumnExpr(`COALESCE(st.released_on, st.created_at) AS "created_at"`).
		ColumnExpr(rating.BandExpr + ` AS "band"`)

	if err := s.db.NewSelect().
		TableExpr(`(?) AS "per_release"`, inner).
		ColumnExpr(`per_release.stream AS "stream"`).
		ColumnExpr(`per_release.stream_name AS "stream_name"`).
		ColumnExpr(`per_release.created_at AS "created_at"`).
		ColumnExpr(`per_release.band AS "band"`).
		ColumnExpr(`COUNT(*) AS "open"`).
		GroupExpr("per_release.stream, per_release.stream_name, per_release.created_at, per_release.band").
		// Newest last, so the chart reads left to right the way time does.
		OrderExpr("created_at, stream, band").
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what each release shipped with: %w", err)
	}

	// Gathered in order, so the sequence is the order they were cut.
	var out []ReleasePoint
	at := map[string]int{}
	for _, row := range rows {
		i, held := at[row.Stream]
		if !held {
			out = append(out, ReleasePoint{
				Stream: row.Stream, StreamName: row.StreamName, Cut: row.CreatedAt,
				BySeverity: map[string]int{},
			})
			i = len(out) - 1
			at[row.Stream] = i
		}
		out[i].Open += row.Open
		out[i].BySeverity[row.Band] += row.Open
	}
	// The most recent, where there are more than a chart can carry. Taken from
	// the end because the releases somebody is comparing are the recent ones,
	// and a chart that dropped those to keep the oldest would be answering
	// about a version nobody runs.
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}
