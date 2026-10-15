// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// The fold a query reads is the fold the Go code reads, on every engine, for
// every word a flaw may be recorded under and for the words nobody recognizes:
// a word folded one way in SQL and another in Go is a finding listed above the
// line and given no clock, or clocked and hidden.
func TestTheBandAQueryReadsIsTheBandTheCodeReads(t *testing.T) {
	words := append(finding.Recordable(), "", "unknown", " High")
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		examined := 0
		for _, word := range words {
			for _, c := range []struct {
				name      string
				published string
				rated     string
				joined    string
			}{
				// Published and nobody here rated it: the product's rating
				// is the absent row of a left join.
				{"published", word, "critical", "1 = 0"},
				// Rated here, over a published word it differs from.
				{"rated here", "critical", word, "1 = 1"},
			} {
				var got string
				if err := db.NewSelect().
					TableExpr(`(SELECT ? AS "severity") AS "v"`, c.published).
					Join(`LEFT JOIN (SELECT ? AS "severity") AS "ir" ON `+c.joined, c.rated).
					ColumnExpr(rating.BandExpr).
					Scan(t.Context(), &got); err != nil {
					t.Fatalf("%s %q: %v", c.name, word, err)
				}
				examined++
				if want := rating.Fold(word); got != want {
					t.Errorf("%s %q folds to %q in SQL and %q in Go", c.name, word, got, want)
				}
			}
		}
		if examined == 0 {
			t.Fatal("no word was folded, so this checked nothing")
		}
	})
}
