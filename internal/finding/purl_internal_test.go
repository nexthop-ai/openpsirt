// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// A filter naming a package identifier is narrowed only once the store has
// resolved the components it chooses. Unresolved, narrowing one leaves the
// error on the statement, so running it fails rather than answering nothing;
// resolved to no component, it keeps nothing.
func TestAPackageIdentifierNarrowedBeforeItIsPreparedFails(t *testing.T) {
	db := bun.NewDB(sql.OpenDB(unconnected{}), sqlitedialect.New())
	narrowed := func(f Filter) *bun.SelectQuery {
		return f.narrowRows(db.NewSelect().TableExpr(`"finding" AS "f"`).Column("f.id"))
	}
	purl := graph.ParsePurlPrefix("pkg:deb/debian/curl")

	if got := narrowed(Filter{Purl: purl, purlComponents: []int64{}}).String(); !strings.Contains(got, "1 = 0") {
		t.Errorf("an identifier choosing no component keeps rows: %s", got)
	}
	if got := narrowed(Filter{Purl: purl, purlComponents: []int64{7}}).String(); !strings.Contains(got, `"f"."component_id" IN (7)`) {
		t.Errorf("an identifier choosing a component does not narrow to it: %s", got)
	}
	if _, err := narrowed(Filter{Purl: purl}).AppendQuery(db.QueryGen(), nil); !errors.Is(err, errUnprepared) {
		t.Errorf("an unprepared identifier was narrowed into a statement: %v", err)
	}
}

// The two-level read embeds the narrowed occurrences in the statement over
// groups, and that statement carries the error as well.
func TestAnUnpreparedPackageIdentifierFailsTheGroupedRead(t *testing.T) {
	db := bun.NewDB(sql.OpenDB(unconnected{}), sqlitedialect.New())
	rows := db.NewSelect().TableExpr(`"finding" AS "f"`)
	grouped := Filter{Purl: graph.ParsePurlPrefix("pkg:deb/debian/curl")}.folded(db, rows, issueAndComponent)
	if _, err := grouped.AppendQuery(db.QueryGen(), nil); !errors.Is(err, errUnprepared) {
		t.Errorf("an unprepared identifier was grouped into a statement: %v", err)
	}
}
