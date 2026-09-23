// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

func TestAColumnReferenceIsQuotedForWhicheverEngineIsAsked(t *testing.T) {
	// A placeholder cannot bind a column name, so a name reaching a statement
	// is the one thing here that is text rather than a value. The package that
	// owns engine-specific SQL owned no quoting at all, so every caller wrote
	// its identifiers bare and a reserved word or a name from somewhere else
	// would have gone straight through.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		quoted := string(database.Column(db.DB, "f.opened_run_id"))
		if strings.Count(quoted, ".") != 1 {
			t.Fatalf("a qualified name came back as %q", quoted)
		}
		for _, part := range strings.Split(quoted, ".") {
			if len(part) < 3 || part[0] != part[len(part)-1] {
				t.Errorf("%q is not quoted at both ends", part)
			}
		}
		// And the statement it reaches runs, which is what makes the quoting
		// the engine's own rather than a guess about it.
		var n int
		if err := db.DB.NewSelect().TableExpr(`"finding" AS "f"`).
			ColumnExpr("COUNT(*)").
			Where(quoted+" IS NULL").Scan(t.Context(), &n); err != nil {
			t.Errorf("a quoted column reference did not run: %v", err)
		}

		// A name carrying this engine's own quote character is escaped rather
		// than closed. Which character that is, is the engine's answer: two
		// of the four name the backtick, and both take it beside the standard
		// quote the schema is written in.
		quote := quoted[:1]
		odd := string(database.Column(db.DB, "we"+quote+"ird"))
		if !strings.Contains(odd, quote+quote) {
			t.Errorf("a name holding %s came back as %s, which closes the identifier early",
				quote, odd)
		}
	})
}
