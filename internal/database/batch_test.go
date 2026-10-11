// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// keptRow is a row of a table with a bounded key, written through the insert
// that leaves another writer's row alone.
type keptRow struct {
	bun.BaseModel `bun:"table:application_setting"`

	Name      string    `bun:"name,pk"`
	Value     string    `bun:"value,notnull"`
	UpdatedAt time.Time `bun:"updated_at,notnull"`
}

// An insert that leaves alone a row another writer got to first skips that
// row and nothing else. A value wider than its column is refused as it is by
// an ordinary insert, on every engine that bounds widths, rather than being
// cut to fit and reported as written.
func TestKeepingAnotherWritersRowSkipsOnlyTheDuplicate(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Second)

		first := []keptRow{{Name: "kept", Value: "first", UpdatedAt: now}}
		if err := database.InBatchesKeeping(ctx, db, first); err != nil {
			t.Fatalf("the first write: %v", err)
		}
		again := []keptRow{{Name: "kept", Value: "second", UpdatedAt: now}}
		if err := database.InBatchesKeeping(ctx, db, again); err != nil {
			t.Fatalf("a row another writer got to first was refused: %v", err)
		}
		held := new(keptRow)
		if err := db.NewSelect().Model(held).Where(`"name" = ?`, "kept").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if held.Value != "first" {
			t.Errorf("the row holds %q, want the first writer's", held.Value)
		}

		if db.Server.Engine == database.SQLite {
			return // A declared width is not enforced here.
		}
		wide := []keptRow{{Name: strings.Repeat("w", 300), Value: "v", UpdatedAt: now}}
		if err := database.InBatchesKeeping(ctx, db, wide); err == nil {
			t.Error("a key wider than its column was written without an error")
		}
	})
}

// issueRow is a row of a table whose columns hold each kind of value a row
// carries: text that may be absent, a flag, numbers that may be absent, and a
// moment.
type issueRow struct {
	bun.BaseModel `bun:"table:vulnerability"`

	ID          int64     `bun:"id,pk,autoincrement"`
	Identifier  string    `bun:"identifier,notnull"`
	Folded      string    `bun:"identifier_folded,notnull"`
	Severity    *string   `bun:"severity"`
	Description *string   `bun:"description"`
	Exploited   bool      `bun:"exploited,notnull"`
	Likelihood  *int64    `bun:"likelihood_ppm"`
	Score       *int      `bun:"score_centi"`
	FirstSeenAt time.Time `bun:"first_seen_at,notnull"`
	IssueID     int64     `bun:"issue_id,notnull"`
}

// An insert that reads nothing back stores every row it is given, in every
// batch, with the values an insert reading the keys back stores: text that
// looks like syntax, absent values and present ones, both flags, and a moment
// to the microsecond in a zone of its own.
func TestAnInsertReadingNothingBackStoresWhatItIsGiven(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		texts := []*string{nil, ptr(""), ptr("NULL"), ptr(`it's "quoted", {braced}, back\slash`),
			ptr("line\nbreak\ttab"), ptr("ünïcode — dash"), ptr("plain")}
		// The severity column is a short one.
		short := []*string{nil, ptr(""), ptr("NULL"), ptr(`a'b"c,{d}\e`), ptr("high")}
		east := time.FixedZone("east", 5*3600+1800)
		rows := func(prefix string) []issueRow {
			made := make([]issueRow, 2*database.BatchSize+1)
			for i := range made {
				var likelihood *int64
				var score *int
				if i%3 > 0 {
					l, s := int64(i)*1000+7, i%1000
					likelihood, score = &l, &s
				}
				made[i] = issueRow{
					Identifier: fmt.Sprintf("%s-%04d", prefix, i), Folded: fmt.Sprintf("%s-%04d", prefix, i),
					Severity: short[i%len(short)], Description: texts[(i+3)%len(texts)],
					Exploited: i%2 == 0, Likelihood: likelihood, Score: score,
					FirstSeenAt: time.Date(2026, 10, 11, 12, 34, 56, 123456000+i*1000, east),
					IssueID:     int64(i),
				}
			}
			return made
		}
		if err := database.InBatches(ctx, db, rows("keyed")); err != nil {
			t.Fatal(err)
		}
		given := rows("unkeyed")
		if err := database.InBatchesUnkeyed(ctx, db, given); err != nil {
			t.Fatal(err)
		}
		read := func(prefix string) []issueRow {
			var stored []issueRow
			if err := db.NewSelect().Model(&stored).Where("identifier LIKE ?", prefix+"-%").
				Order("identifier").Scan(ctx); err != nil {
				t.Fatal(err)
			}
			return stored
		}
		keyed, unkeyed := read("keyed"), read("unkeyed")
		if len(unkeyed) != len(given) || len(keyed) != len(given) {
			t.Fatalf("%d rows stored reading nothing back and %d reading keys, want %d",
				len(unkeyed), len(keyed), len(given))
		}
		for i := range unkeyed {
			want, got := keyed[i], unkeyed[i]
			want.ID, got.ID = 0, 0
			want.Identifier, want.Folded = got.Identifier, got.Folded
			if !sameIssueRow(want, got) {
				t.Errorf("row %d is stored as\n%s\nwhere reading keys back stores\n%s",
					i, describe(got), describe(want))
			}
		}
	})
}

func ptr[T any](v T) *T { return &v }

func sameIssueRow(a, b issueRow) bool {
	return a.Identifier == b.Identifier && a.Folded == b.Folded &&
		text(a.Severity) == text(b.Severity) && (a.Severity == nil) == (b.Severity == nil) &&
		text(a.Description) == text(b.Description) && (a.Description == nil) == (b.Description == nil) &&
		a.Exploited == b.Exploited &&
		(a.Likelihood == nil) == (b.Likelihood == nil) && (a.Likelihood == nil || *a.Likelihood == *b.Likelihood) &&
		(a.Score == nil) == (b.Score == nil) && (a.Score == nil || *a.Score == *b.Score) &&
		a.FirstSeenAt.Equal(b.FirstSeenAt) && a.IssueID == b.IssueID
}

func text(s *string) string {
	if s == nil {
		return "<absent>"
	}
	return fmt.Sprintf("%q", *s)
}

func describe(r issueRow) string {
	number := func(n any) string {
		switch v := n.(type) {
		case *int64:
			if v != nil {
				return fmt.Sprint(*v)
			}
		case *int:
			if v != nil {
				return fmt.Sprint(*v)
			}
		}
		return "<absent>"
	}
	return fmt.Sprintf("severity %s, description %s, exploited %t, likelihood %s, score %s, first seen %s, issue %d",
		text(r.Severity), text(r.Description), r.Exploited, number(r.Likelihood), number(r.Score),
		r.FirstSeenAt.UTC().Format(time.RFC3339Nano), r.IssueID)
}
