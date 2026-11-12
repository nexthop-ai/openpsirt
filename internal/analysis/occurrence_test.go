// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

// columned is a result stated at a column of its line.
type columned struct {
	sent
	column int
}

func (s columned) json() string {
	return fmt.Sprintf(`{"ruleId":%q,"message":{"text":%q},"locations":[{"physicalLocation":`+
		`{"artifactLocation":{"uri":%q,"uriBaseId":%q},"region":{"startLine":%d,"startColumn":%d}}}]}`,
		s.rule, s.message, s.uri, s.base, s.line, s.column)
}

// occurrencesOn is the occurrences of a build's open code findings, sorted.
func (w *world) occurrencesOn(t *testing.T, buildID int64) []string {
	t.Helper()
	var out []string
	for _, f := range w.codeFindings(t, buildID) {
		if f.ClosedAt == nil {
			out = append(out, f.OccurrenceIdentity)
		}
	}
	slices.Sort(out)
	return out
}

func TestResultsSharingAKeyOpenOneOccurrenceEach(t *testing.T) {
	for name, results := range map[string][]interface{ json() string }{
		"apart by column": {
			columned{inSWSS, 5}, columned{inSWSS, 30},
		},
		"apart by the digits of their message": {
			sent{inSWSS.rule, inSWSS.base, inSWSS.uri, "a buffer of size 8 overflows", inSWSS.line},
			sent{inSWSS.rule, inSWSS.base, inSWSS.uri, "a buffer of size 16 overflows", inSWSS.line},
		},
	} {
		t.Run(name, func(t *testing.T) {
			eachWorld(t, func(t *testing.T, w *world) {
				w.inventory(t, w.Build.ID)
				doc := documentOf(results, 10, "")
				now := time.Now().UTC()
				if _, status := w.send(t, w.Build.ID, now.Add(-3*time.Hour), doc); status != series.Applied {
					t.Fatalf("status %s; want applied", status)
				}
				first := w.occurrencesOn(t, w.Build.ID)
				if len(first) != 2 || first[0] == first[1] {
					t.Fatalf("the two results opened at %v; want two occurrences", first)
				}
				// Seen again on the build, both are matched to what they opened.
				if _, status := w.send(t, w.Build.ID, now.Add(-2*time.Hour), doc); status != series.Applied {
					t.Fatalf("status %s; want applied", status)
				}
				if again := w.occurrencesOn(t, w.Build.ID); !slices.Equal(again, first) {
					t.Errorf("seen again, the build holds %v; want %v", again, first)
				}
				// On another build of the series, each takes one of the series'
				// occurrences rather than both taking the first.
				other := w.BuildFor(w.Branch, w.Internal)
				w.inventory(t, other.ID)
				if _, status := w.send(t, other.ID, now.Add(-time.Hour), doc); status != series.Applied {
					t.Fatalf("status %s; want applied", status)
				}
				if elsewhere := w.occurrencesOn(t, other.ID); !slices.Equal(elsewhere, first) {
					t.Errorf("another build holds %v; want the series' %v", elsewhere, first)
				}
			})
		})
	}
}

func TestAResultJoiningOneOfItsKeyOnTheBuildOpensAnOccurrenceOfItsOwn(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		now := time.Now().UTC()
		alone := documentOf([]interface{ json() string }{columned{inSWSS, 5}}, 10, "")
		if _, status := w.send(t, w.Build.ID, now.Add(-2*time.Hour), alone); status != series.Applied {
			t.Fatalf("status %s; want applied", status)
		}
		both := documentOf([]interface{ json() string }{columned{inSWSS, 5}, columned{inSWSS, 30}}, 10, "")
		if _, status := w.send(t, w.Build.ID, now.Add(-time.Hour), both); status != series.Applied {
			t.Fatalf("status %s; want applied", status)
		}
		if got := w.occurrencesOn(t, w.Build.ID); len(got) != 2 || got[0] == got[1] {
			t.Errorf("the build holds %v; want the result it held and the one joining it apart", got)
		}
	})
}

// occurrenceByColumn is the occurrence of each open code finding on a build,
// by the column it was last seen at.
func (w *world) occurrenceByColumn(t *testing.T, buildID int64) map[int]string {
	t.Helper()
	var rows []struct {
		Occurrence string `bun:"occurrence_identity"`
		Column     *int   `bun:"start_column"`
	}
	where, args := kind.In(`"f"."kind"`, []kind.Kind{kind.Analysis})
	if err := w.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		ColumnExpr(`"f"."occurrence_identity", "ar"."start_column"`).
		Where(`"f"."build_id" = ?`, buildID).Where(`"f"."closed_at" IS NULL`).Where(where, args...).
		Scan(t.Context(), &rows); err != nil {
		t.Fatal(err)
	}
	out := map[int]string{}
	for _, r := range rows {
		if r.Column != nil {
			out[*r.Column] = r.Occurrence
		}
	}
	return out
}

func TestResultsSharingAKeyKeepTheirOccurrencesListedInAnotherOrder(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		now := time.Now().UTC()
		forward := documentOf([]interface{ json() string }{columned{inSWSS, 5}, columned{inSWSS, 30}}, 10, "")
		reversed := documentOf([]interface{ json() string }{columned{inSWSS, 30}, columned{inSWSS, 5}}, 10, "")
		if _, status := w.send(t, w.Build.ID, now.Add(-3*time.Hour), forward); status != series.Applied {
			t.Fatalf("status %s; want applied", status)
		}
		first := w.occurrenceByColumn(t, w.Build.ID)
		if len(first) != 2 || first[5] == first[30] {
			t.Fatalf("the two results opened at %v; want two occurrences", first)
		}
		if _, status := w.send(t, w.Build.ID, now.Add(-2*time.Hour), reversed); status != series.Applied {
			t.Fatalf("status %s; want applied", status)
		}
		if again := w.occurrenceByColumn(t, w.Build.ID); !maps.Equal(again, first) {
			t.Errorf("listed the other way round, the build holds %v; want %v", again, first)
		}
		other := w.BuildFor(w.Branch, w.Internal)
		w.inventory(t, other.ID)
		if _, status := w.send(t, other.ID, now.Add(-time.Hour), reversed); status != series.Applied {
			t.Fatalf("status %s; want applied", status)
		}
		if elsewhere := w.occurrenceByColumn(t, other.ID); !maps.Equal(elsewhere, first) {
			t.Errorf("listed the other way round on another build, it holds %v; want %v", elsewhere, first)
		}
	})
}

func TestALoneResultUnderAKeyHeldTwiceKeepsItsOwnOccurrence(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		now := time.Now().UTC()
		both := documentOf([]interface{ json() string }{columned{inSWSS, 5}, columned{inSWSS, 30}}, 10, "")
		later := documentOf([]interface{ json() string }{columned{inSWSS, 30}}, 10, "")
		if _, status := w.send(t, w.Build.ID, now.Add(-3*time.Hour), both); status != series.Applied {
			t.Fatalf("status %s; want applied", status)
		}
		first := w.occurrenceByColumn(t, w.Build.ID)
		if len(first) != 2 {
			t.Fatalf("the two results opened at %v; want two occurrences", first)
		}
		// On another build of the series, the one result takes its own.
		other := w.BuildFor(w.Branch, w.Internal)
		w.inventory(t, other.ID)
		if _, status := w.send(t, other.ID, now.Add(-2*time.Hour), later); status != series.Applied {
			t.Fatalf("status %s; want applied", status)
		}
		if got := w.occurrenceByColumn(t, other.ID); got[30] != first[30] {
			t.Errorf("on another build the result at column 30 is at %s; want its own, %s", got[30], first[30])
		}
		// Seen again alone on its build, it keeps its own code finding there.
		if _, status := w.send(t, w.Build.ID, now.Add(-time.Hour), later); status != series.Applied {
			t.Fatalf("status %s; want applied", status)
		}
		columns := map[string]int{}
		for column, occurrence := range w.occurrenceByColumn(t, w.Build.ID) {
			columns[occurrence] = column
		}
		if columns[first[5]] != 5 {
			t.Errorf("seen again alone, the result at column 30 was recorded on the code finding at column 5")
		}
	})
}
