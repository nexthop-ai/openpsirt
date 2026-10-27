// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package series_test

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

func TestARefusalOfASeriesReplacesTheLastOneOfThatSeriesOnTheBuild(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		build := fixture.New(t, db).Build.ID
		store := series.NewStore(db.DB)
		at := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		for i, r := range []series.Refusal{
			{Series: "nightly", Reason: "first", At: at},
			{Series: "Nightly", Reason: "second", At: at.Add(time.Minute)},
			{Series: "weekly", Reason: "other", At: at.Add(2 * time.Minute)},
		} {
			r.BuildID, r.Kind = build, kind.Analysis
			if err := store.Refused(ctx, r); err != nil {
				t.Fatalf("refusal %d: %v", i, err)
			}
		}
		got, err := store.RefusalsOf(ctx, build, kind.Analysis)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0].Series != "weekly" || got[1].Series != "Nightly" || got[1].Reason != "second" {
			t.Errorf("the refusals recorded are %+v; want the weekly one and the second nightly one", got)
		}
	})
}

func TestALongReasonIsRecordedCutWhereACharacterStarts(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		build := fixture.New(t, db).Build.ID
		store := series.NewStore(db.DB)
		reason := strings.Repeat("a", 1999) + strings.Repeat("é", 10)
		if err := store.Refused(ctx, series.Refusal{BuildID: build, Kind: kind.Analysis,
			Series: "nightly", Reason: reason}); err != nil {
			t.Fatalf("a long reason was not recorded: %v", err)
		}
		got, err := store.RefusalsOf(ctx, build, kind.Analysis)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || !utf8.ValidString(got[0].Reason) || !strings.HasPrefix(reason, got[0].Reason) ||
			len(got[0].Reason) > 2000 {
			t.Errorf("the reason recorded is %d bytes, valid %v; want the head of what was sent, whole characters only",
				len(got[0].Reason), utf8.ValidString(got[0].Reason))
		}
	})
}

func TestTwoRefusalsOfASeriesRacingToWriteAreOneRecordedRefusal(t *testing.T) {
	// The second finds no row to replace and inserts after the first has.
	// The series' refusal is recorded either way, so that is not a failure.
	dbtest.Servers(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		build := fixture.New(t, db).Build.ID
		first, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = first.Rollback() }()
		if err := series.NewStore(first).Refused(ctx, series.Refusal{BuildID: build, Kind: kind.Analysis,
			Series: "nightly", Reason: "first"}); err != nil {
			t.Fatal(err)
		}
		second := make(chan error, 1)
		go func() {
			second <- series.NewStore(db.DB).Refused(ctx, series.Refusal{BuildID: build, Kind: kind.Analysis,
				Series: "nightly", Reason: "second"})
		}()
		time.Sleep(500 * time.Millisecond)
		if err := first.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := <-second; err != nil {
			t.Errorf("the refusal that lost the race reports %v", err)
		}
		got, err := series.NewStore(db.DB).RefusalsOf(ctx, build, kind.Analysis)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Errorf("%d refusals are recorded; want one", len(got))
		}
	})
}
