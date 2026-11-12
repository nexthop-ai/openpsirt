// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package series_test

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

// everything reads every build's receipts.
var everything = access.Everything("the refusal tests")

func TestARefusalIsReadOnlyByAReaderOfTheBuildsReceipts(t *testing.T) {
	// A reason quotes what a sender sent, so it is read under the receipts'
	// rule: somebody reading the product's disclosed work but not its security
	// testing work is refused, as is a key for another product and a build
	// named as one of a product it is not of.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		f := fixture.New(t, db)
		store := series.NewStore(db.DB)
		if err := store.Refused(ctx, series.Refusal{BuildID: f.Build.ID, Kind: kind.Analysis,
			Series: "nightly", Reason: "the document names /src/secret.c"}); err != nil {
			t.Fatal(err)
		}
		for name, who := range map[string]access.Subject{
			"a reader of disclosed work": access.NewPerson(1, "public", false,
				map[int64][]access.Role{f.Product.ID: {access.PublicRead}}, 0),
			"a key for another product": access.NewPipeline(2, "elsewhere", access.Scope{ProductID: f.Product.ID + 1}),
		} {
			got, err := store.RefusalsOf(ctx, who, f.Product.ID, f.Build.ID, kind.Analysis, access.SecurityTesting)
			if !errors.Is(err, access.ErrDenied) {
				t.Errorf("%s was answered %d refusals and %v, want a refusal", name, len(got), err)
			}
		}
		// Named as a build of a product where the subject does read the
		// receipts: the build is of another product, so it is refused.
		elsewhere := access.NewPerson(4, "elsewhere", false, map[int64][]access.Role{
			f.Product.ID:     {access.PublicRead},
			f.Product.ID + 1: {access.PublicRead, access.SecurityTestingRead},
		}, 0)
		if got, err := store.RefusalsOf(ctx, elsewhere, f.Product.ID+1, f.Build.ID, kind.Analysis,
			access.SecurityTesting); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a build named as another product's was answered %d refusals and %v, want a refusal", len(got), err)
		}
		reader := access.NewPerson(3, "tester", false,
			map[int64][]access.Role{f.Product.ID: {access.PublicRead, access.SecurityTestingRead}}, 0)
		got, err := store.RefusalsOf(ctx, reader, f.Product.ID, f.Build.ID, kind.Analysis, access.SecurityTesting)
		if err != nil || len(got) != 1 {
			t.Errorf("a reader of security testing work got %d refusals and %v, want the one", len(got), err)
		}
	})
}

func TestARefusalOfASeriesReplacesTheLastOneOfThatSeriesOnTheBuild(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		f := fixture.New(t, db)
		build := f.Build.ID
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
		got, err := store.RefusalsOf(ctx, everything, f.Product.ID, build, kind.Analysis, access.SecurityTesting)
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
		f := fixture.New(t, db)
		build := f.Build.ID
		store := series.NewStore(db.DB)
		reason := strings.Repeat("a", 1999) + strings.Repeat("é", 10)
		if err := store.Refused(ctx, series.Refusal{BuildID: build, Kind: kind.Analysis,
			Series: "nightly", Reason: reason}); err != nil {
			t.Fatalf("a long reason was not recorded: %v", err)
		}
		got, err := store.RefusalsOf(ctx, everything, f.Product.ID, build, kind.Analysis, access.SecurityTesting)
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
		f := fixture.New(t, db)
		build := f.Build.ID
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
		// Until the second waits on the first's row.
		dbtest.UntilLockWait(ctx, db, nil, 500*time.Millisecond)
		if err := first.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := <-second; err != nil {
			t.Errorf("the refusal that lost the race reports %v", err)
		}
		got, err := series.NewStore(db.DB).RefusalsOf(ctx, everything, f.Product.ID, build, kind.Analysis,
			access.SecurityTesting)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Errorf("%d refusals are recorded; want one", len(got))
		}
	})
}
