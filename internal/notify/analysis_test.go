// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

func TestASharpDropIsToldToTheProductsInternalReadersAlone(t *testing.T) {
	fixtures.Each(t, func(t *testing.T, w *fixtures.World) {
		ctx := t.Context()
		internal := w.DeclarePerson("analyst@example.com", "An Analyst", false)
		public := w.DeclarePerson("reader@example.com", "A Reader", false)
		embargo := w.DeclarePerson("embargo@example.com", "An Embargo Reader", false)
		if err := w.Access.GrantRole(ctx, embargo.ID, w.Product.ID, access.PrivateRead); err != nil {
			t.Fatal(err)
		}
		if err := w.Access.GrantRole(ctx, internal.ID, w.Product.ID, access.InternalRead); err != nil {
			t.Fatal(err)
		}
		if err := w.Access.GrantRole(ctx, public.ID, w.Product.ID, access.PublicRead); err != nil {
			t.Fatal(err)
		}
		set := &series.Series{ProductID: w.Product.ID, Kind: kind.Analysis, Name: "clang-tidy/default",
			NameFolded: "clang-tidy/default", CreatedAt: time.Now().UTC()}
		if _, err := w.DB.DB.NewInsert().Model(set).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		notify.AnalysisDrops(w.DB.DB, slog.New(slog.NewTextHandler(io.Discard, nil)))(ctx,
			analysis.Drop{RunID: 7, SeriesID: set.ID, TargetID: w.Target.ID, Missed: 30, Live: 40})

		told := func(who *access.Account, role access.Role) []notify.Notification {
			subject := access.NewPerson(who.ID, who.Identity, false,
				map[int64][]access.Role{w.Product.ID: {role}}, 0)
			waiting, _, err := notify.NewStore(w.DB.DB).Waiting(ctx, subject, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			var mine []notify.Notification
			for _, one := range waiting {
				if one.Kind == notify.AnalysisDropped {
					mine = append(mine, one)
				}
			}
			return mine
		}
		heard := told(internal, access.InternalRead)
		if len(heard) != 1 || !strings.Contains(heard[0].Body, "clang-tidy/default marked 30 of 40") ||
			!strings.Contains(heard[0].Link, "state=not-reproduced") ||
			!strings.Contains(heard[0].Link, "series=clang-tidy%2Fdefault") {
			t.Errorf("the internal reader was told %+v; want the run, its counts and a link to what it marked", heard)
		}
		if got := told(public, access.PublicRead); len(got) != 0 {
			t.Errorf("a reader of disclosed work was told %+v; want nothing", got)
		}
		// A line about internal work is read by a reader of internal work,
		// whoever it was addressed to.
		productID := w.Product.ID
		if err := notify.NewStore(w.DB.DB).Tell(ctx, notify.Telling{
			PersonID: embargo.ID, Kind: notify.AnalysisDropped, Body: "internal",
			ProductID: &productID, Private: true, Internal: true,
		}); err != nil {
			t.Fatal(err)
		}
		if got := told(embargo, access.PrivateRead); len(got) != 0 {
			t.Errorf("a reader of undisclosed work read %+v; want nothing about internal work", got)
		}
	})
}

// analyzed records an applied run of set against the world's build, received
// at, and comparable or not.
func analyzed(t *testing.T, w *fixtures.World, set *series.Series, at time.Time, comparable bool) {
	t.Helper()
	run := &series.Run{SeriesID: set.ID, TargetID: w.Target.ID,
		ContentHash: strconv.FormatInt(at.UnixNano(), 16), BuiltAt: at, ReceivedAt: at,
		Status: series.Applied, Comparable: &comparable, AppliedAt: &at}
	if !comparable {
		run.Reason = series.UnitsShort
	}
	if _, err := w.DB.DB.NewInsert().Model(run).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// analysisSeries declares an analyzer series in the world's product.
func analysisSeries(t *testing.T, w *fixtures.World) *series.Series {
	t.Helper()
	set := &series.Series{ProductID: w.Product.ID, Kind: kind.Analysis, Name: "clang-tidy/default",
		NameFolded: "clang-tidy/default", CreatedAt: time.Now().UTC()}
	if _, err := w.DB.DB.NewInsert().Model(set).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	return set
}

// toldOf is what one person holds of one kind, after a sweep.
func toldOf(t *testing.T, w *fixtures.World, who *access.Account, role access.Role,
	k notify.Kind) []notify.Notification {
	t.Helper()
	ctx := t.Context()
	if _, _, err := notify.NewWatch(w.DB.DB, slog.New(slog.NewTextHandler(io.Discard, nil))).Once(ctx); err != nil {
		t.Fatal(err)
	}
	subject := access.NewPerson(who.ID, who.Identity, false,
		map[int64][]access.Role{w.Product.ID: {role}}, 0)
	waiting, _, err := notify.NewStore(w.DB.DB).Waiting(ctx, subject, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var mine []notify.Notification
	for _, one := range waiting {
		if one.Kind == k {
			mine = append(mine, one)
		}
	}
	return mine
}

func TestASeriesWhoseNewestRunCouldNotBeComparedIsToldUntilOneCan(t *testing.T) {
	fixtures.Each(t, func(t *testing.T, w *fixtures.World) {
		analyst := w.DeclarePerson("analyst@example.com", "An Analyst", false)
		reader := w.DeclarePerson("reader@example.com", "A Reader", false)
		if err := w.Access.GrantRole(t.Context(), analyst.ID, w.Product.ID, access.InternalRead); err != nil {
			t.Fatal(err)
		}
		if err := w.Access.GrantRole(t.Context(), reader.ID, w.Product.ID, access.PrivateRead); err != nil {
			t.Fatal(err)
		}
		set := analysisSeries(t, w)
		day := time.Now().UTC().Truncate(time.Second).Add(-72 * time.Hour)
		analyzed(t, w, set, day, true)
		analyzed(t, w, set, day.Add(24*time.Hour), false)

		heard := toldOf(t, w, analyst, access.InternalRead, notify.AnalysisNotComparable)
		if len(heard) != 1 || !strings.Contains(heard[0].Body, "analyzed less than it was meant to") {
			t.Fatalf("the internal reader was told %+v; want the run that could not be compared, and why", heard)
		}
		if got := toldOf(t, w, reader, access.PrivateRead, notify.AnalysisNotComparable); len(got) != 0 {
			t.Errorf("a reader of undisclosed work was told %+v; want nothing about internal work", got)
		}

		// A comparable run after it is the newest, and the condition clears.
		analyzed(t, w, set, day.Add(48*time.Hour), true)
		if got := toldOf(t, w, analyst, access.InternalRead, notify.AnalysisNotComparable); len(got) != 0 {
			t.Errorf("after a comparable run the analyst still holds %+v; want it cleared", got)
		}
	})
}

func TestASeriesSilentForThreeOfItsUsualGapsHasGoneQuiet(t *testing.T) {
	fixtures.Each(t, func(t *testing.T, w *fixtures.World) {
		ctx := t.Context()
		analyst := w.DeclarePerson("analyst@example.com", "An Analyst", false)
		if err := w.Access.GrantRole(ctx, analyst.ID, w.Product.ID, access.InternalRead); err != nil {
			t.Fatal(err)
		}
		set := analysisSeries(t, w)
		now := time.Now().UTC().Truncate(time.Second)
		// Two runs a day apart are no rhythm, however long ago the last was.
		analyzed(t, w, set, now.Add(-10*24*time.Hour), true)
		analyzed(t, w, set, now.Add(-9*24*time.Hour), true)
		if got := toldOf(t, w, analyst, access.InternalRead, notify.AnalysisQuiet); len(got) != 0 {
			t.Fatalf("a series with two runs was quiet: %+v; want nothing", got)
		}

		// A third a day later makes a daily series, silent for eight days.
		analyzed(t, w, set, now.Add(-8*24*time.Hour), true)
		heard := toldOf(t, w, analyst, access.InternalRead, notify.AnalysisQuiet)
		if len(heard) != 1 || !strings.Contains(heard[0].Body, "no run of clang-tidy/default has been applied") {
			t.Fatalf("the analyst was told %+v; want the series named as quiet", heard)
		}

		// An upload turned away since is named, with what its sender was told.
		if err := series.NewStore(w.DB.DB).Refused(ctx, series.Refusal{TargetID: w.Target.ID,
			Series: "Clang-Tidy/default", Kind: kind.Analysis, At: now.Add(-time.Hour),
			Reason: "the documents could not be read"}); err != nil {
			t.Fatal(err)
		}
		heard = toldOf(t, w, analyst, access.InternalRead, notify.AnalysisQuiet)
		if len(heard) != 1 || !strings.Contains(heard[0].Body, "turned away") ||
			!strings.Contains(heard[0].Body, "the documents could not be read") {
			t.Fatalf("the analyst was told %+v; want the refusal named", heard)
		}

		// Two days of silence is less than three daily gaps, so a run
		// recently clears it.
		analyzed(t, w, set, now.Add(-2*24*time.Hour), true)
		if got := toldOf(t, w, analyst, access.InternalRead, notify.AnalysisQuiet); len(got) != 0 {
			t.Errorf("a series silent for two of its days was quiet: %+v; want nothing", got)
		}
	})
}
