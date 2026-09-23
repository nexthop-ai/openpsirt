package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

const (
	ratedFour  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N"
	ratedThree = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N"
)

func TestEachGenerationAReportRatesAnIssueUnderIsKept(t *testing.T) {
	// The screen shows the newest and a published advisory states the one its
	// format has a field for, so a second generation is not one to drop. The
	// first stated in each is kept whole, and a re-scan writes nothing.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)
		issues := finding.NewVulnerabilities(db.DB)

		first := finding.Named{
			Identifier: "CVE-2026-6100", Severity: "high",
			Score: 7.1, Vector: ratedFour, ScoreVersion: "4.0",
			Ratings: []finding.CVSS{
				{Generation: 4, ScoreCenti: 710, Vector: ratedFour, Version: "4.0", Source: "cna"},
				{Generation: 3, ScoreCenti: 820, Vector: ratedThree, Version: "3.1", Source: "nvd"},
			},
		}
		filed, err := issues.Intern(ctx, []finding.Named{first})
		if err != nil {
			t.Fatal(err)
		}
		id := filed["CVE-2026-6100"]

		// A later report rating version 3 higher, and adding version 2. The
		// worst in a generation is kept, whole: its own vector and its own
		// publisher, which here is nobody named.
		later := first
		later.Ratings = []finding.CVSS{
			{Generation: 3, ScoreCenti: 980, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Version: "3.1"},
			{Generation: 2, ScoreCenti: 750, Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P", Version: "2.0"},
			// A rating whose generation nothing states is not filed under one.
			{Generation: 0, ScoreCenti: 500, Vector: "whatever"},
		}
		if _, err := issues.Intern(ctx, []finding.Named{later, later}); err != nil {
			t.Fatal(err)
		}

		held, err := issues.Ratings(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		want := []struct {
			generation, centi int
			vector, source    string
		}{
			{4, 710, ratedFour, "cna"},
			{3, 980, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", ""},
			{2, 750, "AV:N/AC:L/Au:N/C:P/I:P/A:P", ""},
		}
		if len(held) != len(want) {
			t.Fatalf("holds %d ratings, want %d: %+v", len(held), len(want), held)
		}
		for at, each := range want {
			got := held[at]
			if got.Generation != each.generation || got.ScoreCenti != each.centi ||
				got.Vector != each.vector || got.Source != each.source {
				t.Errorf("rating %d is %+v, want generation %d at %d from %q",
					at, got, each.generation, each.centi, each.source)
			}
		}

		// And the issue as a page reads it carries them, newest first.
		described, err := issues.Describe(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if len(described.Ratings) != 3 || described.Ratings[0].Generation != 4 {
			t.Errorf("the issue reads its ratings as %+v, want three, newest first", described.Ratings)
		}
	})
}

func TestAPublishedScoreIsStoredAsTheHundredthsItStates(t *testing.T) {
	// 8.2 is 819.999… hundredths as a float, and 0.00397 is 3969.999… parts
	// per million. Cut rather than rounded, each is stored as a number nobody
	// published.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)
		issues := finding.NewVulnerabilities(db.DB)
		filed, err := issues.Intern(ctx, []finding.Named{{
			Identifier: "CVE-2026-6101", Severity: "high", Score: 8.2, Vector: ratedThree,
			Likelihood: 0.00397, LikelihoodPercentile: 0.29,
		}})
		if err != nil {
			t.Fatal(err)
		}
		var row finding.Vulnerability
		if err := db.DB.NewSelect().Model(&row).
			Where("id = ?", filed["CVE-2026-6101"]).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		for _, each := range []struct {
			what   string
			stored *int
			want   int
		}{
			{"score", row.ScoreCenti, 820},
			{"estimate", row.LikelihoodPPM, 3970},
			{"percentile", row.LikelihoodPercentilePPM, 290000},
		} {
			if each.stored == nil {
				t.Errorf("stored no %s", each.what)
			} else if *each.stored != each.want {
				t.Errorf("stored the %s as %d, want %d", each.what, *each.stored, each.want)
			}
		}
	})
}

func TestTheIssuesNumberIsTheNewestRatingWhole(t *testing.T) {
	// The number an issue ranks by is shown beside its scheme everywhere. Raised
	// to the worst claim while its vector and version were filled once, a
	// version 4 rating of 8.7 read "8.7 on CVSS 3.1" under the version 3
	// vector. It is one rating, the newest generation's, copied whole.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)
		issues := finding.NewVulnerabilities(db.DB)
		read := func() finding.Vulnerability {
			t.Helper()
			var row finding.Vulnerability
			if err := db.DB.NewSelect().Model(&row).
				Where("identifier = ?", "CVE-2026-6102").Scan(ctx); err != nil {
				t.Fatal(err)
			}
			return row
		}
		steps := []struct {
			what    string
			named   finding.Named
			centi   int
			version string
			vector  string
			moved   bool
		}{
			{"first seen under 3.1", finding.Named{Score: 7.5, Vector: ratedThree, ScoreVersion: "3.1"},
				750, "3.1", ratedThree, false},
			{"a newer database rates it under 4.0", finding.Named{Score: 8.7, Vector: ratedFour, ScoreVersion: "4.0"},
				870, "4.0", ratedFour, true},
			// A higher version 3 rating is held beside it and does not move
			// the issue off the newest generation.
			{"another publisher rates 3.1 higher", finding.Named{Score: 8.2,
				Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", ScoreVersion: "3.1"},
				870, "4.0", ratedFour, false},
			// A number with no vector is not a rating, and does not raise an
			// issue that holds one.
			{"a bare number", finding.Named{Score: 9.9}, 870, "4.0", ratedFour, false},
		}
		for _, step := range steps {
			step.named.Identifier, step.named.Severity = "CVE-2026-6102", "high"
			issues := finding.NewVulnerabilities(db.DB)
			if _, err := issues.Intern(ctx, []finding.Named{step.named}); err != nil {
				t.Fatalf("%s: %v", step.what, err)
			}
			row := read()
			centi := 0
			if row.ScoreCenti != nil {
				centi = *row.ScoreCenti
			}
			if centi != step.centi ||
				row.ScoreVersion != step.version || row.Vector != step.vector {
				t.Errorf("%s: the issue reads %v on %q with %q, want %d on %q with its own vector",
					step.what, centi, row.ScoreVersion, row.Vector, step.centi, step.version)
			}
			if moved := len(issues.Moved()) > 0; moved != step.moved && step.what != "first seen under 3.1" {
				t.Errorf("%s: moved is %v, want %v", step.what, moved, step.moved)
			}
		}
		held, err := issues.Ratings(ctx, read().ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(held) != 2 || held[1].ScoreCenti != 820 {
			t.Errorf("holds %+v, want the version 3 rating raised to 8.2", held)
		}
	})
}
