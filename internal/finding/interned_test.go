// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// reportsIn is one round of reports about a handful of issues, named in one
// numbering year so that two runs of the same round touch disjoint rows.
//
// The names overlap between issues on purpose: a report naming two issues'
// names is what merges them, and one naming a better-known name than the one
// an issue is filed under is what renames it. Two of the issues are named only
// the one way, so they stay apart.
func reportsIn(r *rand.Rand, year int) []finding.Named {
	name := func() string {
		if r.Intn(2) == 0 {
			return fmt.Sprintf("CVE-%d-%d", year, 1000+r.Intn(4))
		}
		return fmt.Sprintf("GHSA-%d-%d", year, r.Intn(4))
	}
	day := func() *time.Time {
		if r.Intn(3) == 0 {
			return nil
		}
		on := time.Date(2026, 9, 1+r.Intn(3), 0, 0, 0, 0, time.UTC)
		return &on
	}
	pick := func(choices ...string) string { return choices[r.Intn(len(choices))] }
	var out []finding.Named
	for range 1 + r.Intn(6) {
		named := finding.Named{
			Identifier:  name(),
			Severity:    pick("", "low", "high", "critical"),
			Description: pick("", "", "What it is.", "What else it is."),
			Advisory:    pick("", "", "https://example.com/a", "https://example.com/b"),
		}
		// Most reports name an issue the way every scan names it, which is
		// the case resolved from what was read.
		bare := false
		if r.Intn(4) != 0 {
			k := r.Intn(6)
			bare = k >= 4
			named.Identifier = fmt.Sprintf("CVE-%d-%d", year, 1000+k)
			named.Aliases = []string{fmt.Sprintf("GHSA-%d-%d", year, k)}
		}
		// Distinct names: a report naming one name twice is refused by the
		// unique index on names whichever way it is interned.
		given := map[string]bool{named.Identifier: true}
		for _, alias := range named.Aliases {
			given[alias] = true
		}
		for range r.Intn(3) * r.Intn(2) {
			if alias := name(); !given[alias] {
				given[alias] = true
				named.Aliases = append(named.Aliases, alias)
			}
		}
		if r.Intn(2) == 0 {
			named.Likelihood = []float64{0.01, 0.2, 0.5}[r.Intn(3)]
			named.LikelihoodPercentile = 0.9
			named.LikelihoodOn = day()
		}
		if r.Intn(4) == 0 {
			named.Exploited = true
			named.ExploitedOn = day()
		}
		switch r.Intn(4) {
		case 0:
			named.Score = []float64{5.0, 7.5}[r.Intn(2)]
		case 1:
			named.Score = []float64{5.0, 9.8}[r.Intn(2)]
			named.Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		case 2:
			named.Ratings = []finding.CVSS{{
				Generation: []int{3, 4}[r.Intn(2)], ScoreCenti: []int{600, 750, 980}[r.Intn(3)],
				Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Source: pick("nvd", "github"), Kind: pick("primary", "secondary"),
			}}
		}
		for _, cwe := range []string{"CWE-79", "CWE-89", "CWE-20"} {
			if r.Intn(3) == 0 {
				named.Weaknesses = append(named.Weaknesses, cwe)
			}
		}
		if len(named.Weaknesses) > 0 && r.Intn(2) == 0 {
			named.PrimaryWeakness = named.Weaknesses[r.Intn(len(named.Weaknesses))]
		}
		for _, url := range []string{"https://example.com/fix", "https://example.com/notes"} {
			if r.Intn(3) == 0 {
				named.References = append(named.References, finding.Reference{URL: url})
			}
		}
		// Two issues nothing ever dates an estimate for or rates, which is
		// what keeps a bare score and an undated estimate in play.
		if bare {
			named.LikelihoodOn, named.Ratings, named.Vector = nil, nil, ""
			named.ExploitedOn = nil
		}
		out = append(out, named)
	}
	// The same account again, as a scanner gives it for every package the
	// issue was matched in, somewhere after the first: another report in
	// between is what makes keeping the wrong copy visible.
	for i := len(out) - 1; i >= 0; i-- {
		for range r.Intn(3) / 2 * (1 + r.Intn(2)) {
			at := i + 1 + r.Intn(len(out)-i)
			out = append(out[:at], append([]finding.Named{out[i]}, out[at:]...)...)
		}
	}
	return out
}

// seeded is a sequence of choices that is the same every run, so a round that
// fails is the same round when run again.
func seeded(seed int64) *rand.Rand {
	return rand.New(rand.NewSource(seed)) //nolint:gosec // G404: reproducible test input, not a secret
}

// steadily is rounds about one issue that only ever arrives named the same
// way, each moving one thing a rescan can move: the arms a random round
// reaches rarely, because an issue's first report is resolved alone.
func steadily(year int) [][]finding.Named {
	first := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	second := first.AddDate(0, 0, 1)
	issue := func(edit func(*finding.Named)) []finding.Named {
		named := finding.Named{Identifier: fmt.Sprintf("CVE-%d-2000", year)}
		edit(&named)
		return []finding.Named{named}
	}
	return [][]finding.Named{
		issue(func(n *finding.Named) { n.Score = 5.0 }),
		issue(func(n *finding.Named) { n.Score = 7.5 }),
		issue(func(n *finding.Named) { n.Score = 7.5; n.Exploited = true }),
		issue(func(n *finding.Named) { n.Likelihood = 0.2 }),
		issue(func(n *finding.Named) { n.Likelihood = 0.3 }),
		issue(func(n *finding.Named) { n.Likelihood = 0.3 }),
		issue(func(n *finding.Named) { n.Likelihood, n.LikelihoodOn = 0.3, &first }),
		issue(func(n *finding.Named) { n.Likelihood, n.LikelihoodOn = 0.25, &second }),
		issue(func(n *finding.Named) { n.Likelihood, n.LikelihoodOn = 0.25, &second }),
		// An issue already held, then a new one and a report joining the two
		// in one round: the second learns a name the first just wrote.
		{{Identifier: fmt.Sprintf("CVE-%d-3001", year)}},
		{
			{Identifier: fmt.Sprintf("CVE-%d-3000", year), Aliases: []string{fmt.Sprintf("GHSA-%d-3000", year)}},
			{Identifier: fmt.Sprintf("CVE-%d-3001", year), Aliases: []string{fmt.Sprintf("GHSA-%d-3000", year)}},
		},
	}
}

// issueState is everything interning wrote about the issues named in one
// year, with the year taken out so two years compare.
func (f *fixture) issueState(t *testing.T, year int) []string {
	t.Helper()
	ctx := t.Context()
	marker := fmt.Sprintf("-%d-", year)
	plain := func(s string) string { return strings.ReplaceAll(s, marker, "-YEAR-") }
	var rows []finding.Vulnerability
	if err := f.db.DB.NewSelect().Model(&rows).
		Where("vu.identifier LIKE ?", "%"+marker+"%").Scan(ctx); err != nil {
		t.Fatal(err)
	}
	named := map[int64]string{}
	for _, row := range rows {
		named[row.ID] = plain(row.Identifier)
	}
	var out []string
	for _, row := range rows {
		out = append(out, fmt.Sprintf("issue %s filed as %s: %q %q %q %v %v %v %v %v %v %q %q %q %q",
			named[row.ID], named[row.IssueID], row.Severity, row.Description, row.Advisory,
			row.Exploited, day(row.ExploitedOn), deref(row.LikelihoodPPM),
			deref(row.LikelihoodPercentilePPM), day(row.LikelihoodOn), deref(row.ScoreCenti),
			row.Vector, row.ScoreVersion, row.ScoreSource, row.ScoreKind))
	}
	ids := make([]int64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	if len(ids) > 0 {
		var aliases []finding.Alias
		if err := f.db.DB.NewSelect().Model(&aliases).
			Where("vulnerability_id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		for _, alias := range aliases {
			out = append(out, fmt.Sprintf("name %s of %s, by hand %v",
				plain(alias.Identifier), named[alias.VulnerabilityID], alias.ByHand))
		}
		var ratings []finding.CVSS
		if err := f.db.DB.NewSelect().Model(&ratings).
			Where("vulnerability_id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		for _, rating := range ratings {
			out = append(out, fmt.Sprintf("rating of %s: %d %d %q %q %q %q", named[rating.VulnerabilityID],
				rating.Generation, rating.ScoreCenti, rating.Vector, rating.Version, rating.Source,
				rating.Kind))
		}
		var weaknesses []finding.Weakness
		if err := f.db.DB.NewSelect().Model(&weaknesses).
			Where("vulnerability_id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		for _, weakness := range weaknesses {
			out = append(out, fmt.Sprintf("weakness of %s: %s %v", named[weakness.VulnerabilityID],
				weakness.CWE, weakness.Primary))
		}
		var references []finding.Reference
		if err := f.db.DB.NewSelect().Model(&references).
			Where("vulnerability_id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		for _, reference := range references {
			out = append(out, fmt.Sprintf("reference of %s: %s %s", named[reference.VulnerabilityID],
				reference.URL, reference.Kind))
		}
	}
	sort.Strings(out)
	return out
}

// identifierOf is the name an issue is filed under.
func (f *fixture) identifierOf(t *testing.T, id int64) string {
	t.Helper()
	var identifier string
	if err := f.db.DB.NewSelect().TableExpr(`"vulnerability" AS "v"`).ColumnExpr("v.identifier").
		Where("v.id = ?", id).Scan(t.Context(), &identifier); err != nil {
		t.Fatal(err)
	}
	return identifier
}

// plainly is a list of lines with one year's numbering taken out, sorted.
func plainly(lines []string, year int) []string {
	marker := fmt.Sprintf("-%d-", year)
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, strings.ReplaceAll(line, marker, "-YEAR-"))
	}
	sort.Strings(out)
	return out
}

func day(t *time.Time) string {
	if t == nil {
		return "none"
	}
	return t.UTC().Format("2006-01-02")
}

func deref(n *int) string {
	if n == nil {
		return "none"
	}
	return fmt.Sprint(*n)
}

func TestInterningARunOfReportsWritesWhatInterningEachAloneWrites(t *testing.T) {
	// A run of reports is resolved from one read of what is on record about
	// all of them, writing only what that read says would change, and a
	// report the read cannot answer for is resolved alone. The two have to be
	// indistinguishable: the same rows, the same names, the same merges and
	// the same issues reported as moved, round after round over issues whose
	// names overlap.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		merged, moved := 0, 0
		for sequence, start := range []int64{7, 11, 23} {
			r := seeded(start)
			// Each sequence names issues of its own.
			mine, theirs := 3001+2*sequence, 3002+2*sequence
			steady, steadyToo := steadily(mine), steadily(theirs)
			for round := range 60 + len(steady) {
				seed := r.Int63()
				ours := reportsIn(seeded(seed), mine)
				others := reportsIn(seeded(seed), theirs)
				if round < len(steady) {
					ours, others = steady[round], steadyToo[round]
				}
				together := finding.NewVulnerabilities(f.db.DB)
				alone := finding.NewVulnerabilities(f.db.DB)
				gotNames, err := together.Intern(ctx, ours)
				if err != nil {
					t.Fatalf("sequence %d round %d: %v", sequence, round, err)
				}
				wantNames, err := alone.InternAlone(ctx, others)
				if err != nil {
					t.Fatalf("sequence %d round %d alone: %v", sequence, round, err)
				}
				if got, want := f.issueState(t, mine), f.issueState(t, theirs); !reflect.DeepEqual(got, want) {
					t.Fatalf("sequence %d round %d: interned together\n%s\nand alone\n%s", sequence, round,
						strings.Join(got, "\n"), strings.Join(want, "\n"))
				}
				resolved := func(names map[string]int64, year int) []string {
					var out []string
					for name, id := range names {
						out = append(out, name+" is "+f.identifierOf(t, id))
					}
					return plainly(out, year)
				}
				if got, want := resolved(gotNames, mine), resolved(wantNames, theirs); !reflect.DeepEqual(got, want) {
					t.Errorf("sequence %d round %d: resolved together as %v and alone as %v", sequence, round, got, want)
				}
				if got, want := together.Absorbed(), alone.Absorbed(); got != want {
					t.Errorf("sequence %d round %d: %d merges together and %d alone", sequence, round, got, want)
				}
				movedOf := func(ids []int64, year int) []string {
					var out []string
					for _, id := range ids {
						out = append(out, f.identifierOf(t, id))
					}
					return plainly(out, year)
				}
				if got, want := movedOf(together.Moved(), mine), movedOf(alone.Moved(), theirs); !reflect.DeepEqual(got, want) {
					t.Errorf("sequence %d round %d: moved together %v and alone %v", sequence, round, got, want)
				}
				merged += together.Absorbed()
				moved += len(together.Moved())
			}
		}
		// The rounds have to have reached the cases that differ.
		if merged == 0 || moved == 0 {
			t.Fatalf("the rounds merged %d issues and moved %d, so this checked too little", merged, moved)
		}
	})
}

func TestARepeatedReportIsInternedAsItsFirstCopyAsWellAsItsLast(t *testing.T) {
	// Only an insert writes a severity, so the first report about a new issue
	// decides it; and a report naming two issues merges them only once both
	// are on record. Leaving out a repeated report's first copy hands both
	// to whatever arrived between it and the last.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		low := finding.Named{Identifier: "CVE-2026-9001", Severity: "low"}
		high := finding.Named{Identifier: "CVE-2026-9001", Severity: "high", Description: "Another account."}
		names, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx, []finding.Named{low, high, low})
		if err != nil {
			t.Fatal(err)
		}
		var severity string
		if err := f.db.DB.NewSelect().TableExpr(`"vulnerability" AS "v"`).ColumnExpr("v.severity").
			Where("v.id = ?", names["CVE-2026-9001"]).Scan(ctx, &severity); err != nil {
			t.Fatal(err)
		}
		if severity != "low" {
			t.Errorf("an issue first reported low was created %q", severity)
		}

		a := finding.Named{Identifier: "CVE-2026-9002"}
		b := finding.Named{Identifier: "GHSA-2026-9002"}
		both := finding.Named{Identifier: "CVE-2026-9002", Aliases: []string{"GHSA-2026-9002"}}
		interning := finding.NewVulnerabilities(f.db.DB)
		if _, err := interning.Intern(ctx, []finding.Named{a, b, both, a}); err != nil {
			t.Fatal(err)
		}
		if n := interning.Absorbed(); n != 1 {
			t.Errorf("two issues a later report named together were merged %d times, want once", n)
		}
	})
}

func TestAnIssueReportedAtManyPackagesCostsWhatOnePackageDoes(t *testing.T) {
	// A scanner reports an issue once for every package it matched, with the
	// same account of the issue each time, and interning the same account a
	// second time can change nothing the first did not.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		lookups := func(id string, components ...graph.Described) int {
			var reported []finding.Reported
			for _, component := range components {
				r := found(id, component)
				r.Issue.Description = "A flaw in several places."
				reported = append(reported, r)
			}
			asked := &matchedStatements{}
			f.db.AddQueryHook(asked)
			if _, err := f.store.Apply(t.Context(), f.target, f.run(t), reported); err != nil {
				t.Fatal(err)
			}
			n, _ := asked.matching(`SELECT "va"."id"`)
			return n
		}
		once := lookups("CVE-2026-ONCE", libnl)
		thrice := lookups("CVE-2026-THRICE", libnl, swss, teamd)
		if once == 0 {
			t.Fatal("no names were looked up, so this checked nothing")
		}
		if thrice != once {
			t.Errorf("an issue at three packages looked its names up %d times, at one %d", thrice, once)
		}
	})
}

func TestRescanningAnUnchangedIssueWritesNothingAboutIt(t *testing.T) {
	// Everything interning writes about an issue fills a gap, moves toward
	// worse or newer, or adds what is missing, so a report saying what is
	// already held writes nothing. Read once for the run, it asks nothing per
	// report either.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		on := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		r := found("CVE-2026-STEADY", libnl, "GHSA-2026-STEADY")
		r.Issue.Description = "What the flaw is."
		r.Issue.Advisory = "https://example.com/advisory"
		r.Issue.Likelihood, r.Issue.LikelihoodPercentile, r.Issue.LikelihoodOn = 0.2, 0.9, &on
		r.Issue.Exploited, r.Issue.ExploitedOn = true, &on
		r.Issue.Score, r.Issue.Vector = 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		r.Issue.Weaknesses, r.Issue.PrimaryWeakness = []string{"CWE-79", "CWE-89"}, "CWE-79"
		r.Issue.References = []finding.Reference{{URL: "https://example.com/fix"}}
		for range 2 {
			if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{r}); err != nil {
				t.Fatal(err)
			}
		}
		asked := &matchedStatements{}
		f.db.AddQueryHook(asked)
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{r}); err != nil {
			t.Fatal(err)
		}
		for _, prefix := range []string{`UPDATE "vulnerability`, `INSERT INTO "vulnerability`} {
			if n, _ := asked.matching(prefix); n != 0 {
				t.Errorf("a rescan of an unchanged issue sent %d statements beginning %s", n, prefix)
			}
		}
		if n, _ := asked.matching(`SELECT "va"."id"`); n != 1 {
			t.Errorf("the issue's names were looked up %d times, want once for the run", n)
		}
	})
}

func TestADescriptionAlreadyHeldIsNotWrittenAgain(t *testing.T) {
	// The description and the advisory fill a gap and are never overwritten,
	// so the statement filling them matches only a row holding a gap. Two
	// accounts of one issue in one scan, the first adding a reference, have
	// the second resolved alone, which is the path that issues the statement.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		described := found("CVE-2026-DESCRIBED", libnl)
		described.Issue.Description = "What the flaw is."
		described.Issue.Advisory = "https://example.com/advisory"
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{described}); err != nil {
			t.Fatal(err)
		}
		pointing := found("CVE-2026-DESCRIBED", swss)
		pointing.Issue.References = []finding.Reference{{URL: "https://example.com/fix"}}
		asked := &matchedStatements{}
		f.db.AddQueryHook(asked)
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{pointing, described}); err != nil {
			t.Fatal(err)
		}
		n, matched := asked.matching(`UPDATE "vulnerability" `)
		if n == 0 {
			t.Fatal("nothing filled the description, so this checked nothing")
		}
		if matched != 0 {
			t.Errorf("filling an issue already described matched %d rows of it", matched)
		}
	})
}
