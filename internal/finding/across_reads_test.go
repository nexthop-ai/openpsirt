// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// curlTwice is one source package built as two binaries, one of them pulled in
// at two places, carrying three issues: one on both binaries, one on each.
func (f *fixture) curlTwice(t *testing.T) (lib, gnutls graph.Described) {
	t.Helper()
	lib, gnutls = builtFrom("libcurl4t64", "8.5.0-2"), builtFrom("libcurl3t64-gnutls", "8.5.0-2")
	f.shipped(t, graph.Snapshot{
		Root:       root,
		Components: []graph.Described{root, swss, teamd, lib, gnutls},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: swss}, {Parent: root, Child: teamd},
			{Parent: swss, Child: lib}, {Parent: teamd, Child: lib}, {Parent: swss, Child: gnutls},
		},
	})
	rated := func(id, severity string, on graph.Described, fixedIn string) finding.Reported {
		one := finding.Reported{Issue: finding.Named{Identifier: id, Severity: severity}, Component: on}
		if fixedIn != "" {
			one.FixState, one.FixedIn = finding.FixedUpstream, fixedIn
		}
		return one
	}
	if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
		rated("CVE-2026-71", "critical", lib, "8.5.0-3"),
		rated("CVE-2026-71", "critical", gnutls, "8.5.0-3"),
		rated("CVE-2026-72", "low", gnutls, ""),
		rated("CVE-2026-73", "high", lib, "8.5.0-3"),
	}); err != nil {
		t.Fatal(err)
	}
	return lib, gnutls
}

func TestASourcePackageCountsEachIssueOnceAndEveryPlaceAcrossItsBinaries(t *testing.T) {
	// The places are grouped to one row per issue on each binary before the
	// binaries are folded together, so what is counted per issue has to be
	// counted again across binaries rather than summed: an issue on both is
	// one issue, and its three places are three places.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		_, gnutls := f.curlTwice(t)

		later := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
		sooner := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
		if _, err := f.db.DB.NewUpdate().TableExpr(`"finding"`).
			Set("due_at = ?", later).Where("target_id = ?", f.target).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		// The soonest deadline sits on one band and the one exploited place
		// on another, each on the binary carrying the fewest places, so
		// neither survives a fold that keeps one binary's answer or one
		// band's.
		mark := func(issue, column string, value any) {
			t.Helper()
			if _, err := f.db.DB.NewUpdate().TableExpr(`"finding"`).
				Set(column+" = ?", value).
				Where("target_id = ?", f.target).
				Where("vulnerability_id = ?", f.issueID(t, issue)).
				Where("component_id = ?", rowOf(t, f, gnutls)).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		mark("CVE-2026-72", "due_at", sooner)
		mark("CVE-2026-71", "urgency_exploited", true)

		builds, err := f.store.AcrossBuilds(ctx, f.holding(t, access.PublicTriage), f.wholeProduct(), "curl")
		if err != nil {
			t.Fatal(err)
		}
		if len(builds) != 1 {
			t.Fatalf("%d entries, want the one source package in the one build", len(builds))
		}
		got := builds[0]
		if got.Issues != 3 {
			t.Errorf("%d issues, want 3: the one on both binaries counted once", got.Issues)
		}
		if got.Places != 6 {
			t.Errorf("%d places, want 6: three for the issue on both binaries, two and one for the others", got.Places)
		}
		if got.Fixable != 2 {
			t.Errorf("%d fixable, want the 2 issues a version fixes, each once", got.Fixable)
		}
		want := map[string]int{"critical": 1, "high": 1, "low": 1}
		for band, n := range want {
			if got.BySeverity[band] != n {
				t.Errorf("%d %s, want %d: bands %v", got.BySeverity[band], band, n, got.BySeverity)
			}
		}
		if len(got.BySeverity) != len(want) {
			t.Errorf("bands %v, want exactly %v", got.BySeverity, want)
		}
		if got.DueAt == nil || !got.DueAt.Equal(sooner) {
			t.Errorf("due %v, want the soonest of every binary's, %v", got.DueAt, sooner)
		}
		if !got.Exploited {
			t.Error("an exploited issue on one binary did not mark the source package")
		}
		if len(got.Upgrades) != 1 || got.Upgrades[0].To != "8.5.0-3" ||
			got.Upgrades[0].FixedHere != 2 || got.Upgrades[0].Reached != 2 {
			t.Errorf("where it could go is %+v, want 8.5.0-3 closing 2, each issue once", got.Upgrades)
		}
		perBinary := map[string]int{}
		for _, one := range got.Packages {
			perBinary[one.Name] = one.Issues
		}
		if perBinary["libcurl4t64"] != 2 || perBinary["libcurl3t64-gnutls"] != 2 {
			t.Errorf("each binary's own issues are %v, want 2 on each", perBinary)
		}
	})
}

func TestAnIssueWhoseBinariesNameDifferentFixesCountsOnceUnderEach(t *testing.T) {
	// The places are counted under the one fix an issue names across its
	// source package. An issue whose binaries disagree names two, and is
	// counted under each of them once, and once in what is fixable. In
	// another build, where its binaries agree, it is counted under its one
	// fix and nowhere else.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		lib, gnutls := builtFrom("libcurl4t64", "8.5.0-2"), builtFrom("libcurl3t64-gnutls", "8.5.0-2")
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{root, swss, lib, gnutls},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swss}, {Parent: swss, Child: lib}, {Parent: swss, Child: gnutls},
			},
		})
		fixed := func(id string, on graph.Described, fixedIn string) finding.Reported {
			return finding.Reported{Issue: finding.Named{Identifier: id, Severity: "high"}, Component: on,
				FixState: finding.FixedUpstream, FixedIn: fixedIn}
		}
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			fixed("CVE-2026-71", lib, "8.5.0-3"),
			fixed("CVE-2026-71", gnutls, "8.5.0-4"),
			fixed("CVE-2026-73", lib, "8.5.0-3"),
		}); err != nil {
			t.Fatal(err)
		}

		other := f.anotherBranch(t, "next")
		f.shippedTo(t, other, graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{root, swss, lib},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: swss, Child: lib}},
		})
		if _, err := f.store.Apply(ctx, other, f.runOn(t, other), []finding.Reported{
			fixed("CVE-2026-71", lib, "8.5.0-4"),
			fixed("CVE-2026-73", lib, "8.5.0-4"),
		}); err != nil {
			t.Fatal(err)
		}

		builds, err := f.store.AcrossBuilds(ctx, f.holding(t, access.PublicTriage), f.wholeProduct(), "curl")
		if err != nil {
			t.Fatal(err)
		}
		if len(builds) != 2 {
			t.Fatalf("%d entries, want the one source package in each of two builds", len(builds))
		}
		var got, there finding.PerBuild
		for _, one := range builds {
			if one.TargetID == other {
				there = one
			} else {
				got = one
			}
		}
		agreed := []finding.Candidate{{To: "8.5.0-4", FixedHere: 2, Reached: 2, Ordered: true}}
		if there.Issues != 2 || len(there.Upgrades) != 1 || there.Upgrades[0] != agreed[0] {
			t.Errorf("where its binaries agree, %d issues and %+v, want 2 and %+v", there.Issues, there.Upgrades, agreed)
		}
		if got.Issues != 2 || got.Fixable != 2 || got.BySeverity["high"] != 2 {
			t.Errorf("%d issues, %d fixable, bands %v, want 2, 2 and 2 high", got.Issues, got.Fixable, got.BySeverity)
		}
		want := []finding.Candidate{
			{To: "8.5.0-4", FixedHere: 1, Reached: 2, Ordered: true},
			{To: "8.5.0-3", FixedHere: 2, Reached: 2, Ordered: true},
		}
		if len(got.Upgrades) != len(want) {
			t.Fatalf("where it could go is %+v, want %+v", got.Upgrades, want)
		}
		for i := range want {
			if got.Upgrades[i] != want[i] {
				t.Errorf("where it could go is %+v, want %+v", got.Upgrades, want)
				break
			}
		}
	})
}

func TestAPromiseInAnotherProductDoesNotStandOverThisProductsBuild(t *testing.T) {
	// The product a decision is correlated by is the scope's, bound once. Two
	// products shipping one component carry the same issue at the same place
	// identity, so a promise is told apart by its product and nothing else.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		elsewhere := f.inAnotherProduct(t, "hedgehog")
		f.shippedTo(t, elsewhere, through(libnl))
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		somebody, err := access.NewStore(f.db.DB).Ensure(ctx, "somebody@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		promise := func(product int64, to, key string) {
			t.Helper()
			claim := claimSaying(t, f.db, somebody.ID, "upgrade-needed")
			if _, err := f.db.DB.NewUpdate().Table("claim").
				Set("committed_to = ?", time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)).
				Set("upgrade_to = ?", to).Where("id = ?", claim).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.DB.NewInsert().Model(&map[string]any{
				"claim_id": claim, "product_id": product,
				"vulnerability_id": f.issueID(t, "CVE-2026-1"),
				"place_identity":   finding.PlaceIdentity(libnl.Name, swss.Name),
				"visibility":       "public", "state": "approved",
				"needs_approval": true, "proposed_by": somebody.ID,
				"proposed_at":                time.Now().UTC(),
				"component_upstream_version": libnl.Version,
				"live_key":                   key,
			}).TableExpr(`"decision"`).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		read := func() finding.PerBuild {
			t.Helper()
			builds, err := f.store.AcrossBuilds(ctx, f.holding(t, access.PublicTriage), f.wholeProduct(), libnl.Name)
			if err != nil {
				t.Fatal(err)
			}
			if len(builds) != 1 {
				t.Fatalf("%d builds carry it, want one", len(builds))
			}
			return builds[0]
		}

		promise(f.productOf(t, elsewhere), "4.0", "theirs")
		if got := read(); got.UpgradeTo != "" || got.CommittedTo != nil {
			t.Errorf("another product's promise reads as this one's: %q by %v", got.UpgradeTo, got.CommittedTo)
		}
		promise(f.productID, "3.9.0", "ours")
		if got := read(); got.UpgradeTo != "3.9.0" {
			t.Errorf("this product's own promise reads as %q, want 3.9.0", got.UpgradeTo)
		}
	})
}

// returned records each statement a store sends with how many rows came back.
type returned struct {
	mu   sync.Mutex
	sent []string
	rows []int64
}

func (r *returned) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	return ctx
}

func (r *returned) AfterQuery(_ context.Context, event *bun.QueryEvent) {
	var n int64 = -1
	if event.Result != nil {
		if got, err := event.Result.RowsAffected(); err == nil {
			n = got
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, event.Query)
	r.rows = append(r.rows, n)
}

func TestASourcePackagesFindingsAreReadByComponentInOnePassOneRowPerFix(t *testing.T) {
	// Every statement over the findings names the source package's component
	// rows as values, rather than joining the fold key to restrict them: an
	// estimate for an average component is wrong for a kernel by three orders
	// of magnitude. The counts, each binary's count, where it could go and
	// what was promised are one pass over the places, and come back one row
	// per fix and rating rather than one per issue, because one per issue is
	// the size of the kernel.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		lib, gnutls := builtFrom("libcurl4t64", "8.5.0-2"), builtFrom("libcurl3t64-gnutls", "8.5.0-2")
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{root, swss, lib, gnutls},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swss}, {Parent: swss, Child: lib}, {Parent: swss, Child: gnutls},
			},
		})
		var reported []finding.Reported
		for _, on := range []graph.Described{lib, gnutls} {
			for _, id := range []string{"CVE-2026-71", "CVE-2026-72", "CVE-2026-73", "CVE-2026-74"} {
				if on == gnutls && id > "CVE-2026-72" {
					break
				}
				reported = append(reported, finding.Reported{
					Issue: finding.Named{Identifier: id, Severity: "high"}, Component: on,
					FixState: finding.FixedUpstream, FixedIn: "8.5.0-3",
				})
			}
		}
		if _, err := f.store.Apply(ctx, f.target, f.run(t), reported); err != nil {
			t.Fatal(err)
		}
		seen := &returned{}
		f.db.AddQueryHook(seen)
		builds, err := f.store.AcrossBuilds(ctx, f.holding(t, access.PublicTriage), f.wholeProduct(), "curl")
		if err != nil {
			t.Fatal(err)
		}
		if len(builds) != 1 || builds[0].Issues != 4 || len(builds[0].Upgrades) != 1 ||
			builds[0].Upgrades[0].FixedHere != 4 {
			t.Fatalf("read %+v, want four issues under one fix", builds)
		}
		// Each binary's own count is read in the same pass, so it is checked
		// here against binaries carrying different counts.
		for _, one := range builds[0].Packages {
			if want := map[string]int{lib.Name: 4, gnutls.Name: 2}[one.Name]; one.Issues != want {
				t.Errorf("%s carries %d issues, want %d", one.Name, one.Issues, want)
			}
		}

		seen.mu.Lock()
		sent, rows := append([]string{}, seen.sent...), append([]int64{}, seen.rows...)
		seen.mu.Unlock()
		checked, fixes := 0, 0
		for i, statement := range sent {
			if !strings.Contains(statement, `"finding" AS "f"`) {
				continue
			}
			checked++
			if strings.Contains(statement, "fold_key IN") || !strings.Contains(statement, "component_id IN (") {
				t.Errorf("a statement over the findings is not restricted by component:\n  %s", statement)
			}
			if strings.Contains(statement, `f.fixed_in AS "fixed_in"`) {
				fixes++
				// Six places, four issues on one binary and two of them on
				// the other, every one rated high and fixed in one version.
				if rows[i] != 1 {
					t.Errorf("the counts read %d rows, want 1, one per fix and rating", rows[i])
				}
			}
		}
		if checked != 1 {
			t.Errorf("%d statements over the findings, want everything in one pass", checked)
		}
		if fixes != 1 {
			t.Errorf("%d reads of where it could go, want 1", fixes)
		}
	})
}

func TestEachBinarysCountIsTheSameReadInThePassOrOnItsOwn(t *testing.T) {
	// Each binary's count rides the pass over the places as a column of its
	// own, up to a bound past which it is read in a statement of its own. The
	// two give one answer, checked against binaries carrying different counts.
	each(t, func(t *testing.T, f *fixture) {
		lib, gnutls := builtFrom("libcurl4t64", "8.5.0-2"), builtFrom("libcurl3t64-gnutls", "8.5.0-2")
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{root, swss, lib, gnutls},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swss}, {Parent: swss, Child: lib}, {Parent: swss, Child: gnutls},
			},
		})
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-71", lib), found("CVE-2026-73", lib), found("CVE-2026-71", gnutls),
		}); err != nil {
			t.Fatal(err)
		}
		perBinary := func(store *finding.Store) map[string]int {
			t.Helper()
			builds, err := store.AcrossBuilds(t.Context(), f.holding(t, access.PublicTriage), f.wholeProduct(), "curl")
			if err != nil {
				t.Fatal(err)
			}
			if len(builds) != 1 {
				t.Fatalf("%d entries, want the one source package in the one build", len(builds))
			}
			out := map[string]int{}
			for _, one := range builds[0].Packages {
				out[one.Name] = one.Issues
			}
			return out
		}
		want := map[string]int{"libcurl4t64": 2, "libcurl3t64-gnutls": 1}
		for name, store := range map[string]*finding.Store{
			"in the pass": f.store, "on its own": finding.NewStoreCountingApart(f.db.DB, 1),
		} {
			if got := perBinary(store); len(got) != len(want) ||
				got["libcurl4t64"] != want["libcurl4t64"] || got["libcurl3t64-gnutls"] != want["libcurl3t64-gnutls"] {
				t.Errorf("each binary's count read %s is %v, want %v", name, got, want)
			}
		}
	})
}
