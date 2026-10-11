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

func TestASourcePackagesFindingsAreReadByComponentAndOnePerIssue(t *testing.T) {
	// Every statement over the findings names the source package's component
	// rows as values, rather than joining the fold key to restrict them: an
	// estimate for an average component is wrong for a kernel by three orders
	// of magnitude. And where it could go is read one row per issue on each
	// component, because one row per place is the size of the kernel.
	each(t, func(t *testing.T, f *fixture) {
		f.curlTwice(t)
		seen := &returned{}
		f.db.AddQueryHook(seen)
		if _, err := f.store.AcrossBuilds(t.Context(), f.holding(t, access.PublicTriage),
			f.wholeProduct(), "curl"); err != nil {
			t.Fatal(err)
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
				// Six places, four issues on a component, three of them with
				// a version to move to.
				if rows[i] != 3 {
					t.Errorf("where it could go read %d rows, want 3, one per issue on each component", rows[i])
				}
			}
		}
		if checked == 0 {
			t.Fatal("no statement over the findings was seen, so this checked nothing")
		}
		if fixes != 1 {
			t.Errorf("%d reads of where it could go, want 1", fixes)
		}
	})
}
