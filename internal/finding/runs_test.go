// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// A run's own account of itself, and the cost of reading it back.
//
// A receipt names the scanner and the vulnerability database it was measured
// with, because a feed ships bad data for a week and is corrected afterwards.

func TestNamingAPageOfFindingsDoesNotCostAQueryPerRow(t *testing.T) {
	// This is the screen somebody opens first, against the largest product
	// they have. Naming each row with two queries of its own makes a page of
	// fifty a hundred and one round trips, with the cost growing with the
	// page instead of staying flat.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
			found("CVE-2026-3", swss), found("CVE-2026-4", teamd),
		}); err != nil {
			t.Fatal(err)
		}

		// Four more issues over the same components, so the same fixture
		// answers a page of four and a page of eight.
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
			found("CVE-2026-3", swss), found("CVE-2026-4", teamd),
			found("CVE-2026-5", libnl), found("CVE-2026-6", swss),
			found("CVE-2026-7", teamd), found("CVE-2026-8", teamd),
		}); err != nil {
			t.Fatal(err)
		}

		read := func(limit int) (int, int64) {
			counted := &counter{}
			f.db.AddQueryHook(counted)
			groups, _, err := f.store.Groups(t.Context(), f.holding(t, access.PublicRead),
				f.scope, limit, 0, finding.Filter{})
			if err != nil {
				t.Fatal(err)
			}
			for _, group := range groups {
				if group.Vulnerability == "" || group.Component == "" {
					t.Errorf("a row came back unnamed: %+v", group)
				}
			}
			return len(groups), counted.queries.Load()
		}

		few, atFew := read(4)
		many, atMany := read(8)
		if few != 4 || many != 8 {
			t.Fatalf("read %d and %d rows, want 4 and 8", few, many)
		}
		// The invariant is that the cost does not grow with the page, stated
		// by comparing two page sizes rather than by a number somebody has to
		// keep up to date. A count is a moving target — a pass that is itself
		// flat legitimately adds to it, and a test pinned to the total fails
		// for that and reads as a regression.
		if atFew != atMany {
			t.Errorf("four rows took %d statements and eight took %d; "+
				"the cost grows with the page", atFew, atMany)
		}
		// And a loose ceiling, so a flat pass nobody needs is still noticed:
		// which product this is, the groups, the count, what is shown about
		// them, a lookup per kind of name, and — for both ends of the chain
		// each row sits at — the build's product and one climb to its root.
		const ceiling = 12
		if atMany > ceiling {
			t.Errorf("naming a page took %d statements, want no more than %d", atMany, ceiling)
		}
	})
}

// The number a release-over-release chart is drawn from. Nothing reported it
// before, so the comparison screen could say what changed between two builds
// and not whether the estate was getting better or worse across all of them.
func TestWhatIsOpenIsReportedPerBuild(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		// A second build, because "per build" tested against one build
		// proves nothing: collapsing the grouping key to a constant passed.
		second := f.anotherBuild(t, "202411")

		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
			found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		// One issue on the other build, so the two must not be added together.
		f.shippedTo(t, second, twoConsumers())
		if _, err := f.store.Apply(t.Context(), second, f.runOn(t, second),
			[]finding.Reported{found("CVE-2026-3", libnl)}); err != nil {
			t.Fatal(err)
		}

		releases, err := f.store.Releases(t.Context(),
			f.holding(t, access.PublicRead), f.productID)
		if err != nil {
			t.Fatalf("releases: %v", err)
		}
		if len(releases) != 2 {
			t.Fatalf("reported %d builds, expected 2: %+v", len(releases), releases)
		}
		by := map[string]finding.Release{}
		for _, r := range releases {
			by[r.Stream] = r
		}
		// Two issues at one component is two rows on the findings list, not
		// the six places they sit at. Counting places is the mistake the trend
		// chart already made and recorded.
		if got := by["master"].Open; got != 2 {
			t.Errorf("master reports %d open, expected 2 — one per issue at a "+
				"component, not one per place", got)
		}
		if got := by["202411"].Open; got != 1 {
			t.Errorf("202411 reports %d open, expected 1", got)
		}
		// The split has to name the band, not merely add up: incrementing both
		// counters from the same value in the same loop is a tautology that
		// passes with the band renamed to nonsense.
		if got := by["master"].BySeverity["high"]; got != 2 {
			t.Errorf("master reports %d high, expected 2 (by_severity: %v)",
				got, by["master"].BySeverity)
		}
	})
}

// A build reporting nothing wrong and a build last measured against a database
// from March look identical on every screen without this.
func TestTheLastRunSaysWhatItWasMeasuredWith(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.holding(t, access.PublicRead)
		f.shipped(t, twoConsumers())

		// A run that has started and not finished is not an answer. Reporting
		// it would say the build was measured against a database version that
		// nothing has been measured against yet.
		running := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, running,
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		unfinished, err := f.store.LatestRun(t.Context(), who, f.target)
		if err != nil {
			t.Fatalf("latest run: %v", err)
		}
		if unfinished != nil {
			t.Fatalf("an unfinished run was reported: %+v", unfinished)
		}
		if err := f.store.Finish(t.Context(), running, "0.100.1", "2026-08-29", "", nil); err != nil {
			t.Fatal(err)
		}

		// A second, later run. "Most recent" is untestable with one.
		later := f.run(t)
		if err := f.store.Finish(t.Context(), later, "0.101.0", "2026-09-02", "", nil); err != nil {
			t.Fatal(err)
		}

		last, err := f.store.LatestRun(t.Context(), who, f.target)
		if err != nil {
			t.Fatalf("latest run: %v", err)
		}
		if last == nil {
			t.Fatal("nothing reported after two runs finished")
		}
		if last.ID != later {
			t.Errorf("reported run %d, expected the most recent (%d)", last.ID, later)
		}
		if last.DatabaseVersion != "2026-09-02" {
			t.Errorf("database version is %q, expected the later run's",
				last.DatabaseVersion)
		}
		if last.Scanner != "grype" || last.FinishedAt == nil {
			t.Errorf("a finished run reported without its scanner or time: %+v", last)
		}

		// And somebody who may not see this product is told nothing, on the
		// query rather than by the caller remembering to ask.
		stranger := access.NewPerson(2, "stranger", false, nil, 0)
		if hidden, err := f.store.LatestRun(t.Context(), stranger, f.target); err != nil {
			t.Fatalf("latest run for a stranger: %v", err)
		} else if hidden != nil {
			t.Errorf("somebody with no rights was told what it was measured with: %+v", hidden)
		}
	})
}

// A name that ships at several versions is answerable, and answering with
// every version of the name is a list where most choices lead to "no such
// finding" — which is a worse answer than the refusal it replaced.
func TestOnlyTheVersionsCarryingTheIssueAreOffered(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		// Enough that every filter has something to exclude. With one finding
		// and one component this test passed with every filter deleted —
		// the vulnerability, the closed check, the name and the visibility —
		// because a join through `finding` could not return anything else
		// whatever the query said. Absent data was doing the work the code was
		// supposed to do.
		carrying := graph.Described{
			Purl: "pkg:golang/example.com/lib@v1", Name: "example.com/lib", Version: "v1",
		}
		clean := graph.Described{
			Purl: "pkg:golang/example.com/lib@v2", Name: "example.com/lib", Version: "v2",
		}
		// Same version, different ecosystem: the source repository and the
		// package built from it, which is why a version alone cannot pick one.
		sibling := graph.Described{
			Purl: "pkg:github/example.com/lib@v1", Name: "example.com/lib", Version: "v1",
		}
		// Another name entirely, so the name filter has something to drop.
		elsewhere := graph.Described{
			Purl: "pkg:golang/example.com/other@v9", Name: "example.com/other", Version: "v9",
		}
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{carrying, clean, sibling, elsewhere},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: carrying}, {Parent: root, Child: clean},
				{Parent: root, Child: sibling}, {Parent: root, Child: elsewhere},
			},
		})
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-9", carrying),
			// A different issue at the clean version: the vulnerability filter
			// has to drop this, not the absence of a row.
			found("CVE-2026-8", clean),
			// The same issue under a different name.
			found("CVE-2026-9", elsewhere),
			// And the same issue at the same version in another ecosystem.
			found("CVE-2026-9", sibling),
		}); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicRead)
		issue := f.issueID(t, "CVE-2026-9")
		got, err := f.store.VersionsWithIssue(t.Context(), who, f.target, issue,
			"example.com/lib")
		if err != nil {
			t.Fatalf("versions: %v", err)
		}
		want := []graph.Choice{
			{Version: "v1", Ecosystem: "golang"},
			{Version: "v1", Ecosystem: "github"},
		}
		if !sameChoices(got, want) {
			t.Errorf("offered %v, expected %v", got, want)
		}

		// Closed findings are not offered: following one leads to a finding
		// that is not there.
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("closed_at = ?", time.Now().UTC()).
			Set("closed_run_id = ?", f.run(t)).
			Where("target_id = ?", f.target).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		closed, err := f.store.VersionsWithIssue(t.Context(), who, f.target, issue,
			"example.com/lib")
		if err != nil {
			t.Fatalf("versions after closing: %v", err)
		}
		if len(closed) != 0 {
			t.Errorf("offered %v after every finding closed", closed)
		}
	})
}

// sameChoices compares without caring about order, which the query does not
// promise beyond being stable.
func sameChoices(got, want []graph.Choice) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[graph.Choice]int{}
	for _, c := range got {
		seen[c]++
	}
	for _, c := range want {
		seen[c]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// issueID resolves an issue by the name it was reported under.
func (f *fixture) issueID(t *testing.T, identifier string) int64 {
	t.Helper()
	id, err := finding.NewVulnerabilities(f.db.DB).ByName(t.Context(), identifier)
	if err != nil {
		t.Fatalf("resolve %s: %v", identifier, err)
	}
	return id
}

// backdate moves a scan run's start into the past, so that a deadline counted
// from the opening and a deadline counted from the scan in hand land far
// enough apart to tell apart.
func (f *fixture) backdate(t *testing.T, runID int64, by time.Duration) {
	t.Helper()
	var started time.Time
	if err := f.db.DB.NewSelect().TableExpr("\"scan_run\" AS \"r\"").
		ColumnExpr("r.started_at").Where("r.id = ?", runID).
		Scan(t.Context(), &started); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DB.NewUpdate().TableExpr("\"scan_run\"").
		Set("started_at = ?", started.Add(-by)).
		Where("id = ?", runID).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// startedAt is when a scan run began, as stored.
func (f *fixture) startedAt(t *testing.T, runID int64) time.Time {
	t.Helper()
	var started time.Time
	if err := f.db.DB.NewSelect().TableExpr("\"scan_run\" AS \"r\"").
		ColumnExpr("r.started_at").Where("r.id = ?", runID).
		Scan(t.Context(), &started); err != nil {
		t.Fatal(err)
	}
	return started
}

// assessment reads one claim back, whatever state it is in.
func (f *fixture) assessment(t *testing.T, id int64) finding.Assessment {
	t.Helper()
	var held finding.Assessment
	if err := f.db.DB.NewSelect().Model(&held).Where("id = ?", id).
		Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return held
}

// liveAssessments counts the claims still standing about an issue, in every
// product at once. A rating belongs to a product, so more than one standing
// claim is the ordinary answer where two products have both rated it.
func (f *fixture) liveAssessments(t *testing.T, vulnerabilityID int64) int {
	t.Helper()
	n, err := f.db.DB.NewSelect().Model((*finding.Assessment)(nil)).
		Where("live_vulnerability_id = ?", vulnerabilityID).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// vulnerability names one of a run of issues, zero-padded so the order a test
// reads them in is the order it wrote them.
func vulnerability(i int) string { return fmt.Sprintf("CVE-2026-%04d", i) }

// inAnotherProduct declares a build of a product of its own and returns its
// target, for the checks about reaching across products.
func (f *fixture) inAnotherProduct(t *testing.T, name string) int64 {
	t.Helper()
	ctx := t.Context()
	cat := catalog.NewStore(f.db.DB)
	product, err := cat.DeclareProduct(ctx, name, name)
	if err != nil {
		t.Fatalf("declare %s: %v", name, err)
	}
	stream, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
	if err != nil {
		t.Fatalf("declare a line of %s: %v", name, err)
	}
	variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
	if err != nil {
		t.Fatalf("declare a variant of %s: %v", name, err)
	}
	target, err := cat.TargetFor(ctx, stream.ID, variant.ID)
	if err != nil {
		t.Fatalf("target for %s: %v", name, err)
	}
	return target.ID
}

// productOf is which product a build belongs to.
func (f *fixture) productOf(t *testing.T, target int64) int64 {
	t.Helper()
	var productID int64
	if err := f.db.DB.NewSelect().
		TableExpr("\"target\" AS \"tg\"").
		Join("JOIN \"stream\" AS \"st\" ON st.id = tg.stream_id").
		ColumnExpr("st.product_id").
		Where("tg.id = ?", target).
		Scan(t.Context(), &productID); err != nil {
		t.Fatal(err)
	}
	return productID
}

// streamOf is which release a build belongs to.
func (f *fixture) streamOf(t *testing.T, target int64) int64 {
	t.Helper()
	var streamID int64
	if err := f.db.DB.NewSelect().
		TableExpr("\"target\" AS \"tg\"").
		ColumnExpr("tg.stream_id").
		Where("tg.id = ?", target).
		Scan(t.Context(), &streamID); err != nil {
		t.Fatal(err)
	}
	return streamID
}

// anotherVariant declares a second way this product is built and returns the
// target for it on the fixture's own stream.
func (f *fixture) anotherVariant(t *testing.T, name string) int64 {
	t.Helper()
	ctx := t.Context()
	cat := catalog.NewStore(f.db.DB)
	variant, err := cat.DeclareVariant(ctx, f.productID, name, true)
	if err != nil {
		t.Fatalf("declare variant %s: %v", name, err)
	}
	var streamID int64
	if err := f.db.DB.NewSelect().
		TableExpr("\"target\" AS \"tg\"").ColumnExpr("tg.stream_id").
		Where("tg.id = ?", f.target).Scan(ctx, &streamID); err != nil {
		t.Fatal(err)
	}
	target, err := cat.TargetFor(ctx, streamID, variant.ID)
	if err != nil {
		t.Fatalf("target for %s: %v", name, err)
	}
	return target.ID
}

// scopeOf is one build as a selection, for a build that is not the fixture's
// own — a second variant, or a second branch.
func (f *fixture) scopeOf(t *testing.T, targetID int64) finding.Scope {
	t.Helper()
	var row struct {
		ProductID int64 `bun:"product_id"`
		StreamID  int64 `bun:"stream_id"`
		VariantID int64 `bun:"variant_id"`
	}
	if err := f.db.DB.NewSelect().
		TableExpr("\"target\" AS \"tg\"").
		Join("JOIN \"stream\" AS \"st\" ON st.id = tg.stream_id").
		ColumnExpr("st.product_id AS \"product_id\"").
		ColumnExpr("tg.stream_id AS \"stream_id\"").
		ColumnExpr("tg.variant_id AS \"variant_id\"").
		Where("tg.id = ?", targetID).Scan(t.Context(), &row); err != nil {
		t.Fatalf("look up build %d: %v", targetID, err)
	}
	return finding.Scope{
		ProductID: &row.ProductID, StreamID: &row.StreamID, VariantID: &row.VariantID,
	}
}

// wholeProduct is every build of the fixture's product: what the picker
// selects with the branch and the variant left at "all".
func (f *fixture) wholeProduct() finding.Scope {
	return finding.Scope{ProductID: &f.productID}
}

// componentID is the component row one name resolves to in the fixture's build.
func (f *fixture) componentID(t *testing.T, name string) int64 {
	t.Helper()
	id, err := graph.NewStore(f.db.DB).ComponentAt(t.Context(), f.target, name)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	return id
}

func TestARunThatWarnsWhileSucceedingKeepsWhatItSaid(t *testing.T) {
	// The scanner's own words were read only when it failed, which discarded
	// the case that matters: a run that answers and says its answer is coarse.
	// Told to match Go binaries carrying no function symbols it falls back to
	// module granularity, which can report a component as affected when the
	// vulnerable function is not linked in — a qualification on every finding
	// the run produced.
	//
	// Kept apart from the failure, because a run that warned and a run that
	// failed are different things and one column holding either makes them one.
	each(t, func(t *testing.T, f *fixture) {
		const said = "go binary packages were found but none carry function symbols"
		run := f.run(t)
		if err := f.store.Finish(t.Context(), run, "0.118.0", "2026-09-04", said, nil); err != nil {
			t.Fatal(err)
		}

		var kept finding.Run
		if err := f.db.DB.NewSelect().Model(&kept).Where("id = ?", run).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if kept.Caution != said {
			t.Errorf("what the scanner said reads %q", kept.Caution)
		}
		if kept.Failure != "" {
			t.Errorf("a run that warned reads as failed: %q", kept.Failure)
		}
	})
}

// admin returns somebody who administers this deployment and has granted
// themselves roles on this fixture's product, which is how an administrator
// reaches findings now that administering grants no reading.
func (f *fixture) admin(t *testing.T, roles ...access.Role) access.Subject {
	t.Helper()
	return access.NewPerson(1, "admin", true, map[int64][]access.Role{f.productID: roles}, 0)
}

// holdingIn returns somebody holding roles on several products, for the reads
// that cross one.
func (f *fixture) holdingIn(t *testing.T, products []int64, roles ...access.Role) access.Subject {
	t.Helper()
	grants := map[int64][]access.Role{}
	for _, id := range products {
		grants[id] = roles
	}
	return access.NewPerson(1, "someone", false, grants, 101)
}

// backdateOpenings moves when every open finding was first seen, which is what
// a deadline counted from the opening is counted from.
func (f *fixture) backdateOpenings(t *testing.T, by time.Duration) {
	t.Helper()
	for _, row := range f.open(t) {
		if _, err := f.db.DB.NewUpdate().TableExpr("\"finding\"").
			Set("opened_at = ?", row.OpenedAt.Add(-by)).
			Where("id = ?", row.ID).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}
