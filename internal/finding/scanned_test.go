package finding_test

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// What a scan run opens, moves and closes.
//
// One reported issue becomes one finding per place it occupies, and the next
// scan is a difference rather than a rewrite: what is still there is left
// alone, what has gone is closed with the reason it went, and what moved is
// updated in place.

func TestOneReportedIssueBecomesOneFindingPerConsumer(t *testing.T) {
	// The whole point of the fan-out. A scanner says "libnl-3-200 3.7.0 is
	// affected" and stops, because it never saw the graph. Two things pull it
	// in, so there are two decisions to make about it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Opened != 2 {
			t.Fatalf("opened %d findings, want one per consumer", applied.Opened)
		}

		consumers := map[int64]bool{}
		for _, row := range f.open(t) {
			if row.ConsumerID == nil {
				t.Error("a finding under a consumer recorded none")
				continue
			}
			consumers[*row.ConsumerID] = true
		}
		if len(consumers) != 2 {
			t.Errorf("findings sit under %d distinct consumers, want 2", len(consumers))
		}
	})
}

func TestTheSamePlaceInTwoVariantsKeysTheSame(t *testing.T) {
	// A decision is carried forward by the place, so the key must not contain
	// anything that differs between variants or moves on a rebuild.
	first := finding.PlaceIdentity("libnl-3-200", "libswsscommon")
	again := finding.PlaceIdentity("libnl-3-200", "libswsscommon")
	if first != again {
		t.Error("the same place keyed differently")
	}
	if finding.PlaceIdentity("libnl-3-200", "teamd") == first {
		t.Error("two consumers of one component share a key")
	}
	// Under the product itself, the component stands alone: the product's name
	// differs per variant, so including it would stop the same place being
	// recognized across them.
	if finding.PlaceIdentity("libnl-3-200", "") == first {
		t.Error("a component under the product keys the same as one under a consumer")
	}
}

func TestRescanningWithNothingChangedWritesNothing(t *testing.T) {
	// Re-scanning runs nightly against a database that has barely moved. If an
	// unchanged run wrote rows, storage would track the calendar rather than
	// what is actually happening.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		reported := []finding.Reported{found("CVE-2026-1", libnl)}

		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), reported); err != nil {
			t.Fatal(err)
		}
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t), reported)
		if err != nil {
			t.Fatal(err)
		}
		if !applied.Unchanged() {
			t.Errorf("an unchanged re-scan wrote %+v", applied)
		}
	})
}

func TestAnUpgradeClosesWithTheReason(t *testing.T) {
	// "Fixed by upgrading" and "we cannot account for this" are different
	// things to whoever reads the report later.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		// The next build ships a newer libnl, and the scanner no longer
		// reports it.
		upgraded := twoConsumers()
		upgraded.Components = []graph.Described{swss, teamd, libnlNew}
		upgraded.Dependencies = []graph.Dependency{
			{Parent: root, Child: swss}, {Parent: root, Child: teamd},
			{Parent: swss, Child: libnlNew}, {Parent: teamd, Child: libnlNew},
		}
		f.shipped(t, upgraded)

		applied, err := f.store.Apply(t.Context(), f.target, f.run(t), nil)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Closed != 2 {
			t.Fatalf("closed %d findings, want 2", applied.Closed)
		}
		if applied.Unexplained != 0 {
			t.Errorf("%d closures went unexplained", applied.Unexplained)
		}

		var closed []finding.Finding
		if err := f.db.DB.NewSelect().Model(&closed).
			Where("closed_at IS NOT NULL").Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, row := range closed {
			if row.ClosedBecause != finding.Upgraded {
				t.Errorf("closed because %q, want %q", row.ClosedBecause, finding.Upgraded)
			}
		}
	})
}

func TestAComponentGoneAltogetherClosesAsRemoved(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		f.shipped(t, graph.Snapshot{
			Root: root, Components: []graph.Described{swss, teamd},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: root, Child: teamd}},
		})
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), nil); err != nil {
			t.Fatal(err)
		}

		var closed []finding.Finding
		if err := f.db.DB.NewSelect().Model(&closed).
			Where("closed_at IS NOT NULL").Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(closed) != 2 {
			t.Fatalf("closed %d findings, want 2", len(closed))
		}
		for _, row := range closed {
			if row.ClosedBecause != finding.Removed {
				t.Errorf("closed because %q, want %q", row.ClosedBecause, finding.Removed)
			}
		}
	})
}

func TestADisappearanceNothingExplainsIsFlagged(t *testing.T) {
	// The component is present, unchanged, and the scanner stopped reporting
	// it. There is no volume at which "we cannot account for this" stops
	// mattering, so it is never quietly folded into the others.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		applied, err := f.store.Apply(t.Context(), f.target, f.run(t), nil)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Unexplained != 2 {
			t.Errorf("%d closures were flagged as unexplained, want 2", applied.Unexplained)
		}
	})
}

func TestAComponentUnderTheProductSitsUnderNothing(t *testing.T) {
	// The product's name differs per variant, so a place under it keys on the
	// component alone — otherwise the same place in two variants would be two
	// places and a decision would not carry.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-2", swss)}); err != nil {
			t.Fatal(err)
		}
		rows := f.open(t)
		if len(rows) != 1 {
			t.Fatalf("opened %d findings, want 1", len(rows))
		}
		if rows[0].ConsumerID != nil {
			t.Error("a component under the product recorded a consumer")
		}
		if rows[0].PlaceIdentity != finding.PlaceIdentity("libswsscommon", "") {
			t.Error("a component under the product keyed on something else")
		}
	})
}

// aClaim is what a build argues about one of its components.
func aClaim(vulnerability string, status sbom.Status, subject graph.Described, origin sbom.Origin) sbom.Suppression {
	return sbom.Suppression{
		Vulnerability: vulnerability, Status: status,
		Justification: "vulnerable_code_not_in_execute_path",
		Statement:     "resolved by a patch the build carries",
		Targets:       []sbom.Target{{Purl: subject.Purl, Name: subject.Name}},
		Origin:        origin,
	}
}

func TestAFindingThatMovesIsUpdated(t *testing.T) {
	// Somebody waiting on a fix is waiting for exactly this. A finding opened
	// when no fix existed would otherwise report that indefinitely, however
	// many times it was re-scanned.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		noFix := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "high"},
			Component: libnl, FixState: finding.NoFix,
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{noFix}); err != nil {
			t.Fatal(err)
		}
		opened := f.open(t)
		if len(opened) != 2 {
			t.Fatalf("opened %d findings", len(opened))
		}
		was := opened[0].LastChangedAt

		// The next run knows a fix exists.
		fixed := noFix
		fixed.FixState = finding.FixedUpstream
		fixed.FixedIn = "3.9.0"
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{fixed})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Updated != 2 {
			t.Errorf("%d findings moved, want 2", applied.Updated)
		}
		if applied.Opened != 0 || applied.Closed != 0 {
			t.Errorf("a fix appearing opened %d and closed %d findings", applied.Opened, applied.Closed)
		}
		if applied.Unchanged() {
			t.Error("a fix appearing reported as no change at all")
		}

		for _, row := range f.open(t) {
			if row.FixState != finding.FixedUpstream || row.FixedIn != "3.9.0" {
				t.Errorf("still reports %q / %q", row.FixState, row.FixedIn)
			}
			if !row.LastChangedAt.After(was) {
				t.Error("nothing recorded that it moved")
			}
		}

		// And a run that finds the same thing again still writes nothing.
		applied, err = f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{fixed})
		if err != nil {
			t.Fatal(err)
		}
		if !applied.Unchanged() {
			t.Errorf("an unchanged re-scan wrote %+v", applied)
		}

	})
}

func TestUpstreamDecliningToFixIsAMovement(t *testing.T) {
	// The only thing that changes is the state — there is no version to point
	// at either before or after. It is a permanent condition that changes the
	// outcome somebody should reach, so it must not be the one kind of
	// movement that slips past because nothing else moved with it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		noFix := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "high"},
			Component: libnl, FixState: finding.NoFix,
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{noFix}); err != nil {
			t.Fatal(err)
		}

		declined := noFix
		declined.FixState = finding.WontFix
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{declined})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Updated != 2 {
			t.Errorf("upstream declining to fix moved %d findings, want 2", applied.Updated)
		}
		for _, row := range f.open(t) {
			if row.FixState != finding.WontFix {
				t.Errorf("still reports %q", row.FixState)
			}
		}
	})
}

func TestAnAbsurdlyLongValueDoesNotFailTheScanThatCarriedIt(t *testing.T) {
	// Everything here comes from somebody else's output. A value longer than a
	// column would fail the whole run, and a run that failed is
	// indistinguishable from a product that stopped having problems.
	each(t, func(t *testing.T, f *fixture) {
		long := strings.Repeat("x", 5000)
		f.shipped(t, graph.Snapshot{
			Root: root,
			Components: []graph.Described{{
				Purl: "pkg:deb/debian/sprawling@1.0", Name: "sprawling", Version: long,
				UpstreamName: long, UpstreamVersion: long,
			}},
			Dependencies: []graph.Dependency{{Parent: root, Child: graph.Described{
				Purl: "pkg:deb/debian/sprawling@1.0", Name: "sprawling", Version: long,
				UpstreamName: long, UpstreamVersion: long,
			}}},
		})

		applied, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{{
			Issue: finding.Named{Identifier: "CVE-2026-1" + long, Severity: "high"},
			Component: graph.Described{
				Purl: "pkg:deb/debian/sprawling@1.0", Name: "sprawling", Version: long,
				UpstreamName: long, UpstreamVersion: long,
			},
			FixState: finding.FixedUpstream, FixedIn: long,
		}})
		if err != nil {
			t.Fatalf("a long value failed the scan carrying it: %v", err)
		}
		if applied.Opened != 1 {
			t.Errorf("opened %d findings", applied.Opened)
		}
	})
}

// interned records one vulnerability by name and returns its identifier, for
// the findings a test writes directly rather than through a scan. Unlike
// issue, which looks up what a scan already stored, this puts it there.
func (f *fixture) interned(t *testing.T, name string) int64 {
	t.Helper()
	ids, err := finding.NewVulnerabilities(f.db.DB).Intern(t.Context(),
		[]finding.Named{{Identifier: name, Severity: "high"}})
	if err != nil {
		t.Fatal(err)
	}
	return ids[name]
}

// someoneElse is a second real person holding a role here, for the checks that
// need two — agreeing to somebody else's request, most of all.
func (f *fixture) someoneElse(t *testing.T, roles ...access.Role) access.Subject {
	t.Helper()
	person, err := access.NewStore(f.db.DB).Ensure(t.Context(), "other@example.com", "Other", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return access.NewPerson(person.ID, "other@example.com", false,
		map[int64][]access.Role{f.productID: roles}, 0)
}

// holding returns a subject holding one role on the product this fixture's
// target belongs to.
func (f *fixture) holding(t *testing.T, roles ...access.Role) access.Subject {
	t.Helper()
	grants := map[int64][]access.Role{f.productID: roles}
	// The party they are assignable as, deliberately not their person
	// identifier: the two are different numbers in a real deployment as soon
	// as a team exists, and anything still comparing the wrong one has to
	// fail here rather than pass by coincidence.
	return access.NewPerson(1, "someone", false, grants, 101)
}

func TestTwoRunsAgainstOneTargetDoNotBothOpenTheSameFinding(t *testing.T) {
	// The queue hands different jobs to different workers by design, so two
	// runs against one target overlapping is ordinary rather than exotic.
	// Without a hold on the target, both read the same open findings, both
	// compute the same difference, and both write it — leaving two open rows
	// for one finding, which everything downstream reads as two problems and
	// which two separate triage decisions can then be made about.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		first, second := f.run(t), f.run(t)
		reported := []finding.Reported{found("CVE-2026-1", libnl)}

		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, runID := range []int64{first, second} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = f.store.Apply(context.WithoutCancel(t.Context()), f.target, runID, reported)
			}()
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}

		// Two consumers pull the component in, so two findings — not four, and
		// not two of one and two of the other.
		open := f.open(t)
		if len(open) != 2 {
			t.Fatalf("%d findings are open after two overlapping runs, want 2", len(open))
		}
		seen := map[string]bool{}
		for _, row := range open {
			if seen[row.PlaceIdentity] {
				t.Errorf("two open findings for one place: %s", row.PlaceIdentity)
			}
			seen[row.PlaceIdentity] = true
		}
	})
}

func TestWhatIsStoredAboutAnIssueDoesNotDependOnWhichScanRanLast(t *testing.T) {
	// Reports disagree and arrive in an order nobody controls. Overwriting
	// makes what is stored a fact about scheduling; filling only the gap makes
	// it a fact about which report arrived first. Neither is a fact about the
	// vulnerability.
	//
	// So the worst claim anybody made wins, whichever order it arrived in —
	// and this puts the same two reports through in both orders and asserts
	// they agree.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())

		graded := func(id string, score, likelihood float64) finding.Reported {
			r := found(id, libnl)
			r.Issue.Score, r.Issue.Likelihood = score, likelihood
			return r
		}
		// One issue hears the mild report first, the other the severe one.
		for _, order := range [][]finding.Reported{
			{graded("CVE-2026-A", 4.2, 0.01), graded("CVE-2026-A", 9.1, 0.86)},
			{graded("CVE-2026-B", 9.1, 0.86), graded("CVE-2026-B", 4.2, 0.01)},
		} {
			for _, report := range order {
				if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
					[]finding.Reported{report}); err != nil {
					t.Fatal(err)
				}
			}
		}

		rising, falling := f.issueScore(t, "CVE-2026-A"), f.issueScore(t, "CVE-2026-B")
		if rising != falling {
			t.Errorf("the stored score is %d one way round and %d the other", rising, falling)
		}
		if rising != 910 {
			t.Errorf("kept %d, want 910 — the worst claim anybody made", rising)
		}
	})
}

// issueScore reads what is stored about an issue, in hundredths.
func (f *fixture) issueScore(t *testing.T, name string) int {
	t.Helper()
	var score int
	if err := f.db.DB.NewSelect().
		TableExpr("\"vulnerability\" AS \"v\"").
		ColumnExpr("COALESCE(v.score_centi, 0)").
		Where("v.identifier = ?", name).
		Scan(t.Context(), &score); err != nil {
		t.Fatal(err)
	}
	return score
}

// counter counts the statements a store actually issues.
//
// "It batches" is exactly the kind of claim that stays in a comment after the
// code stops doing it, so the test counts instead of asserting.
type counter struct{ queries atomic.Int64 }

func (c *counter) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	c.queries.Add(1)
	return ctx
}

func (c *counter) AfterQuery(context.Context, *bun.QueryEvent) {}

func TestABumpThatFixedNothingIsNotRecordedAsAFix(t *testing.T) {
	// A version change closes the old row and opens a new one, because
	// component identity carries the version. Nothing asked whether the issue
	// had actually gone, so a bump that resolved nothing was recorded as
	// "fixed by upgrading" — and the same issue then appeared as fixed and as
	// newly present in one release comparison, which is a document that goes
	// to customers.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		// Bumped, and the scanner still reports it: 3.9.0 is not far enough.
		f.shipped(t, movedTo(libnlNew))
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnlNew)}); err != nil {
			t.Fatal(err)
		}

		closed, opened := f.byState(t)
		if len(closed) != 2 || len(opened) != 2 {
			t.Fatalf("closed %d and opened %d, want 2 and 2", len(closed), len(opened))
		}
		for _, row := range closed {
			if row.ClosedBecause != finding.Superseded {
				t.Errorf("a bump that fixed nothing closed as %q", row.ClosedBecause)
			}
		}
		// And what it moved from is on the new row, so saying "3.7.0 → 3.9.0"
		// costs no second query.
		for _, row := range opened {
			if row.ArrivedFrom != "3.7.0" {
				t.Errorf("the new finding says it arrived from %q, want 3.7.0", row.ArrivedFrom)
			}
		}
	})
}

func TestABumpThatDidFixItStillReadsAsAFix(t *testing.T) {
	// The direction that must not break. An upgrade that actually resolved
	// something is the ordinary good case, and calling it superseded would
	// make every real fix disappear from what was fixed.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		// Bumped, and the scanner reports nothing against the new version.
		f.shipped(t, movedTo(libnlNew))
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{}); err != nil {
			t.Fatal(err)
		}

		closed, opened := f.byState(t)
		if len(opened) != 0 {
			t.Fatalf("%d findings are still open after a real fix", len(opened))
		}
		for _, row := range closed {
			if row.ClosedBecause != finding.Upgraded {
				t.Errorf("a bump that resolved it closed as %q", row.ClosedBecause)
			}
			if row.ArrivedFrom != "" {
				t.Errorf("a resolved finding was marked as having arrived from %q", row.ArrivedFrom)
			}
		}
	})
}

// movedTo is the same graph with the library at another version.
func movedTo(library graph.Described) graph.Snapshot {
	return graph.Snapshot{
		Root:       root,
		Components: []graph.Described{swss, teamd, library},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: swss}, {Parent: root, Child: teamd},
			{Parent: swss, Child: library}, {Parent: teamd, Child: library},
		},
	}
}

// byState splits this target's findings into closed and open.
func (f *fixture) byState(t *testing.T) (closed, opened []finding.Finding) {
	t.Helper()
	var rows []finding.Finding
	if err := f.db.NewSelect().Model(&rows).
		Where("target_id = ?", f.target).Order("id").Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ClosedRunID != nil {
			closed = append(closed, row)
			continue
		}
		opened = append(opened, row)
	}
	return closed, opened
}
