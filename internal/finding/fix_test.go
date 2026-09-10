package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// planner is somebody who exists, holding triage on this fixture's product.
//
// Recorded rather than invented, because a declaration names who made it and
// the schema says that has to be a person — a plan attributed to nobody is a
// plan nobody can be asked about.
func (f *fixture) planner(t *testing.T, roles ...access.Role) access.Subject {
	t.Helper()
	person, err := access.NewStore(f.db.DB).Ensure(t.Context(), "them@example.com", "Them", false)
	if err != nil {
		t.Fatal(err)
	}
	return access.NewPerson(person.ID, "them@example.com", false,
		map[int64][]access.Role{f.productID: roles}, 0)
}

// fixing declares a graph and one issue against a build and returns the issue
// and component the fix is planned for.
func (f *fixture) fixing(t *testing.T, target int64) (issue, component int64) {
	t.Helper()
	f.shippedTo(t, target, twoConsumers())
	if _, err := f.store.Apply(t.Context(), target, f.runOn(t, target),
		[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
		t.Fatal(err)
	}
	var row finding.Finding
	if err := f.db.DB.NewSelect().Model(&row).
		Where("target_id = ?", target).Where("closed_at IS NULL").
		Limit(1).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return row.VulnerabilityID, row.ComponentID
}

// stateOf finds one build in the list, by the release it belongs to.
func stateOf(t *testing.T, intents []finding.Intent, stream string) finding.Intent {
	t.Helper()
	for _, intent := range intents {
		if intent.Stream == stream {
			return intent
		}
	}
	t.Fatalf("no build of %q in the list of %d", stream, len(intents))
	return finding.Intent{}
}

func TestAFixIsResolvedByScansRatherThanByAnybodySayingSo(t *testing.T) {
	// Nothing records "done". An issue is fixed in a build when the build
	// stops holding it, which the findings already say — a second record
	// of the same fact is one somebody has to keep true, and the way that
	// fails is the tool reporting a fix that shipped in nobody's release.
	each(t, func(t *testing.T, f *fixture) {
		second := f.anotherBuild(t, "2.4")
		issue, component := f.fixing(t, f.target)
		f.shippedTo(t, second, twoConsumers())
		if _, err := f.store.Apply(t.Context(), second, f.runOn(t, second),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		who := f.planner(t, access.PublicTriage)
		if _, err := f.store.FixIn(t.Context(), who, f.productID, issue, component,
			[]int64{f.target, second}, nil); err != nil {
			t.Fatalf("declaring the fix: %v", err)
		}

		intents, err := f.store.FixingIn(t.Context(), who, f.productID, issue, component)
		if err != nil {
			t.Fatal(err)
		}
		if len(intents) != 2 {
			t.Fatalf("%d builds in the plan, want 2", len(intents))
		}
		for _, intent := range intents {
			if !intent.Declared || intent.Clear() || intent.Missed() {
				t.Errorf("%s reads as %+v before anything shipped", intent.Stream, intent)
			}
		}

		// The next scan of one build no longer reports it. Nobody said
		// anything; the scan did.
		if _, err := f.store.Apply(t.Context(), second, f.runOn(t, second),
			nil); err != nil {
			t.Fatal(err)
		}
		intents, err = f.store.FixingIn(t.Context(), who, f.productID, issue, component)
		if err != nil {
			t.Fatal(err)
		}
		if !stateOf(t, intents, "2.4").Clear() {
			t.Errorf("a build that stopped holding the issue does not read as clear")
		}
		if stateOf(t, intents, "master").Clear() {
			t.Errorf("a build that still holds the issue reads as clear")
		}
	})
}

func TestAChosenBuildScannedSinceAndStillHoldingItIsAMissedTarget(t *testing.T) {
	// The scan is independent evidence against the claim — and only a scan
	// that ran *after* the claim is evidence at all. Without the "since",
	// every declaration made between two nights would be flagged the
	// moment it was written, which is most of them.
	each(t, func(t *testing.T, f *fixture) {
		issue, component := f.fixing(t, f.target)
		who := f.planner(t, access.PublicTriage)
		if _, err := f.store.FixIn(t.Context(), who, f.productID, issue, component,
			[]int64{f.target}, nil); err != nil {
			t.Fatal(err)
		}

		intents, err := f.store.FixingIn(t.Context(), who, f.productID, issue, component)
		if err != nil {
			t.Fatal(err)
		}
		if stateOf(t, intents, "master").Missed() {
			t.Fatal("a declaration nothing has looked at yet is already a missed target")
		}

		// A scan runs, finishes, and the issue is still there.
		run := f.runOn(t, f.target)
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Finish(t.Context(), run, "0.100.0", "2026-09-03", "", nil); err != nil {
			t.Fatal(err)
		}

		intents, err = f.store.FixingIn(t.Context(), who, f.productID, issue, component)
		if err != nil {
			t.Fatal(err)
		}
		if !stateOf(t, intents, "master").Missed() {
			t.Errorf("a fix declared and not delivered, with a scan since, is not flagged: %+v",
				stateOf(t, intents, "master"))
		}
	})
}

func TestABuildNobodyChoseIsUndecidedRatherThanOutstanding(t *testing.T) {
	// Nobody is made to answer the same question for six releases, so
	// silence is allowed — but "open because we chose not to fix it here"
	// and "open because nobody thought about it" are different answers,
	// and one list holding both loses the second.
	each(t, func(t *testing.T, f *fixture) {
		second := f.anotherBuild(t, "2.3")
		issue, component := f.fixing(t, f.target)
		f.shippedTo(t, second, twoConsumers())
		if _, err := f.store.Apply(t.Context(), second, f.runOn(t, second),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		who := f.planner(t, access.PublicTriage)
		if _, err := f.store.FixIn(t.Context(), who, f.productID, issue, component,
			[]int64{f.target}, nil); err != nil {
			t.Fatal(err)
		}
		intents, err := f.store.FixingIn(t.Context(), who, f.productID, issue, component)
		if err != nil {
			t.Fatal(err)
		}
		untouched := stateOf(t, intents, "2.3")
		if !untouched.Undecided() {
			t.Errorf("a build nobody chose reads as %+v, not as undecided", untouched)
		}
		if untouched.Declared || untouched.Missed() {
			t.Errorf("a build nobody chose is counted as part of the plan: %+v", untouched)
		}
	})
}

func TestAReleaseOutOfSupportCarriesNoTarget(t *testing.T) {
	// Nothing on it will be fixed, so counting it as outstanding fills the
	// figure permanently and counting it as delivered claims a fix nobody
	// shipped. It is neither, and it is still listed, so somebody who
	// chose it before the date can see what became of it.
	each(t, func(t *testing.T, f *fixture) {
		issue, component := f.fixing(t, f.target)
		who := f.planner(t, access.PublicTriage)
		if _, err := f.store.FixIn(t.Context(), who, f.productID, issue, component,
			[]int64{f.target}, nil); err != nil {
			t.Fatal(err)
		}

		// It goes out of support after it was chosen, which is the case that
		// can actually happen: choosing one already retired is refused.
		cat := catalog.NewStore(f.db.DB)
		stream, err := cat.StreamByName(t.Context(), f.productID, "master")
		if err != nil {
			t.Fatal(err)
		}
		gone := time.Now().UTC().Add(-48 * time.Hour)
		if err := cat.SetStreamEndOfLife(t.Context(), stream.ID, &gone); err != nil {
			t.Fatal(err)
		}

		intents, err := f.store.FixingIn(t.Context(), who, f.productID, issue, component)
		if err != nil {
			t.Fatal(err)
		}
		retired := stateOf(t, intents, "master")
		if !retired.PastEndOfLife {
			t.Fatalf("a release out of support does not say so: %+v", retired)
		}
		if retired.Counts() || retired.Missed() || retired.Clear() || retired.Undecided() {
			t.Errorf("a release out of support is still being counted: %+v", retired)
		}

		// And it cannot be chosen now. Refused rather than dropped: dropping
		// it leaves somebody believing a release is covered.
		if _, err := f.store.FixIn(t.Context(), who, f.productID, issue, component,
			[]int64{f.target}, nil); err == nil {
			t.Errorf("a release out of support was accepted as somewhere to fix this")
		}
	})
}

func TestSayingWhatIsFixedIsTriageWork(t *testing.T) {
	// Being able to see a finding is not being able to plan the work on it.
	each(t, func(t *testing.T, f *fixture) {
		issue, component := f.fixing(t, f.target)
		reader := f.planner(t, access.PublicRead)
		if _, err := f.store.FixIn(t.Context(), reader, f.productID, issue, component,
			[]int64{f.target}, nil); err == nil {
			t.Errorf("somebody who may only read declared what will be fixed")
		}
		// And reading the plan is reading.
		if _, err := f.store.FixingIn(t.Context(), reader, f.productID, issue, component); err != nil {
			t.Errorf("somebody who may read the product cannot read the plan: %v", err)
		}
	})
}

func TestDeclaringTheSameBuildAgainKeepsWhenItWasFirstSaid(t *testing.T) {
	// When somebody committed to a release is a fact about a moment. Adding a
	// second release to the plan must not move the first one's date to today,
	// or the record of what was promised when is rewritten by an edit that
	// said nothing about it.
	each(t, func(t *testing.T, f *fixture) {
		second := f.anotherBuild(t, "2.2")
		issue, component := f.fixing(t, f.target)
		f.shippedTo(t, second, twoConsumers())
		if _, err := f.store.Apply(t.Context(), second, f.runOn(t, second),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		who := f.planner(t, access.PublicTriage)
		declared, err := f.store.FixIn(t.Context(), who, f.productID, issue, component,
			[]int64{f.target}, nil)
		if err != nil || declared != 1 {
			t.Fatalf("declaring one build reported %d (%v)", declared, err)
		}
		first, err := f.store.FixingIn(t.Context(), who, f.productID, issue, component)
		if err != nil {
			t.Fatal(err)
		}
		was := stateOf(t, first, "master").DeclaredAt

		declared, err = f.store.FixIn(t.Context(), who, f.productID, issue, component,
			[]int64{f.target, second}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if declared != 1 {
			t.Errorf("adding one build to the plan reported %d newly chosen, want 1", declared)
		}
		after, err := f.store.FixingIn(t.Context(), who, f.productID, issue, component)
		if err != nil {
			t.Fatal(err)
		}
		now := stateOf(t, after, "master").DeclaredAt
		if was == nil || now == nil || !now.Equal(*was) {
			t.Errorf("the first build's date moved from %v to %v when a second was added", was, now)
		}

		// And an empty set withdraws the plan.
		if _, err := f.store.FixIn(t.Context(), who, f.productID, issue, component, nil, nil); err != nil {
			t.Fatal(err)
		}
		withdrawn, err := f.store.FixingIn(t.Context(), who, f.productID, issue, component)
		if err != nil {
			t.Fatal(err)
		}
		for _, intent := range withdrawn {
			if intent.Declared {
				t.Errorf("%s is still declared after the plan was withdrawn", intent.Stream)
			}
		}
	})
}

func TestAPlanCannotReachIntoAnotherProduct(t *testing.T) {
	// A plan belongs to one product's work. Naming another product's build is
	// either a mistake worth reporting or a write across a boundary, and both
	// want the same answer — the whole set is refused rather than narrowed,
	// because a partly-applied plan leaves somebody believing a release is
	// covered.
	each(t, func(t *testing.T, f *fixture) {
		theirs := f.inAnotherProduct(t, "edge-router")
		issue, component := f.fixing(t, f.target)
		who := f.planner(t, access.PublicTriage)

		if _, err := f.store.FixIn(t.Context(), who, f.productID, issue, component,
			[]int64{theirs}, nil); err == nil {
			t.Errorf("another product's build was accepted into this product's plan")
		}
		// And the legitimate half of the same request does not slip through.
		if _, err := f.store.FixIn(t.Context(), who, f.productID, issue, component,
			[]int64{f.target, theirs}, nil); err == nil {
			t.Errorf("a plan naming one build here and one elsewhere was accepted")
		}
		intents, err := f.store.FixingIn(t.Context(), who, f.productID, issue, component)
		if err != nil {
			t.Fatal(err)
		}
		for _, intent := range intents {
			if intent.Declared {
				t.Errorf("a refused plan declared %s anyway", intent.Stream)
			}
		}
	})
}

func TestABuildTheIssueHasLeftSaysSoRatherThanVanishing(t *testing.T) {
	// "gone from main, still present in 2.4 and 2.3", derived only from
	// scans.
	//
	// Listing only where the issue still is leaves a build that was fixed
	// missing from the list, which reads identically to a build that never
	// shipped the component at all. Those are opposite answers, and the
	// first is the one somebody came to find out.
	each(t, func(t *testing.T, f *fixture) {
		old := f.anotherBuild(t, "2.3")
		issue, component := f.fixing(t, f.target)
		f.shippedTo(t, old, twoConsumers())
		if _, err := f.store.Apply(t.Context(), old, f.runOn(t, old),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		// The newer build stops reporting it. Nobody planned anything.
		if _, err := f.store.Apply(t.Context(), f.target, f.runOn(t, f.target), nil); err != nil {
			t.Fatal(err)
		}

		who := f.planner(t, access.PublicTriage)
		intents, err := f.store.FixingIn(t.Context(), who, f.productID, issue, component)
		if err != nil {
			t.Fatal(err)
		}
		if len(intents) != 2 {
			t.Fatalf("%d builds in the answer, want both the one it left and the one it is in",
				len(intents))
		}
		left := stateOf(t, intents, "master")
		if !left.Gone() {
			t.Errorf("the build the issue left reads as %+v, not as gone", left)
		}
		if left.Places != 0 || !left.WasHere {
			t.Errorf("the build the issue left reports places=%d wasHere=%v",
				left.Places, left.WasHere)
		}
		still := stateOf(t, intents, "2.3")
		if !still.Undecided() || still.Gone() {
			t.Errorf("the build still holding it reads as %+v", still)
		}

		// And it counts as nobody's plan: gone is what the scans say, not
		// something anybody claimed.
		if left.Declared || left.Clear() {
			t.Errorf("a build nobody chose is being reported as part of a plan: %+v", left)
		}
	})
}
