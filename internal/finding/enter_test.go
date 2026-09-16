package finding_test

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

func TestAFlawInWhatWeShipIsRecordedAndSurvivesTheNextScan(t *testing.T) {
	// The case Phase 2 exists for: somebody knows about a flaw in their own
	// product before anybody outside does. It has no CVE, no scanner said
	// anything about it, and it still has to be triaged, assigned, decided and
	// reported like everything else.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		who := f.planner(t, access.PrivateTriage)
		rows, identifier, err := f.store.Enter(t.Context(), who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "high",
			Summary: "The management socket accepts a request nobody authenticated.",
		})
		if err != nil {
			t.Fatal(err)
		}
		row := rows[0]
		if err != nil {
			t.Fatalf("recording a flaw: %v", err)
		}
		if !mintedFor(identifier, "SONIC", 2026) {
			t.Errorf("filed under %q, want the product's own name, the year and a number",
				identifier)
		}
		if row.Visibility != access.Private {
			t.Errorf("a flaw nobody has announced was recorded as %q", row.Visibility)
		}
		if row.OpenedRunID != nil {
			t.Errorf("a finding a person recorded claims run %d opened it", *row.OpenedRunID)
		}
		if row.OpenedAt.IsZero() {
			t.Error("a recorded finding does not say when it opened")
		}
		// On the clock like anything else. A finding that expired differently
		// because a person typed it would be a second policy nobody chose.
		if row.DueAt == nil {
			t.Error("a recorded finding carries no deadline")
		}

		// The next scan says nothing about it, and leaves it alone.
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		var open int
		if err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
			Where("kind = ?", finding.Entered).Where("closed_at IS NULL").
			ColumnExpr("COUNT(*)").Scan(t.Context(), &open); err != nil {
			t.Fatal(err)
		}
		if open != 1 {
			t.Errorf("%d recorded findings are open after a scan, want 1", open)
		}

		// The second one is a different identifier, and nothing about
		// it says how many came before it.
		_, next, err := f.store.Enter(t.Context(), who, finding.Entering{
			TargetIDs: []int64{f.target}, Severity: "medium",
			Summary: "The recovery console does not clear the previous session.",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !mintedFor(next, "SONIC", 2026) {
			t.Errorf("the second identifier this year is %q", next)
		}
		if next == identifier {
			t.Errorf("both flaws were filed under %q", next)
		}
		// The property the shape exists for: the number is not the count of
		// what has been recorded, so a reader cannot walk it or read a total
		// off it. Counting from one lands exactly here, which is what makes
		// this the assertion rather than a distance between two draws — those
		// are as likely to be close together as far apart.
		if drawn(t, next) == drawn(t, identifier)+1 {
			t.Errorf("identifiers %q then %q are a counter", identifier, next)
		}
	})
}

func TestRecordingAnUndisclosedFlawNeedsThePrivateRight(t *testing.T) {
	// Somebody who may argue about known issues in shipped components has not
	// been handed the ones nobody has announced. The two rights are separate
	// for exactly this, and recording is the act that creates one.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		entering := finding.Entering{
			TargetIDs: []int64{f.target}, Severity: "high", Summary: "Something we have not announced.",
		}

		if _, _, err := f.store.Enter(t.Context(), f.planner(t, access.PublicTriage),
			entering); err == nil {
			t.Error("somebody holding only public triage recorded an undisclosed flaw")
		}
		if _, _, err := f.store.Enter(t.Context(), f.planner(t, access.PublicRead),
			entering); err == nil {
			t.Error("somebody who may only read recorded a flaw")
		}
		if _, _, err := f.store.Enter(t.Context(), f.planner(t, access.PrivateTriage),
			entering); err != nil {
			t.Errorf("somebody holding private triage could not record one: %v", err)
		}

		// Already public is the other case, and it asks for the ordinary right.
		disclosed := entering
		disclosed.Disclosed = true
		disclosed.Summary = "Something already announced."
		if _, _, err := f.store.Enter(t.Context(), f.planner(t, access.PublicTriage),
			disclosed); err != nil {
			t.Errorf("a disclosed finding needed the private right: %v", err)
		}
	})
}

func TestARecordedFlawSaysWhatItIsAndWhereItIs(t *testing.T) {
	// A row with no summary is a row nobody can act on, and one hung off a
	// component the build does not contain is a claim about somebody else's
	// software.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PrivateTriage)

		// Whitespace passes a minimum length and is not a summary, so this
		// arrives from a request rather than only from inside this process —
		// which is why it is a sentinel rather than a sentence, and why the
		// caller is told to fix it rather than that something went wrong here.
		if _, _, err := f.store.Enter(t.Context(), who, finding.Entering{
			TargetIDs: []int64{f.target}, Severity: "high", Summary: "   ",
		}); !errors.Is(err, finding.ErrNothingSaid) {
			t.Errorf("a finding with nothing said about it was recorded: %v", err)
		}
		if _, _, err := f.store.Enter(t.Context(), who, finding.Entering{
			TargetIDs: []int64{f.target}, Severity: "urgent", Summary: "Something.",
		}); err == nil {
			t.Error("a severity that is not one was accepted")
		}
		_, _, err := f.store.Enter(t.Context(), who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: "not-in-this-build", Severity: "high",
			Summary: "Something.",
		})
		if !errors.Is(err, finding.ErrNoSuchComponent) {
			t.Errorf("a component the build does not hold was accepted: %v", err)
		}

		// Naming nothing puts it on the build itself, which is the honest
		// answer where the flaw is in how the pieces fit together.
		rows, _, err := f.store.Enter(t.Context(), who, finding.Entering{
			TargetIDs: []int64{f.target}, Severity: "high",
			Summary: "The pieces are wired together wrongly.",
		})
		if err != nil {
			t.Fatal(err)
		}
		row := rows[0]
		if err != nil {
			t.Fatal(err)
		}
		var name string
		if err := f.db.DB.NewSelect().TableExpr("\"component\" AS \"c\"").
			ColumnExpr("c.name").Where("c.id = ?", row.ComponentID).
			Scan(t.Context(), &name); err != nil {
			t.Fatal(err)
		}
		if name != root.Name {
			t.Errorf("a flaw naming no component hangs off %q, want the build itself", name)
		}
	})
}

func TestRecordingAgainstANameTheBuildHoldsTwiceIsRefusedRatherThanGuessed(t *testing.T) {
	// A name is not unique within a build, and not rarely. This lookup took
	// the first row a name matched, so a flaw recorded against one of several
	// vendored versions of a library was filed against whichever had been
	// interned first, with nothing saying which — the same guess that was
	// measured wrong when a real image shipped three of one library and two of
	// the three findings answered about a version nobody asked about.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{swss, libnl, libnlNew},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swss},
				{Parent: swss, Child: libnl},
				{Parent: swss, Child: libnlNew},
			},
		})
		who := f.planner(t, access.PrivateTriage)
		const said = "The parser accepts a message it should refuse."

		_, _, err := f.store.Enter(t.Context(), who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: libnl.Name, Severity: "high", Summary: said,
		})
		var several *graph.Ambiguous
		if !errors.As(err, &several) {
			t.Fatalf("a name held at two versions resolved to one of them: %v", err)
		}
		// The versions, not only the fact. "Say which one" is not answerable
		// by somebody who does not know what the choices are.
		if got := several.Versions(); len(got) != 2 {
			t.Errorf("the refusal offers %v, want both versions", got)
		}

		// Naming the version settles it, and it settles it on the one named
		// rather than on whichever came first.
		rows, _, err := f.store.Enter(t.Context(), who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: libnl.Name, Version: libnlNew.Version,
			Severity: "high", Summary: said,
		})
		if err != nil {
			t.Fatal(err)
		}
		row := rows[0]
		if err != nil {
			t.Fatalf("naming the version: %v", err)
		}
		var version string
		if err := f.db.DB.NewSelect().TableExpr("\"component\" AS \"c\"").
			ColumnExpr("c.version").Where("c.id = ?", row.ComponentID).
			Scan(t.Context(), &version); err != nil {
			t.Fatal(err)
		}
		if version != libnlNew.Version {
			t.Errorf("recorded against %s, want the version that was named", version)
		}
	})
}

func TestOneFlawIsRecordedAgainstEveryBuildThatShipsIt(t *testing.T) {
	// The same code goes out on several lines and as several variants at once,
	// so a flaw in it is one issue in several builds. One identifier, one row
	// per build — which is the shape a scanner's findings already take, so
	// everything downstream treats it the same way.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		other := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, other, through(libnl))

		rows, identifier, err := f.store.Enter(ctx, f.planner(t, access.PrivateTriage),
			finding.Entering{
				TargetIDs: []int64{f.target, other},
				Component: libnl.Name, Severity: "high",
				Summary: "The parser accepts a message it should refuse.",
			})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatalf("recorded %d findings, want one per build", len(rows))
		}
		// One issue, however many builds ship it.
		if rows[0].VulnerabilityID != rows[1].VulnerabilityID {
			t.Error("the two builds got two issues rather than one")
		}
		if identifier == "" {
			t.Error("nothing was minted to file it under")
		}
		// And it reads back as one piece of work across the product, which is
		// what the findings list groups by.
		groups, total, err := f.store.Groups(ctx, f.holding(t, access.PrivateRead),
			f.wholeProduct(), 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, group := range groups {
			if group.Vulnerability == identifier {
				found = true
				if group.Places != 2 {
					t.Errorf("it reads as %d places, want one in each build", group.Places)
				}
				if group.Builds != 2 {
					t.Errorf("it says %d builds hold it, want 2", group.Builds)
				}
			}
		}
		if !found {
			t.Errorf("what was recorded is not in the product's list of %d", total)
		}
	})
}

func TestAFlawIsNotRecordedAgainstBuildsThatDoNotHoldIt(t *testing.T) {
	// A name one build holds and another does not is a question about which
	// builds are affected. Refused, naming the build, rather than recorded
	// against some of them and silently not the rest.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		other := f.anotherVariant(t, "mellanox")
		// The second build ships something else entirely.
		f.shippedTo(t, other, through(teamd))

		if _, _, err := f.store.Enter(ctx, f.planner(t, access.PrivateTriage),
			finding.Entering{
				TargetIDs: []int64{f.target, other},
				Component: libnl.Name, Severity: "high",
				Summary: "The parser accepts a message it should refuse.",
			}); err == nil {
			t.Error("it was recorded against a build that does not hold the component")
		}
	})
}

func TestRecordingNeedsAtLeastOneBuild(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, through(libnl))
		if _, _, err := f.store.Enter(t.Context(), f.planner(t, access.PrivateTriage),
			finding.Entering{Severity: "high", Summary: "Something is wrong."}); err == nil {
			t.Error("a flaw was recorded against no build at all")
		}
	})
}

func TestWhichBuildsAFlawAffectsIsCorrectedAsResearchGoes(t *testing.T) {
	// The first belief is written down before the analysis is finished — that
	// is the point of recording one early — so the set is editable. Widening
	// opens findings; narrowing closes them as never having been affected.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		other := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, other, through(libnl))
		who := f.planner(t, access.PrivateTriage)

		// Recorded against one build to begin with.
		rows, identifier, err := f.store.Enter(ctx, who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: libnl.Name, Severity: "high",
			Summary: "The parser accepts a message it should refuse.",
		})
		if err != nil {
			t.Fatal(err)
		}
		issue := rows[0].VulnerabilityID

		// Research says the other variant ships it too.
		changed, err := f.store.Affects(ctx, who, f.productID, issue,
			[]int64{f.target, other}, "")
		if err != nil {
			t.Fatalf("widening: %v", err)
		}
		if changed.Added != 1 || changed.Closed != 0 {
			t.Errorf("widening added %d and closed %d, want 1 and 0", changed.Added, changed.Closed)
		}

		// And then that the first one was never affected after all.
		changed, err = f.store.Affects(ctx, who, f.productID, issue,
			[]int64{other}, "the management socket is not built on broadcom")
		if err != nil {
			t.Fatalf("narrowing: %v", err)
		}
		if changed.Added != 0 || changed.Closed != 1 {
			t.Errorf("narrowing added %d and closed %d, want 0 and 1", changed.Added, changed.Closed)
		}

		// The record of it stays, saying what happened and why.
		var closed finding.Finding
		if err := f.db.DB.NewSelect().Model(&closed).
			Where("vulnerability_id = ?", issue).
			Where("target_id = ?", f.target).
			Where("closed_at IS NOT NULL").Scan(ctx); err != nil {
			t.Fatalf("the record went with the build: %v", err)
		}
		if closed.ClosedBecause != finding.Invalid {
			t.Errorf("it was closed as %q, want invalid", closed.ClosedBecause)
		}
		if strings.TrimSpace(closed.ClosedNote) == "" {
			t.Error("a build was taken out with no reason on record")
		}
		_ = identifier
	})
}

func TestTakingABuildOutNeedsAReasonAndAddingOneDoesNot(t *testing.T) {
	// Removing a build from an advisory's affected list with no explanation is
	// the state a history exists to prevent. Adding one explains itself.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		other := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, other, through(libnl))
		who := f.planner(t, access.PrivateTriage)

		rows, _, err := f.store.Enter(ctx, who, finding.Entering{
			TargetIDs: []int64{f.target, other}, Component: libnl.Name, Severity: "high",
			Summary: "The parser accepts a message it should refuse.",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Affects(ctx, who, f.productID, rows[0].VulnerabilityID,
			[]int64{other}, "  "); err == nil {
			t.Error("a build was taken out with no reason")
		}
	})
}

func TestWhichBuildsAScannedIssueIsInIsNotOursToSet(t *testing.T) {
	// That is what the scans found. Setting it here would overwrite what was
	// found with what somebody thinks.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Affects(ctx, f.planner(t, access.PrivateTriage), f.productID,
			f.issueID(t, "CVE-2026-1"), []int64{f.target}, "because"); err == nil {
			t.Error("a scanned issue's builds were set by hand")
		}
	})
}

func TestABuildTakenBackOutIsNeitherAFixNorANote(t *testing.T) {
	// It did not get fixed and it did not move: it leaves the affected list
	// rather than moving within it, so a release note mentioning it would be
	// describing a mistake of ours as news about somebody's software.
	notes := finding.Notes(about("2.4.0"), &finding.Comparison{
		Fixed: []finding.Changed{
			{Vulnerability: "SONIC-2026-0001", Component: "libnl", Because: finding.Invalid},
			{Vulnerability: "CVE-2026-2", Component: "zlib", Because: finding.Upgraded},
		},
	})
	if strings.Contains(notes, "SONIC-2026-0001") {
		t.Errorf("a record taken back is in the release note:\n%s", notes)
	}
	if !strings.Contains(notes, "CVE-2026-2") {
		t.Errorf("a real fix went missing:\n%s", notes)
	}
}

// mintedFor reports whether an identifier is one this deployment issued for a
// product in a year: the name, the year, and a number.
func mintedFor(identifier, product string, year int) bool {
	prefix := fmt.Sprintf("%s-%d-", product, year)
	if !strings.HasPrefix(identifier, prefix) {
		return false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(identifier, prefix))
	return err == nil && n > 0
}

// drawn is the number in one of those, for the checks about how it was chosen.
func drawn(t *testing.T, identifier string) int {
	t.Helper()
	at := strings.LastIndex(identifier, "-")
	if at < 0 {
		t.Fatalf("%q carries no number", identifier)
	}
	n, err := strconv.Atoi(identifier[at+1:])
	if err != nil {
		t.Fatalf("the number in %q does not parse: %v", identifier, err)
	}
	return n
}

// A report is readable in the product it was made against and nowhere else.
//
// An issue's identity spans its aliases, so the moment a CVE is recorded for
// a flaw entered here, the same issue is open in every other product a scan
// reports it in. The report itself carries no product and was read by
// vulnerability alone, so a triager holding rights in one of those products —
// and nothing at all here — read the researcher's name, address and the day
// they wrote, about a flaw in a product they cannot see. They could
// acknowledge it too, clearing the unanswered-report condition out of this
// product's queue.
func TestAFlawReportIsReadableOnlyWhereItWasMade(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())

		who := f.planner(t, access.PrivateTriage)
		rows, _, err := f.store.Enter(ctx, who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "high",
			Summary: "The management socket accepts a request nobody authenticated.",
			Told: finding.Told{
				ReportedBy: "A. Researcher", Contact: "a@example.org",
				Credit: "anonymous",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		issue := rows[0].VulnerabilityID

		// Whoever recorded it reads it.
		told, err := f.store.ReportFor(ctx, who, issue)
		if err != nil {
			t.Fatal(err)
		}
		if told == nil || told.Contact != "a@example.org" {
			t.Fatalf("the product it was reported against cannot read it: %+v", told)
		}

		// Somebody holding private triage on another product entirely does
		// not, however the issue reached them.
		stranger := access.NewPerson(2, "stranger", false,
			map[int64][]access.Role{f.productID + 999: {access.PrivateTriage}}, 0)
		hidden, err := f.store.ReportFor(ctx, stranger, issue)
		if err != nil {
			t.Fatal(err)
		}
		if hidden != nil {
			t.Errorf("a reporter's address was readable from another product: %+v", hidden)
		}
		// And they cannot answer the reporter either.
		if err := f.store.Acknowledge(ctx, stranger, issue); err != nil {
			t.Fatal(err)
		}
		again, err := f.store.ReportFor(ctx, who, issue)
		if err != nil {
			t.Fatal(err)
		}
		if again.AcknowledgedAt != nil {
			t.Error("somebody who cannot read the report cleared its condition")
		}
	})
}

func TestAFlawRecordedByHandIsKeyedWhereAScanWouldKeyIt(t *testing.T) {
	// A decision is keyed on the place. The entry path recorded every finding
	// as sitting directly under the product, whatever the graph said, so a
	// flaw recorded by hand against a nested component and the same flaw
	// found there by a scan were two places and two decisions — one flaw
	// triaged twice, and triaging either did nothing for the other.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// libnl sits under two consumers, which is what a place is for.
		f.shipped(t, twoConsumers())

		rows, _, err := f.store.Enter(ctx, f.planner(t, access.PrivateTriage),
			finding.Entering{
				TargetIDs: []int64{f.target}, Component: libnl.Name, Severity: "high",
				Summary: "The parser accepts a message it should refuse.",
			})
		if err != nil {
			t.Fatal(err)
		}
		// One finding per place, as a scan of the same component opens.
		if len(rows) != 2 {
			t.Fatalf("recorded %d findings, want one per place the component sits in", len(rows))
		}
		recorded := map[string]bool{}
		for _, row := range rows {
			recorded[row.PlaceIdentity] = true
		}

		// What a scan of the same build writes for the same component.
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		var scanned []string
		if err := f.db.DB.NewSelect().TableExpr(`finding AS "f"`).
			ColumnExpr("f.place_identity").
			Where("f.target_id = ?", f.target).
			Where("f.kind = ?", finding.Vulnerable).
			Scan(ctx, &scanned); err != nil {
			t.Fatal(err)
		}
		if len(scanned) != 2 {
			t.Fatalf("the scan opened %d findings, want one per place", len(scanned))
		}
		for _, place := range scanned {
			if !recorded[place] {
				t.Errorf("a scan keys a place the hand-recorded flaw does not: %s", place)
			}
		}
	})
}

func TestAFlawRecordedAgainstTheBuildIsOnePlaceInEveryVariant(t *testing.T) {
	// The product's name differs per variant, so a place keyed on it is a
	// different place in each of them: one flaw across three variants was
	// three places and three decisions. The build's root has no name of its
	// own, which is what the scan path already does with a root parent.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		other := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, other, graph.Snapshot{
			// A variant of its own, named as it ships, which is the whole
			// reason the root is not part of the key.
			Root:         at("sonic-mellanox", "1.0"),
			Components:   []graph.Described{swss, libnl},
			Dependencies: []graph.Dependency{{Parent: at("sonic-mellanox", "1.0"), Child: swss}, {Parent: swss, Child: libnl}},
		})

		rows, _, err := f.store.Enter(ctx, f.planner(t, access.PrivateTriage),
			finding.Entering{
				TargetIDs: []int64{f.target, other}, Severity: "high",
				Summary: "The pieces are assembled in a way that defeats the sandbox.",
			})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatalf("recorded %d findings, want one per build", len(rows))
		}
		if rows[0].PlaceIdentity != rows[1].PlaceIdentity {
			t.Errorf("two variants of one flaw sit at two places: %s and %s",
				rows[0].PlaceIdentity, rows[1].PlaceIdentity)
		}
	})
}
