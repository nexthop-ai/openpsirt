package advisory_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
)

// issuer is a deployment that has been told who it publishes as.
var issuer = publisher.Named{Name: "Example Networks", Namespace: "https://example.test"}

type fixture struct {
	db      *database.DB
	store   *advisory.Store
	finds   *finding.Store
	graph   *graph.Store
	scans   *ingest.Store
	product int64
	// master is the branch and v2.4.1 the tagged release, so an advisory has
	// more than one release to name. With one, the list cannot be told from
	// "whichever build was asked from".
	master, tagged int64
	// A second tag, for the claims that are about more than one release at
	// once. With one fixed release, "all of them, in the order the tree names
	// them" passes just as well as "the first" or "the last".
	older int64
	who   access.Subject
	seq   int
	built time.Time
}

var (
	root    = graph.Described{Purl: "pkg:deb/debian/sonic@1.0", Name: "sonic", Version: "1.0"}
	carrier = graph.Described{
		Purl: "pkg:deb/debian/libswsscommon@1.0.0", Name: "libswsscommon", Version: "1.0.0",
	}
)

func each(t *testing.T, fn func(t *testing.T, f *fixture)) {
	t.Helper()
	fixtures.Each(t, func(t *testing.T, w *fixtures.World) {
		// The branch is the seeded target; the tag needs one of its own,
		// because what an advisory says about a release that never moves is
		// half of what this store answers.
		tagged := w.TargetFor(w.Tag, w.Customer)
		earlier := w.DeclareStream(w.Product, "v2.3.9", catalog.Tag, &w.Branch.ID)
		older := w.TargetFor(earlier, w.Customer)
		f := &fixture{
			db: w.DB, store: advisory.NewStore(w.DB.DB), finds: finding.NewStore(w.DB.DB),
			graph: graph.NewStore(w.DB.DB), scans: ingest.NewStore(w.DB.DB),
			product: w.Product.ID, master: w.Target.ID, tagged: tagged.ID,
			older: older.ID,
			who: access.NewPerson(w.Person.ID, w.Person.Identity, false, map[int64][]access.Role{
				w.Product.ID: {access.PublicRead, access.PrivateRead, access.PrivateTriage},
			}, 0),
			built: time.Now().UTC().Add(-72 * time.Hour),
		}
		f.shipped(t, f.master)
		f.shipped(t, f.tagged)
		f.shipped(t, f.older)
		fn(t, f)
	})
}

// shipped stores a graph against one build, as an inventory naming its own
// root does.
func (f *fixture) shipped(t *testing.T, target int64) {
	t.Helper()
	f.shippedAs(t, target, root.Purl)
}

// shippedAs is the same, with what the document declared itself to be — empty
// for a document that named no component of its own.
func (f *fixture) shippedAs(t *testing.T, target int64, declared string) {
	t.Helper()
	ctx := t.Context()
	f.seq++
	f.built = f.built.Add(time.Hour)
	scan, outcome, err := f.scans.Record(ctx, ingest.Arriving{
		TargetID: target, ContentHash: fmt.Sprintf("hash-%d", f.seq), BuiltAt: f.built,
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if _, err := f.graph.Apply(ctx, target, scan.ID, graph.Snapshot{
		Root: root, Components: []graph.Described{carrier},
		Dependencies: []graph.Dependency{{Parent: root, Child: carrier}},
	}); err != nil {
		t.Fatalf("apply graph: %v", err)
	}
	// The document's own subject, which ingest records beside what
	// the inventory was made of.
	if err := f.scans.Made(ctx, scan.ID, 1, 1, declared); err != nil {
		t.Fatalf("record what the document declared: %v", err)
	}
}

// recorded enters a flaw against one build and returns what it was filed as.
func (f *fixture) recorded(t *testing.T, target int64) string {
	t.Helper()
	return f.recordedAs(t, target)
}

// recordedAs is the same, classified as these kinds of flaw, the root cause
// first.
func (f *fixture) recordedAs(t *testing.T, target int64, weaknesses ...string) string {
	t.Helper()
	_, identifier, err := f.finds.Enter(t.Context(), f.who, finding.Entering{
		TargetIDs: []int64{target}, Component: carrier.Name, Severity: "high",
		Summary:    "The management socket answers before anyone authenticated.",
		Weaknesses: weaknesses,
	})
	if err != nil {
		t.Fatalf("recording a flaw: %v", err)
	}
	return identifier
}

func TestAnAdvisoryNamesEveryReleaseHoldingTheFlawAndNamesEachInTheTree(t *testing.T) {
	// A reader of an advisory is asking "am I affected", and the answer is
	// a release rather than a dependency path. Two releases, because a
	// document with one cannot show that the list follows the findings
	// rather than the build somebody happened to ask from.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		identifier := f.recorded(t, f.master)
		// The same issue in the tagged release. Recording again would mint a
		// second identifier, so the row is filed against the issue that
		// already exists — which is what one flaw in two releases is.
		f.alsoIn(t, identifier, f.tagged)

		doc, err := f.store.For(ctx, f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		if len(doc.Vulnerabilities) != 1 {
			t.Fatalf("the document carries %d vulnerabilities", len(doc.Vulnerabilities))
		}
		affected := doc.Vulnerabilities[0].Status.KnownAffected
		// Named by stream and variant together, never by one of them: the same
		// branch built two ways is two builds, and naming only the branch
		// would claim something about hardware nobody built for. In name
		// order, which is what a reader of the document sees.
		want := []string{
			"sonic:" + fixtures.BranchName + ":broadcom",
			"sonic:" + fixtures.TagName + ":broadcom",
		}
		slices.Sort(want)
		if len(affected) != len(want) {
			t.Fatalf("affected: %v, want %v", affected, want)
		}
		for i := range want {
			if affected[i] != want[i] {
				t.Errorf("affected[%d] is %q, want %q", i, affected[i], want[i])
			}
		}

		// Every release a status names is named in the tree, or the document
		// makes a statement about something it never introduced.
		named := map[string]bool{}
		for _, vendor := range doc.ProductTree.Branches {
			for _, product := range vendor.Branches {
				for _, release := range product.Branches {
					named[release.Product.ID] = true
				}
			}
		}
		for _, id := range affected {
			if !named[id] {
				t.Errorf("the product tree does not name %q", id)
			}
		}
	})
}

func TestAReleaseThatFixedTheFlawIsNamedAsFixedRatherThanLeftOut(t *testing.T) {
	// The answer a reader of an advisory is hoping for. A release that held
	// the flaw and no longer does is the one to upgrade to, and leaving it out
	// of the document reads identically to a release that never shipped the
	// thing at all.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		identifier := f.recorded(t, f.master)
		f.alsoIn(t, identifier, f.tagged)

		issueID, err := finding.NewVulnerabilities(f.db.DB).ByName(ctx, identifier)
		if err != nil {
			t.Fatal(err)
		}
		done, err := f.finds.Resolve(ctx, f.who, f.tagged, issueID,
			"Shipped in v2.4.1, which carries the patch.")
		if err != nil {
			t.Fatalf("closing it in the tagged release: %v", err)
		}
		if done.Closed != 1 {
			t.Errorf("closed %d locations, want the one the release holds", done.Closed)
		}

		doc, err := f.store.For(ctx, f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		status := doc.Vulnerabilities[0].Status
		if len(status.KnownAffected) != 1 || status.KnownAffected[0] != "sonic:master:broadcom" {
			t.Errorf("affected: %v, want the branch alone", status.KnownAffected)
		}
		if len(status.Fixed) != 1 || status.Fixed[0] != "sonic:"+fixtures.TagName+":broadcom" {
			t.Errorf("fixed: %v, want the release it left", status.Fixed)
		}
	})
}

func TestAnAdvisoryIsRefusedWhereNobodyHasSaidWhoPublishesIt(t *testing.T) {
	// A CSAF document requires a publisher, so one generated without a
	// configured identity would fail validation wherever somebody took it
	// next — after they had already sent it. Refused here instead, saying
	// which part is missing.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		_, err := f.store.For(t.Context(), f.who, publisher.Named{}, "sonic", identifier)
		if !errors.Is(err, advisory.ErrNoPublisher) {
			t.Errorf("an unconfigured deployment generated a document: %v", err)
		}
		if !strings.Contains(err.Error(), "PUBLISHER_NAME") ||
			!strings.Contains(err.Error(), "PUBLISHER_NAMESPACE") {
			t.Errorf("the refusal does not say what to set: %v", err)
		}
		// A name with no namespace is the same gap: both fields are required.
		// The message names the half that is missing, and only that half —
		// whoever reads it cannot fix it, and the operator who can is reading
		// it relayed rather than sitting at the process.
		_, err = f.store.For(t.Context(), f.who,
			publisher.Named{Name: "Example Networks"}, "sonic", identifier)
		if !errors.Is(err, advisory.ErrNoPublisher) {
			t.Errorf("a publisher with no namespace was accepted: %v", err)
		}
		if !strings.Contains(err.Error(), "PUBLISHER_NAMESPACE") ||
			strings.Contains(err.Error(), "PUBLISHER_NAME ") {
			t.Errorf("the refusal does not name the missing half: %v", err)
		}
	})
}

// alsoIn files the same issue against a second build.
//
// Recording it again would mint a second identifier, which is a second flaw.
// One flaw present in two releases is one issue with a finding in each, and
// that is what an advisory aggregates.
func (f *fixture) alsoIn(t *testing.T, identifier string, target int64) {
	t.Helper()
	ctx := t.Context()
	issueID, err := finding.NewVulnerabilities(f.db.DB).ByName(ctx, identifier)
	if err != nil {
		t.Fatal(err)
	}
	var componentID int64
	if err := f.db.DB.NewSelect().
		TableExpr("\"graph_node\" AS \"n\"").
		Join("JOIN \"component\" AS \"c\" ON c.id = n.component_id").
		ColumnExpr("c.id").
		Where("n.target_id = ?", target).
		Where("c.name = ?", carrier.Name).
		Limit(1).Scan(ctx, &componentID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := &finding.Finding{
		TargetID: target, Kind: finding.Entered, Visibility: access.Private,
		VulnerabilityID: issueID, ComponentID: componentID,
		PlaceIdentity: finding.PlaceIdentity(carrier.Name, ""),
		LastChangedAt: now, OpenedAt: now,
	}
	if _, err := f.db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestADocumentCarriesEveryNameTheIssueGoesByAndSaysWhenItIsFinal covers three
// paths in the generator that had never been entered.
//
// The alias loop had never run, so IDs had never carried a second entry and
// CVE had never been filled from an alias — which is the one lookup a published
// advisory exists to serve: a reader searching by the identifier a coordinator
// gave them. And every document generated in every test was a draft, so the
// final arm and the "Issued" fallback summary had never been executed either.
func TestADocumentCarriesEveryNameTheIssueGoesByAndSaysWhenItIsFinal(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// Disclosed, so the document is final rather than a draft.
		_, identifier, err := f.finds.Enter(ctx, f.who, finding.Entering{
			TargetIDs: []int64{f.master}, Component: carrier.Name, Severity: "high",
			Summary:   "The management socket answers before anyone authenticated.",
			Disclosed: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		// A CVE assigned afterwards, which is the ordinary way one arrives:
		// the issue stays filed under what we minted and goes by both.
		issue, err := finding.NewVulnerabilities(f.db.DB).ByName(ctx, identifier)
		if err != nil {
			t.Fatal(err)
		}
		if err := finding.NewVulnerabilities(f.db.DB).
			AlsoKnownAs(ctx, f.who, issue, "CVE-2026-4242"); err != nil {
			t.Fatal(err)
		}

		// Refiled under the better-known name, which is what recording a CVE
		// does: what somebody sees should be the name they will find in an
		// advisory, and the minted name stays an alias so nothing that used
		// it stops resolving.
		doc, err := f.store.For(ctx, f.who, issuer, "sonic", "CVE-2026-4242")
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		if len(doc.Vulnerabilities) != 1 {
			t.Fatalf("the document carries %d vulnerabilities", len(doc.Vulnerabilities))
		}
		one := doc.Vulnerabilities[0]

		// The CVE in the field a reader looks in, filled from the alias
		// because the issue is still filed under what we minted.
		if one.CVE != "CVE-2026-4242" {
			t.Errorf("the document names the CVE as %q", one.CVE)
		}
		// And both names in the field that carries names, each said once.
		var minted, alias int
		for _, id := range one.IDs {
			switch id.Text {
			case identifier:
				minted++
			case "CVE-2026-4242":
				alias++
			}
		}
		if minted != 1 || alias != 1 {
			t.Errorf("the document lists the minted name %d times and the CVE %d: %+v",
				minted, alias, one.IDs)
		}

		// Disclosed, so it is a document rather than a draft of one.
		if doc.Document.Tracking.Status != "final" {
			t.Errorf("a disclosed flaw generates a %q document", doc.Document.Tracking.Status)
		}

		// Issued with no summary, so the history says what happened rather
		// than nothing.
		if _, err := f.store.Issued(ctx, f.who, issuer, "sonic", "CVE-2026-4242", ""); err != nil {
			t.Fatal(err)
		}
		doc, err = f.store.For(ctx, f.who, issuer, "sonic", "CVE-2026-4242")
		if err != nil {
			t.Fatal(err)
		}
		var said bool
		for _, revision := range doc.Document.Tracking.RevisionHistory {
			said = said || revision.Summary == "Issued"
		}
		if !said {
			t.Errorf("issuing with no summary left the history saying nothing: %+v",
				doc.Document.Tracking.RevisionHistory)
		}
	})
}

func TestTheDocumentsVersionIsTheLastNumberItsHistoryStates(t *testing.T) {
	// The two were counted separately and disagreed the moment an advisory
	// had been issued once: the history numbered this document N+2 and the
	// version said N+1. A CSAF validator compares them, and a document that
	// fails validation is one a customer's tooling drops — which is the one
	// use a generated advisory has.
	//
	// Checked at each of the three states an advisory passes through, because
	// the two agreed by accident at the first of them.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		identifier := f.recorded(t, f.master)
		matches := func(t *testing.T, when string) {
			t.Helper()
			doc, err := f.store.For(ctx, f.who, issuer, "sonic", identifier)
			if err != nil {
				t.Fatal(err)
			}
			history := doc.Document.Tracking.RevisionHistory
			if len(history) == 0 {
				t.Fatalf("%s: the document states no history at all", when)
			}
			newest := history[len(history)-1].Number
			if doc.Document.Tracking.Version != newest {
				t.Errorf("%s: the document is version %q and its history ends at %q",
					when, doc.Document.Tracking.Version, newest)
			}
		}

		matches(t, "before anything has gone out")
		if _, err := f.store.Issued(ctx, f.who, issuer, "sonic", identifier, "First"); err != nil {
			t.Fatal(err)
		}
		matches(t, "after one issuance")
		if _, err := f.store.Issued(ctx, f.who, issuer, "sonic", identifier, "Second"); err != nil {
			t.Fatal(err)
		}
		matches(t, "after two")
	})
}

// pointsAt records what a report says about the issue: where it is written up,
// and everywhere else it points.
//
// Through the interning path a scan takes rather than by writing the rows,
// because what the document carries has to be what arrives that way.
func (f *fixture) pointsAt(t *testing.T, identifier, advisory string,
	references ...finding.Reference) {

	t.Helper()
	if _, err := finding.NewVulnerabilities(f.db.DB).Intern(t.Context(),
		[]finding.Named{{
			Identifier: identifier, Advisory: advisory, References: references,
		}}); err != nil {
		t.Fatalf("recording where the issue is written up: %v", err)
	}
}

func TestAFlawAssessedUnderAnUncarriedSchemeStatesNoScore(t *testing.T) {
	// The standard's score object has a field for a version 2 score and a
	// version 3 score, and version 4 arrives with its next version. The
	// number is held and shown here; a document that put it in the version 3
	// field would state a version the field's own schema does not have.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		for _, c := range []struct {
			what   string
			vector string
			scores int
		}{
			{"a scheme the document carries", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 1},
			{"one it does not",
				"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 0},
		} {
			t.Run(c.what, func(t *testing.T) {
				_, identifier, err := f.finds.Enter(ctx, f.who, finding.Entering{
					TargetIDs: []int64{f.master}, Component: carrier.Name,
					Summary: "The management socket answers before anyone authenticated.",
					Vector:  c.vector,
				})
				if err != nil {
					t.Fatalf("recording a flaw: %v", err)
				}
				doc, err := f.store.For(ctx, f.who, issuer, "sonic", identifier)
				if err != nil {
					t.Fatalf("generating: %v", err)
				}
				if got := len(doc.Vulnerabilities[0].Scores); got != c.scores {
					t.Fatalf("the document states %d scores, want %d", got, c.scores)
				}
				if c.scores == 0 {
					return
				}
				// The version the field states is one its schema knows.
				if v := doc.Vulnerabilities[0].Scores[0].CVSSv3.Version; v != "3.1" {
					t.Errorf("the score states version %q", v)
				}
			})
		}
	})
}

func TestTheDocumentCarriesWhatIsHeldAboutTheFlaw(t *testing.T) {
	// The score, the credit, the places to go and what to do about it are all
	// held, and the document carried none of them: a reader got which
	// releases are affected and nothing they could act on.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		_, identifier, err := f.finds.Enter(ctx, f.who, finding.Entering{
			TargetIDs: []int64{f.master}, Component: carrier.Name,
			Summary: "The management socket answers before anyone authenticated.",
			Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Told:    finding.Told{ReportedBy: "A. Reporter", Credit: "anonymous"},
		})
		if err != nil {
			t.Fatalf("recording a flaw: %v", err)
		}
		f.alsoIn(t, identifier, f.tagged)
		f.pointsAt(t, identifier, "https://example.test/advisories/1",
			finding.Reference{URL: "https://example.test/commit/abc", Kind: finding.Patch},
			// The same address twice, which is what two reports pointing at
			// one page is, and one a browser must not be handed.
			finding.Reference{URL: "https://example.test/commit/abc", Kind: finding.Report},
			finding.Reference{URL: "ms-msdt:calc", Kind: finding.Report})

		doc, err := f.store.For(ctx, f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		one := doc.Vulnerabilities[0]

		// The score, worked out from the vector rather than read beside it,
		// stated for every release the document names.
		if len(one.Scores) != 1 || one.Scores[0].CVSSv3 == nil {
			t.Fatalf("the document states %d scores", len(one.Scores))
		}
		score := one.Scores[0].CVSSv3
		if score.Version != "3.1" || score.BaseScore != 9.8 || score.BaseSeverity != "CRITICAL" {
			t.Errorf("the score reads %+v", score)
		}
		if len(one.Scores[0].Products) != 2 {
			t.Errorf("the score is stated for %v", one.Scores[0].Products)
		}

		// Credited the way they asked to be, and never by the name they
		// reported under: "anonymous" is a real answer to the question the
		// credit field asks, and it is the one the document has to carry.
		if len(one.Acknowledgments) != 1 ||
			!slices.Equal(one.Acknowledgments[0].Names, []string{"anonymous"}) {
			t.Errorf("the acknowledgments read %+v", one.Acknowledgments)
		}

		// Somewhere to go, each address once, and nothing a browser acts on
		// as an installed program.
		var addresses []string
		for _, reference := range doc.Document.References {
			addresses = append(addresses, reference.URL)
			if reference.Category != "external" {
				t.Errorf("a reference claims category %q", reference.Category)
			}
		}
		want := []string{"https://example.test/advisories/1", "https://example.test/commit/abc"}
		if !slices.Equal(addresses, want) {
			t.Errorf("the document points at %v, want %v", addresses, want)
		}

		// Nothing has been disclosed, so the document is a draft and says so
		// in the field that decides whether a reader may pass it on.
		if doc.Document.Distribution == nil || doc.Document.Distribution.TLP == nil ||
			doc.Document.Distribution.TLP.Label != "RED" {
			t.Errorf("a draft is distributed as %+v", doc.Document.Distribution)
		}

		// Nothing is fixed anywhere, so there is nothing to upgrade to and
		// the document says that rather than naming a release.
		if len(one.Remediations) != 1 || one.Remediations[0].Category != "none_available" {
			t.Fatalf("the remediations read %+v", one.Remediations)
		}

		// And once a release no longer carries it, that release is what to
		// update to. Two of them, because the claim is "all of them, in the
		// order the tree names them" — against one fixed release that passes
		// just as well as naming the first, or the last, or any one of them.
		issueID, err := finding.NewVulnerabilities(f.db.DB).ByName(ctx, identifier)
		if err != nil {
			t.Fatal(err)
		}
		f.alsoIn(t, identifier, f.older)
		for _, fixedIn := range []int64{f.tagged, f.older} {
			if _, err := f.finds.Resolve(ctx, f.who, fixedIn, issueID,
				"Shipped in the tag, which carries the patch."); err != nil {
				t.Fatalf("closing it in a tagged release: %v", err)
			}
		}
		doc, err = f.store.For(ctx, f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatal(err)
		}
		// Stated for the release that still carries it, which is who a
		// remediation is for: the one that is already fixed has nothing to do,
		// and naming it leaves the customer who has to act reading an advisory
		// with no remediation in it.
		fix := doc.Vulnerabilities[0].Remediations
		if len(fix) != 1 || fix[0].Category != "vendor_fix" ||
			!slices.Equal(fix[0].ProductIDs, []string{"sonic:master:broadcom"}) {
			t.Errorf("the remediations read %+v", fix)
		}
		// And it says which release, by the name the product tree gives it.
		// "Update to a release in which this flaw is fixed" is the instruction
		// with the answer left out, and the answer is in the same document.
		// Both of them, joined, in the order the product tree names them —
		// which is the order the releases sort in and not the order they were
		// fixed in. Asserted as the whole sentence, because that is what a
		// reader gets.
		says := "Update to a release in which this flaw is fixed: " +
			fixtures.ProductDisplayName + " v2.3.9 (broadcom), " +
			fixtures.ProductDisplayName + " " + fixtures.TagName + " (broadcom)."
		if fix[0].Details != says {
			t.Errorf("the remediation reads %q, want %q", fix[0].Details, says)
		}
	})
}

func TestTheDocumentDeclaresOnlyAProfileItSatisfies(t *testing.T) {
	// The document declared the security-advisory profile unconditionally and
	// failed two of its mandatory tests, which is a document a customer's
	// tooling drops — the one use a generated advisory has.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		identifier := f.recorded(t, f.master)

		// A flaw of our own that nobody outside has written up: no references
		// anywhere, and the security-advisory profile asks for none. Gated on
		// the informational advisory's list instead, this declared the base
		// profile and a customer's tooling filtering for security advisories
		// skipped it.
		doc, err := f.store.For(ctx, f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		if len(doc.Document.References) != 0 {
			t.Fatalf("the fixture holds references, so this checks nothing: %+v",
				doc.Document.References)
		}
		if doc.Document.Category != "csaf_security_advisory" {
			t.Errorf("a flaw nobody has written up declares %q", doc.Document.Category)
		}
		required(t, doc)

		// And a document that carries nothing to make a statement about is
		// not one: the profile is the product tree and the vulnerabilities.
		bare := *doc
		bare.Vulnerabilities = nil
		if got := advisory.Categorized(&bare); got != "csaf_base" {
			t.Errorf("a document with no vulnerabilities declares %q", got)
		}

		f.pointsAt(t, identifier, "https://example.test/advisories/1")
		doc, err = f.store.For(ctx, f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatal(err)
		}
		if doc.Document.Category != "csaf_security_advisory" {
			t.Errorf("a document meeting the profile declares %q", doc.Document.Category)
		}
		required(t, doc)
	})
}

// required fails on any element the profile the document declares demands.
//
// Walked over the document as it is serialized rather than over the structs,
// because what a validator reads is the JSON — a field the profile names and
// the encoder omits is exactly the failure this exists to catch, and from the
// Go side it looks present.
func required(t *testing.T, doc *advisory.Document) {
	t.Helper()
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var tree any
	if err := json.Unmarshal(body, &tree); err != nil {
		t.Fatal(err)
	}

	// Every element the generic profile requires, and the five the
	// security-advisory profile adds. A document declaring the base profile
	// is held to the first group alone.
	generic := []string{
		"/document/category", "/document/csaf_version", "/document/title",
		"/document/publisher/category", "/document/publisher/name",
		"/document/publisher/namespace",
		"/document/tracking/id", "/document/tracking/status",
		"/document/tracking/version", "/document/tracking/initial_release_date",
		"/document/tracking/current_release_date", "/document/tracking/revision_history",
	}
	// CSAF 2.0 § 4.4: the base profile plus these. Notes and references on
	// the document are § 4.3's requirement — the informational advisory,
	// which carries no vulnerabilities at all.
	profile := []string{
		"/product_tree", "/vulnerabilities", "/vulnerabilities/0/notes",
		"/vulnerabilities/0/product_status",
	}
	wanted := generic
	if doc.Document.Category == "csaf_security_advisory" {
		wanted = append(slices.Clone(generic), profile...)
	}

	examined := 0
	for _, pointer := range wanted {
		examined++
		value, found := at(tree, pointer)
		if !found {
			t.Errorf("the document declares %q and carries no %s",
				doc.Document.Category, pointer)
			continue
		}
		switch held := value.(type) {
		case string:
			if strings.TrimSpace(held) == "" {
				t.Errorf("%s is empty", pointer)
			}
		case []any:
			if len(held) == 0 {
				t.Errorf("%s is empty", pointer)
			}
		case map[string]any:
			if len(held) == 0 {
				t.Errorf("%s is empty", pointer)
			}
		}
	}
	// A list that went empty would report nothing rather than failing, which
	// is how a check that examines nothing passes.
	if examined == 0 {
		t.Fatal("no elements were checked, so this checked nothing")
	}

	// The notes are the one element with a condition beyond being present:
	// the categories a reader of a note can act on.
	for _, pointer := range []string{"/vulnerabilities/0/notes"} {
		if doc.Document.Category != "csaf_security_advisory" {
			continue
		}
		notes, found := at(tree, pointer)
		if !found {
			continue
		}
		var usable bool
		for _, note := range notes.([]any) {
			switch note.(map[string]any)["category"] {
			case "description", "details", "general", "summary":
				usable = true
			}
		}
		if !usable {
			t.Errorf("%s carries no note a reader can act on", pointer)
		}
	}
}

// at resolves a JSON pointer against a decoded document.
func at(tree any, pointer string) (any, bool) {
	for _, step := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		switch held := tree.(type) {
		case map[string]any:
			value, found := held[step]
			if !found {
				return nil, false
			}
			tree = value
		case []any:
			index, err := strconv.Atoi(step)
			if err != nil || index >= len(held) {
				return nil, false
			}
			tree = held[index]
		default:
			return nil, false
		}
	}
	return tree, true
}

func TestTheProductTreeNamesEachReleaseByWhatItsOwnInventoryCalledIt(t *testing.T) {
	// A reader matches an advisory against what they hold, and the identifier
	// that lets them is the one their copy of the inventory carries — which is
	// the one the build wrote. So the tree states that and never a spelling
	// minted here, which would appear on one side of the comparison only.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)

		doc, err := f.store.For(t.Context(), f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatal(err)
		}
		leaves := releaseLeaves(doc)
		if len(leaves) == 0 {
			t.Fatal("the tree names no release")
		}
		for _, leaf := range leaves {
			if leaf.Helper == nil {
				t.Errorf("%q carries no identifier for a reader to match on", leaf.ID)
				continue
			}
			if leaf.Helper.Purl != root.Purl {
				t.Errorf("%q says it is %q, want what the build declared, %q",
					leaf.ID, leaf.Helper.Purl, root.Purl)
			}
		}
	})
}

func TestAReleaseWhoseInventoryNamedNoRootOffersNothingToMatchOn(t *testing.T) {
	// A document that names no component of its own is ordinary, and the
	// tracked unit stands in for the root. What stands in is ours rather than
	// the producer's, so there is nothing a reader could match against and the
	// field is absent — which is the failure the field exists to avoid.
	each(t, func(t *testing.T, f *fixture) {
		f.shippedAs(t, f.master, "")
		identifier := f.recorded(t, f.master)

		doc, err := f.store.For(t.Context(), f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatal(err)
		}
		branch := "sonic:" + fixtures.BranchName + ":broadcom"
		for _, leaf := range releaseLeaves(doc) {
			if leaf.ID == branch && leaf.Helper != nil {
				t.Errorf("%q claims to be %+v, and its inventory named nothing",
					leaf.ID, leaf.Helper)
			}
		}
	})
}

// releaseLeaves is every release the product tree names.
func releaseLeaves(doc *advisory.Document) []advisory.Named {
	var out []advisory.Named
	var walk func(branches []advisory.Branch)
	walk = func(branches []advisory.Branch) {
		for _, branch := range branches {
			if branch.Product != nil {
				out = append(out, *branch.Product)
			}
			walk(branch.Branches)
		}
	}
	walk(doc.ProductTree.Branches)
	return out
}

func TestTheAdvisoryNamesTheFlawInTheCatalogsOwnWordsRatherThanTheScreens(t *testing.T) {
	// The standard states a weakness as the identifier and the name the
	// catalog gives it, and a consumer's validator compares the pair. The
	// interface calls this one "Buffer overflow", which is right for somebody
	// scanning a list and fails that comparison. Two lists rather than one
	// used twice.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recordedAs(t, f.master, "CWE-119")

		doc, err := f.store.For(t.Context(), f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatal(err)
		}
		got := doc.Vulnerabilities[0].CWE
		if got == nil {
			t.Fatal("the document says nothing about what kind of flaw this is")
		}
		want := "Improper Restriction of Operations within the Bounds of a Memory Buffer"
		if got.ID != "CWE-119" || got.Name != want {
			t.Errorf("the document states %+v, want CWE-119 named %q", got, want)
		}
	})
}

func TestTheAdvisoryStatesTheRootCauseRatherThanWhicheverSortsFirst(t *testing.T) {
	// The standard carries one weakness and an issue is commonly classified as
	// several, so something has to say which. These two are chosen because
	// every order that is not the recorded one picks the wrong one: CWE-20 is
	// the lower number and "CWE-119" is the earlier string, and the root cause
	// here is CWE-20 — so a document stating CWE-119 is a document that sorted
	// rather than read.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recordedAs(t, f.master, "CWE-20", "CWE-119")

		doc, err := f.store.For(t.Context(), f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatal(err)
		}
		got := doc.Vulnerabilities[0].CWE
		if got == nil {
			t.Fatal("the document says nothing about what kind of flaw this is")
		}
		if got.ID != "CWE-20" {
			t.Errorf("the document states %q, want the one recorded as the root cause", got.ID)
		}
	})
}

func TestAWeaknessTheCatalogDoesNotAssignIsLeftOutRatherThanNamed(t *testing.T) {
	// A category, a view, or a number from a catalog newer than the one read.
	// The name is the half that cannot be invented, so a flaw whose kind
	// cannot be named says nothing about its kind — which is what every other
	// field the record cannot fill does.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recordedAs(t, f.master, "CWE-999999")

		doc, err := f.store.For(t.Context(), f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatal(err)
		}
		if got := doc.Vulnerabilities[0].CWE; got != nil {
			t.Errorf("the document calls it %+v, and the catalog assigns no such weakness", got)
		}
	})
}

func TestAFlawNobodyClassifiedSaysNothingAboutItsKind(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)

		doc, err := f.store.For(t.Context(), f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatal(err)
		}
		if got := doc.Vulnerabilities[0].CWE; got != nil {
			t.Errorf("the document calls it %+v, and nobody classified it", got)
		}
	})
}

func TestAnIdentifierThatIsNotOneIsNotPublished(t *testing.T) {
	// The string is a producer's, out of a scan file, and a scan file is
	// hostile input. The standard states a pattern for this field and a
	// consumer's validator applies it to the whole document — so one producer
	// writing something else into the component its inventory is about would
	// fail every advisory about that build, rather than losing one field.
	for _, one := range []struct {
		what      string
		declared  string
		published bool
	}{
		{"a package identifier", "pkg:generic/sonic-broadcom.bin@1.0", true},
		{"one with a namespace", "pkg:deb/debian/linux@6.12", true},
		// Values a producer might reasonably put there and the standard
		// refuses.
		{"a path", "/build/out/sonic-broadcom.bin", false},
		{"a bare name", "sonic-broadcom.bin", false},
		{"a scheme with nothing after it", "pkg:generic", false},
		{"a scheme and a type and no name", "pkg:generic/", false},
		{"something that is not an identifier at all", "the nightly build", false},
	} {
		t.Run(one.what, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				f.shippedAs(t, f.master, one.declared)
				identifier := f.recorded(t, f.master)

				doc, err := f.store.For(t.Context(), f.who, issuer, "sonic", identifier)
				if err != nil {
					t.Fatal(err)
				}
				branch := "sonic:" + fixtures.BranchName + ":broadcom"
				for _, leaf := range releaseLeaves(doc) {
					if leaf.ID != branch {
						continue
					}
					stated := leaf.Helper != nil
					if stated != one.published {
						t.Errorf("%q published as %+v, want published=%v",
							one.declared, leaf.Helper, one.published)
					}
					if stated && leaf.Helper.Purl != one.declared {
						t.Errorf("published %q, want what the build declared, %q",
							leaf.Helper.Purl, one.declared)
					}
				}
			})
		})
	}
}
