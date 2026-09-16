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
	who            access.Subject
	seq            int
	built          time.Time
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
		f := &fixture{
			db: w.DB, store: advisory.NewStore(w.DB.DB), finds: finding.NewStore(w.DB.DB),
			graph: graph.NewStore(w.DB.DB), scans: ingest.NewStore(w.DB.DB),
			product: w.Product.ID, master: w.Target.ID, tagged: tagged.ID,
			who: access.NewPerson(w.Person.ID, w.Person.Identity, false, map[int64][]access.Role{
				w.Product.ID: {access.PublicRead, access.PrivateRead, access.PrivateTriage},
			}, 0),
			built: time.Now().UTC().Add(-72 * time.Hour),
		}
		f.shipped(t, f.master)
		f.shipped(t, f.tagged)
		fn(t, f)
	})
}

// shipped stores a graph against one build.
func (f *fixture) shipped(t *testing.T, target int64) {
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
}

// recorded enters a flaw against one build and returns what it was filed as.
func (f *fixture) recorded(t *testing.T, target int64) string {
	t.Helper()
	_, identifier, err := f.finds.Enter(t.Context(), f.who, finding.Entering{
		TargetIDs: []int64{target}, Component: carrier.Name, Severity: "high",
		Summary: "The management socket answers before anyone authenticated.",
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
		// update to.
		issueID, err := finding.NewVulnerabilities(f.db.DB).ByName(ctx, identifier)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.finds.Resolve(ctx, f.who, f.tagged, issueID,
			"Shipped in the tag, which carries the patch."); err != nil {
			t.Fatalf("closing it in the tagged release: %v", err)
		}
		doc, err = f.store.For(ctx, f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatal(err)
		}
		fix := doc.Vulnerabilities[0].Remediations
		if len(fix) != 1 || fix[0].Category != "vendor_fix" ||
			!slices.Equal(fix[0].ProductIDs, []string{"sonic:" + fixtures.TagName + ":broadcom"}) {
			t.Errorf("the remediations read %+v", fix)
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

		// Nothing is held to point at, so the profile cannot be satisfied and
		// the document does not claim it.
		doc, err := f.store.For(ctx, f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		if doc.Document.Category != "csaf_base" {
			t.Errorf("a document with nothing to point at declares %q", doc.Document.Category)
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
	profile := []string{
		"/document/notes", "/document/references", "/product_tree",
		"/vulnerabilities", "/vulnerabilities/0/notes",
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
	for _, pointer := range []string{"/document/notes", "/vulnerabilities/0/notes"} {
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
