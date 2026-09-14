package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
)

func TestAVEXDocumentSaysWhatStandsAboutWhatWeShip(t *testing.T) {
	// A customer running their own scanner against a shipped image gets a
	// list of CVEs in our dependencies and asks what we say about them,
	// which is more often than they ask for an advisory. It is mostly
	// formatting over decisions already made and approved.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom/vex"

		// Nothing approved yet, so the document says nothing. Silence reads as
		// affected in this format, which is the honest answer.
		var empty struct {
			Context    string `json:"@context"`
			Author     string `json:"author"`
			Statements []any  `json:"statements"`
		}
		read(t, r, "triager", at, &empty)
		if len(empty.Statements) != 0 {
			t.Fatalf("a build with nothing approved says %d things", len(empty.Statements))
		}
		if !contains(empty.Context, "openvex.dev") || empty.Author == "" {
			t.Errorf("the document does not name its format and its author: %+v", empty)
		}

		// One dismissal, agreed to by a second person.
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)
		// And one deferral, which must not appear as anything.
		later, _ := r.claimed(t, "triager", "CVE-2026-1000", "linux-image",
			`{"outcome":"deferred","deferred_until":"2030-01-01",`+
				`"reasoning":"Waiting on the vendor's next image."}`)
		for _, id := range []int64{claim, later} {
			if got := asPerson(t, r, "reviewer", http.MethodPost,
				fmt.Sprintf("/v1/claims/%d/approval", id), `{}`); got.Code != http.StatusOK {
				t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
			}
		}

		var doc struct {
			Statements []struct {
				Vulnerability struct {
					Name string `json:"name"`
				} `json:"vulnerability"`
				Status          string `json:"status"`
				Justification   string `json:"justification"`
				ImpactStatement string `json:"impact_statement"`
				Products        []struct {
					ID            string `json:"@id"`
					Subcomponents []struct {
						ID string `json:"@id"`
					} `json:"subcomponents"`
				} `json:"products"`
			} `json:"statements"`
		}
		read(t, r, "triager", at, &doc)
		if len(doc.Statements) != 1 {
			t.Fatalf("the document carries %d statements, want the one approved dismissal: %+v",
				len(doc.Statements), doc.Statements)
		}
		one := doc.Statements[0]
		if one.Vulnerability.Name != "CVE-2026-9999" || one.Status != "not_affected" {
			t.Errorf("the statement reads as %+v", one)
		}
		// The vocabulary needs no translation: a dismissal already carries it.
		if one.Justification != "vulnerable_code_not_present" {
			t.Errorf("the justification reads as %q", one.Justification)
		}
		// And the reasoning, which is the part worth reading and the part a
		// second person agreed to.
		if !contains(one.ImpactStatement, "driver") {
			t.Errorf("the statement carries no reasoning: %q", one.ImpactStatement)
		}
		// The product is what somebody has, with the component underneath it.
		if len(one.Products) != 1 || one.Products[0].ID != "mine:master:broadcom" {
			t.Errorf("the statement is about %+v, want the build", one.Products)
		}
		if len(one.Products[0].Subcomponents) != 1 ||
			!contains(one.Products[0].Subcomponents[0].ID, "linux-image") {
			t.Errorf("the statement does not name the component: %+v", one.Products[0])
		}
	})
}

func TestAVEXDocumentCarriesNothingNobodyHasAnnounced(t *testing.T) {
	// Every statement names an issue and a component in something we ship, so
	// a document built from undisclosed work would announce the undisclosed
	// work.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		hidden := r.embargoed(t)
		claim, _ := r.claimed(t, "private-triage", hidden, "libnl-3-200", dismissal)
		if got := asPerson(t, r, "private-dispatcher", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}

		const at = "/v1/products/mine/streams/master/variants/broadcom/vex"
		var doc struct {
			Statements []struct {
				Vulnerability struct {
					Name string `json:"name"`
				} `json:"vulnerability"`
			} `json:"statements"`
		}
		// Even to somebody who may read it, the document is public by default:
		// it is a thing to publish.
		read(t, r, "private-triage", at, &doc)
		for _, one := range doc.Statements {
			if one.Vulnerability.Name == hidden {
				t.Fatalf("an undisclosed flaw is in a document meant for customers: %+v", doc)
			}
		}

		// Asked for as a preview, somebody who may read it sees it.
		read(t, r, "private-triage", at+"?undisclosed=true", &doc)
		var found bool
		for _, one := range doc.Statements {
			found = found || one.Vulnerability.Name == hidden
		}
		if !found {
			t.Errorf("the preview leaves out what it is for: %+v", doc.Statements)
		}

		// And somebody who may not read undisclosed work cannot ask for it.
		if got := asPerson(t, r, "triager", http.MethodGet, at+"?undisclosed=true", ""); got.Code < 400 {
			t.Errorf("somebody who may not read undisclosed work previewed it: %d", got.Code)
		}
	})
}

func TestAVEXStatementCarriesTheOtherNamesItsIssueAnswersTo(t *testing.T) {
	// and the whole point of the field: a customer's scanner matched under
	// the name its own database uses, which is often not the one we filed
	// under. The document declared aliases from the start and never put
	// anything in them, so the one search it exists to satisfy — find what
	// they say about the name I have — found nothing.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom/vex"

		if got := asPerson(t, r, "triager", http.MethodPut,
			"/v1/products/mine/issues/CVE-2026-9999/aliases/GHSA-xxxx-yyyy-zzzz",
			""); got.Code >= 300 {
			t.Fatalf("recording another name answered %d: %s", got.Code, got.Body.String())
		}

		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)
		if ok := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); ok.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", ok.Code, ok.Body.String())
		}

		var doc struct {
			Statements []struct {
				Vulnerability struct {
					Name    string   `json:"name"`
					Aliases []string `json:"aliases"`
				} `json:"vulnerability"`
			} `json:"statements"`
		}
		read(t, r, "triager", at, &doc)
		if len(doc.Statements) == 0 {
			t.Fatal("the document says nothing, so this proves nothing")
		}
		var found bool
		for _, each := range doc.Statements {
			if each.Vulnerability.Name != "CVE-2026-9999" {
				continue
			}
			for _, alias := range each.Vulnerability.Aliases {
				// Folded, because an identifier is stored
				// normalized so that every engine compares it
				// alike.
				if strings.EqualFold(alias, "GHSA-xxxx-yyyy-zzzz") {
					found = true
				}
				if strings.EqualFold(alias, each.Vulnerability.Name) {
					t.Errorf("the statement lists its own name as another name: %v",
						each.Vulnerability.Aliases)
				}
			}
		}
		if !found {
			t.Errorf("the statement does not carry the other name its issue answers to: %+v", doc)
		}
	})
}

func TestAVEXStatementCoversEveryPlaceOrIsAbsent(t *testing.T) {
	// The format says "this product, this component, not affected" and has no
	// finer grain than that. A finding is an issue at a place, and a component
	// commonly sits at many — so one dismissal agreed at one place used to
	// speak for a component still open at all the others. That is a
	// machine-readable claim of "not affected" about something that is
	// affected, published to every customer running a scanner against the
	// image, which is the most expensive wrong answer this tool can produce.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedAtTwoPlaces(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom/vex"

		// The issue sits at more than one place in this component.
		var places struct {
			Places []struct {
				Place string `json:"place"`
			} `json:"places"`
		}
		read(t, r, "triager", findingAt("CVE-2026-9999"), &places)
		if len(places.Places) < 2 {
			t.Fatalf("the fixture holds this issue at %d places, so there is nothing "+
				"to prove", len(places.Places))
		}

		// Agreed at one place only.
		one := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/places/"+places.Places[0].Place+"/decision", dismissal)
		if one.Code != http.StatusCreated {
			t.Fatalf("deciding one place answered %d: %s", one.Code, one.Body.String())
		}
		var made struct {
			ClaimID int64 `json:"claim_id"`
		}
		if err := json.Unmarshal(one.Body.Bytes(), &made); err != nil {
			t.Fatal(err)
		}
		if ok := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", made.ClaimID), `{}`); ok.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", ok.Code, ok.Body.String())
		}

		var doc struct {
			Statements []struct {
				Vulnerability struct {
					Name string `json:"name"`
				} `json:"vulnerability"`
			} `json:"statements"`
		}
		read(t, r, "triager", at, &doc)
		for _, each := range doc.Statements {
			if each.Vulnerability.Name == "CVE-2026-9999" {
				t.Errorf("a component dismissed at one place of several is published as "+
					"not affected: %+v", doc.Statements)
			}
		}
	})
}

// scannedAtTwoPlaces is one issue in one component pulled in by two things, so
// the component sits at two places in the build.
//
// The ordinary case — a library is pulled in by several things — and the one a
// fixture with a single place cannot represent: it cannot tell a rule about a
// place from a rule about a component, which is exactly the distinction a
// document with no place granularity turns on.
func (r *reach) scannedAtTwoPlaces(t *testing.T) {
	t.Helper()
	ctx := t.Context()

	names := catalog.NewStore(r.db.DB)
	located, err := names.Locate(ctx, "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	scan, outcome, err := ingest.NewStore(r.db.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "two-places", BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}

	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	first := graph.Described{
		Purl: "pkg:deb/debian/libswsscommon@1.0.0", Name: "libswsscommon", Version: "1.0.0",
	}
	second := graph.Described{
		Purl: "pkg:deb/debian/libteam5@1.31", Name: "libteam5", Version: "1.31",
	}
	library := graph.Described{
		Purl: "pkg:deb/debian/libnl-3-200@3.7.0", Name: "libnl-3-200", Version: "3.7.0",
	}
	if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root:       product,
		Components: []graph.Described{first, second, library},
		Dependencies: []graph.Dependency{
			{Parent: product, Child: first}, {Parent: first, Child: library},
			{Parent: product, Child: second}, {Parent: second, Child: library},
		},
	}); err != nil {
		t.Fatal(err)
	}

	findings := finding.NewStore(r.db.DB)
	run, err := findings.Begin(ctx, finding.Run{
		TargetID: target.ID, Scanner: "grype", ScannerVersion: "0.112.0",
		DatabaseVersion: "2026-08-28", RanHere: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// One report, two places: the places come from the graph, and the library
	// hangs off both consumers.
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{
		{
			Issue:     finding.Named{Identifier: "CVE-2026-9999", Severity: "high"},
			Component: library, FixState: finding.NoFix,
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestADeploymentThatHasNotSaidWhoItPublishesAsAnswersAConflict(t *testing.T) {
	// A configuration gap rather than a bad request. Whoever is asking cannot
	// fix it from here and an operator can, so it is a conflict naming what is
	// unconfigured rather than a 500 that says something went wrong.
	//
	// That distinction is one line in the handler and nothing executed it: the
	// fixture every other test here uses is configured, and the predicate the
	// line reads had a wrapper of its own that no test called either.
	reachAs(t, dbtest.Two, publisher.Named{}, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/streams/master/variants/broadcom/vex", "")
		if got.Code != http.StatusConflict {
			t.Fatalf("answered %d, want a conflict naming what is unconfigured: %s",
				got.Code, got.Body.String())
		}
		if !strings.Contains(strings.ToLower(got.Body.String()), "publish") {
			t.Errorf("the refusal does not say what is unconfigured: %s", got.Body.String())
		}
	})
}
