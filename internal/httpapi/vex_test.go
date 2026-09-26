// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/vex"
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
		// And nothing else. The reasoning beside this dismissal is addressed
		// to the second person who checked it, and this document is read by
		// every customer running a scanner — so where no mitigation was named
		// the field is absent rather than filled with the review.
		if one.ImpactStatement != "" {
			t.Errorf("the statement publishes %q, and nothing named a mitigation",
				one.ImpactStatement)
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
		// Answered as a product nobody declared rather than as a refusal, on
		// purpose: 403 here would say "there is undisclosed work in this
		// product and you may not see it", which is the fact being withheld.
		refusedWith(t, asPerson(t, r, "triager", http.MethodGet, at+"?undisclosed=true", ""),
			http.StatusNotFound)
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
	// commonly sits at many, so one dismissal agreed at one place speaks for
	// a component still open at all the others. That is a
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
	reachAs(t, castSeed.Two, publisher.Named{}, func(t *testing.T, r *reach) {
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

		// Reading what has gone out is answered all the same. It assembles
		// nothing and names no author, so the sentence about an unconfigured
		// publisher answers a question it was never asked.
		if gone := asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/streams/master/variants/broadcom/vex/issuance",
			""); gone.Code != http.StatusOK {
			t.Errorf("reading what has gone out answered %d: %s",
				gone.Code, gone.Body.String())
		}
	})
}

func TestACaseCollaboratorIsNotHandedTheBuildsWholeVEXDocument(t *testing.T) {
	// The document is the deployment's word about everything this build ships,
	// which is a product-wide read. A case grant does not answer a
	// product-wide question: somebody brought onto one embargoed issue holds
	// nothing on the product, and the build lookup admits them only so that
	// the names their own issue sits at resolve.
	//
	// A route stopping at that lookup, with the only authorization after it
	// running when the undisclosed preview is asked for, hands out every
	// approved statement about the build — unrelated issue identifiers, the
	// components they sit in, the justification, and the free-text reasoning
	// somebody wrote for a second person to check — about a product the reader
	// may not otherwise see.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		embargoed := r.embargoed(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom/vex"

		// Something for the document to carry, so that what is measured is a
		// refusal rather than an empty answer either way.
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}
		var doc struct {
			Statements []any `json:"statements"`
		}
		read(t, r, "reader", at, &doc)
		if len(doc.Statements) == 0 {
			t.Fatal("the document says nothing, so a refusal proves nothing")
		}

		// A judgment on the embargoed issue, which is what the collaborator is
		// brought in to argue about and the thing their grant does reach.
		made := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom/findings/"+
				embargoed+"/components/libnl-3-200/decision", dismissal)
		if made.Code != http.StatusCreated {
			t.Fatalf("deciding answered %d: %s", made.Code, made.Body.String())
		}
		var decided struct {
			IDs []int64 `json:"ids"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &decided); err != nil {
			t.Fatal(err)
		}

		// Somebody holding nothing on this product. Before the grant the build
		// is not theirs to name, which is the answer the grant must not
		// change.
		if got := asPerson(t, r, "outsider", http.MethodGet, at, ""); got.Code != http.StatusNotFound {
			t.Fatalf("somebody holding nothing here reached the document before any "+
				"grant: %d", got.Code)
		}
		if got := asPerson(t, r, "private-triage", http.MethodPut,
			"/v1/products/mine/issues/"+embargoed+"/collaborators/outsider",
			""); got.Code != http.StatusNoContent {
			t.Fatalf("bringing somebody in answered %d: %s", got.Code, got.Body.String())
		}

		// The grant is live and reaches the case: they read what was decided
		// about the issue they are on.
		if got := asPerson(t, r, "outsider", http.MethodGet,
			fmt.Sprintf("/v1/decisions/%d", decided.IDs[0]), ""); got.Code != http.StatusOK {
			t.Fatalf("the collaborator does not reach their own case, so this proves "+
				"nothing: %d %s", got.Code, got.Body.String())
		}

		// And the document is still not theirs to have.
		if got := asPerson(t, r, "outsider", http.MethodGet, at, ""); got.Code != http.StatusNotFound {
			t.Errorf("a case collaborator holding nothing on the product received the "+
				"build's whole document: %d %s", got.Code, got.Body.String())
		}

		// An administrator reads it by granting themselves reading, like
		// anybody else: administering the catalog is not reading what is open
		// against it, which is the rule the findings list already applies.
		if got := asPerson(t, r, "admin", http.MethodGet, at, ""); got.Code != http.StatusNotFound {
			t.Errorf("an administrator holding no role on the product received the "+
				"document: %d", got.Code)
		}
		read(t, r, "admin-reader", at, &doc)
	})
}

func TestABuildStandingOnMoreDismissalsThanOneDocumentCarriesIsAnsweredAsTooLarge(t *testing.T) {
	// Refused rather than truncated, because a document that stopped at a
	// ceiling would say "nothing is claimed about this" by omission about
	// everything past it. But the refusal has to reach the person asking:
	// returned bare it fell through to "the document could not be generated"
	// with a 500, which reads as the tool being broken rather than as
	// something to narrow, and the sentence naming the build and the limit
	// went only to the log.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		// Two dismissals agreed to, so a ceiling of one is past rather than
		// reached: landing on the limit exactly is not a refusal.
		for _, issue := range []string{"CVE-2026-9999", "CVE-2026-1000"} {
			claim, _ := r.claimed(t, "triager", issue, "linux-image", dismissal)
			if ok := asPerson(t, r, "reviewer", http.MethodPost,
				fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); ok.Code != http.StatusOK {
				t.Fatalf("approving answered %d: %s", ok.Code, ok.Body.String())
			}
		}

		// The ceiling is brought down to the fixture rather than the fixture
		// built up to twenty thousand, which is how the routing reach is
		// tested and for the same reason. On the store rather than on the
		// package variable, because the engines run in parallel.
		who, err := r.rights.Resolve(t.Context(), "triager")
		if err != nil {
			t.Fatal(err)
		}
		_, err = vex.NewStoreCarrying(r.db.DB, 1).For(t.Context(), who,
			publisher.Named{Name: "Example Networks", Namespace: "https://example.test"},
			"mine", "master", "broadcom", false)
		if !errors.Is(err, vex.ErrTooLarge) {
			t.Fatalf("a build past the ceiling answered %v, wanted a refusal naming itself", err)
		}
		if !strings.Contains(err.Error(), "mine") || !strings.Contains(err.Error(), "master") {
			t.Errorf("the refusal does not say which build: %s", err)
		}
	})
}

func TestAVEXStatementPublishesTheMitigationAndNeverTheReasoning(t *testing.T) {
	// The two texts answer different readers. A mitigation says what stops
	// the flaw, which is what somebody holding the build can act on. The
	// reasoning is the argument a triager put to a second person here, and
	// publishing it hands every customer this deployment's review of itself.
	//
	// On every engine, because what this pins is what a query does: the
	// document is assembled by a join whose predicate decides what a customer
	// is told, and two engines of four is not where a portability trap shows.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom/vex"

		const stops = "The service is bound to the management VLAN only."
		const argued = "Checked the build flags and the exposed sockets."
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "linux-image",
			`{"outcome":"not-applicable","justification":"inline_mitigations_already_exist",`+
				`"mitigation":"`+stops+`","reasoning":"`+argued+`"}`)
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}

		var doc struct {
			Statements []struct {
				ImpactStatement string `json:"impact_statement"`
			} `json:"statements"`
		}
		read(t, r, "triager", at, &doc)
		if len(doc.Statements) != 1 {
			t.Fatalf("the document carries %d statements, want the one approved dismissal",
				len(doc.Statements))
		}
		if got := doc.Statements[0].ImpactStatement; got != stops {
			t.Errorf("the statement says %q, want what stops it", got)
		}
		if contains(doc.Statements[0].ImpactStatement, "build flags") {
			t.Errorf("the reasoning reached the document: %q", doc.Statements[0].ImpactStatement)
		}
	})
}

func TestAFlawThatWillNotBeFixedReachesCustomersOnlyWithSomethingToDo(t *testing.T) {
	// A standing property of a shipped feature — a protocol that cannot change
	// without breaking what it is compatible with. No scan closes it, no
	// advisory is issued about it, and under silence it reaches a customer
	// never. The format has a status for exactly this and a field for what to
	// do instead, and the second is why the first is publishable at all.
	//
	// On every engine. The new arm of the join — a claim that will not be
	// fixed, joined only where it says what to do instead — is what decides
	// whether such a flaw is published at all, and it is the half a comparison
	// against an empty string is most likely to answer differently on.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom/vex"

		const instead = "Use SSH, or reach it from the management VLAN only."
		// One that says what to do, and one that says nothing.
		told, _ := r.claimed(t, "triager", "CVE-2026-9999", "linux-image",
			`{"outcome":"wont-fix","mitigation":"`+instead+`",`+
				`"reasoning":"The protocol is fixed by the compatibility promise."}`)
		silent, _ := r.claimed(t, "triager", "CVE-2026-1000", "linux-image",
			`{"outcome":"wont-fix","reasoning":"Nothing can be done about this one."}`)
		for _, id := range []int64{told, silent} {
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
				ActionStatement string `json:"action_statement"`
				ImpactStatement string `json:"impact_statement"`
				Justification   string `json:"justification"`
			} `json:"statements"`
		}
		read(t, r, "triager", at, &doc)
		if len(doc.Statements) != 1 {
			t.Fatalf("the document carries %d statements, want only the one with an "+
				"action: %+v", len(doc.Statements), doc.Statements)
		}
		one := doc.Statements[0]
		if one.Vulnerability.Name != "CVE-2026-9999" {
			t.Fatalf("the statement is about %q", one.Vulnerability.Name)
		}
		// Affected rather than dismissed, which is what the claim says: the
		// flaw is there and it is staying.
		if one.Status != "affected" {
			t.Errorf("a flaw that will not be fixed reads as %q", one.Status)
		}
		if one.ActionStatement != instead {
			t.Errorf("the statement offers %q, want what to do instead", one.ActionStatement)
		}
		// The fields that belong to the other status stay empty. An affected
		// statement carrying a not-affected justification is a document saying
		// both things at once.
		if one.ImpactStatement != "" || one.Justification != "" {
			t.Errorf("an affected statement also reads as not affected: %+v", one)
		}
	})
}

func TestAWrongMatchPublishesAsNotAffectedAndStaysThereWhenTheVersionMoves(t *testing.T) {
	// The one change a correction makes that reaches somebody outside the
	// deployment. The format has words for both reasons a correction may
	// state, so nothing about the match being ours to correct has to be
	// explained to a reader — and the statement has to survive the bump,
	// because surviving the bump is the whole of what a correction is.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom/vex"

		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "linux-image",
			`{"outcome":"mismatched","justification":"component_not_present",`+
				`"reasoning":"The advisory is about an unrelated project of a similar name."}`)
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}

		var doc struct {
			Statements []struct {
				Vulnerability struct {
					Name string `json:"name"`
				} `json:"vulnerability"`
				Status        string `json:"status"`
				Justification string `json:"justification"`
			} `json:"statements"`
		}
		read(t, r, "triager", at, &doc)
		if len(doc.Statements) != 1 {
			t.Fatalf("the document carries %d statements, want the correction: %+v",
				len(doc.Statements), doc.Statements)
		}
		if doc.Statements[0].Status != "not_affected" {
			t.Errorf("a wrong match publishes as %q", doc.Statements[0].Status)
		}
		if doc.Statements[0].Justification != "component_not_present" {
			t.Errorf("the statement carries %q, want the reason the claim stated",
				doc.Statements[0].Justification)
		}

		// The component moves to a version nobody decided anything about. A
		// judgment about risk would be gone from this document; this one is
		// a claim about the match, and the match is as wrong as it was.
		if _, err := r.db.DB.NewUpdate().Table("component").
			Set("version = ?", "5.11").
			Set("upstream_version = ?", "5.11").
			Where("name = ?", "linux-image").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		var after struct {
			Statements []struct {
				Status        string `json:"status"`
				Justification string `json:"justification"`
			} `json:"statements"`
		}
		read(t, r, "triager", at, &after)
		if len(after.Statements) != 1 {
			t.Fatalf("after the version moved the document carries %d statements, "+
				"want the correction still there: %+v", len(after.Statements), after.Statements)
		}
		if after.Statements[0].Status != "not_affected" ||
			after.Statements[0].Justification != "component_not_present" {
			t.Errorf("after the version moved the statement reads as %+v", after.Statements[0])
		}
	})
}

func TestComparingABuildPastTheCeilingAnswersAsTooLarge(t *testing.T) {
	// The issuance list maps this answer to no comparison rather than a
	// failed read: what went out is still what went out.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		recordedIssuance(t, r, "triager")
		for _, issue := range []string{"CVE-2026-9999", "CVE-2026-1000"} {
			claim, _ := r.claimed(t, "triager", issue, "linux-image", dismissal)
			if ok := asPerson(t, r, "reviewer", http.MethodPost,
				fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); ok.Code != http.StatusOK {
				t.Fatalf("approving answered %d: %s", ok.Code, ok.Body.String())
			}
		}
		who, err := r.rights.Resolve(t.Context(), "triager")
		if err != nil {
			t.Fatal(err)
		}
		_, err = vex.NewStoreCarrying(r.db.DB, 1).Changed(t.Context(), who,
			publisher.Named{Name: "Example Networks", Namespace: "https://example.test"},
			"mine", "master", "broadcom")
		if !errors.Is(err, vex.ErrTooLarge) {
			t.Fatalf("comparing a build past the ceiling answered %v", err)
		}
	})
}

// patchedKernel is the two-issue build with the first issue patched in the
// kernel, as the build declares it.
func (r *reach) patchedKernel(t *testing.T) {
	t.Helper()
	r.scannedTwoIssuesArguing(t, "patched", []sbom.Suppression{{
		Vulnerability: "CVE-2026-9999", Status: sbom.AlreadyFixed,
		Statement: "resolved by a patch the build carries",
		Targets:   []sbom.Target{{Purl: "pkg:deb/debian/linux-image@5.10", Name: "linux-image"}},
		Origin:    sbom.FromPedigree,
	}})
}

// fixedIn reads the document and returns what it says is fixed, by issue.
func (r *reach) fixedIn(t *testing.T) map[string][]string {
	t.Helper()
	var doc struct {
		Statements []struct {
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
			Status   string `json:"status"`
			Products []struct {
				Subcomponents []struct {
					ID string `json:"@id"`
				} `json:"subcomponents"`
			} `json:"products"`
		} `json:"statements"`
	}
	read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom/vex", &doc)
	fixed := map[string][]string{}
	for _, one := range doc.Statements {
		if one.Status != "fixed" {
			t.Errorf("%s is said as %q, and nothing here was agreed to", one.Vulnerability.Name, one.Status)
			continue
		}
		for _, product := range one.Products {
			for _, inside := range product.Subcomponents {
				fixed[one.Vulnerability.Name] = append(fixed[one.Vulnerability.Name], inside.ID)
			}
		}
	}
	return fixed
}

// patchedRows runs a statement against the rows the patch closed.
func (r *reach) patchedRows(t *testing.T, statement string) {
	t.Helper()
	if _, err := r.db.ExecContext(t.Context(), statement); err != nil {
		t.Fatal(err)
	}
}

func TestAVEXDocumentSaysFixedWhereTheBuildDeclaresAPatch(t *testing.T) {
	// A build carrying a backport says so in its inventory. The finding closes
	// as patched, and a customer's scanner still matches the upstream version,
	// so the document is what tells it the build is fixed. Silence would read
	// as affected.
	eachReach(t, func(t *testing.T, r *reach) {
		r.patchedKernel(t)
		fixed := r.fixedIn(t)
		if len(fixed) != 1 || len(fixed["CVE-2026-9999"]) != 1 ||
			fixed["CVE-2026-9999"][0] != "pkg:deb/debian/linux-image@5.10" {
			t.Fatalf("the document says %v fixed, want CVE-2026-9999 in the kernel", fixed)
		}

		// A later build without the patch reopens the finding, and the
		// statement goes with it.
		r.scannedTwoIssuesArguing(t, "unpatched", nil)
		if fixed := r.fixedIn(t); len(fixed) != 0 {
			t.Errorf("a build that dropped the patch still says %v fixed", fixed)
		}
	})
}

func TestAVEXDocumentDropsAPatchTheBuildNoLongerDeclares(t *testing.T) {
	// Between the inventory arriving and the scan running, the finding is
	// still closed. The build has already withdrawn the patch, and that is
	// what the document goes by.
	eachReach(t, func(t *testing.T, r *reach) {
		r.patchedKernel(t)
		r.patchedRows(t, `UPDATE "suppression" SET "closed_scan_id" = "opened_scan_id"`)
		if fixed := r.fixedIn(t); len(fixed) != 0 {
			t.Errorf("a patch the build withdrew is still said as %v fixed", fixed)
		}
	})
}

func TestAVEXDocumentSaysNothingFixedAboutAComponentNoLongerShipped(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.patchedKernel(t)
		r.patchedRows(t, `UPDATE "graph_node" SET "closed_scan_id" = "opened_scan_id"
			WHERE "component_id" IN (SELECT "id" FROM "component" WHERE "name" = 'linux-image')`)
		if fixed := r.fixedIn(t); len(fixed) != 0 {
			t.Errorf("a component this build no longer ships is said as %v fixed", fixed)
		}
	})
}

func TestAVEXDocumentSaysNothingFixedWhileAPlaceIsOpen(t *testing.T) {
	// A statement names a component by name and package identifier, which can
	// be more than one component. The kernel at a second version the patch
	// does not reach is open against the issue, and "fixed" beside it would
	// contradict the findings list.
	eachReach(t, func(t *testing.T, r *reach) {
		r.patchedKernel(t)
		const hash = "5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e"
		r.patchedRows(t, `INSERT INTO "component" ("identity", "purl", "name", "version",
				"fold_key", "first_seen_at")
			SELECT '`+hash+`', "purl", "name", '5.10-2', '`+hash+`', "first_seen_at"
			FROM "component" WHERE "name" = 'linux-image'`)
		r.patchedRows(t, `INSERT INTO "finding" ("target_id", "kind", "vulnerability_id",
				"visibility", "component_id", "place_identity", "urgency",
				"urgency_exploited", "urgency_exploited_here", "urgency_shipped",
				"opened_at", "last_changed_at")
			SELECT "target_id", "kind", "vulnerability_id", "visibility",
				(SELECT "id" FROM "component" WHERE "identity" = '`+hash+`'),
				"place_identity", "urgency", "urgency_exploited", "urgency_exploited_here",
				"urgency_shipped", "opened_at", "last_changed_at"
			FROM "finding" WHERE "closed_because" = 'patched'`)
		if fixed := r.fixedIn(t); len(fixed) != 0 {
			t.Errorf("an issue open at another version of the component is said as %v fixed", fixed)
		}
	})
}
