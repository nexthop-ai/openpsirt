package httpapi_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// Dealing with something: giving work out, taking it back, and what each of
// the three rights it takes may actually do.

func TestWorkNobodyOwnsCanBeFoundAndGivenToSomebody(t *testing.T) {
	// Work falling between people is what hides when every screen shows one
	// product: assigned, so not in the shared list; assigned to nobody who is
	// looking, so not in anybody's own.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"

		var waiting struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
				Component     string `json:"component"`
				Product       string `json:"product"`
			} `json:"items"`
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/unassigned", &waiting)
		if waiting.Total != 1 || len(waiting.Items) != 1 {
			t.Fatalf("%d findings are waiting for an owner, want 1", waiting.Total)
		}
		if waiting.Items[0].Component != "libnl-3-200" || waiting.Items[0].Product != "Mine" {
			t.Errorf("the unassigned row does not say what it is: %+v", waiting.Items[0])
		}

		if got := asPerson(t, r, "assigner", http.MethodPut, at,
			`{"person":"reader"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}

		read(t, r, "triager", "/v1/unassigned", &waiting)
		if waiting.Total != 0 {
			t.Errorf("%d findings still have no owner after being assigned", waiting.Total)
		}

		var holdings struct {
			Items []struct {
				Person string `json:"person"`
				Open   int    `json:"open"`
			} `json:"items"`
		}
		read(t, r, "triager", "/v1/assignments", &holdings)
		if len(holdings.Items) != 1 || holdings.Items[0].Person != "reader" {
			t.Fatalf("who is holding what reads as %+v", holdings.Items)
		}

		// Handing it back is the same action, not a different one — and it is
		// somebody else's work here, so it is the assigner's to hand back.
		// A triager hands back their own; taking something off a colleague,
		// including to leave it unowned, is what the other right names.
		if got := asPerson(t, r, "assigner", http.MethodPut, at,
			`{"person":""}`); got.Code != http.StatusNoContent {
			t.Fatalf("handing it back answered %d: %s", got.Code, got.Body.String())
		}
		read(t, r, "triager", "/v1/unassigned", &waiting)
		if waiting.Total != 1 {
			t.Errorf("handing it back left %d waiting for an owner", waiting.Total)
		}
	})
}

func TestSomethingUndisclosedReachesOnlyWhoMayReadIt(t *testing.T) {
	// The message names the issue, the component and the build, and it is
	// stored as written — so there is no filter downstream that could
	// repair it, and the check belongs at the moment of telling. Gating it
	// on the product being visible handed the name of an embargoed finding
	// to anybody holding public reading there: the announcement an embargo
	// exists to prevent, sent by the act of assigning it.
	//
	// The assignment itself is now refused for the same population, which
	// a capability without a read role settled after this was written: an
	// assignment carries visibility of what was assigned, so handing an
	// embargoed finding to somebody cleared for nothing embargoed would
	// make the assignment the disclosure. The check on this channel stays
	// — it is a different check at a different moment, and a channel that
	// leaks only when another rule is wrong is a channel nobody notices is
	// leaking.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("visibility = ?", "private").
			Where("1 = 1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"
		// The identity holding private triage and the assigner right,
		// because giving work to somebody else asks for both and this
		// test is about what the recipient is told rather than about
		// who may hand it over. An administrator used to stand here
		// and no longer holds either .
		refused := asPerson(t, r, "private-dispatcher", http.MethodPut, at,
			`{"person":"reader"}`)
		if refused.Code != http.StatusUnprocessableEntity {
			t.Fatalf("handing an embargoed finding to somebody who may not read one "+
				"answered %d: %s", refused.Code, refused.Body.String())
		}

		type waiting struct {
			Items []struct {
				Body string `json:"body"`
			} `json:"items"`
			Total int `json:"total"`
		}
		var told waiting
		read(t, r, "reader", "/v1/notifications", &told)
		for _, item := range told.Items {
			if strings.Contains(item.Body, "CVE-2026-9999") {
				t.Errorf("somebody who may not read undisclosed findings was told about one: %q",
					item.Body)
			}
		}

		// And somebody who may read them is told, so the rule narrows rather
		// than silences.
		if got := asPerson(t, r, "private-dispatcher", http.MethodPut, at,
			`{"person":"private"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}
		var reached waiting
		read(t, r, "private", "/v1/notifications", &reached)
		named := false
		for _, item := range reached.Items {
			if strings.Contains(item.Body, "CVE-2026-9999") {
				named = true
			}
		}
		if !named {
			t.Error("somebody who may read undisclosed findings was told nothing")
		}
	})
}

func TestTheAssignerRightAloneHandsNobodyAnything(t *testing.T) {
	// Assigning is triage *and* the assigner right, not either. The role
	// by itself is held by somebody who may not argue about this product's
	// findings at all, and handing work around a product you cannot reach
	// is the reach the visibility rules exist to refuse — so the endpoint
	// answers as though the finding were not there.
	//
	// Pinned in both places a client could learn it: the refusal itself,
	// and what /v1/session/me says the caller may do. A screen that drew
	// the control from a widened may_assign would offer an action that
	// always fails.
	//
	// The refusal is enforced twice — at the endpoint and again in the
	// store — so this assertion only moves when both go. The store's own
	// half is broken and watched in internal/finding.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"

		if got := asPerson(t, r, "dispatcher", http.MethodPut, at,
			`{"person":"reader"}`); got.Code < 400 {
			t.Errorf("the assigner role alone assigned work: %d", got.Code)
		}
		// Nor to themselves, which is the exception triage carries and this
		// identity does not hold.
		if got := asPerson(t, r, "dispatcher", http.MethodPut, at,
			`{"person":"dispatcher"}`); got.Code < 400 {
			t.Errorf("the assigner role alone took work: %d", got.Code)
		}

		var told struct {
			Reach []struct {
				Product   string `json:"product"`
				MayAssign bool   `json:"may_assign"`
				MayTriage bool   `json:"may_triage"`
			} `json:"reach"`
		}
		read(t, r, "dispatcher", "/v1/session/me", &told)
		for _, each := range told.Reach {
			if each.MayAssign {
				t.Errorf("%s is offered assignment to somebody who may not triage it", each.Product)
			}
			if each.MayTriage {
				t.Errorf("%s is offered triage to somebody holding only the assigner role", each.Product)
			}
		}
	})
}

func TestOnlyAnAdministratorMovesSomebodyElsesWork(t *testing.T) {
	// A person hands back their own by assigning it to nobody. Moving what
	// somebody else was given is an administrative act, and it is the one that
	// matters when they have gone.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"
		if got := asPerson(t, r, "assigner", http.MethodPut, at,
			`{"person":"reader"}`); got.Code != http.StatusNoContent {
			t.Fatal(got.Body.String())
		}

		release := "/v1/people/reader/assignments/hand-back"
		if got := asPerson(t, r, "triager", http.MethodPost, release, `{}`); got.Code < 400 {
			t.Errorf("a triager released somebody else's work: %d", got.Code)
		}

		got := asPerson(t, r, "admin", http.MethodPost, release, `{}`)
		if got.Code != http.StatusOK {
			t.Fatalf("an administrator releasing work answered %d: %s", got.Code, got.Body.String())
		}
		var moved struct {
			Moved int64 `json:"moved"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &moved); err != nil {
			t.Fatal(err)
		}
		if moved.Moved == 0 {
			t.Error("releasing an absent person's work moved nothing")
		}
	})
}

// scannedAlso is a second build of the same product, holding the same issue at
// the same place, with the library at the given version.
func (r *reach) scannedAlso(t *testing.T, variant, version string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.db.DB)
	first, err := names.Locate(ctx, "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	declared, err := names.DeclareVariant(ctx, first.ProductID, variant, true)
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, first.StreamID, declared.ID)
	if err != nil {
		t.Fatal(err)
	}
	scan, outcome, err := ingest.NewStore(r.db.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "also-" + variant, BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	library := graph.Described{
		Purl: "pkg:deb/debian/libnl-3-200@" + version, Name: "libnl-3-200", Version: version,
	}
	if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root:         product,
		Components:   []graph.Described{library},
		Dependencies: []graph.Dependency{{Parent: product, Child: library}},
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
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{{
		Issue:     finding.Named{Identifier: "CVE-2026-9999", Severity: "high"},
		Component: library,
		FixState:  finding.FixedUpstream, FixedIn: "3.9.0",
	}}); err != nil {
		t.Fatal(err)
	}
}

func TestWithdrawingSomebodysLastRoleHandsBackWhatTheyHeld(t *testing.T) {
	// Otherwise their work is in no list at all: assigned, so not in the
	// shared one, and assigned to somebody who can no longer open it.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"
		if got := asPerson(t, r, "triager", http.MethodPut, at,
			`{"person":"triager"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}

		var holdings struct {
			Items []struct {
				Person string `json:"person"`
				Open   int    `json:"open"`
			} `json:"items"`
		}
		// Read as the administrator who granted themselves reading:
		// who holds how much open work is a count of findings, which
		// administering does not reach. Withdrawing the role below is
		// administration and is still done as the plain administrator,
		// which is the split.
		read(t, r, "admin-reader", "/v1/assignments", &holdings)
		if len(holdings.Items) == 0 {
			t.Fatal("nothing was assigned to begin with")
		}

		got := asPerson(t, r, "admin", http.MethodDelete,
			"/v1/people/triager/roles/mine/public-triage", "")
		if got.Code != http.StatusOK {
			t.Fatalf("withdrawing a role answered %d: %s", got.Code, got.Body.String())
		}
		var withdrawn struct {
			Released int64 `json:"released"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &withdrawn); err != nil {
			t.Fatal(err)
		}
		if withdrawn.Released == 0 {
			t.Error("withdrawing their last role here handed nothing back")
		}

		read(t, r, "admin", "/v1/assignments", &holdings)
		if len(holdings.Items) != 0 {
			t.Errorf("%d people still hold work here after losing their role",
				len(holdings.Items))
		}
	})
}

func TestHandingWorkBackToYourselfDoesNotNeedTheRightToGiveItAway(t *testing.T) {
	// An identity is stored folded and a person types their own name with the
	// capitals they use. Compared exactly, "Triager" was not "triager", so
	// somebody taking their own work — or handing it back — was told they
	// needed the right that names giving work to somebody else.
	//
	// Two sites, because the same comparison is made twice: assigning one
	// finding, and planning an upgrade across a component.
	twoReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"

		// "triager" holds triage and deliberately not the right to give work
		// away, which is what makes this the case being pinned.
		for _, spelled := range []string{"triager", "Triager", "TRIAGER", " triager "} {
			got := asPerson(t, r, "triager", http.MethodPut, at,
				`{"person":`+strconv.Quote(spelled)+`}`)
			if got.Code >= 300 {
				t.Errorf("taking their own work as %q answered %d: %s",
					spelled, got.Code, got.Body.String())
			}
		}

		// And the rule still holds for somebody else, which is what makes the
		// above a spelling rather than a hole.
		if got := asPerson(t, r, "triager", http.MethodPut, at,
			`{"person":"reader"}`); got.Code < 300 {
			t.Errorf("somebody without the right gave work away, answering %d", got.Code)
		}
		_ = place
	})
}

// TestATeamsQueueCanBeOpened pins the list behind a team's own number.
//
// Auto-assignment and an assignment naming a team both put work into a team's
// queue, and the totals list said the team was holding it. Nothing could open
// it: the drill-down resolved an identity, so a team's name matched nobody and
// the screen answered "they are not holding anything" over work it had just
// counted. Worse than an absent view, because it answered.
func TestATeamsQueueCanBeOpened(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"platform","display_name":"Platform","members":["triager"]}`); made.Code >= 300 {
			t.Fatalf("declaring a team answered %d: %s", made.Code, made.Body.String())
		}
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"
		if got := asPerson(t, r, "assigner", http.MethodPut, at,
			`{"team":"platform"}`); got.Code != http.StatusNoContent {
			t.Fatalf("routing work to a team answered %d: %s", got.Code, got.Body.String())
		}

		// The totals list says the team holds it.
		var holdings struct {
			Items []struct {
				Person string `json:"person"`
				Team   bool   `json:"team"`
				Open   int    `json:"open"`
			} `json:"items"`
		}
		read(t, r, "triager", "/v1/assignments", &holdings)
		if len(holdings.Items) != 1 || !holdings.Items[0].Team || holdings.Items[0].Open == 0 {
			t.Fatalf("who is holding what reads as %+v", holdings.Items)
		}

		// And the list behind that number holds the same work.
		var queue struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
				Component     string `json:"component"`
			} `json:"items"`
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/teams/platform/assignments", &queue)
		if queue.Total != holdings.Items[0].Open {
			t.Errorf("the team's queue holds %d and the total beside it says %d",
				queue.Total, holdings.Items[0].Open)
		}
		if len(queue.Items) != 1 || queue.Items[0].Component != "libnl-3-200" {
			t.Fatalf("the team's queue reads as %+v", queue.Items)
		}

		// A name nothing matches holds nothing rather than being refused:
		// refusing would answer "is there a team called this" for any
		// credential at all.
		read(t, r, "triager", "/v1/teams/no-such-team/assignments", &queue)
		if queue.Total != 0 {
			t.Errorf("a team nobody declared holds %d pieces of work", queue.Total)
		}
	})
}
