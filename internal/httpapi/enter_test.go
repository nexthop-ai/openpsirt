package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

func TestAFlawInOurOwnProductIsRecordedAndReadBackLikeAnyOther(t *testing.T) {
	// The point of doing this before the reports and the channels: from the
	// moment it is recorded it is an ordinary finding. It appears in the list,
	// it can be assigned, it can be decided — with one difference, which is
	// that nobody outside has been told about it.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const at = "/v1/products/mine/findings"
		// Recording belongs to a build; the list it appears in takes
		// the build as a selection.
		const listing = "/v1/products/mine/findings?stream=master&variant=broadcom"

		// A reader cannot, and neither can somebody who may only argue about
		// known issues in shipped components.
		body := `{"builds":[{"stream":"master","variant":"broadcom"}],` +
			`"summary":"The management socket answers before anyone authenticated.",` +
			`"severity":"critical"}`
		for _, who := range []string{"reader", "triager"} {
			if got := asPerson(t, r, who, http.MethodPost, at, body); got.Code < 400 {
				t.Errorf("%s recorded an undisclosed flaw: %d", who, got.Code)
			}
		}

		got := asPerson(t, r, "private-triage", http.MethodPost, at, body)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", got.Code, got.Body.String())
		}
		var recorded struct {
			Identifier string `json:"identifier"`
			Component  string `json:"component"`
			Visibility string `json:"visibility"`
			DueAt      string `json:"due_at"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatalf("decode: %v (%s)", err, got.Body.String())
		}
		if !strings.HasPrefix(recorded.Identifier, "MINE-2026-") {
			t.Errorf("filed under %q, want one of the product's own identifiers",
				recorded.Identifier)
		}
		if recorded.Visibility != "private" {
			t.Errorf("a flaw nobody announced was recorded as %q", recorded.Visibility)
		}
		if recorded.DueAt == "" {
			t.Error("it carries no deadline, so it is on nobody's clock")
		}

		// And it reads back only for somebody who may see undisclosed work.
		var mine struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
			} `json:"items"`
			Total int `json:"total"`
		}
		read(t, r, "private-triage", listing, &mine)
		var listed bool
		for _, item := range mine.Items {
			if item.Vulnerability == recorded.Identifier {
				listed = true
			}
		}
		if !listed {
			t.Errorf("what was just recorded is not in the list its author can see: %+v",
				mine.Items)
		}

		var theirs struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
			} `json:"items"`
		}
		read(t, r, "triager", listing, &theirs)
		for _, item := range theirs.Items {
			if item.Vulnerability == recorded.Identifier {
				t.Errorf("an undisclosed finding is listed for somebody who may not see one")
			}
		}
	})
}

func TestWhatIsApproachingDisclosureIsAnsweredOnlyToWhoMaySeeIt(t *testing.T) {
	// Every row is a finding nobody has announced, so the list is a disclosure
	// in its own right. A product somebody may not read undisclosed work in
	// contributes nothing to it — not even a count, because a count says as
	// much as a row.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const at = "/v1/products/mine/findings"
		got := asPerson(t, r, "private-triage", http.MethodPost, at,
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"Not announced anywhere.","severity":"critical"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", got.Code, got.Body.String())
		}

		var listed struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
				DiscloseAt    string `json:"disclose_at"`
				Passed        bool   `json:"passed"`
			} `json:"items"`
		}
		read(t, r, "private-triage", "/v1/disclosing?within=365", &listed)
		if len(listed.Items) != 1 {
			t.Fatalf("%d findings are approaching disclosure for somebody who may see them",
				len(listed.Items))
		}
		if listed.Items[0].DiscloseAt == "" {
			t.Error("the row does not say when the embargo ends")
		}
		if listed.Items[0].Passed {
			t.Error("an embargo ninety days out reads as passed")
		}

		for _, who := range []string{"reader", "triager"} {
			var theirs struct {
				Items []struct {
					Vulnerability string `json:"vulnerability"`
				} `json:"items"`
			}
			read(t, r, who, "/v1/disclosing?within=365", &theirs)
			if len(theirs.Items) != 0 {
				t.Errorf("%s was shown %d undisclosed findings", who, len(theirs.Items))
			}
		}
	})
}

func TestMovingADisclosureDateIsRecordedAndGatedTheSameWayADeferralIs(t *testing.T) {
	// A short extension is ordinary triage; past the threshold it needs a
	// second person, and until it has one the date has not moved. The request
	// is on record either way, because what was asked for is part of how long
	// this stayed hidden.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const findings = "/v1/products/mine/findings"
		got := asPerson(t, r, "private-triage", http.MethodPost, findings,
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"Not announced anywhere.","severity":"high"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", got.Code, got.Body.String())
		}
		var recorded struct {
			Identifier string `json:"identifier"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		at := "/v1/products/mine/issues/" + recorded.Identifier + "/disclosure"

		// A reason is required.
		if got := asPerson(t, r, "private-triage", http.MethodPost, at,
			`{"until":"2030-01-01","reason":""}`); got.Code < 400 {
			t.Errorf("an embargo was extended for no stated reason: %d", got.Code)
		}
		// And somebody who may not see undisclosed work cannot move one.
		if got := asPerson(t, r, "triager", http.MethodPost, at,
			`{"until":"2030-01-01","reason":"Because."}`); got.Code < 400 {
			t.Errorf("somebody holding only public triage moved an embargo: %d", got.Code)
		}

		// Years out, so well past the threshold: it waits.
		got = asPerson(t, r, "private-triage", http.MethodPost, at,
			`{"until":"2030-01-01","reason":"Upstream has not answered."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("asking answered %d: %s", got.Code, got.Body.String())
		}
		var asked struct {
			ID            int64 `json:"id"`
			NeedsApproval bool  `json:"needs_approval"`
			InForce       bool  `json:"in_force"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &asked); err != nil {
			t.Fatal(err)
		}
		if !asked.NeedsApproval || asked.InForce {
			t.Errorf("a four-year extension stood on one person's say-so: %+v", asked)
		}

		// The person who asked may not agree to it.
		approval := fmt.Sprintf("/v1/disclosure-extensions/%d/approval", asked.ID)
		if got := asPerson(t, r, "private-triage", http.MethodPost, approval, `{}`); got.Code != http.StatusConflict {
			t.Errorf("agreeing to one's own extension answered %d, want 409", got.Code)
		}

		// The history is kept whether or not anybody agreed.
		var history struct {
			Items []struct {
				Reason  string `json:"reason"`
				InForce bool   `json:"in_force"`
			} `json:"items"`
		}
		read(t, r, "private-triage", at, &history)
		if len(history.Items) != 1 || history.Items[0].Reason == "" {
			t.Fatalf("the record of what was asked reads as %+v", history.Items)
		}
		if history.Items[0].InForce {
			t.Error("an extension nobody agreed to is reported as in force")
		}

		// And there is somewhere to be the second person. Until this, a
		// request could be read on the finding it belongs to and nowhere else,
		// so the only way to find one was to already know it existed.
		var pending struct {
			Items []struct {
				ID            int64  `json:"id"`
				Vulnerability string `json:"vulnerability"`
				Product       string `json:"product"`
				Days          int    `json:"days"`
				By            string `json:"by"`
				Mine          bool   `json:"mine"`
			} `json:"items"`
		}
		read(t, r, "private-dispatcher", "/v1/disclosure-extensions", &pending)
		if len(pending.Items) != 1 || pending.Items[0].ID != asked.ID {
			t.Fatalf("what is waiting to be agreed to reads as %+v", pending.Items)
		}
		if pending.Items[0].Days <= 0 || pending.Items[0].By == "" {
			t.Errorf("the row does not say how much longer, or who asked: %+v", pending.Items[0])
		}
		if pending.Items[0].Mine {
			t.Error("somebody else's request is reported as this reader's own")
		}

		// Their own is shown and marked, because hiding it would leave
		// somebody hunting for what is holding their case up.
		var theirs struct {
			Items []struct {
				Mine bool `json:"mine"`
			} `json:"items"`
		}
		read(t, r, "private-triage", "/v1/disclosure-extensions", &theirs)
		if len(theirs.Items) != 1 || !theirs.Items[0].Mine {
			t.Errorf("a proposer's own request reads as %+v", theirs.Items)
		}

		// Somebody who may not read undisclosed work sees nothing: the list is
		// itself a disclosure, because a row says an issue exists and is being
		// kept hidden longer.
		var public struct {
			Items []struct {
				ID int64 `json:"id"`
			} `json:"items"`
		}
		read(t, r, "triager", "/v1/disclosure-extensions", &public)
		if len(public.Items) != 0 {
			t.Errorf("somebody who may not read undisclosed work sees %+v", public.Items)
		}

		// A request in a product they read nothing undisclosed in is not
		// theirs to see either. Written straight to the table, because no
		// route can make one there — which is the point: the narrowing has to
		// be in the query rather than in what the routes happen to allow.
		theirProduct, err := catalog.NewStore(r.db.DB).ProductByName(t.Context(), "theirs")
		if err != nil {
			t.Fatal(err)
		}
		var issue int64
		if err := r.db.DB.NewSelect().Table("vulnerability").ColumnExpr("id").
			Limit(1).Scan(t.Context(), &issue); err != nil {
			t.Fatal(err)
		}
		// A real person, resolved rather than assumed: identifiers are not the
		// same number on every engine, and a foreign key is enforced on three
		// of the four.
		asker, err := access.NewStore(r.db.DB).Resolve(t.Context(), "admin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.db.DB.NewInsert().Model(&finding.Extension{
			VulnerabilityID: issue, ProductID: theirProduct.ID,
			Was: time.Now().UTC(), Until: time.Now().UTC().AddDate(1, 0, 0),
			Reason: "Somebody else's case.", AskedBy: asker.ID, AskedAt: time.Now().UTC(),
			NeedsApproval: true,
		}).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		read(t, r, "private-triage", "/v1/disclosure-extensions", &pending)
		if len(pending.Items) != 1 {
			t.Errorf("a request in a product they read nothing undisclosed in is listed: %+v",
				pending.Items)
		}

		// A second person agrees, and it leaves the list because it has been
		// answered rather than because anybody dismissed it.
		if got := asPerson(t, r, "private-dispatcher", http.MethodPost,
			approval, `{}`); got.Code != http.StatusNoContent {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}
		read(t, r, "private-dispatcher", "/v1/disclosure-extensions", &pending)
		if len(pending.Items) != 0 {
			t.Errorf("an extension somebody agreed to is still waiting: %+v", pending.Items)
		}
	})
}

// shipsTwice re-applies the build's graph holding one name at two versions,
// which is the ordinary case rather than a contrived one: a real image ships
// three vendored copies of one library.
func (r *reach) shipsTwice(t *testing.T) {
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
		TargetID: target.ID, ContentHash: "two-versions", ParserVersion: "test",
		// Newer than the first, and not ahead of the clock: a build stamped in
		// the future is refused, because accepting one means no later scan is
		// ever newer.
		BuiltAt: time.Now().UTC(),
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}

	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	consumer := graph.Described{
		Purl: "pkg:deb/debian/libswsscommon@1.0.0", Name: "libswsscommon", Version: "1.0.0",
	}
	older := graph.Described{
		Purl: "pkg:deb/debian/libnl-3-200@3.7.0", Name: "libnl-3-200", Version: "3.7.0",
	}
	newer := graph.Described{
		Purl: "pkg:deb/debian/libnl-3-200@3.9.0", Name: "libnl-3-200", Version: "3.9.0",
	}
	if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root:       product,
		Components: []graph.Described{consumer, older, newer},
		Dependencies: []graph.Dependency{
			{Parent: product, Child: consumer},
			{Parent: consumer, Child: older},
			{Parent: consumer, Child: newer},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestANameTheBuildHoldsTwiceIsRefusedWithTheChoicesToPickFrom(t *testing.T) {
	// The screen recording a flaw offers the choices back, so what it needs is
	// which versions rather than only that it could not tell. Resolving to one
	// of them would file a flaw against a version nobody named and say nothing.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		r.shipsTwice(t)
		const at = "/v1/products/mine/findings"
		const said = `"summary":"The parser accepts a message it should refuse.","severity":"high"`

		got := asPerson(t, r, "private-triage", http.MethodPost, at,
			`{"builds":[{"stream":"master","variant":"broadcom"}],`+said+`,"component":"libnl-3-200"}`)
		if got.Code != http.StatusConflict {
			t.Fatalf("an ambiguous name answered %d: %s", got.Code, got.Body.String())
		}
		var refused struct {
			Errors []struct {
				Location string            `json:"location"`
				Message  string            `json:"message"`
				Value    map[string]string `json:"value"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &refused); err != nil {
			t.Fatalf("decode: %v (%s)", err, got.Body.String())
		}
		if len(refused.Errors) != 2 {
			t.Fatalf("the refusal offers %d choices, want both: %s", len(refused.Errors),
				got.Body.String())
		}
		// The ecosystem travels with each, because a version alone does not
		// always resolve one — a source repository and the package built from
		// it share both a name and a version.
		for _, choice := range refused.Errors {
			if choice.Value["ecosystem"] == "" {
				t.Errorf("choice %q offers no ecosystem", choice.Message)
			}
		}

		// Named, it is recorded against that one.
		made := asPerson(t, r, "private-triage", http.MethodPost, at,
			`{"builds":[{"stream":"master","variant":"broadcom"}],`+said+`,"component":"libnl-3-200","version":"3.9.0"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("naming the version answered %d: %s", made.Code, made.Body.String())
		}
	})
}

func TestASummaryOfNothingButSpacesIsTheCallersToFix(t *testing.T) {
	// Whitespace passes a minimum length, so this reaches the store, and the
	// store's refusal is the caller's to fix rather than a 500 saying
	// something went wrong here. Nothing went wrong here.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		got := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/findings",
			`{"summary":"   ","severity":"high"}`)
		if got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a summary of spaces answered %d, want it named as the caller's to fix: %s",
				got.Code, got.Body.String())
		}
	})
}

func TestAVectorThisCannotScoreIsTheCallersToFix(t *testing.T) {
	// A caller's input, answered as theirs. Falling through to the generic
	// refusal tells somebody to report a fault when what they have to do is
	// send a different vector — and this is the endpoint whose own comment
	// says so about every other refusal it makes.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const at = "/v1/products/mine/findings"
		got := asPerson(t, r, "private-triage", http.MethodPost, at,
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"Something is wrong.",`+
				`"vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}`)
		if got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a version this cannot score answered %d, want it named as the caller's"+
				" to fix: %s", got.Code, got.Body.String())
		}
	})
}

func TestAFlawMayBeRecordedBeforeAnybodyHasRatedIt(t *testing.T) {
	// Early triage. Making somebody pick a severity to get the record written
	// is how a guess ends up stored as a judgment.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const at = "/v1/products/mine/findings"
		got := asPerson(t, r, "private-triage", http.MethodPost, at,
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"Found during early triage; how bad it is comes later."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("an unrated flaw answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestAVectorSettlesTheSeverityRatherThanBeingAskedTwice(t *testing.T) {
	// Somebody who has done the analysis has already answered this, and asking
	// again invites a word that disagrees with the vector beside it.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const at = "/v1/products/mine/findings"
		made := asPerson(t, r, "private-triage", http.MethodPost, at,
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"The management socket answers before anyone authenticated.",`+
				`"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",`+
				`"weaknesses":["CWE-306","cwe-306","  "]}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", made.Code, made.Body.String())
		}
		var recorded struct {
			Identifier string `json:"identifier"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		var listed struct {
			Items []struct {
				Vulnerability string  `json:"vulnerability"`
				Severity      string  `json:"severity"`
				Score         float64 `json:"score"`
			} `json:"items"`
		}
		read(t, r, "private-triage",
			"/v1/products/mine/findings?stream=master&variant=broadcom", &listed)
		for _, item := range listed.Items {
			if item.Vulnerability != recorded.Identifier {
				continue
			}
			// 9.8 by the published formula, which is "critical".
			if item.Severity != "critical" {
				t.Errorf("the vector said critical and the finding reads %q", item.Severity)
			}
			if item.Score < 9.7 || item.Score > 9.9 {
				t.Errorf("the score is %v, want the 9.8 the vector works out to", item.Score)
			}
			return
		}
		t.Error("what was recorded is not in the list")
	})
}

func TestAHiddenIssueAndAnAbsentOneAnswerTheSameOnEveryRoute(t *testing.T) {
	// authorizing before resolving a name applied to issues. Every route
	// shaped "this issue, at this place" resolved the name first and
	// checked what it reached second, so a name somebody holds and a name
	// nobody holds came back differently — and on two of them the check
	// that came second was not a refusal at all: a fix target answered an
	// empty list and an assignment answered "done" while writing nothing.
	// Both disclose by succeeding.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		// An undisclosed flaw somebody recorded, at a component the prober can
		// otherwise read.
		recorded := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/findings",
			`{"builds":[{"stream":"master","variant":"broadcom"}],`+
				`"summary":"The management socket answers before anyone authenticated.",`+
				`"severity":"critical"}`)
		if recorded.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", recorded.Code, recorded.Body.String())
		}
		var flaw struct {
			Identifier string `json:"identifier"`
			Component  string `json:"component"`
		}
		if err := json.Unmarshal(recorded.Body.Bytes(), &flaw); err != nil {
			t.Fatalf("decode: %v (%s)", err, recorded.Body.String())
		}
		// A name of the same shape that nobody has ever issued.
		absent := "MINE-2026-404404"
		if flaw.Identifier == absent {
			t.Fatalf("the drawn identifier collided with the one used as absent")
		}

		const build = "/v1/products/mine/streams/master/variants/broadcom"
		routes := []struct {
			what   string
			method string
			path   string
			body   string
		}{
			{"the finding itself", http.MethodGet,
				build + "/findings/%s/components/" + flaw.Component, ""},
			{"a decision about it", http.MethodPost,
				build + "/findings/%s/components/" + flaw.Component + "/decision",
				`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",` +
					`"reasoning":"Probing."}`},
			{"who is holding it", http.MethodPut,
				build + "/findings/%s/components/" + flaw.Component + "/assignment",
				`{"person":"reader"}`},
			{"closing it", http.MethodPost, build + "/findings/%s/resolve",
				`{"because":"invalid"}`},
			{"extending the embargo", http.MethodPost,
				"/v1/products/mine/issues/%s/disclosure",
				`{"until":"2027-01-01T00:00:00Z","reason":"Probing for the date."}`},
			{"its attachments", http.MethodGet,
				"/v1/products/mine/issues/%s/attachments", ""},
			{"when it is disclosed", http.MethodGet,
				"/v1/products/mine/issues/%s/disclosure", ""},
			{"which builds it affects", http.MethodPut,
				"/v1/products/mine/issues/%s/builds",
				`{"builds":[{"stream":"master","variant":"broadcom"}]}`},
		}

		// The prober triages this product and may not read undisclosed work,
		// which is the credential the leak was demonstrated with.
		for _, route := range routes {
			hidden := asPerson(t, r, "triager", route.method,
				fmt.Sprintf(route.path, flaw.Identifier), route.body)
			unused := asPerson(t, r, "triager", route.method,
				fmt.Sprintf(route.path, absent), route.body)

			if hidden.Code != unused.Code {
				t.Errorf("%s: a hidden issue answers %d and an unused name %d",
					route.what, hidden.Code, unused.Code)
			}
			if hidden.Code < 400 {
				t.Errorf("%s: probing a hidden issue succeeded with %d: %s",
					route.what, hidden.Code, hidden.Body.String())
			}
			if hidden.Body.String() != unused.Body.String() {
				t.Errorf("%s: the two answers read differently\n hidden: %s\n unused: %s",
					route.what, hidden.Body.String(), unused.Body.String())
			}
		}
	})
}

func TestARecordedSummaryGoesThroughTheSamePolicyAsAJustification(t *testing.T) {
	// our own prose rendered says a summary somebody types goes through
	// the same editor and the same submission policy as a justification.
	// It went through neither: no scheme check, no refusal of raw HTML,
	// and no bound on length at all — and it is rendered as markdown where
	// it is read back, which is what makes the first two matter and what
	// makes the third a rendering nobody bounded.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const at = "/v1/products/mine/findings"
		body := func(summary string) string {
			return `{"builds":[{"stream":"master","variant":"broadcom"}],` +
				`"summary":` + quotedJSON(summary) + `,"severity":"high",` +
				`"component":"libnl-3-200"}`
		}

		for _, each := range []struct{ why, summary string }{
			{"a link nothing here may follow",
				"The socket answers early. [detail](javascript:alert(1))"},
			{"raw markup", "The socket answers early.<script>alert(1)</script>"},
		} {
			got := asPerson(t, r, "private-triage", http.MethodPost, at, body(each.summary))
			if got.Code < 400 {
				t.Errorf("%s was accepted in a recorded summary: %d", each.why, got.Code)
			}
		}

		// And the ordinary case still lands, so the checks above are not
		// passing because everything is refused.
		if got := asPerson(t, r, "private-triage", http.MethodPost, at,
			body("The management socket answers before anyone has authenticated.")); got.Code != http.StatusCreated {
			t.Errorf("an ordinary summary answered %d: %s", got.Code, got.Body.String())
		}
	})
}

// quotedJSON is a JSON string literal for text a test is embedding.
func quotedJSON(s string) string {
	encoded, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}
