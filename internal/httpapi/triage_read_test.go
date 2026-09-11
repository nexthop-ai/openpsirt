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
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// scanned puts a build behind the handler: one component under the product,
// with one issue reported against it. Reading what has been decided is only
// testable against something that was found.
func (r *reach) scanned(t *testing.T) (place string) {
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
		TargetID: target.ID, ContentHash: "read-test", BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}

	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	library := graph.Described{
		Purl: "pkg:deb/debian/libnl-3-200@3.7.0", Name: "libnl-3-200", Version: "3.7.0",
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

	// Under the product itself, the component stands alone.
	return finding.PlaceIdentity("libnl-3-200", "")
}

// scannedWithEvidence is a build whose one finding carries everything a report
// can carry, so a test can ask whether any of it survives the trip.
func (r *reach) scannedWithEvidence(t *testing.T) {
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
		TargetID: target.ID, ContentHash: "evidence-test", BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}

	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	consumer := graph.Described{
		Purl: "pkg:deb/debian/libswsscommon@1.0.0", Name: "libswsscommon", Version: "1.0.0",
	}
	library := graph.Described{
		Purl: "pkg:deb/debian/libnl-3-200@3.7.0", Name: "libnl-3-200", Version: "3.7.0",
	}
	if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root:       product,
		Components: []graph.Described{consumer, library},
		Dependencies: []graph.Dependency{
			{Parent: product, Child: consumer}, {Parent: consumer, Child: library},
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
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{{
		Issue: finding.Named{
			Identifier:  "CVE-2026-9999",
			Severity:    "high",
			Description: "A crafted attribute length causes a read past the end of the buffer.",
			Advisory:    "https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
			References: []finding.Reference{
				{URL: "https://github.com/thom311/libnl/commit/abc123", Kind: finding.Patch},
				{URL: "https://example.org/write-up", Kind: finding.AdvisoryRef},
			},
			Exploited:  true,
			Likelihood: 0.86,
			Score:      8.1,
			Vector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
			Weaknesses: []string{"CWE-125"},
		},
		Component: library,
		FixState:  finding.FixedUpstream, FixedIn: "3.9.0",
	}}); err != nil {
		t.Fatal(err)
	}
}

// decided proposes a claim through the API and returns its identifier.
func (r *reach) decided(t *testing.T, place string) int64 {
	t.Helper()
	id, _ := r.decidedAt(t, place)
	return id
}

// decidedAt records one judgment and answers with the row it wrote and the
// claim it belongs to. What the judgment says — and so what may be revised,
// agreed to, commented on or withdrawn — is the claim's.
func (r *reach) decidedAt(t *testing.T, place string) (decision, claim int64) {
	t.Helper()
	path := fmt.Sprintf("/v1/products/mine/streams/master/variants/broadcom"+
		"/findings/CVE-2026-9999/places/%s/decision", place)
	got := asPerson(t, r, "triager", http.MethodPost, path,
		`{"outcome":"not-applicable","justification":"vulnerable_code_not_in_execute_path",`+
			`"reasoning":"The parser is never reached: we only call the encoder."}`)
	if got.Code != http.StatusCreated {
		t.Fatalf("proposing answered %d: %s", got.Code, got.Body.String())
	}
	var out struct {
		ID      int64 `json:"id"`
		ClaimID int64 `json:"claim_id"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, got.Body.String())
	}
	if out.ClaimID == 0 {
		t.Fatalf("a judgment came back without the claim it made: %s", got.Body.String())
	}
	return out.ID, out.ClaimID
}

func TestEverythingWrittenAboutADecisionCanBeReadBack(t *testing.T) {
	// The gap this closes. A tool that lets somebody argue, agree and annotate
	// and then offers no way to see what any of it produced sends every reader
	// to the review queue — which by definition no longer holds what was
	// agreed to.
	eachReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		id, claim := r.decidedAt(t, place)

		if got := asPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/comments", claim),
			`{"body":"Re-checked against 3.7.0; still true."}`); got.Code != http.StatusCreated {
			t.Fatalf("commenting answered %d: %s", got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}

		// The decision itself, saying what it is about rather than by number.
		var detail struct {
			Decision struct {
				Outcome string `json:"outcome"`
				State   string `json:"state"`
			} `json:"decision"`
			Place struct {
				Product       string `json:"product"`
				Vulnerability string `json:"vulnerability"`
				Place         string `json:"place"`
			} `json:"place"`
			Reasoning  string `json:"reasoning"`
			ProposedBy string `json:"proposed_by"`
		}
		read(t, r, "triager", fmt.Sprintf("/v1/decisions/%d", id), &detail)
		if detail.Decision.State != "approved" {
			t.Errorf("the decision reads as %q after being approved", detail.Decision.State)
		}
		// "Mine" rather than "mine": what comes back is the spelling somebody
		// declared, not the normalized form we match on.
		if detail.Place.Product != "Mine" || detail.Place.Vulnerability != "CVE-2026-9999" {
			t.Errorf("the decision does not say what it is about: %+v", detail.Place)
		}
		if detail.Reasoning == "" {
			t.Error("the decision came back with no reasoning to read")
		}
		if detail.ProposedBy != "triager" {
			t.Errorf("proposed by %q, want the person who made the claim", detail.ProposedBy)
		}

		// The reasoning, the agreement, and the discussion, each on its own.
		var revisions struct {
			Items []struct {
				ID        int64  `json:"id"`
				Body      string `json:"body"`
				WrittenBy string `json:"written_by"`
			} `json:"items"`
		}
		read(t, r, "triager", fmt.Sprintf("/v1/claims/%d/revisions", claim), &revisions)
		if len(revisions.Items) != 1 || revisions.Items[0].WrittenBy != "triager" {
			t.Errorf("the reasoning history reads as %+v", revisions.Items)
		}

		var approvals struct {
			Items []struct {
				RevisionID int64  `json:"revision_id"`
				ApprovedBy string `json:"approved_by"`
			} `json:"items"`
		}
		read(t, r, "triager", fmt.Sprintf("/v1/claims/%d/approvals", claim), &approvals)
		if len(approvals.Items) != 1 || approvals.Items[0].ApprovedBy != "reviewer" {
			t.Fatalf("who agreed reads as %+v", approvals.Items)
		}
		// The agreement names the words that were agreed to, which is the
		// whole point of keeping revisions.
		if approvals.Items[0].RevisionID != revisions.Items[0].ID {
			t.Error("the approval does not name a revision anybody can read")
		}

		var comments struct {
			Items []struct {
				Body      string `json:"body"`
				WrittenBy string `json:"written_by"`
			} `json:"items"`
		}
		read(t, r, "triager", fmt.Sprintf("/v1/claims/%d/comments", claim), &comments)
		if len(comments.Items) != 1 || comments.Items[0].WrittenBy != "triager" {
			t.Errorf("the discussion reads as %+v", comments.Items)
		}
	})
}

func TestWhatWasDismissedCanBeListed(t *testing.T) {
	// The question somebody auditing asks: what have we decided not to fix,
	// and on what grounds. Without it the only list of decisions is the review
	// queue, which holds exactly the ones nobody has agreed to yet.
	eachReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		r.decided(t, place)

		var listed struct {
			Items []struct {
				Decision struct {
					Outcome string `json:"outcome"`
				} `json:"decision"`
				Reasoning string `json:"reasoning"`
			} `json:"items"`
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/decisions?outcome=not-applicable", &listed)
		if listed.Total != 1 || len(listed.Items) != 1 {
			t.Fatalf("%d dismissals listed, want 1", listed.Total)
		}
		if listed.Items[0].Reasoning == "" {
			t.Error("a dismissal listed without the reason it was dismissed for")
		}

		// A filter that matches nothing says so rather than falling back to
		// everything, which is how a filtered list becomes dangerous.
		var none struct {
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/decisions?outcome=wont-fix", &none)
		if none.Total != 0 {
			t.Errorf("filtering by an outcome nothing has returned %d", none.Total)
		}
	})
}

func TestAClaimReadsWholeRatherThanThroughARow(t *testing.T) {
	// A claim is one argument however many rows it wrote, and the page people
	// act on is the claim. Read through a representative row, its state stood
	// in for the claim's — which is how one row approved beside forty-three
	// sent back read as approved.
	eachReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		_, claim := r.decidedAt(t, place)

		var whole struct {
			Claim struct {
				ID         int64  `json:"id"`
				Kind       string `json:"kind"`
				ProposedBy string `json:"proposed_by"`
			} `json:"claim"`
			Argument struct {
				ID            int64  `json:"id"`
				ClaimID       int64  `json:"claim_id"`
				Outcome       string `json:"outcome"`
				Justification string `json:"justification"`
				Reasoning     string `json:"reasoning"`
				State         string `json:"state"`
			} `json:"argument"`
			Place struct {
				Product       string `json:"product"`
				Vulnerability string `json:"vulnerability"`
			} `json:"place"`
			Happened           string   `json:"happened"`
			By                 string   `json:"by"`
			PreviouslyApproved bool     `json:"previously_approved"`
			Rows               int      `json:"rows"`
			Issues             int      `json:"issues"`
			Places             int      `json:"places"`
			Folds              int      `json:"folds"`
			Packages           int      `json:"packages"`
			Consumers          int      `json:"consumers"`
			Findings           int      `json:"findings"`
			Builds             []string `json:"builds"`
		}
		read(t, r, "triager", fmt.Sprintf("/v1/claims/%d", claim), &whole)

		if whole.Claim.ID != claim || whole.Claim.Kind != "finding" {
			t.Errorf("the claim reads as %+v", whole.Claim)
		}
		if whole.Claim.ProposedBy != "triager" {
			t.Errorf("proposed by %q, want the person who made the claim", whole.Claim.ProposedBy)
		}
		if whole.Argument.Outcome != "not-applicable" ||
			whole.Argument.Justification != "vulnerable_code_not_in_execute_path" {
			t.Errorf("what the claim says reads as %+v", whole.Argument)
		}
		// The argument is the claim's, so it names no row and carries no row
		// state. Anything acting on one of those would be acting at the wrong
		// grain, and the claim page is where every act lives.
		if whole.Argument.ID != 0 || whole.Argument.State != "" {
			t.Errorf("the argument carries a row: %+v", whole.Argument)
		}
		if whole.Argument.ClaimID != claim {
			t.Errorf("the argument belongs to claim %d, want %d", whole.Argument.ClaimID, claim)
		}
		if whole.Place.Vulnerability != "CVE-2026-9999" || whole.Place.Product != "Mine" {
			t.Errorf("the claim does not say what it is about: %+v", whole.Place)
		}
		if whole.Argument.Reasoning == "" {
			t.Error("the claim came back with no reasoning to read")
		}
		if whole.Happened != "waiting" || whole.By != "" {
			t.Errorf("a claim nobody has answered reads as %q by %q", whole.Happened, whole.By)
		}
		if whole.Rows != 1 || whole.Issues != 1 || whole.Places != 1 {
			t.Errorf("what the claim wrote reads as %d rows, %d issues, %d places",
				whole.Rows, whole.Issues, whole.Places)
		}
		// What it covers now, in the units somebody acts in. One judgment at
		// one fold, over the one package that fold holds here, under whatever
		// pulls it in — never a place count, which is a unit nobody acted in.
		if whole.Folds != 1 || whole.Packages != 1 || whole.Consumers != 1 ||
			whole.Findings != 1 {
			t.Errorf("what it covers reads as %d folds, %d packages, %d consumers, "+
				"%d findings", whole.Folds, whole.Packages, whole.Consumers, whole.Findings)
		}
		if len(whole.Builds) != 1 {
			t.Errorf("the builds it covers read as %v", whole.Builds)
		}

		// Agreed to, and the claim says so as a whole with who did it.
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}
		read(t, r, "triager", fmt.Sprintf("/v1/claims/%d", claim), &whole)
		if whole.Happened != "approved" || whole.By != "reviewer" {
			t.Errorf("an agreed claim reads as %q by %q", whole.Happened, whole.By)
		}
		// "Agreed to before and came back" is about a claim waiting again. A
		// claim standing on an agreement has an approval on record, and
		// reading that as having come back tells whoever opens it that they
		// are re-reading something nobody has answered.
		if whole.PreviouslyApproved {
			t.Error("a claim that was just agreed to reads as having come back")
		}
	})
}

func TestTheRecordIsReadableAtTheFindingsVisibility(t *testing.T) {
	// Reading what was decided asked whether the reader may decide or
	// approve, which is narrower than disclosure opening the record: the
	// whole record — comments, decisions, actors — goes public when a
	// private issue is disclosed, and under the old rule that was true
	// only for people who could already see it. A reader saw "deferred"
	// with no way to see why or by whom.
	//
	// Every read is still narrowed. A decision on a product somebody may
	// not read answers as one that is not there, so guessing identifiers
	// says nothing, and acting on it is unchanged.
	eachReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		id, claim := r.decidedAt(t, place)

		// Holding the approver capability and nothing to read it against
		// reaches nothing, which is what makes a capability a capability.
		if got := asPerson(t, r, "approver", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code != http.StatusNotFound {
			t.Errorf("an approver with no visibility approved: %d", got.Code)
		}
		for _, path := range []string{
			fmt.Sprintf("/v1/decisions/%d", id),
			fmt.Sprintf("/v1/claims/%d", claim),
			fmt.Sprintf("/v1/claims/%d/revisions", claim),
			fmt.Sprintf("/v1/claims/%d/approvals", claim),
			fmt.Sprintf("/v1/claims/%d/comments", claim),
		} {
			if got := asPerson(t, r, "approver", http.MethodGet, path, ""); got.Code != http.StatusNotFound {
				t.Errorf("%s answered %d to somebody who reads nothing, want 404", path, got.Code)
			}
		}

		// Somebody who may read the finding reads its record, all four parts
		// of it, though they may argue about none of it.
		for _, path := range []string{
			fmt.Sprintf("/v1/decisions/%d", id),
			fmt.Sprintf("/v1/claims/%d", claim),
			fmt.Sprintf("/v1/claims/%d/revisions", claim),
			fmt.Sprintf("/v1/claims/%d/approvals", claim),
			fmt.Sprintf("/v1/claims/%d/comments", claim),
		} {
			got := asPerson(t, r, "reader", http.MethodGet, path, "")
			if got.Code != http.StatusOK {
				t.Errorf("%s answered %d to somebody who may read the finding, want 200",
					path, got.Code)
			}
		}

		// And the list answers for them, rather than reporting that nothing
		// was ever decided.
		var listed struct {
			Total int `json:"total"`
		}
		read(t, r, "reader", "/v1/decisions", &listed)
		if listed.Total == 0 {
			t.Error("a reader was told no decisions exist")
		}

		// Reading is not acting. Arguing still asks for triage, and the
		// refusal says nothing about whether the decision is there.
		if got := asPerson(t, r, "reader", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/comments", claim),
			`{"body":"a reader should not be able to write this"}`); got.Code == http.StatusOK ||
			got.Code == http.StatusCreated {
			t.Errorf("a reader wrote on a decision: %d", got.Code)
		}

		// The finding's visibility is the whole of the rule, so an undisclosed
		// one closes the record again to somebody who reads only what has been
		// disclosed. This is the half that would leak if the widening had been
		// written as "anybody on the product".
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("visibility = ?", "private").
			Where("1 = 1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := r.db.DB.NewUpdate().Table("decision").
			Set("visibility = ?", "private").
			Where("1 = 1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{
			fmt.Sprintf("/v1/decisions/%d", id),
			fmt.Sprintf("/v1/claims/%d", claim),
			fmt.Sprintf("/v1/claims/%d/revisions", claim),
			fmt.Sprintf("/v1/claims/%d/approvals", claim),
			fmt.Sprintf("/v1/claims/%d/comments", claim),
		} {
			if got := asPerson(t, r, "reader", http.MethodGet, path, ""); got.Code != http.StatusNotFound {
				t.Errorf("%s answered %d on an undisclosed finding to somebody who reads "+
					"only disclosed ones, want 404", path, got.Code)
			}
		}
		read(t, r, "reader", "/v1/decisions", &listed)
		if listed.Total != 0 {
			t.Errorf("a public reader was told %d undisclosed decisions exist", listed.Total)
		}
		// And somebody who reads undisclosed work still reads it.
		if got := asPerson(t, r, "private", http.MethodGet,
			fmt.Sprintf("/v1/decisions/%d", id), ""); got.Code != http.StatusOK {
			t.Errorf("a private reader was refused an undisclosed decision: %d", got.Code)
		}
	})
}

func TestWhatAppliesToAFindingIsReadableWithItsHistory(t *testing.T) {
	// Somebody deciding needs to know what was decided here before. Making
	// them start from a blank page, having thrown away what was written last
	// time, is how a tool teaches people to stop writing reasoning at all.
	eachReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		_, claim := r.decidedAt(t, place)
		path := fmt.Sprintf("/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/places/%s/decision", place)

		var before struct {
			Standing   *struct{} `json:"standing"`
			Previously []struct {
				Decision struct {
					State string `json:"state"`
				} `json:"decision"`
			} `json:"previously"`
		}
		read(t, r, "triager", path, &before)
		// Nobody has agreed to it yet, so it suppresses nothing — but it is
		// there to be read.
		if before.Standing != nil {
			t.Error("a claim nobody agreed to reads as standing")
		}
		if len(before.Previously) != 1 {
			t.Fatalf("the history reads as %+v", before.Previously)
		}

		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}

		var after struct {
			Standing *struct {
				Decision struct {
					Outcome string `json:"outcome"`
					State   string `json:"state"`
				} `json:"decision"`
				Reasoning string `json:"reasoning"`
			} `json:"standing"`
		}
		read(t, r, "triager", path, &after)
		if after.Standing == nil {
			t.Fatal("an agreed decision does not read as standing where it was made")
		}
		if after.Standing.Decision.Outcome != "not-applicable" || after.Standing.Reasoning == "" {
			t.Errorf("what stands here reads as %+v", after.Standing)
		}
	})
}

// read makes a GET as somebody and decodes what came back.
func read(t *testing.T, r *reach, who, path string, into any) {
	t.Helper()
	got := asPerson(t, r, who, http.MethodGet, path, "")
	if got.Code != http.StatusOK {
		t.Fatalf("GET %s answered %d: %s", path, got.Code, got.Body.String())
	}
	if err := json.Unmarshal(got.Body.Bytes(), into); err != nil {
		t.Fatalf("decode %s: %v (%s)", path, err, got.Body.String())
	}
}

func TestTheAPIReturnsMarkdownAndNeverMarkup(t *testing.T) {
	// One representation, to every consumer. HTML assumes a browser, and in an
	// API-first tool most callers are not one — the adapters already on the
	// books want neither HTML nor markdown, and markdown is the form an
	// integrating application can most easily lay out and re-render.
	//
	// Our own interface renders in the browser, so it needs no server-rendered
	// half either, and a second renderer is the thing that eventually
	// disagrees with the first.
	twoReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		id, _ := r.decidedAt(t, place)

		var body map[string]any
		read(t, r, "triager", fmt.Sprintf("/v1/decisions/%d", id), &body)
		if body["reasoning"] == "" || body["reasoning"] == nil {
			t.Error("the answer carries no text at all")
		}
		for key := range body {
			if strings.HasSuffix(key, "_html") {
				t.Errorf("the answer carries a rendered field %q", key)
			}
		}

		// And there is no longer any way to ask for markup. An old client
		// still sending html=true is answered rather than refused — unknown
		// query parameters are ignored — and what it gets is the source,
		// never a rendered field it might display without sanitizing.
		var asked map[string]any
		read(t, r, "triager", fmt.Sprintf("/v1/decisions/%d?html=true", id), &asked)
		for key := range asked {
			if strings.HasSuffix(key, "_html") {
				t.Errorf("html=true still produced a rendered field %q", key)
			}
		}
		if asked["reasoning"] != body["reasoning"] {
			t.Error("html=true changed the answer")
		}
	})
}

func TestStoredTextComesBackExactlyAsWritten(t *testing.T) {
	// The counterpart to rendering in the browser: the server hands back the
	// source it holds, unaltered, so whatever renders it is rendering the
	// authoritative form rather than something already transformed.
	//
	// Sanitizing is the renderer's job and is tested where the renderer lives
	// (internal/markdown). What matters here is that nothing between the row
	// and the reader quietly rewrites the text — a reader that trusted a
	// half-cleaned string would be trusting the wrong control.
	eachReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		id, _ := r.decidedAt(t, place)

		// Straight into the row, the way text stored under an older rule would
		// already be sitting there.
		hostile := "Fine, then <img src=x onerror=alert(1)> and " +
			"[a link](javascript:alert(2))."
		if _, err := r.db.DB.NewUpdate().
			Table("claim_revision").
			Set("body = ?", hostile).
			Where(`claim_id = (SELECT claim_id FROM "decision" WHERE id = ?)`, id).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		var body struct {
			Reasoning string `json:"reasoning"`
		}
		read(t, r, "triager", fmt.Sprintf("/v1/decisions/%d", id), &body)
		if body.Reasoning != hostile {
			t.Errorf("the source came back altered:\n got %q\nwant %q", body.Reasoning, hostile)
		}
	})
}

func TestAFindingCarriesEverythingNeededToActOnIt(t *testing.T) {
	// The measure this is built against: nothing here should send somebody to
	// a search engine. There may be thousands of findings and very few people,
	// so a finding that carries its own evidence and one that does not are the
	// difference between a queue that gets worked and one that does not.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		var detail struct {
			Vulnerability string   `json:"vulnerability"`
			Severity      string   `json:"severity"`
			Score         float64  `json:"score"`
			Vector        string   `json:"vector"`
			Exploited     bool     `json:"exploited"`
			Likelihood    float64  `json:"likelihood"`
			Weaknesses    []string `json:"weaknesses"`
			Description   string   `json:"description"`
			Advisory      string   `json:"advisory"`
			References    []struct {
				URL  string `json:"url"`
				Kind string `json:"kind"`
			} `json:"references"`
			Component string `json:"component"`
			FixState  string `json:"fix_state"`
			FixedIn   string `json:"fixed_in"`
			Places    []struct {
				Place    string `json:"place"`
				Consumer string `json:"consumer"`
			} `json:"places"`
		}
		read(t, r, "reader", "/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/components/libnl-3-200", &detail)

		for what, got := range map[string]string{
			"the issue":     detail.Vulnerability,
			"the component": detail.Component,
			"the write-up":  detail.Description,
			"the advisory":  detail.Advisory,
			"the vector":    detail.Vector,
			"the fix state": detail.FixState,
			"the fix":       detail.FixedIn,
		} {
			if got == "" {
				t.Errorf("%s is missing, so somebody has to go and look it up", what)
			}
		}
		if detail.Score == 0 || detail.Likelihood == 0 || !detail.Exploited {
			t.Errorf("what makes this urgent is missing: score=%v likelihood=%v exploited=%v",
				detail.Score, detail.Likelihood, detail.Exploited)
		}
		if len(detail.Weaknesses) == 0 {
			t.Error("what kind of flaw this is was not kept")
		}
		if len(detail.Places) == 0 || detail.Places[0].Place == "" {
			t.Fatalf("the answer does not say where it sits: %+v", detail.Places)
		}

		// The patch comes first. Somebody deciding whether to backport rather
		// than upgrade needs the change itself, and hunting for it among the
		// write-ups is the step that does not happen with a thousand waiting.
		if len(detail.References) < 2 {
			t.Fatalf("the references were not kept: %+v", detail.References)
		}
		if detail.References[0].Kind != "patch" {
			t.Errorf("the first reference is %q, not the change that fixes it",
				detail.References[0].Kind)
		}
	})
}

func TestTheNewEndpointsAnswerRatherThanExist(t *testing.T) {
	// Each of these was added to close a gap the interface work found, and
	// each one is the kind of thing that can be registered, return an empty
	// shape, and look finished. This drives them against a build that has
	// something in it.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		// Walking the graph, one step at a time.
		var top struct {
			Items []struct {
				Component string `json:"component"`
				Findings  int    `json:"findings"`
				Children  int    `json:"children"`
			} `json:"items"`
		}
		read(t, r, "reader", "/v1/products/mine/streams/master/variants/broadcom/components", &top)
		if len(top.Items) == 0 {
			t.Fatal("the build reports pulling nothing in")
		}
		var around struct {
			Above []struct {
				Component string `json:"component"`
			} `json:"above"`
			Below []struct {
				Component string `json:"component"`
			} `json:"below"`
		}
		read(t, r, "reader", "/v1/products/mine/streams/master/variants/broadcom"+
			"/components/libnl-3-200/around", &around)
		if len(around.Above) == 0 {
			t.Errorf("nothing pulls libnl-3-200 in, which cannot be true: %+v", around)
		}

		// The issues at a component, which is what a bulk claim narrows.
		var issues struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
				Severity      string `json:"severity"`
				Places        int    `json:"places"`
				FixedIn       string `json:"fixed_in"`
			} `json:"items"`
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
			"/components/libnl-3-200/issues", &issues)
		if issues.Total != 1 || len(issues.Items) != 1 {
			t.Fatalf("%d issues at the component, want 1", issues.Total)
		}
		// The list a person picks from carries what they need to pick: how bad
		// it is, how much of the build it sits in, and whether there is
		// anywhere to go.
		if issues.Items[0].Severity == "" || issues.Items[0].FixedIn == "" ||
			issues.Items[0].Places == 0 {
			t.Errorf("the list to choose from says nothing to choose on: %+v", issues.Items[0])
		}

		// One claim across a named set.
		got := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/components/libnl-3-200/decisions",
			`{"vulnerabilities":["CVE-2026-9999"],"outcome":"not-applicable",`+
				`"justification":"vulnerable_code_not_in_execute_path",`+
				`"selected_by":"searched the reports for \"driver\"",`+
				`"reasoning":"These are in drivers absent from our kernel config."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("deciding a set together answered %d: %s", got.Code, got.Body.String())
		}
		var recorded struct {
			Recorded int     `json:"recorded"`
			IDs      []int64 `json:"ids"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		// One per *place*, not one per name. A decision is keyed on a place,
		// so a claim built from one of them would silence one consumer and
		// leave the rest open while reporting that it had covered them.
		var places int
		for _, each := range issues.Items {
			places += each.Places
		}
		if recorded.Recorded != places {
			t.Errorf("recorded %d decisions for %d places, want one each",
				recorded.Recorded, places)
		}

		// And how the set was narrowed is on the record, because "how were
		// these chosen" is the question asked of a bulk judgment later.
		var made struct {
			Decision struct {
				SelectedBy string `json:"selected_by"`
			} `json:"decision"`
		}
		read(t, r, "triager", fmt.Sprintf("/v1/decisions/%d", recorded.IDs[0]), &made)
		if made.Decision.SelectedBy == "" {
			t.Error("a claim recorded as one of many does not say how the set was narrowed")
		}

		// A deferral with nowhere to say until when is refused rather than
		// recorded as a postponement with no end.
		if got := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/components/libnl-3-200/decisions",
			`{"vulnerabilities":["CVE-2026-9999"],"outcome":"deferred",`+
				`"selected_by":"the same search","reasoning":"Not this release."}`,
		); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("deferring with no date answered %d: %s", got.Code, got.Body.String())
		}

		// A name nobody here knows says which name, so a person who pasted a
		// list can fix the list rather than bisect it.
		if got := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/components/libnl-3-200/decisions",
			`{"vulnerabilities":["CVE-2026-9999","CVE-1999-0001"],"outcome":"wont-fix",`+
				`"selected_by":"a list somebody pasted","reasoning":"Not worth it."}`,
		); got.Code != http.StatusNotFound ||
			!strings.Contains(got.Body.String(), "CVE-1999-0001") {
			t.Errorf("an unknown issue answered %d without naming it: %s",
				got.Code, got.Body.String())
		}

		// The trend, worked out rather than stored.
		var trend struct {
			Items []struct {
				At   string `json:"at"`
				Open int    `json:"open"`
			} `json:"items"`
		}
		read(t, r, "reader", "/v1/trend?weeks=4", &trend)
		if len(trend.Items) != 4 {
			t.Errorf("asked for four weeks and got %d points", len(trend.Items))
		}
		if trend.Items[len(trend.Items)-1].Open == 0 {
			t.Error("the trend ends with nothing open, but something is")
		}

		// Settings, which had no way to be set at all.
		var settings struct {
			Items []struct {
				Name    string `json:"name"`
				Value   string `json:"value"`
				Default bool   `json:"default"`
			} `json:"items"`
		}
		read(t, r, "admin", "/v1/settings", &settings)
		if len(settings.Items) == 0 {
			t.Fatal("no settings are listed")
		}
		if got := asPerson(t, r, "admin", http.MethodPut,
			"/v1/settings/remediation.due.critical",
			`{"value":"nonsense"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("an unreadable duration was accepted: %d", got.Code)
		}
		if got := asPerson(t, r, "admin", http.MethodPut,
			"/v1/settings/remediation.due.critical",
			`{"value":"48h"}`); got.Code != http.StatusNoContent {
			t.Errorf("setting a deadline answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestNobodyLearnsWhoHasAnAccountByBeingRefused(t *testing.T) {
	// A name nobody holds and a name somebody holds must come back the same
	// way to anybody not authorized to act on either, or the refusal is a
	// directory of the organization readable by every account.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)

		// Handing back somebody's work is administrative. A reader asking
		// about a real account and a made-up one gets one answer.
		real := asPerson(t, r, "reader", http.MethodPost,
			"/v1/people/triager/assignments/hand-back", `{}`)
		invented := asPerson(t, r, "reader", http.MethodPost,
			"/v1/people/nobody-at-all/assignments/hand-back", `{}`)
		if real.Code != invented.Code {
			t.Errorf("releasing a real person's work answered %d and an invented one %d",
				real.Code, invented.Code)
		}
		if real.Code != http.StatusForbidden {
			t.Errorf("a reader releasing somebody's work answered %d, want 403", real.Code)
		}

		// Assigning is the same shape: reading a product is not being able to
		// hand its findings around, so the name is never resolved first.
		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"
		known := asPerson(t, r, "reader", http.MethodPut, at, `{"person":"triager"}`)
		unknown := asPerson(t, r, "reader", http.MethodPut, at, `{"person":"nobody-at-all"}`)
		if known.Code != unknown.Code || known.Body.String() != unknown.Body.String() {
			t.Errorf("assigning to a real person answered %d %s and to an invented one %d %s",
				known.Code, known.Body.String(), unknown.Code, unknown.Body.String())
		}
	})
}

func TestASettingThatWouldReadAsUnsetIsRefused(t *testing.T) {
	// Every reader treats zero and negative as unset and falls back to the
	// shipped value, so storing one produces a setting that looks set on the
	// administration screen and does nothing at all.
	twoReach(t, func(t *testing.T, r *reach) {
		for _, value := range []string{"0h", "-48h", "nonsense"} {
			if got := asPerson(t, r, "admin", http.MethodPut,
				"/v1/settings/remediation.due.critical",
				`{"value":"`+value+`"}`); got.Code != http.StatusUnprocessableEntity {
				t.Errorf("%q was accepted as a deadline: %d %s",
					value, got.Code, got.Body.String())
			}
		}

		// The one setting that is a count rather than a duration is checked as
		// a count. A duration there would be stored and then ignored.
		cap := "/v1/settings/triage.together-cap"
		if got := asPerson(t, r, "admin", http.MethodPut, cap,
			`{"value":"48h"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a duration was accepted as a count: %d %s", got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "admin", http.MethodPut, cap,
			`{"value":"0"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a cap of nothing was accepted: %d %s", got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "admin", http.MethodPut, cap,
			`{"value":"5"}`); got.Code != http.StatusNoContent {
			t.Errorf("setting the cap answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestABulkClaimCoversWhatTheClaimantCanSeeAndNoMore(t *testing.T) {
	// A public triager's judgment covers the places they can read. The
	// undisclosed ones stay open for whoever can read them — which is the
	// ordinary division of work, not a gap. Refusing the whole action because
	// something undisclosed sits at the same component would answer somebody
	// who picked from the list they were shown with a bare "not found".
	eachReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)

		// A second place for the same issue, so the component holds one the
		// public triager may read and one they may not.
		var rows []finding.Finding
		if err := r.db.DB.NewSelect().Model(&rows).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("the fixture has %d findings, want 1", len(rows))
		}
		second := rows[0]
		second.ID = 0
		// A different identity of the same width. A place identity is a hash
		// stored in a fixed-width column, so appending to one overflows on
		// three of the four engines and is silently accepted on the fourth.
		second.PlaceIdentity = second.PlaceIdentity[:len(second.PlaceIdentity)-4] + "beef"
		if _, err := r.db.DB.NewInsert().Model(&second).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("visibility = ?", "private").
			Where("id = ?", rows[0].ID).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/components/libnl-3-200/decisions"
		body := `{"vulnerabilities":["CVE-2026-9999"],"outcome":"wont-fix",` +
			`"selected_by":"everything at this component","reasoning":"Not worth the churn."}`

		// One of the two places is theirs to argue about, and that is what the
		// claim covers.
		got := asPerson(t, r, "triager", http.MethodPost, at, body)
		if got.Code != http.StatusCreated {
			t.Fatalf("a public triager answered %d: %s", got.Code, got.Body.String())
		}
		var recorded struct {
			Recorded int `json:"recorded"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		if recorded.Recorded != 1 {
			t.Errorf("a public triager covered %d places, want only the disclosed one",
				recorded.Recorded)
		}

		// And the undisclosed one is still open, waiting for somebody who can
		// see it.
		standing, err := r.db.DB.NewSelect().Table("decision").
			Where("place_identity = ?", rows[0].PlaceIdentity).
			Where("live_key IS NOT NULL").Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if standing != 0 {
			t.Errorf("%d claims stand against a place the claimant cannot read", standing)
		}
	})
}

func TestTheCallerIsToldWhatTheyMayDoRatherThanFindingOut(t *testing.T) {
	// A screen has to know whether to offer an action before it draws one.
	// Without this the client either offers everything and lets people walk
	// into a refusal, or re-implements the mapping from roles to capabilities
	// and drifts from the one the server actually enforces.
	twoReach(t, func(t *testing.T, r *reach) {
		type can struct {
			Product   string `json:"product"`
			MaySee    bool   `json:"may_see"`
			SeesAll   bool   `json:"sees_all"`
			MayTriage bool   `json:"may_triage"`
			MayHide   bool   `json:"may_hide"`
			MayAgree  bool   `json:"may_agree"`
		}
		type who struct {
			Identity string `json:"identity"`
			Name     string `json:"name"`
			Admin    bool   `json:"admin"`
			Kind     string `json:"kind"`
			Reach    []can  `json:"reach"`
		}

		var reader who
		read(t, r, "reader", "/v1/session/me", &reader)
		if reader.Identity != "reader" || reader.Kind != "person" {
			t.Errorf("a reader is described as %+v", reader)
		}
		if reader.Name == "" {
			t.Error("nothing to show in a header")
		}
		if reader.Admin {
			t.Error("a reader is reported as an administrator")
		}
		if len(reader.Reach) == 0 {
			t.Fatal("a reader reaches no product at all")
		}
		for _, each := range reader.Reach {
			if !each.MaySee {
				t.Errorf("%s is listed but cannot be seen", each.Product)
			}
			// Reading what is disclosed is not reading what is not, and it is
			// certainly not deciding. This is the assertion that catches a
			// capability widened by accident.
			if each.SeesAll || each.MayTriage || each.MayHide || each.MayAgree {
				t.Errorf("a reader is offered more than reading in %s: %+v", each.Product, each)
			}
		}

		var triager who
		read(t, r, "triager", "/v1/session/me", &triager)
		for _, each := range triager.Reach {
			if !each.MayTriage {
				t.Errorf("a triager may not triage %s", each.Product)
			}
			if each.MayHide {
				t.Errorf("a public triager is offered undisclosed findings in %s", each.Product)
			}
		}

		// An administrator reaches everything, which is the one role not held
		// against a product.
		var admin who
		read(t, r, "admin", "/v1/session/me", &admin)
		if !admin.Admin {
			t.Error("the administrator is not described as one")
		}
		if len(admin.Reach) < len(reader.Reach) {
			t.Errorf("an administrator reaches %d products where a reader reaches %d",
				len(admin.Reach), len(reader.Reach))
		}
	})
}

func TestOnlyPeopleWhoCanAlreadySeeItAreOfferedAsMentions(t *testing.T) {
	// An autocomplete listing everybody teaches somebody to name a colleague
	// who then cannot open what they were called to. On an undisclosed finding
	// it is worse than unhelpful: the mention itself says a finding exists,
	// which is the disclosure the visibility rule is there to prevent.
	eachReach(t, func(t *testing.T, r *reach) {
		type person struct {
			Identity string `json:"identity"`
			Name     string `json:"name"`
		}
		type list struct {
			Items []person `json:"items"`
		}
		has := func(items []person, who string) bool {
			for _, each := range items {
				if each.Identity == who {
					return true
				}
			}
			return false
		}

		// Everybody who can read what has been disclosed.
		var public list
		read(t, r, "triager", "/v1/products/mine/mentionable", &public)
		if !has(public.Items, "reader") {
			t.Errorf("somebody who can read the product is not offered: %+v", public.Items)
		}
		if has(public.Items, "nothing") {
			t.Error("somebody granted nothing here is offered as a mention")
		}

		// And undisclosed findings are a narrower set. Somebody trusted only
		// with what has been disclosed must not be offered for one that has
		// not — naming them would call them to something they cannot open.
		var private list
		read(t, r, "private-triage", "/v1/products/mine/mentionable?visibility=private", &private)
		if has(private.Items, "reader") {
			t.Errorf("somebody who reads only disclosed findings is offered on an undisclosed one: %+v",
				private.Items)
		}
		if len(private.Items) == 0 {
			t.Error("nobody at all may be mentioned on an undisclosed finding")
		}

		// Asking who may be told about an undisclosed finding is itself a
		// question about undisclosed findings, so somebody who cannot read
		// them is answered as though the product were not there.
		if got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/mentionable?visibility=private", ""); got.Code != http.StatusNotFound {
			t.Errorf("a public triager asked about undisclosed mentions and got %d: %s",
				got.Code, got.Body.String())
		}
	})
}

func TestAPlaceNamesTheClaimStandingOnIt(t *testing.T) {
	// A claim shown on a finding says how many places it covers. That is how
	// big the judgment was and not which code it was about, and on a finding
	// only partly decided — some places answered and the rest never touched —
	// which ones is the whole question. The place carries the claim so the
	// screen can name them rather than only count them.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		var detail struct {
			Places []struct {
				Place    string `json:"place"`
				Consumer string `json:"consumer"`
				Decision int64  `json:"decision"`
				Claim    int64  `json:"claim"`
			} `json:"places"`
		}
		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200"
		read(t, r, "reader", at, &detail)
		if len(detail.Places) == 0 {
			t.Fatal("the finding sits nowhere")
		}
		for _, place := range detail.Places {
			if place.Claim != 0 {
				t.Errorf("a place nobody has decided names claim %d", place.Claim)
			}
		}

		made := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/places/"+detail.Places[0].Place+"/decision",
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_in_execute_path",`+
				`"reasoning":"The parser is never reached."}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("recording a decision answered %d: %s", made.Code, made.Body.String())
		}
		var recorded struct {
			ClaimID int64 `json:"claim_id"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &recorded); err != nil {
			t.Fatalf("decode: %v", err)
		}

		read(t, r, "reader", at, &detail)
		var named int
		for _, place := range detail.Places {
			if place.Decision == 0 {
				if place.Claim != 0 {
					t.Errorf("a place with no decision names claim %d", place.Claim)
				}
				continue
			}
			named++
			if place.Claim != recorded.ClaimID {
				t.Errorf("the decided place names claim %d, want %d", place.Claim, recorded.ClaimID)
			}
		}
		if named == 0 {
			t.Error("no place carries the decision that was just recorded")
		}
	})
}

func TestBeingToldAboutWorkKeepsItOutOfTheDigest(t *testing.T) {
	// the digest carries what nothing else told you. That rests on the key
	// written when somebody is told matching the key read when the digest
	// asks — and the first version of this did not: one side keyed on the
	// name in the request path and the other on the display name from a
	// query, so they never compared equal and the digest repeated every
	// message.
	//
	// So this asserts across the seam rather than round-tripping one side
	// against itself, which is what let that through.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"
		if got := asPerson(t, r, "assigner", http.MethodPut, at,
			`{"person":"reader"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}

		reader, err := access.NewStore(r.db.DB).ByIdentity(t.Context(), "reader")
		if err != nil {
			t.Fatal(err)
		}
		told, err := notify.ToldAbout(t.Context(), r.db.DB, reader.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(told) != 1 {
			t.Fatalf("%d things were recorded as told, want 1", len(told))
		}

		// The digest reads what it holds and must recognize the same work.
		digest, err := notify.Assemble(t.Context(), r.db.DB, reader, 50)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range digest.Mine {
			if item.Issue == "CVE-2026-9999" {
				t.Errorf("the digest repeats work its owner was already told about: %+v", item)
			}
		}
	})
}

// The bound is on what would be written, charged as each build resolves.
//
// It was consulted after every named build had been resolved and every place
// accumulated, so the work one request did was bounded by the request array
// rather than by the limit: REQ-27's "a limit checked against the request lets
// a small request do a large amount of work", which is why the entry's own
// note about each build costing a resolution was answered with a maxItems.
func TestTheBulkBoundIsChargedAsEachBuildResolves(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		// A second place of the same finding in the build the path names, so
		// that build alone is already past a cap of one.
		var rows []finding.Finding
		if err := r.db.DB.NewSelect().Model(&rows).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("the fixture has %d findings, want 1", len(rows))
		}
		second := rows[0]
		second.ID = 0
		second.PlaceIdentity = second.PlaceIdentity[:len(second.PlaceIdentity)-4] + "beef"
		if _, err := r.db.DB.NewInsert().Model(&second).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.together-cap",
			`{"value":"1"}`); got.Code != http.StatusNoContent {
			t.Fatalf("setting the cap answered %d: %s", got.Code, got.Body.String())
		}

		// And a second build named that was never declared. Charged as each
		// build resolves, the act is refused on the bound before anything
		// tries to resolve that one; charged afterwards, every named build is
		// resolved first and the answer is about the build instead.
		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/decision"
		got := asPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_in_execute_path",`+
				`"reasoning":"The parser is never reached.",`+
				`"also":[{"stream":"never-declared","variant":"broadcom"}]}`)
		if got.Code != http.StatusUnprocessableEntity {
			t.Errorf("an act past the cap answered %d: %s", got.Code, got.Body.String())
		}
		if !strings.Contains(got.Body.String(), "one action may write") {
			t.Errorf("the refusal does not name the bound: %s", got.Body.String())
		}
	})
}
