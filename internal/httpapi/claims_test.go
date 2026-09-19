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
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// scannedTwoIssues is a build whose one component carries two issues that
// look nothing alike: one exploited, high and fixable, one low with no fix and
// a driver in its description. The shape a bulk claim's outliers are read from.
func (r *reach) scannedTwoIssues(t *testing.T) {
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
		TargetID: target.ID, ContentHash: "two-issues", BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}

	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	kernel := graph.Described{
		Purl: "pkg:deb/debian/linux-image@5.10", Name: "linux-image", Version: "5.10",
	}
	if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root:         product,
		Components:   []graph.Described{kernel},
		Dependencies: []graph.Dependency{{Parent: product, Child: kernel}},
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
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{
		{
			Issue: finding.Named{
				Identifier: "CVE-2026-9999", Severity: "high",
				Description: "A crafted packet writes past the end of a buffer in the netfilter connection tracker.",
				Exploited:   true, Score: 8.1,
			},
			Component: kernel, FixState: finding.FixedUpstream, FixedIn: "5.10.0-27",
		},
		{
			Issue: finding.Named{
				Identifier: "CVE-2026-1000", Severity: "low",
				Description: "Race in a joystick driver.",
				Score:       3.1,
			},
			Component: kernel, FixState: finding.NoFix,
		},
	}); err != nil {
		t.Fatal(err)
	}
}

// claimed records one judgment about a finding through the API and returns
// the claim it made.
func (r *reach) claimed(t *testing.T, who, vulnerability, component, body string) (claim int64, ids []int64) {
	t.Helper()
	path := fmt.Sprintf("/v1/products/mine/streams/master/variants/broadcom"+
		"/findings/%s/components/%s/decision", vulnerability, component)
	got := asPerson(t, r, who, http.MethodPost, path, body)
	if got.Code != http.StatusCreated {
		t.Fatalf("deciding answered %d: %s", got.Code, got.Body.String())
	}
	var out struct {
		ClaimID int64   `json:"claim_id"`
		IDs     []int64 `json:"ids"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, got.Body.String())
	}
	if out.ClaimID == 0 {
		t.Fatalf("a judgment came back without the claim it made: %s", got.Body.String())
	}
	return out.ClaimID, out.IDs
}

const dismissal = `{"outcome":"not-applicable","justification":"vulnerable_code_not_present",` +
	`"reasoning":"The driver is not built for this image."}`

func TestTheQueueListsOneEntryPerClaimWithItsSize(t *testing.T) {
	// One judgment, one entry — with how many rows it wrote, how many
	// issues and places it covers, and the builds it reaches.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		claim, ids := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)

		got := asPerson(t, r, "reviewer", http.MethodGet, "/v1/review-queue", "")
		if got.Code != http.StatusOK {
			t.Fatalf("reading the queue answered %d: %s", got.Code, got.Body.String())
		}
		var out struct {
			Items []struct {
				Claim struct {
					ID   int64  `json:"id"`
					Kind string `json:"kind"`
				} `json:"claim"`
				Decision struct {
					ClaimID int64 `json:"claim_id"`
				} `json:"decision"`
				Decisions int      `json:"decisions"`
				Issues    int      `json:"issues"`
				Places    int      `json:"places"`
				Builds    []string `json:"builds"`
				Reasoning string   `json:"reasoning"`
			} `json:"items"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, got.Body.String())
		}
		if out.Total != 1 || len(out.Items) != 1 {
			t.Fatalf("%d entries (total %d), want one claim: %s", len(out.Items), out.Total, got.Body.String())
		}
		one := out.Items[0]
		if one.Claim.ID != claim || one.Decision.ClaimID != claim || one.Claim.Kind != "finding" {
			t.Errorf("the entry does not name the claim %d: %+v", claim, one)
		}
		if one.Decisions != len(ids) || one.Issues != 1 || one.Places != len(ids) {
			t.Errorf("the entry's size reads as %d/%d/%d, want %d/1/%d", one.Decisions, one.Issues, one.Places, len(ids), len(ids))
		}
		if len(one.Builds) != 1 || one.Builds[0] != "master · broadcom" {
			t.Errorf("the entry names builds %v, want the one it sits in", one.Builds)
		}
	})
}

func TestAClaimIsApprovedAsOneAndByAnotherPerson(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)

		if got := asPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code != http.StatusConflict {
			t.Errorf("the proposer approving their own claim answered %d: %s", got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			"/v1/claims/999999/approval", `{}`); got.Code != http.StatusNotFound {
			t.Errorf("approving a claim that is not there answered %d", got.Code)
		}
		if got := asPerson(t, r, "reader", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code != http.StatusNotFound {
			t.Errorf("somebody who may not approve answered %d, want the same as not there", got.Code)
		}

		got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{"batch":"tuesday"}`)
		if got.Code != http.StatusOK {
			t.Fatalf("approving the claim answered %d: %s", got.Code, got.Body.String())
		}
		var out struct {
			Approved int `json:"approved"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil || out.Approved != 1 {
			t.Errorf("approving reported %+v (%v)", out, err)
		}

		// Under a batch, so undone as one.
		got = asPerson(t, r, "reviewer", http.MethodDelete, "/v1/approval-batches/tuesday", "")
		if got.Code != http.StatusOK {
			t.Fatalf("undoing the batch answered %d: %s", got.Code, got.Body.String())
		}
		got = asPerson(t, r, "reviewer", http.MethodGet, "/v1/review-queue", "")
		var queue struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &queue); err != nil || queue.Total != 1 {
			t.Errorf("after undoing the batch the claim is not back in the queue: %+v", queue)
		}
	})
}

func TestABulkClaimCarriesItsOutliersAndTheyCanBeSetAside(t *testing.T) {
	// Nobody reads three hundred rows. What a careful approver checks is
	// the handful that contradict the shape of the claim, and those are
	// handed to them — and may be set aside, so the rest is not held up.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		got := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom/components/linux-image/decisions",
			`{"vulnerabilities":["CVE-2026-9999","CVE-2026-1000"],"outcome":"not-applicable",`+
				`"justification":"vulnerable_code_not_present",`+
				`"selected_by":"undecided, description contains \"driver\"",`+
				`"reasoning":"None of these drivers are built for this image."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("a bulk claim answered %d: %s", got.Code, got.Body.String())
		}
		var made struct {
			ClaimID int64 `json:"claim_id"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &made); err != nil || made.ClaimID == 0 {
			t.Fatalf("a bulk claim did not say which claim it made: %s", got.Body.String())
		}

		got = asPerson(t, r, "reviewer", http.MethodGet, "/v1/review-queue", "")
		var out struct {
			Items []struct {
				Claim struct {
					Kind       string `json:"kind"`
					SelectedBy string `json:"selected_by"`
				} `json:"claim"`
				Issues   int `json:"issues"`
				Outliers *struct {
					Exploited int `json:"exploited"`
					Severe    int `json:"severe"`
					Fixable   int `json:"fixable"`
					Unmatched int `json:"unmatched"`
					Rows      []struct {
						DecisionID    int64    `json:"decision_id"`
						Vulnerability string   `json:"vulnerability"`
						Why           []string `json:"why"`
					} `json:"rows"`
				} `json:"outliers"`
			} `json:"items"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil || len(out.Items) != 1 {
			t.Fatalf("the queue reads as %s (%v)", got.Body.String(), err)
		}
		one := out.Items[0]
		if one.Claim.Kind != "together" || one.Issues != 2 || one.Outliers == nil {
			t.Fatalf("a bulk claim reads as %+v", one)
		}
		o := one.Outliers
		if o.Exploited != 1 || o.Severe != 1 || o.Fixable != 1 || o.Unmatched != 1 {
			t.Errorf("outliers counted %d exploited, %d severe, %d fixable, %d unmatched; want 1 of each", o.Exploited, o.Severe, o.Fixable, o.Unmatched)
		}
		if len(o.Rows) != 1 || o.Rows[0].Vulnerability != "CVE-2026-9999" || len(o.Rows[0].Why) != 4 {
			t.Fatalf("the rows that stood out are %+v, want the one that is exploited, severe, fixable and not about a driver", o.Rows)
		}

		// Set it aside: the other is approved, this one goes back.
		got = asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", made.ClaimID),
			fmt.Sprintf(`{"except":[%d],"because":"Netfilter is not a driver, and it is exploited."}`, o.Rows[0].DecisionID))
		if got.Code != http.StatusOK {
			t.Fatalf("approving with a row set aside answered %d: %s", got.Code, got.Body.String())
		}
		var done struct {
			Approved      int   `json:"approved"`
			ReturnedClaim int64 `json:"returned_claim"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &done); err != nil || done.Approved != 1 || done.ReturnedClaim == 0 {
			t.Fatalf("setting aside reported %+v (%v)", done, err)
		}

		// The row set aside is the proposer's again, in a claim of its own,
		// with the reason on it.
		got = asPerson(t, r, "triager", http.MethodGet,
			fmt.Sprintf("/v1/claims/%d/comments", done.ReturnedClaim), "")
		var said struct {
			Items []struct {
				Body string `json:"body"`
			} `json:"items"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &said); err != nil || len(said.Items) != 1 ||
			said.Items[0].Body != "Netfilter is not a driver, and it is exploited." {
			t.Errorf("the reason did not travel with the row: %s", got.Body.String())
		}
		// And nothing is waiting: one approved, one sent back.
		got = asPerson(t, r, "reviewer", http.MethodGet, "/v1/review-queue", "")
		var queue struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &queue); err != nil || queue.Total != 0 {
			t.Errorf("%d still waiting after approving with a row set aside", queue.Total)
		}
	})
}

func TestAFindingReportsItsDecisionsAndWhatMayCarryToIt(t *testing.T) {
	// The finding is the working screen after a decision as well as before
	// it : what stands, what stood, and what argued about a neighbor may
	// be carried here.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		at := "/v1/products/mine/streams/master/variants/broadcom/findings/%s/components/linux-image"

		read := func(vulnerability string) (body []byte) {
			t.Helper()
			got := asPerson(t, r, "triager", http.MethodGet, fmt.Sprintf(at, vulnerability), "")
			if got.Code != http.StatusOK {
				t.Fatalf("reading the finding answered %d: %s", got.Code, got.Body.String())
			}
			return got.Body.Bytes()
		}
		type finding struct {
			Standing []struct {
				ClaimID    int64  `json:"claim_id"`
				State      string `json:"state"`
				ApprovedBy string `json:"approved_by"`
				Places     int    `json:"places"`
				Rows       struct {
					Proposed int `json:"proposed"`
					SentBack int `json:"sent_back"`
					Approved int `json:"approved"`
				} `json:"rows"`
				SentBackAt      string `json:"sent_back_at"`
				SentBackBecause string `json:"sent_back_because"`
			} `json:"standing"`
			Previous []struct {
				DecisionID int64  `json:"decision_id"`
				Ended      string `json:"ended"`
				EndedAt    string `json:"ended_at"`
				Reasoning  string `json:"reasoning"`
			} `json:"previous"`
			Similar []struct {
				ClaimID   int64  `json:"claim_id"`
				Reasoning string `json:"reasoning"`
				Issues    int    `json:"issues"`
			} `json:"similar"`
		}
		var f finding
		if err := json.Unmarshal(read("CVE-2026-1000"), &f); err != nil {
			t.Fatal(err)
		}
		if len(f.Standing) != 0 || len(f.Previous) != 0 || len(f.Similar) != 0 {
			t.Fatalf("an undecided finding reports %+v", f)
		}

		// A claim about the neighbor, approved.
		neighbor, _ := r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", neighbor), `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}
		if err := json.Unmarshal(read("CVE-2026-1000"), &f); err != nil {
			t.Fatal(err)
		}
		if len(f.Similar) != 1 || f.Similar[0].ClaimID != neighbor || f.Similar[0].Issues != 1 || f.Similar[0].Reasoning == "" {
			t.Fatalf("the approved claim about the neighbor is not offered: %+v", f.Similar)
		}

		// Carried here as an extension.
		got := asPerson(t, r, "triager", http.MethodPost, fmt.Sprintf(at, "CVE-2026-1000")+"/decision",
			fmt.Sprintf(`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
				`"reasoning":"Same kernel config; still not built.","extends":%d}`, neighbor))
		if got.Code != http.StatusCreated {
			t.Fatalf("extending answered %d: %s", got.Code, got.Body.String())
		}
		var made struct {
			ClaimID int64   `json:"claim_id"`
			IDs     []int64 `json:"ids"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &made); err != nil {
			t.Fatal(err)
		}
		got = asPerson(t, r, "reviewer", http.MethodGet, "/v1/review-queue", "")
		var queue struct {
			Items []struct {
				Claim struct {
					ID          int64  `json:"id"`
					Kind        string `json:"kind"`
					DerivedFrom int64  `json:"derived_from"`
				} `json:"claim"`
			} `json:"items"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &queue); err != nil || len(queue.Items) != 1 {
			t.Fatalf("the queue reads as %s (%v)", got.Body.String(), err)
		}
		if queue.Items[0].Claim.Kind != "extension" || queue.Items[0].Claim.DerivedFrom != neighbor {
			t.Errorf("the extension does not say what it carries: %+v", queue.Items[0].Claim)
		}

		// Standing, pending; then withdrawn, and offered back with a date.
		if err := json.Unmarshal(read("CVE-2026-1000"), &f); err != nil {
			t.Fatal(err)
		}
		if len(f.Standing) != 1 || f.Standing[0].ClaimID != made.ClaimID || f.Standing[0].State != "proposed" {
			t.Fatalf("the extension does not stand as pending: %+v", f.Standing)
		}
		if f.Standing[0].Rows.Proposed != 1 || f.Standing[0].Rows.SentBack != 0 || f.Standing[0].Rows.Approved != 0 {
			t.Errorf("a pending claim's rows read as %+v", f.Standing[0].Rows)
		}

		// Sent back, the finding says so and says why.
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/send-back", made.ClaimID),
			`{"because":"Name the kconfig option."}`); got.Code != http.StatusNoContent {
			t.Fatalf("sending the claim back answered %d: %s", got.Code, got.Body.String())
		}
		if err := json.Unmarshal(read("CVE-2026-1000"), &f); err != nil {
			t.Fatal(err)
		}
		if len(f.Standing) != 1 || f.Standing[0].Rows.SentBack != 1 || f.Standing[0].SentBackAt == "" ||
			f.Standing[0].SentBackBecause != "Name the kconfig option." {
			t.Errorf("a claim sent back does not say so on the finding: %+v", f.Standing)
		}
		if got := asPerson(t, r, "triager", http.MethodDelete,
			fmt.Sprintf("/v1/claims/%d", made.ClaimID), ""); got.Code != http.StatusNoContent {
			t.Fatalf("withdrawing answered %d: %s", got.Code, got.Body.String())
		}
		if err := json.Unmarshal(read("CVE-2026-1000"), &f); err != nil {
			t.Fatal(err)
		}
		if len(f.Standing) != 0 || len(f.Previous) != 1 {
			t.Fatalf("after withdrawing, the finding reports %+v", f)
		}
		if f.Previous[0].Ended != "withdrawn" || f.Previous[0].EndedAt == "" || f.Previous[0].Reasoning == "" {
			t.Errorf("what was decided before does not say how it ended, when, or what it argued: %+v", f.Previous[0])
		}

		// An extension that keeps neither outcome nor justification is refused.
		got = asPerson(t, r, "triager", http.MethodPost, fmt.Sprintf(at, "CVE-2026-1000")+"/decision",
			fmt.Sprintf(`{"outcome":"wont-fix","reasoning":"Different claim.","extends":%d}`, neighbor))
		if got.Code != http.StatusUnprocessableEntity {
			t.Errorf("an extension with a different outcome answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestAFindingsRowSaysHowFarItIsDecidedAndWhetherItCameBack(t *testing.T) {
	// The list carried no decision state, so the interface guessed from what
	// the build had argued away and showed "Undecided" over forty-four
	// proposed records. The row now says it, by the state filter's own
	// definition, and says when a claim is back with its author.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		const list = "/v1/products/mine/findings?stream=master&variant=broadcom"
		row := func() (state string, sentBack bool) {
			t.Helper()
			got := asPerson(t, r, "triager", http.MethodGet, list, "")
			if got.Code != http.StatusOK {
				t.Fatalf("listing answered %d: %s", got.Code, got.Body.String())
			}
			var out struct {
				Items []struct {
					State    string `json:"state"`
					SentBack bool   `json:"sent_back"`
				} `json:"items"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil || len(out.Items) != 1 {
				t.Fatalf("the list reads as %s (%v)", got.Body.String(), err)
			}
			return out.Items[0].State, out.Items[0].SentBack
		}

		if state, back := row(); state != "undecided" || back {
			t.Errorf("an undecided finding reads as %q, sent back %v", state, back)
		}
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)
		if state, back := row(); state != "waiting" || back {
			t.Errorf("a proposed claim reads as %q, sent back %v", state, back)
		}
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/send-back", claim), `{"because":"Which encoder?"}`); got.Code != http.StatusNoContent {
			t.Fatalf("sending back answered %d: %s", got.Code, got.Body.String())
		}
		if state, back := row(); state != "waiting" || !back {
			t.Errorf("a claim sent back reads as %q, sent back %v", state, back)
		}
		var ids struct {
			Standing []struct {
				DecisionID int64 `json:"decision_id"`
				ClaimID    int64 `json:"claim_id"`
			} `json:"standing"`
		}
		// The finding itself is still a build's, and says so in its path.
		got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/components/libnl-3-200", "")
		if err := json.Unmarshal(got.Body.Bytes(), &ids); err != nil || len(ids.Standing) != 1 {
			t.Fatalf("the finding reads as %s (%v)", got.Body.String(), err)
		}
		// Revised, it is waiting again; approved, it is agreed.
		if got := asPerson(t, r, "triager", http.MethodPut,
			fmt.Sprintf("/v1/claims/%d/reasoning", ids.Standing[0].ClaimID),
			`{"reasoning":"The encoder only. Re-checked the call sites."}`); got.Code != http.StatusOK {
			// 200 rather than 204: it answers which names in the text reached
			// nobody, so the author is told a mention did not land.
			t.Fatalf("revising answered %d: %s", got.Code, got.Body.String())
		}
		if state, back := row(); state != "waiting" || back {
			t.Errorf("a revised claim reads as %q, sent back %v", state, back)
		}
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}
		if state, back := row(); state != "agreed" || back {
			t.Errorf("an approved claim reads as %q, sent back %v", state, back)
		}
	})
}

func TestAQueueEntryAndADecisionSayWhatTheyAreAbout(t *testing.T) {
	// An approver judges a row from the row: what the issue is, which
	// component, how bad, where it sits, and which build to open. The
	// entry carried only an identifier, and the decision screen no more.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		claim, ids := r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)

		type ref struct {
			Product       string  `json:"product"`
			Stream        string  `json:"stream"`
			Variant       string  `json:"variant"`
			Vulnerability string  `json:"vulnerability"`
			Component     string  `json:"component"`
			Version       string  `json:"version"`
			Severity      string  `json:"severity"`
			Score         float64 `json:"score"`
			Exploited     bool    `json:"exploited"`
			FixState      string  `json:"fix_state"`
			FixedIn       string  `json:"fixed_in"`
			Description   string  `json:"description"`
			Owner         string  `json:"owner"`
			Parent        string  `json:"parent"`
			Places        int     `json:"places"`
			Decided       int     `json:"decided"`
		}
		check := func(what string, f *ref) {
			t.Helper()
			if f == nil {
				t.Fatalf("%s carries no finding", what)
			}
			if f.Product != "Mine" || f.Stream != "master" || f.Variant != "broadcom" {
				t.Errorf("%s names build %s · %s · %s", what, f.Product, f.Stream, f.Variant)
			}
			if f.Vulnerability != "CVE-2026-9999" || f.Component != "linux-image" || f.Version != "5.10" {
				t.Errorf("%s names %s in %s %s", what, f.Vulnerability, f.Component, f.Version)
			}
			if f.Severity != "high" || f.Score != 8.1 || !f.Exploited || f.FixState != "fixed" || f.FixedIn != "5.10.0-27" {
				t.Errorf("%s says %s %.1f exploited=%v %s %s", what, f.Severity, f.Score, f.Exploited, f.FixState, f.FixedIn)
			}
			// The build holds the kernel directly, and the findings list names
			// both ends of a two-step way down as the component itself.
			if f.Description == "" || f.Owner != "linux-image" || f.Parent != "linux-image" {
				t.Errorf("%s says %q, owner %q, parent %q", what, f.Description, f.Owner, f.Parent)
			}
			if f.Places != 1 || f.Decided != 1 {
				t.Errorf("%s counts %d places, %d decided; want 1 and 1", what, f.Places, f.Decided)
			}
		}

		got := asPerson(t, r, "reviewer", http.MethodGet, "/v1/review-queue", "")
		var queue struct {
			Items []struct {
				Finding *ref `json:"finding"`
			} `json:"items"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &queue); err != nil || len(queue.Items) != 1 {
			t.Fatalf("the queue reads as %s (%v)", got.Body.String(), err)
		}
		check("the queue entry", queue.Items[0].Finding)

		got = asPerson(t, r, "triager", http.MethodGet, fmt.Sprintf("/v1/decisions/%d", ids[0]), "")
		if got.Code != http.StatusOK {
			t.Fatalf("reading the decision answered %d: %s", got.Code, got.Body.String())
		}
		var detail struct {
			Finding *ref `json:"finding"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &detail); err != nil {
			t.Fatal(err)
		}
		check("the decision", detail.Finding)
		_ = claim
	})
}

// scannedShared is a build where one library sits under two containers and
// carries two issues: the shape a tree count has to answer per path.
func (r *reach) scannedShared(t *testing.T) {
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
		TargetID: target.ID, ContentHash: "shared", BuiltAt: time.Now().UTC(), ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	a := graph.Described{Purl: "pkg:oci/docker-a@1", Name: "docker-a", Version: "1"}
	b := graph.Described{Purl: "pkg:oci/docker-b@1", Name: "docker-b", Version: "1"}
	lib := graph.Described{Purl: "pkg:deb/debian/libyang@2.1", Name: "libyang", Version: "2.1"}
	if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root:       product,
		Components: []graph.Described{a, b, lib},
		Dependencies: []graph.Dependency{
			{Parent: product, Child: a}, {Parent: product, Child: b},
			{Parent: a, Child: lib}, {Parent: b, Child: lib},
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
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{
		{Issue: finding.Named{Identifier: "CVE-2026-1", Severity: "high"}, Component: lib, FixState: finding.NoFix},
		{Issue: finding.Named{Identifier: "CVE-2026-2", Severity: "low"}, Component: lib, FixState: finding.NoFix},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestATreeCountIsPerPathAndTheListItOpensAgrees(t *testing.T) {
	// A library at two places with two issues reads four under every parent
	// where the count is per finding, because a finding is one issue at one
	// place. Somebody who drilled down one path is looking at one place and
	// expects two — and the list the number opens has to show the same.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedShared(t)
		const build = "/v1/products/mine/streams/master/variants/broadcom"

		type node struct {
			Component string `json:"component"`
			Findings  int    `json:"findings"`
			Beneath   int    `json:"beneath"`
		}
		around := func(name string) (above, below []node) {
			t.Helper()
			got := asPerson(t, r, "triager", http.MethodGet, build+"/components/"+name+"/around", "")
			if got.Code != http.StatusOK {
				t.Fatalf("around %s answered %d: %s", name, got.Code, got.Body.String())
			}
			var out struct {
				Above []node `json:"above"`
				Below []node `json:"below"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			return out.Above, out.Below
		}
		for _, parent := range []string{"docker-a", "docker-b"} {
			_, below := around(parent)
			if len(below) != 1 || below[0].Component != "libyang" {
				t.Fatalf("under %s: %+v", parent, below)
			}
			if below[0].Findings != 2 || below[0].Beneath != 2 {
				t.Errorf("libyang under %s reads %d findings, %d beneath; want 2 and 2", parent, below[0].Findings, below[0].Beneath)
			}
		}
		// The root counts distinct issues open in the build.
		got := asPerson(t, r, "triager", http.MethodGet, build+"/components", "")
		var roots struct {
			Root  *node  `json:"root"`
			Items []node `json:"items"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &roots); err != nil || roots.Root == nil {
			t.Fatalf("the roots read as %s (%v)", got.Body.String(), err)
		}
		if roots.Root.Beneath != 2 {
			t.Errorf("the root reads %d beneath, want the 2 distinct issues", roots.Root.Beneath)
		}
		for _, item := range roots.Items {
			if item.Beneath != 2 {
				t.Errorf("%s reads %d beneath, want 2", item.Component, item.Beneath)
			}
		}

		// The list the number opens: two rows, one per issue and
		// component. The list is scoped by query rather than by path:
		// with the branch and the variant named it is this one build.
		const listing = "/v1/products/mine/findings?stream=master&variant=broadcom"
		list := func(query string) (total int, code int) {
			t.Helper()
			got := asPerson(t, r, "triager", http.MethodGet, listing+query, "")
			var out struct {
				Total int `json:"total"`
			}
			_ = json.Unmarshal(got.Body.Bytes(), &out)
			return out.Total, got.Code
		}
		if total, code := list("&beneath=docker-a"); code != http.StatusOK || total != 2 {
			t.Errorf("beneath docker-a answered %d with %d rows, want 2", code, total)
		}
		if total, code := list("&beneath=libyang"); code != http.StatusOK || total != 2 {
			t.Errorf("beneath libyang answered %d with %d rows, want 2", code, total)
		}
		if total, code := list("&beneath=mine"); code != http.StatusOK || total != 2 {
			t.Errorf("beneath the root answered %d with %d rows, want 2", code, total)
		}
		// under is still the direct consumer, and beneath refuses a name the
		// build does not hold.
		if total, code := list("&under=docker-a"); code != http.StatusOK || total != 2 {
			t.Errorf("under docker-a answered %d with %d rows, want 2", code, total)
		}
		if _, code := list("&beneath=nothing-here"); code != http.StatusUnprocessableEntity {
			t.Errorf("beneath a name the build lacks answered %d, want 422", code)
		}
		got = asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/findings/components?stream=master&variant=broadcom&beneath=docker-b", "")
		var byComponent struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &byComponent); err != nil || got.Code != http.StatusOK || byComponent.Total != 1 {
			t.Errorf("by component beneath docker-b answered %d with %d components, want 1", got.Code, byComponent.Total)
		}
	})
}

func TestTheTreeIsReachedByNameAndVersionWhereANameIsNotEnough(t *testing.T) {
	// A build ships one name at several versions, and arriving from a finding
	// at one of them had no way to say which — the reader saw an error
	// instead of the tree.
	eachReach(t, func(t *testing.T, r *reach) {
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
			TargetID: target.ID, ContentHash: "versions", BuiltAt: time.Now().UTC(), ParserVersion: "test",
		})
		if err != nil || outcome != ingest.Accept {
			t.Fatalf("record scan: %v %v", outcome, err)
		}
		product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
		old := graph.Described{Purl: "pkg:golang/stdlib@go1.24.9", Name: "stdlib", Version: "go1.24.9"}
		newer := graph.Described{Purl: "pkg:golang/stdlib@go1.25.6", Name: "stdlib", Version: "go1.25.6"}
		if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
			Root:       product,
			Components: []graph.Described{old, newer},
			Dependencies: []graph.Dependency{
				{Parent: product, Child: old}, {Parent: product, Child: newer},
			},
		}); err != nil {
			t.Fatal(err)
		}

		const at = "/v1/products/mine/streams/master/variants/broadcom/components/stdlib/around"
		got := asPerson(t, r, "triager", http.MethodGet, at, "")
		if got.Code != http.StatusConflict {
			t.Errorf("a name the build holds at two versions answered %d, want 409: %s", got.Code, got.Body.String())
		}
		got = asPerson(t, r, "triager", http.MethodGet, at+"?version=go1.25.6", "")
		if got.Code != http.StatusOK {
			t.Fatalf("naming the version answered %d: %s", got.Code, got.Body.String())
		}
		var out struct {
			Above []struct {
				Component string `json:"component"`
			} `json:"above"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil || len(out.Above) != 1 || out.Above[0].Component != "mine" {
			t.Errorf("the tree around stdlib go1.25.6 reads as %s (%v)", got.Body.String(), err)
		}
		got = asPerson(t, r, "triager", http.MethodGet, at+"?version=go1.0.0", "")
		if got.Code != http.StatusNotFound {
			t.Errorf("a version the build lacks answered %d, want 404", got.Code)
		}
	})
}

func TestAProposerHoldsPartOfTheirOwnClaimBack(t *testing.T) {
	// Recording in bulk and changing your mind one row at a time was the
	// split, and it was the wrong middle: an approver could hold rows back and
	// the author could only withdraw everything and start again.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		got := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom/components/linux-image/decisions",
			`{"vulnerabilities":["CVE-2026-9999","CVE-2026-1000"],"outcome":"not-applicable",`+
				`"justification":"vulnerable_code_not_present",`+
				`"selected_by":"undecided, description contains \"driver\"",`+
				`"reasoning":"None of these drivers are built for this image."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("deciding answered %d: %s", got.Code, got.Body.String())
		}
		var made struct {
			ClaimID int64   `json:"claim_id"`
			IDs     []int64 `json:"ids"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &made); err != nil || len(made.IDs) < 2 {
			t.Fatalf("the claim reads as %s (%v)", got.Body.String(), err)
		}

		// Somebody who did not make it cannot hold part of it back: that is
		// setting rows aside, and setting rows aside agrees to the rest.
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/split", made.ClaimID),
			fmt.Sprintf(`{"rows":[%d],"because":"Not this one."}`, made.IDs[0])); got.Code < 400 {
			t.Errorf("an approver held part of somebody's claim back: %d", got.Code)
		}

		got = asPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/split", made.ClaimID),
			fmt.Sprintf(`{"rows":[%d],"because":"This one is the driver after all."}`, made.IDs[0]))
		if got.Code != http.StatusCreated {
			t.Fatalf("holding a row back answered %d: %s", got.Code, got.Body.String())
		}
		var held struct {
			ClaimID int64 `json:"claim_id"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &held); err != nil || held.ClaimID == 0 {
			t.Fatalf("holding back answered %s (%v)", got.Body.String(), err)
		}
		if held.ClaimID == made.ClaimID {
			t.Fatal("the rows held back stayed in the claim they came from")
		}

		// The reason is on the new claim, which is where its author reads it.
		var said struct {
			Items []struct {
				Body string `json:"body"`
			} `json:"items"`
		}
		read(t, r, "triager", fmt.Sprintf("/v1/claims/%d/comments", held.ClaimID), &said)
		if len(said.Items) != 1 || said.Items[0].Body != "This one is the driver after all." {
			t.Errorf("the reason did not travel with the rows: %+v", said.Items)
		}
	})
}

func TestOneActionRestoresEverythingOneActionClaimed(t *testing.T) {
	// Deciding is bulk-capable at three grains and re-deciding was capable at
	// none. A team answering one kernel issue writes a decision at each of its
	// places in one action; when the kernel moves those lapse, and restoring
	// them was one request each with a separately typed justification — on a
	// demo image the kernel sits at 45 places per issue.
	//
	// This is the one path that is safe to make cheap. A version bump is a
	// prompt to re-check rather than a new claim, and the earlier agreement is
	// already carried forward.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		claimed := r.agreedThenLapsed(t)

		// One act restores both, with one reasoning and no second person: two
		// people already agreed, and nothing about the issue has changed.
		again := asPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/reaffirmation", claimed),
			`{"reasoning":"Checked again at 8.6.0; the transfer path is still not reached."}`)
		if again.Code != http.StatusCreated {
			t.Fatalf("re-affirming the claim answered %d: %s", again.Code, again.Body.String())
		}
		var restored struct {
			ClaimID   int64   `json:"claim_id"`
			Decisions []int64 `json:"decisions"`
			Places    int     `json:"places"`
			Waiting   bool    `json:"waiting"`
		}
		if err := json.Unmarshal(again.Body.Bytes(), &restored); err != nil {
			t.Fatal(err)
		}
		if len(restored.Decisions) != 2 || restored.Places != 2 {
			t.Errorf("re-affirming wrote %d decisions over %d places, want two of each",
				len(restored.Decisions), restored.Places)
		}
		if restored.Waiting {
			t.Error("re-affirming an agreed claim after a bump asked for a second person")
		}
		if restored.ClaimID == claimed {
			t.Error("a re-affirmation reused the claim it re-makes rather than being its own act")
		}
		// Every row stands, not the first of them. One agreement is an
		// agreement to a claim's words, so it takes effect on all of them
		// together or the act is half decided.
		standing, err := r.db.DB.NewSelect().Table("decision").
			Where("claim_id = ?", restored.ClaimID).Where("state = ?", "approved").
			Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if standing != len(restored.Decisions) {
			t.Errorf("%d of %d re-affirmed rows stand, want all of them",
				standing, len(restored.Decisions))
		}
		// And the agreement is recorded once, not once per row.
		carried, err := r.db.DB.NewSelect().Table("claim_approval").
			Where("claim_id = ?", restored.ClaimID).Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if carried != 1 {
			t.Errorf("one carried agreement was recorded %d times", carried)
		}

		// And nobody else may do it. Re-affirming is the claimant's right: an
		// approver doing it becomes proposer of the new claim while their own
		// earlier agreement is carried onto it.
		if theirs := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/reaffirmation", claimed),
			`{"reasoning":"Looks fine to me."}`); theirs.Code < 400 {
			t.Errorf("somebody else re-affirmed the claim: %d %s",
				theirs.Code, theirs.Body.String())
		}
	})
}

// agreedThenLapsed claims one issue across the whole curl fold, has it agreed
// to, then moves the code under it — which is what makes a decision lapse. It
// answers with the claim whose rows are now lapsed.
func (r *reach) agreedThenLapsed(t *testing.T) int64 {
	t.Helper()
	ctx := t.Context()
	// One judgment over the fold: two packages, two places, one claim.
	decided := asPerson(t, r, "triager", http.MethodPost,
		"/v1/products/mine/streams/master/variants/broadcom"+
			"/components/libcurl4t64/decisions",
		`{"vulnerabilities":["CVE-2026-CURL1"],"outcome":"not-applicable",`+
			`"justification":"vulnerable_code_not_in_execute_path",`+
			`"selected_by":"the transfer path",`+
			`"reasoning":"The transfer path is never reached from this image."}`)
	if decided.Code != http.StatusCreated {
		t.Fatalf("deciding together answered %d: %s", decided.Code, decided.Body.String())
	}
	var made struct {
		ClaimID int64   `json:"claim_id"`
		IDs     []int64 `json:"ids"`
	}
	if err := json.Unmarshal(decided.Body.Bytes(), &made); err != nil {
		t.Fatal(err)
	}
	if len(made.IDs) != 2 {
		t.Fatalf("the claim covers %d places, want the two of the fold", len(made.IDs))
	}
	if ok := asPerson(t, r, "reviewer", http.MethodPost,
		fmt.Sprintf("/v1/claims/%d/approval", made.ClaimID), `{}`); ok.Code != http.StatusOK {
		t.Fatalf("approving answered %d: %s", ok.Code, ok.Body.String())
	}

	// The code moves under them, which is what a lapse is.
	if _, err := r.db.DB.NewUpdate().Table("component").
		Set("version = ?", "8.6.0-1").Set("upstream_version = ?", "8.6.0").
		Where("name LIKE ?", "%curl%").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	var targets []int64
	if err := r.db.DB.NewSelect().TableExpr(`"target" AS "t"`).
		ColumnExpr("t.id").Scan(ctx, &targets); err != nil {
		t.Fatal(err)
	}
	store := triage.NewStore(r.db.DB)
	for _, target := range targets {
		if _, err := store.Lapse(ctx, target); err != nil {
			t.Fatal(err)
		}
	}
	var lapsed int
	lapsed, err := r.db.DB.NewSelect().Table("decision").
		Where("claim_id = ?", made.ClaimID).Where("state = ?", "lapsed").Count(ctx)
	if err != nil || lapsed != 2 {
		t.Fatalf("%d rows of the claim lapsed (err %v), want both", lapsed, err)
	}

	return made.ClaimID
}

func TestOneRowEscalatingSendsTheWholeReAffirmationBack(t *testing.T) {
	// The agreement was that this did not matter much, and that is not an
	// agreement about what it has become. The single form already asks this
	// per row; asked per row here, an act covering forty-five places could
	// have written forty-four standing decisions and one waiting — an approver
	// agreeing to part of an argument they were shown whole.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		claimed := r.agreedThenLapsed(t)

		// The world re-rates it upward after the agreement.
		if _, err := r.db.DB.NewUpdate().Table("vulnerability").
			Set("score_centi = ?", 980).Set("severity = ?", "critical").
			Where("identifier = ?", "CVE-2026-CURL1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		again := asPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/reaffirmation", claimed),
			`{"reasoning":"Checked again at 8.6.0; still not reached."}`)
		if again.Code != http.StatusCreated {
			t.Fatalf("re-affirming answered %d: %s", again.Code, again.Body.String())
		}
		var restored struct {
			ClaimID   int64   `json:"claim_id"`
			Decisions []int64 `json:"decisions"`
			Waiting   bool    `json:"waiting"`
		}
		if err := json.Unmarshal(again.Body.Bytes(), &restored); err != nil {
			t.Fatal(err)
		}
		if !restored.Waiting {
			t.Error("a re-affirmation of something rated worse since stood on its own")
		}
		// And every row of it waits, rather than the one that escalated.
		waiting, err := r.db.DB.NewSelect().Table("decision").
			Where("claim_id = ?", restored.ClaimID).Where("state = ?", "proposed").
			Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if waiting != len(restored.Decisions) {
			t.Errorf("%d of %d rows wait, want all of them",
				waiting, len(restored.Decisions))
		}
		// So it is in the review queue, which is where the second person is.
		var queue struct {
			Items []struct {
				Claim struct {
					ID int64 `json:"id"`
				} `json:"claim"`
			} `json:"items"`
		}
		read(t, r, "reviewer", "/v1/review-queue", &queue)
		found := false
		for _, item := range queue.Items {
			if item.Claim.ID == restored.ClaimID {
				found = true
			}
		}
		if !found {
			t.Error("a re-affirmation needing a second person is not in the review queue")
		}
	})
}

// alsoScannedInto puts the same component and issue behind a second product,
// so that a place identity — which carries no product, deliberately — is the
// same key in both.
func (r *reach) alsoScannedInto(t *testing.T, product, stream, variant string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.db.DB)
	located, err := names.Locate(ctx, product, stream, variant)
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	made, outcome, err := ingest.NewStore(r.db.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "elsewhere-" + product, BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, made.ID, graph.Snapshot{
		Root:         seededRoot,
		Components:   []graph.Described{seededLib},
		Dependencies: []graph.Dependency{{Parent: seededRoot, Child: seededLib}},
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
		Component: seededLib,
		FixState:  finding.FixedUpstream, FixedIn: "3.9.0",
	}}); err != nil {
		t.Fatal(err)
	}
}

func TestAJudgmentAboutTheSameCodeInAnotherProductIsOffered(t *testing.T) {
	// A place identity is a hash of a consumer and a component with no product
	// in it, deliberately, so that a place is recognized across variants. The
	// same key recognizes it across products — two products shipping the same
	// library under the same consumer are the same code in the same position —
	// and without it no team is offered the judgment another team has already
	// made about it. Deciding it again from scratch is the work the grouping
	// exists to avoid.
	eachReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		r.scanned(t)
		r.alsoScannedInto(t, "theirs", "master", "mellanox")

		// Somebody who triages both products, which is what makes the other
		// team's judgment reachable at all.
		theirs, err := catalog.NewStore(r.db.DB).ProductByName(ctx, "theirs")
		if err != nil {
			t.Fatal(err)
		}
		for _, who := range []string{"triager", "reviewer"} {
			person, err := r.rights.Ensure(ctx, who, "", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.rights.GrantRole(ctx, person.ID, theirs.ID,
				access.PublicTriage); err != nil {
				t.Fatal(err)
			}
		}

		// The other team decides, and agrees.
		at := "/v1/products/theirs/streams/master/variants/mellanox" +
			"/findings/CVE-2026-9999/components/libnl-3-200/decision"
		decided := asPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
				`"reasoning":"The affected protocol is not compiled into our build."}`)
		if decided.Code != http.StatusCreated {
			t.Fatalf("deciding in the other product answered %d: %s",
				decided.Code, decided.Body.String())
		}
		var made struct {
			ClaimID int64 `json:"claim_id"`
		}
		if err := json.Unmarshal(decided.Body.Bytes(), &made); err != nil {
			t.Fatal(err)
		}
		if ok := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", made.ClaimID), `{}`); ok.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", ok.Code, ok.Body.String())
		}

		// And it is offered on this product's finding, as evidence.
		here := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200"
		var evidence struct {
			Elsewhere []struct {
				Product    string `json:"product"`
				Outcome    string `json:"outcome"`
				Reasoning  string `json:"reasoning"`
				ApprovedBy string `json:"approved_by"`
			} `json:"elsewhere"`
		}
		read(t, r, "triager", here, &evidence)
		if len(evidence.Elsewhere) != 1 {
			t.Fatalf("this finding offers %d judgments from elsewhere, want the one: %+v",
				len(evidence.Elsewhere), evidence.Elsewhere)
		}
		one := evidence.Elsewhere[0]
		if one.Product != "theirs" || one.Outcome != "not-applicable" {
			t.Errorf("the judgment offered is %+v", one)
		}
		if one.Reasoning == "" || one.ApprovedBy == "" {
			t.Errorf("the judgment is offered with nothing to read: %+v", one)
		}

		// And only to somebody who may read it. A place identity spans
		// products, so a join that did not carry the subject would hand
		// somebody the reasoning, the approver and the existence of a judgment
		// in a product they cannot see at all.
		var blind struct {
			Elsewhere []struct {
				Product string `json:"product"`
			} `json:"elsewhere"`
		}
		read(t, r, "reader", here, &blind)
		if len(blind.Elsewhere) != 0 {
			t.Errorf("somebody with no rights in the other product was shown %d of its "+
				"judgments: %+v", len(blind.Elsewhere), blind.Elsewhere)
		}
	})
}

func TestReAffirmingADismissalIsBoundedAndAPromiseIsNot(t *testing.T) {
	// The outcome comes from the claim being re-made, so a lapsed bulk
	// dismissal comes back through this path — and nothing re-checks a
	// dismissal, which is the reason the cap exists. Unbounded it would write
	// as many rows as it liked, and with the earlier agreement carried on,
	// nobody would stand between the request and the rows.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		claimed := r.agreedThenLapsed(t)

		// One, so the two places of the fold are already past it.
		if got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.together-cap",
			`{"value":"1"}`); got.Code != http.StatusNoContent {
			t.Fatalf("setting the cap answered %d: %s", got.Code, got.Body.String())
		}
		refused := asPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/reaffirmation", claimed),
			`{"reasoning":"Checked again at 8.6.0; still not reached."}`)
		if refused.Code != http.StatusUnprocessableEntity {
			t.Fatalf("re-affirming a dismissal past the cap answered %d: %s",
				refused.Code, refused.Body.String())
		}
		if !strings.Contains(refused.Body.String(), "the limit here is") {
			t.Errorf("the refusal does not name the bound: %s", refused.Body.String())
		}

		// And raising it deliberately is the way through, which is what the
		// refusal offers.
		if got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.together-cap",
			`{"value":"50"}`); got.Code != http.StatusNoContent {
			t.Fatalf("raising the cap answered %d: %s", got.Code, got.Body.String())
		}
		if again := asPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/reaffirmation", claimed),
			`{"reasoning":"Checked again at 8.6.0; still not reached."}`,
		); again.Code != http.StatusCreated {
			t.Fatalf("re-affirming inside the cap answered %d: %s",
				again.Code, again.Body.String())
		}
	})
}

func TestTwoLapsedRowsAtOnePlaceAreOneReAffirmation(t *testing.T) {
	// A place identity is names alone while a decision is keyed on the
	// versions too, so one component at two versions under one consumer is two
	// lapsed rows sharing a place. Walked twice, the act resolved the same
	// current place twice, wrote the same live key twice, and refused the
	// whole of itself with "a decision already stands here" — which is false
	// and leaves the caller nowhere to go.
	twoReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		r.scannedSiblings(t)
		claimed := r.agreedThenLapsed(t)

		// A second lapsed row of the same claim at a place it already covers,
		// written directly: how one place comes to hold two versions is the
		// applying side's subject and has its own tests. What is pinned here
		// is that the act reads one place out of two rows.
		var rows []triage.Decision
		if err := r.db.DB.NewSelect().Model(&rows).
			Where("de.claim_id = ?", claimed).Order("de.id ASC").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			t.Fatal("the claim covers nothing, so this checks nothing")
		}
		twin := rows[0]
		twin.ID = 0
		twin.LiveKey = nil
		was := "0.0.1"
		twin.ComponentUpstreamVersion = &was
		if _, err := r.db.DB.NewInsert().Model(&twin).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		again := asPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/reaffirmation", claimed),
			`{"reasoning":"Checked again at 8.6.0; still not reached."}`)
		if again.Code != http.StatusCreated {
			t.Fatalf("re-affirming a claim with two rows at one place answered %d: %s",
				again.Code, again.Body.String())
		}
		var restored struct {
			Decisions []int64 `json:"decisions"`
			Places    int     `json:"places"`
		}
		if err := json.Unmarshal(again.Body.Bytes(), &restored); err != nil {
			t.Fatal(err)
		}
		// Two places, not three: the twin shares one of them.
		if restored.Places != 2 || len(restored.Decisions) != 2 {
			t.Errorf("re-affirming wrote %d decisions over %d places, want two of each",
				len(restored.Decisions), restored.Places)
		}
	})
}

func TestAClaimInAProductYouCannotSeeAnswersLikeOneThatIsNotThere(t *testing.T) {
	// Refusing on the proposer before anything checks visibility answered a
	// claim elsewhere with one sentence and a missing claim with another, so
	// walking claim identifiers was a directory of every product in the
	// deployment (REQ-42).
	twoReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		r.scanned(t)
		r.alsoScannedInto(t, "theirs", "master", "mellanox")

		// Somebody who triages the other product makes a claim there. The
		// reader below holds nothing in it at all.
		theirs, err := catalog.NewStore(r.db.DB).ProductByName(ctx, "theirs")
		if err != nil {
			t.Fatal(err)
		}
		person, err := r.rights.Ensure(ctx, "private-triage", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.rights.GrantRole(ctx, person.ID, theirs.ID, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		made := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/theirs/streams/master/variants/mellanox"+
				"/findings/CVE-2026-9999/components/libnl-3-200/decision",
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
				`"reasoning":"Not compiled into that build."}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("deciding in the other product answered %d: %s",
				made.Code, made.Body.String())
		}
		var theirClaim struct {
			ClaimID int64 `json:"claim_id"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &theirClaim); err != nil {
			t.Fatal(err)
		}

		// A claim that exists and one that does not, asked by somebody who may
		// see neither. The two answers have to be the same answer.
		invisible := asPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/reaffirmation", theirClaim.ClaimID),
			`{"reasoning":"Still true."}`)
		absent := asPerson(t, r, "triager", http.MethodPost,
			"/v1/claims/999999/reaffirmation", `{"reasoning":"Still true."}`)
		if invisible.Code != absent.Code {
			t.Errorf("a claim elsewhere answered %d and a missing one %d",
				invisible.Code, absent.Code)
		}
		if invisible.Body.String() != absent.Body.String() {
			t.Errorf("a claim elsewhere answered %q and a missing one %q",
				invisible.Body.String(), absent.Body.String())
		}
	})
}
