// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

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
		r.agreed(t, neighbor)
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
		r.agreed(t, claim)
		if state, back := row(); state != "agreed" || back {
			t.Errorf("an approved claim reads as %q, sent back %v", state, back)
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
		r.agreed(t, made.ClaimID)

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
