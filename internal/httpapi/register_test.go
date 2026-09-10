package httpapi_test

import (
	"fmt"
	"net/http"
	"testing"
)

func TestTheRegisterHoldsWhatNobodyHasDecided(t *testing.T) {
	// The audit list says what was decided; an auditor's first question is
	// what was *known*, decided or not. A register of only what somebody
	// answered is the report they already have.
	twoReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)

		const at = "/v1/products/mine/streams/master/variants/broadcom/register"
		var register struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
				State         string `json:"state"`
				Outcome       string `json:"outcome"`
				ProposedBy    string `json:"proposed_by"`
				ApprovedBy    string `json:"approved_by"`
				Opened        string `json:"opened"`
				Due           string `json:"due"`
			} `json:"items"`
			Total int `json:"total"`
		}
		read(t, r, "triager", at, &register)
		if register.Total == 0 || len(register.Items) == 0 {
			t.Fatal("the register is empty for a build that holds a finding")
		}
		// The row the other reports leave out.
		one := register.Items[0]
		if one.State != "undecided" {
			t.Errorf("nobody has decided anything and the register says %q", one.State)
		}
		if one.Opened == "" {
			t.Error("the register does not say when this was known")
		}
		if one.ProposedBy != "" || one.ApprovedBy != "" {
			t.Errorf("a row nobody decided names %q and %q", one.ProposedBy, one.ApprovedBy)
		}

		// And once somebody decides, the row carries who and when — both
		// names, because two different people is the whole of the control.
		made := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/places/"+place+"/decision",
			`{"outcome":"wont-fix","reasoning":"Not worth it here."}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("deciding answered %d: %s", made.Code, made.Body.String())
		}
		read(t, r, "triager", at, &register)
		after := register.Items[0]
		if after.State != "waiting" || after.Outcome != "wont-fix" {
			t.Errorf("after a claim the register says %q/%q", after.State, after.Outcome)
		}
		if after.ProposedBy == "" {
			t.Error("the register does not say who claimed it")
		}
		if after.ApprovedBy != "" {
			t.Errorf("nobody has agreed and the register names %q", after.ApprovedBy)
		}
	})
}

func TestTheRegisterLeavesAsAFileWithTheSameVisibility(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/streams/master/variants/broadcom/register.csv", "")
		if got.Code != http.StatusOK {
			t.Fatalf("exporting the register answered %d: %s", got.Code, got.Body.String())
		}
		// It states no triage line, because it applies none. The register is
		// every place in the build with what stands there, which is what makes
		// it answerable to an auditor — and a header saying things were left
		// out above a file that left nothing out is worse than saying nothing,
		// because it reads as complete about what remains.
		if contains(got.Body.String(), "# triaged at or above") {
			t.Error("the register export claims a triage line it does not apply")
		}
		if !contains(got.Body.String(), "CVE-2026-9999") {
			t.Error("the register export holds no rows")
		}
		// Somebody who holds nothing on the product gets nothing at all.
		if refused := asPerson(t, r, "approver", http.MethodGet,
			"/v1/products/mine/streams/master/variants/broadcom/register.csv",
			""); refused.Code < 400 {
			t.Errorf("somebody holding no read role exported the register: %d", refused.Code)
		}
	})
}

func TestTheRegisterPagesWithoutSkippingRows(t *testing.T) {
	// Nothing makes an approval unique per decision — a second approver adds a
	// row — and it was joined, so each extra one multiplied its finding into
	// two rows on a page whose total counts findings. The page then held one
	// row fewer than it said, and every later offset skipped one, so an
	// auditor paging a register never saw some of it and nothing said so.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		claim, ids := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)
		if ok := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); ok.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", ok.Code, ok.Body.String())
		}
		// A second agreement on the same claim, which is what the schema
		// allows and what multiplied the row. Written directly, because a
		// second approver going through the endpoint is a different subject
		// and this is about the shape of the row rather than about who may
		// add one.
		if _, err := r.db.DB.NewRaw(
			`INSERT INTO "claim_approval"
				("claim_id", "revision_id", "approved_by", "approved_at")
			 SELECT "claim_id", "revision_id", "approved_by", "approved_at"
			 FROM "claim_approval"
			 WHERE "claim_id" = (SELECT "claim_id" FROM "decision" WHERE "id" = ?)`,
			ids[0]).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		at := "/v1/products/mine/streams/master/variants/broadcom/register"
		var whole struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
				PlaceIdentity string `json:"place_identity"`
			} `json:"items"`
			Total int `json:"total"`
		}
		read(t, r, "triager", at+"?limit=200", &whole)
		if len(whole.Items) != whole.Total {
			t.Errorf("the register lists %d rows of %d, which do not agree",
				len(whole.Items), whole.Total)
		}
		seen := map[string]bool{}
		for _, row := range whole.Items {
			key := row.Vulnerability + " " + row.PlaceIdentity
			if seen[key] {
				t.Errorf("the register lists %q twice", key)
			}
			seen[key] = true
		}
	})
}
