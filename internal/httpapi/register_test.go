// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
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

// TestTheRegisterNamesWhatItWasMeasuredWith is the auditor's chain.
//
// Shipped artifact, inventory, run, scanner and database, disposition. The
// register is the last link and named none of the first four, so what it said
// stood on nothing a reader could check — while every one of them was already
// recorded, and the route that hands back the inventory it names already
// existed and was reachable from nothing.
func TestTheRegisterNamesWhatItWasMeasuredWith(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		document := r.inventoryOf(t, "the inventory this build shipped")

		const at = "/v1/products/mine/streams/master/variants/broadcom/register"
		var register struct {
			Measured struct {
				Scan            int64  `json:"scan"`
				ScanHash        string `json:"scan_hash"`
				BuiltAt         string `json:"built_at"`
				Run             int64  `json:"run"`
				Scanner         string `json:"scanner"`
				ScannerVersion  string `json:"scanner_version"`
				DatabaseVersion string `json:"database_version"`
				RanAt           string `json:"ran_at"`
				Document        int64  `json:"document"`
				DocumentHash    string `json:"document_hash"`
				DocumentHeld    *bool  `json:"document_held"`
				DocumentAt      string `json:"document_at"`
			} `json:"measured"`
		}
		read(t, r, "triager", at, &register)
		measured := register.Measured

		if measured.Scan == 0 || measured.ScanHash == "" || measured.BuiltAt == "" {
			t.Errorf("the register does not name the upload it describes: %+v", measured)
		}
		if measured.Run == 0 || measured.Scanner == "" || measured.ScannerVersion == "" ||
			measured.DatabaseVersion == "" || measured.RanAt == "" {
			t.Errorf("the register does not name the run it came from: %+v", measured)
		}
		if measured.Document != document || measured.DocumentHash == "" {
			t.Errorf("the register does not name the inventory that was read: %+v", measured)
		}
		if measured.DocumentHeld == nil || !*measured.DocumentHeld {
			t.Fatalf("the inventory is here and the register says otherwise: %+v", measured)
		}

		// And the link is one somebody can follow, which is the difference
		// between evidence and a claim: the hash comes back over the bytes
		// this hands over.
		fetched := asPerson(t, r, "triager", http.MethodGet, measured.DocumentAt, "")
		if fetched.Code != http.StatusOK {
			t.Fatalf("the inventory the register names answered %d: %s",
				fetched.Code, fetched.Body.String())
		}
		if fetched.Body.String() != "the inventory this build shipped" {
			t.Errorf("the link hands back %q", fetched.Body.String())
		}

		// The file says the same, because a spreadsheet is where this is read
		// six months later and it has nowhere else to carry it.
		file := asPerson(t, r, "triager", http.MethodGet, at+".csv", "")
		if file.Code != http.StatusOK {
			t.Fatalf("exporting answered %d", file.Code)
		}
		rows, err := csv.NewReader(strings.NewReader(file.Body.String())).ReadAll()
		if err != nil {
			t.Fatalf("the register is not a spreadsheet: %v", err)
		}
		says := states(rows)
		if says["scan"] == "" || says["inventory hash"] == "" || says["scanner"] == "" ||
			says["vulnerability data"] == "" || says["measured at"] == "" {
			t.Errorf("the file does not say what it was measured with: %v", says)
		}
	})
}

// inventoryOf gives the build's newest upload the inventory it was read from,
// and finishes the run so it is one somebody could have read.
func (r *reach) inventoryOf(t *testing.T, contents string) int64 {
	t.Helper()
	ctx := t.Context()
	located, err := catalog.NewStore(r.db.DB).Locate(ctx, "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	target, err := catalog.NewStore(r.db.DB).TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	scan, err := ingest.NewStore(r.db.DB).Newest(ctx, target.ID)
	if err != nil || scan == nil {
		t.Fatalf("the build has no upload to hang an inventory on: %v", err)
	}
	document, err := ingest.NewDocuments(r.db.DB).Write(ctx, scan.ID, ingest.InventoryKind, 0,
		strings.NewReader(contents))
	if err != nil {
		t.Fatal(err)
	}
	var runID int64
	if err := r.db.DB.NewSelect().Table("scan_run").ColumnExpr("id").
		Where("target_id = ?", target.ID).Order("id DESC").Limit(1).
		Scan(ctx, &runID); err != nil {
		t.Fatal(err)
	}
	if err := finding.NewStore(r.db.DB).Finish(ctx, runID, "0.112.0", "2026-08-28",
		"", nil); err != nil {
		t.Fatal(err)
	}
	return document.ID
}

// TestTheRegisterNarrows is what an auditor does with it.
//
// It took no filters at all, so "show me what nobody decided" on a build of a
// quarter of a million rows was a spreadsheet and a search box.
func TestTheRegisterNarrows(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)

		const at = "/v1/products/mine/streams/master/variants/broadcom/register"
		rows := func(t *testing.T, query string) []struct {
			Vulnerability string `json:"vulnerability"`
			State         string `json:"state"`
			Outcome       string `json:"outcome"`
		} {
			t.Helper()
			var out struct {
				Items []struct {
					Vulnerability string `json:"vulnerability"`
					State         string `json:"state"`
					Outcome       string `json:"outcome"`
				} `json:"items"`
				Total int `json:"total"`
			}
			read(t, r, "private-triage", at+query, &out)
			// The count is of the narrowed list, not of the build: counted
			// over the build, a filtered page says how many rows the build
			// holds and every later offset is a page of a different list.
			if out.Total != len(out.Items) {
				t.Errorf("%q says %d rows and carries %d", query, out.Total, len(out.Items))
			}
			return out.Items
		}

		if whole := rows(t, ""); len(whole) != 2 {
			t.Fatalf("the whole register holds %d rows, want both issues", len(whole))
		}
		// The row every other report leaves out, which is what an auditor is
		// looking for.
		undecided := rows(t, "?state=undecided")
		if len(undecided) != 1 || undecided[0].Vulnerability != "CVE-2026-1000" {
			t.Errorf("narrowed to undecided the register holds %+v", undecided)
		}
		waiting := rows(t, "?state=waiting")
		if len(waiting) != 1 || waiting[0].Vulnerability != "CVE-2026-9999" {
			t.Errorf("narrowed to waiting the register holds %+v", waiting)
		}
		// Two words is either of them, which is how "anything nobody has
		// agreed to" is asked.
		if both := rows(t, "?state=undecided&state=waiting"); len(both) != 2 {
			t.Errorf("two words kept %d rows", len(both))
		}
		if dismissals := rows(t, "?outcome=not-applicable"); len(dismissals) != 1 {
			t.Errorf("narrowed to a dismissal the register holds %+v", dismissals)
		}
		if named := rows(t, "?component=linux-image"); len(named) != 2 {
			t.Errorf("narrowed to the component both sit on, %d rows", len(named))
		}
		if elsewhere := rows(t, "?component=nothing-is-called-this"); len(elsewhere) != 0 {
			t.Errorf("a component the build does not hold kept %d rows", len(elsewhere))
		}
		if open := rows(t, "?standing=open"); len(open) != 2 {
			t.Errorf("both are open and %d came back", len(open))
		}
		if closed := rows(t, "?standing=closed"); len(closed) != 0 {
			t.Errorf("nothing is closed and %d came back", len(closed))
		}

		// And the file takes the same filters, so a spreadsheet taken from a
		// narrowed screen is that narrowing rather than the whole build.
		file := asPerson(t, r, "private-triage", http.MethodGet,
			at+".csv?state=undecided", "")
		if file.Code != http.StatusOK {
			t.Fatalf("exporting answered %d", file.Code)
		}
		lines, err := csv.NewReader(strings.NewReader(file.Body.String())).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if body := rowsUnder(lines); len(body) != 2 {
			t.Errorf("the narrowed file holds %d rows under its header", len(body)-1)
		}
		if !strings.Contains(file.Body.String(), "CVE-2026-1000") {
			t.Error("the narrowed file does not hold the undecided row")
		}
	})
}
