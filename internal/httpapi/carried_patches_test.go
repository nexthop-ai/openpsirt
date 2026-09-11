package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

func TestWhatABuildCarriesIsReachableAndNarrowedLikeEverythingElse(t *testing.T) {
	// The store's own test covers the history; this covers that it can be
	// reached at all, and by whom — a build's claims say what it ships and
	// what it has already patched, which is as much about the build as its
	// inventory is.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)

		// Recorded against the scan the fixture just filed, which is what the
		// reader would have done with a component's pedigree.
		names := catalog.NewStore(r.db.DB)
		located, err := names.Locate(t.Context(), "mine", "master", "broadcom")
		if err != nil {
			t.Fatal(err)
		}
		target, err := names.TargetFor(t.Context(), located.StreamID, located.VariantID)
		if err != nil {
			t.Fatal(err)
		}
		var scanID int64
		if err := r.db.DB.NewSelect().TableExpr("scan").ColumnExpr("MAX(id)").
			Where("target_id = ?", target.ID).Scan(t.Context(), &scanID); err != nil {
			t.Fatal(err)
		}
		if _, err := finding.NewStore(r.db.DB).RecordClaims(t.Context(), target.ID, scanID,
			[]sbom.Suppression{{
				Vulnerability: "CVE-2026-9999", Status: sbom.AlreadyFixed,
				Origin: sbom.FromPedigree, Statement: "Backported as a distro patch.",
				Targets: []sbom.Target{{Name: "libnl-3-200"}},
			}},
			// A CycloneDX scan, which can state a claim of either origin.
			map[sbom.Origin]bool{sbom.FromStatement: true, sbom.FromPedigree: true}); err != nil {
			t.Fatal(err)
		}

		const at = "/v1/products/mine/streams/master/variants/broadcom/carried-patches"
		var body struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
				Subject       string `json:"subject"`
				Pedigree      bool   `json:"pedigree"`
				Suppresses    bool   `json:"suppresses"`
				Since         string `json:"since"`
				Until         string `json:"until"`
			} `json:"items"`
			Total int `json:"total"`
		}
		read(t, r, "triager", at, &body)
		if body.Total != 1 || len(body.Items) != 1 {
			t.Fatalf("%d of %d rows: %+v", len(body.Items), body.Total, body.Items)
		}
		one := body.Items[0]
		if !one.Pedigree || !one.Suppresses || one.Since == "" || one.Until != "" {
			t.Errorf("the carried patch reads as %+v", one)
		}

		// Narrowed on what the claim says it is about.
		read(t, r, "triager", at+"?component=nothing-called-this", &body)
		if body.Total != 0 {
			t.Errorf("a package nothing was claimed about found %d rows", body.Total)
		}

		// A build's claims are read by whoever may read its findings and by
		// nobody else: a claim names an issue and a package, which is the
		// finding said another way.
		if got := asPerson(t, r, "approver", http.MethodGet, at, ""); got.Code < 400 {
			var refused struct {
				Total int `json:"total"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &refused); err == nil && refused.Total > 0 {
				t.Errorf("somebody who may read nothing here was told about %d claims",
					refused.Total)
			}
		}
	})
}
