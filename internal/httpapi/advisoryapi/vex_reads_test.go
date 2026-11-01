// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// A decision filed under an issue that has since merged into another is about
// the issue it merged into, and the VEX document states it under that issue.
func TestADecisionFiledUnderAMergedIssueIsStatedUnderTheIssueItJoined(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		r.ScannedTwoIssues(t)
		decision, _ := r.Claimed(t, "triager", "CVE-2026-1000", "linux-image", httpapitest.Dismissal)
		r.Agreed(t, decision)

		db := r.DB.DB
		kept, err := finding.NewVulnerabilities(db).ByName(ctx, "CVE-2026-1000")
		if err != nil {
			t.Fatal(err)
		}
		at := time.Now().UTC().Truncate(time.Microsecond)
		absorbed := &finding.Vulnerability{
			Identifier: "GHSA-2026-merged", IdentifierFolded: finding.FoldIdentifier("GHSA-2026-merged"),
			FirstSeenAt: at,
		}
		if _, err := db.NewInsert().Model(absorbed).Value("issue_id", "?", kept).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		r.PatchedRows(t, fmt.Sprintf(`UPDATE "decision_occurrence" SET "vulnerability_id" = %d
			WHERE "vulnerability_id" = %d`, absorbed.ID, kept))

		got := r.VexStatements(t)
		if len(got) != 1 || got[0][0] != "CVE-2026-1000" || got[0][1] != "not_affected" {
			t.Errorf("a decision filed under a merged issue published as %v, want CVE-2026-1000 not affected", got)
		}
	})
}

// Two occurrences of one component covered with different outcomes are no
// statement about the component: each is stated about its own consumer.
func TestOccurrencesCoveredWithDifferentOutcomesAreNoStatementAboutTheBuild(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedInTwoImages(t)
		var occurrences struct {
			Occurrences []struct {
				Occurrence string `json:"occurrence"`
			} `json:"occurrences"`
		}
		httpapitest.Read(t, r, "triager", httpapitest.FindingAt("CVE-2026-9999"), &occurrences)
		if len(occurrences.Occurrences) != 2 {
			t.Fatalf("the fixture holds this issue at %d occurrences, want two", len(occurrences.Occurrences))
		}
		for i, body := range []string{httpapitest.Dismissal,
			`{"outcome":"already-fixed","fixed_version":"3.7.1","reasoning":"The vendor backported the fix."}`} {
			got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
				"/v1/products/mine/branches-and-tags/master/variants/broadcom"+
					"/findings/CVE-2026-9999/occurrences/"+occurrences.Occurrences[i].Occurrence+"/decision", body)
			if got.Code != http.StatusCreated {
				t.Fatalf("deciding occurrence %d answered %d: %s", i, got.Code, got.Body.String())
			}
			var made struct {
				DecisionID int64 `json:"decision_id"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &made); err != nil {
				t.Fatal(err)
			}
			r.Agreed(t, made.DecisionID)
		}

		images := map[string]bool{
			"pkg:oci/docker-swss@master.7-abc?arch=amd64":  true,
			"pkg:oci/docker-teamd@master.7-abc?arch=amd64": true,
		}
		stated := 0
		for _, each := range buildVEX(t, r).Statements {
			if each.Vulnerability.Name != "CVE-2026-9999" {
				continue
			}
			stated++
			if !images[each.Products[0].ID] {
				t.Errorf("occurrences decided differently are stated %q about %s, want each about its image",
					each.Status, each.Products[0].ID)
			}
		}
		if stated != 2 {
			t.Errorf("%d statements about the issue, want one per occurrence", stated)
		}
	})
}

// A statement names the component as the build states it now: its open node,
// and that node's open image version, never one a later scan closed.
func TestAStatementNamesWhatTheBuildStatesNowAndNotWhatItClosed(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedInTwoImages(t)
		decision, _ := r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", httpapitest.Dismissal)
		r.Agreed(t, decision)
		// A closed node of the component and a closed version of each image,
		// each naming an identifier that sorts ahead of the one standing.
		r.PatchedRows(t, `INSERT INTO "graph_node" ("build_id", "component_id", "opened_scan_id",
				"closed_scan_id", "purl", "is_root")
			SELECT "build_id", "component_id", "opened_scan_id", "opened_scan_id", 'pkg:deb/debian/aaa-closed', "is_root"
			FROM "graph_node" WHERE "purl" = 'pkg:deb/debian/libnl-3-200@3.7.0'`)
		r.PatchedRows(t, `INSERT INTO "image_version" ("node_id", "version", "purl", "opened_scan_id", "closed_scan_id")
			SELECT "node_id", 'closed', 'pkg:oci/aaa-closed', "opened_scan_id", "opened_scan_id"
			FROM "image_version" WHERE "closed_scan_id" IS NULL`)

		stated := 0
		for _, each := range buildVEX(t, r).Statements {
			if each.Vulnerability.Name != "CVE-2026-9999" {
				continue
			}
			stated++
			if got := each.Products[0].Subcomponents[0].ID; got != "pkg:deb/debian/libnl-3-200@3.7.0" {
				t.Errorf("the component is named %s, want the identifier its open node states", got)
			}
		}
		if stated != 1 {
			t.Errorf("%d statements about the issue, want one", stated)
		}

		var occurrences struct {
			Occurrences []struct {
				Occurrence string `json:"occurrence"`
			} `json:"occurrences"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/branches-and-tags/master/variants/broadcom"+
			"/findings/CVE-2026-9998/components/docker-swss", &occurrences)
		if len(occurrences.Occurrences) != 1 {
			t.Fatalf("the image's own issue sits at %d occurrences, want one", len(occurrences.Occurrences))
		}
		one := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom"+
				"/findings/CVE-2026-9998/occurrences/"+occurrences.Occurrences[0].Occurrence+"/decision", httpapitest.Dismissal)
		if one.Code != http.StatusCreated {
			t.Fatalf("deciding the image's issue answered %d: %s", one.Code, one.Body.String())
		}
		var made struct {
			DecisionID int64 `json:"decision_id"`
		}
		if err := json.Unmarshal(one.Body.Bytes(), &made); err != nil {
			t.Fatal(err)
		}
		r.Agreed(t, made.DecisionID)
		for _, each := range buildVEX(t, r).Statements {
			if each.Vulnerability.Name != "CVE-2026-9998" {
				continue
			}
			if got := each.Products[0].Subcomponents[0].ID; got != "pkg:oci/docker-swss@master.7-abc?arch=amd64" {
				t.Errorf("the image is named %s, want its open version's stamp", got)
			}
		}
	})
}

// buildVEX reads the scanned build's VEX document.
func buildVEX(t *testing.T, r *httpapitest.Reach) builtVEX {
	t.Helper()
	var doc builtVEX
	httpapitest.Read(t, r, "triager", "/v1/products/mine/branches-and-tags/master/variants/broadcom/vex", &doc)
	return doc
}

// builtVEX is what these tests read of a VEX document.
type builtVEX struct {
	Statements []struct {
		Vulnerability struct {
			Name string `json:"name"`
		} `json:"vulnerability"`
		Status   string `json:"status"`
		Products []struct {
			ID            string `json:"@id"`
			Subcomponents []struct {
				ID string `json:"@id"`
			} `json:"subcomponents"`
		} `json:"products"`
	} `json:"statements"`
}
