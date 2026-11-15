// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// TestReadinessSaysWhatIsBlocking is the list behind the count.
//
// "8 criticals now, v2.4.1 shipped with 4" is read at the moment there is no
// time to go and assemble what the 8 are, and the answer carried no list at
// all — so the one screen a release conversation happens in sent everybody
// back to the findings list to rebuild the same narrowing by hand.
func TestReadinessSaysWhatIsBlocking(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)

		const at = "/v1/products/mine/branches-and-tags/master/variants/broadcom/readiness"
		ready := func(t *testing.T) struct {
			Blockers int `json:"blockers"`
			Blocking []struct {
				Vulnerability string `json:"vulnerability"`
				State         string `json:"state"`
				Occurrences   int    `json:"occurrences"`
			} `json:"blocking"`
		} {
			t.Helper()
			var out struct {
				Blockers int `json:"blockers"`
				Blocking []struct {
					Vulnerability string `json:"vulnerability"`
					State         string `json:"state"`
					Occurrences   int    `json:"occurrences"`
				} `json:"blocking"`
			}
			httpapitest.Read(t, r, "private-triage", at, &out)
			return out
		}

		first := ready(t)
		if first.Blockers != 2 || len(first.Blocking) != 2 {
			t.Fatalf("nothing is decided and the blocker list holds %d of %d",
				len(first.Blocking), first.Blockers)
		}
		if first.Blocking[0].State != "undecided" || first.Blocking[0].Occurrences == 0 {
			t.Errorf("a blocker reads as %+v", first.Blocking[0])
		}

		// Agreeing to ship with something is the decision this list is about,
		// so it leaves: a row somebody agreed to is not standing between the
		// branch and the release.
		decision, _ := r.Claimed(t, "triager", "CVE-2026-9999", "linux-image", httpapitest.Dismissal)
		r.Agreed(t, decision)
		after := ready(t)
		if after.Blockers != 1 || len(after.Blocking) != 1 {
			t.Fatalf("after agreeing to one, %d of %d block",
				len(after.Blocking), after.Blockers)
		}
		if after.Blocking[0].Vulnerability != "CVE-2026-1000" {
			t.Errorf("the row somebody agreed to is still blocking: %+v", after.Blocking[0])
		}
	})
}

// TestBlockingRowsOfOneComponentAreToldApart pins the version on the row.
//
// A group is keyed on the issue and the fold, and a fold is the source package
// at the version it was built at — so one issue on one component at two
// versions is two rows. Named by component alone they arrive identical: the
// panel drew the same line twice, under the same React key, and a reader had
// no way to tell which of the two a row was about.
func TestBlockingRowsOfOneComponentAreToldApart(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedOneIssueAtTwoVersions(t)

		var out struct {
			Blocking []struct {
				Vulnerability string `json:"vulnerability"`
				Component     string `json:"component"`
				Version       string `json:"version"`
			} `json:"blocking"`
		}
		httpapitest.Read(t, r, "private-triage",
			"/v1/products/mine/branches-and-tags/master/variants/broadcom/readiness", &out)

		if len(out.Blocking) != 2 {
			t.Fatalf("one issue at two versions of one component is %d rows", len(out.Blocking))
		}
		first, second := out.Blocking[0], out.Blocking[1]
		if first.Component != second.Component || first.Vulnerability != second.Vulnerability {
			t.Fatalf("the fixture stopped being one issue at one component: %+v %+v", first, second)
		}
		if first.Version == "" || second.Version == "" {
			t.Fatalf("a row carries no version: %+v %+v", first, second)
		}
		if first.Version == second.Version {
			t.Errorf("two rows of %q are identical at version %q",
				first.Component, first.Version)
		}
	})
}

// A tag declared and not yet built is the ordinary state of a tag between
// being cut and its pipeline running. It answers, saying nothing has been
// scanned there, rather than failing or reporting a clean build. A tag whose
// first upload was refused has a build and no scan, and reads the same: the
// upload handler names the build before it records the refusal.
//
// On every engine, because the build with no match is what the standing
// query's outer join is for.
func TestReadinessForATagNotYetBuiltSaysNothingHasBeenScanned(t *testing.T) {
	for _, refused := range []bool{false, true} {
		name := "never built"
		if refused {
			name = "an upload refused"
		}
		t.Run(name, func(t *testing.T) {
			httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
				ctx := t.Context()
				r.ScannedTwoIssues(t)
				names := catalog.NewStore(r.DB.DB)
				product, err := names.ProductByName(ctx, "mine")
				if err != nil {
					t.Fatal(err)
				}
				tag, err := names.DeclareBranchOrTag(ctx, product.ID, "v2.5.0", catalog.Tag, nil)
				if err != nil {
					t.Fatal(err)
				}
				if refused {
					variant, err := names.VariantByName(ctx, product.ID, "broadcom")
					if err != nil {
						t.Fatal(err)
					}
					if _, err := names.BuildFor(ctx, tag.ID, variant.ID); err != nil {
						t.Fatal(err)
					}
				}

				const at = "/v1/products/mine/branches-and-tags/v2.5.0/variants/broadcom/readiness"
				answered := httpapitest.AsPerson(t, r, "reader", http.MethodGet, at, "")
				if answered.Code != http.StatusOK {
					t.Fatalf("readiness for a tag not yet built answered %d: %s", answered.Code,
						answered.Body.String())
				}
				var out struct {
					Now struct {
						BranchOrTag   string `json:"branch_or_tag"`
						Total         int    `json:"total"`
						LastScannedAt string `json:"last_scanned_at"`
					} `json:"now"`
					Why string `json:"why"`
				}
				if err := json.Unmarshal(answered.Body.Bytes(), &out); err != nil {
					t.Fatal(err)
				}
				if out.Why != finding.NothingScannedYet {
					t.Errorf("why reads %q, want %q", out.Why, finding.NothingScannedYet)
				}
				if out.Now.BranchOrTag != "v2.5.0" || out.Now.Total != 0 || out.Now.LastScannedAt != "" {
					t.Errorf("the build reads %+v", out.Now)
				}
			})
		})
	}
}

// Readiness compares a branch with the last release cut from it, built the
// same way and scanned, and says the least severity it counts where the
// product hides what is below it.
func TestReadinessComparesWithTheLastReleaseCutFromTheBranch(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		r.ScannedTwoIssues(t)
		names := catalog.NewStore(r.DB.DB)
		product, err := names.ProductByName(ctx, "mine")
		if err != nil {
			t.Fatal(err)
		}
		master, err := names.BranchOrTagByName(ctx, product.ID, "master")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := names.DeclareBranchOrTag(ctx, product.ID, "v1.0", catalog.Tag, &master.ID); err != nil {
			t.Fatal(err)
		}
		kernel := graph.Described{Purl: "pkg:deb/debian/linux-image@5.10", Name: "linux-image", Version: "5.10"}
		r.ScanAt(t, httpapitest.Build{Product: "mine", BranchOrTag: "v1.0", Variant: "broadcom"},
			"released", graph.Snapshot{Root: httpapitest.SeededRoot, Components: []graph.Described{kernel},
				Dependencies: []graph.Dependency{{Parent: httpapitest.SeededRoot, Child: kernel}}},
			[]finding.Reported{{Issue: finding.Named{Identifier: "CVE-2026-9999", Severity: "high"},
				Component: kernel, FixState: finding.NoFix}})
		// A build is compared once a scan of it has finished.
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"scan_run"`).Set(`"finished_at" = "started_at"`).
			Where(`"finished_at" IS NULL`).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		type counts struct {
			BranchOrTag string `json:"branch_or_tag"`
			High        int    `json:"high"`
			Low         int    `json:"low"`
			Total       int    `json:"total"`
		}
		read := func(t *testing.T) (now counts, shipped *counts, minimum string) {
			t.Helper()
			var out struct {
				Now             counts  `json:"now"`
				Shipped         *counts `json:"shipped"`
				MinimumSeverity string  `json:"minimum_severity"`
			}
			httpapitest.Read(t, r, "private-triage",
				"/v1/products/mine/branches-and-tags/master/variants/broadcom/readiness", &out)
			return out.Now, out.Shipped, out.MinimumSeverity
		}
		now, shipped, minimum := read(t)
		if now.Total != 2 || shipped == nil || shipped.BranchOrTag != "v1.0" ||
			shipped.Total != 1 || shipped.High != 1 {
			t.Fatalf("now %+v against shipped %+v, want two now against the release's one high", now, shipped)
		}
		if minimum != "" {
			t.Errorf("a product hiding nothing says it counts from %q", minimum)
		}

		if err := names.SetMinimumSeverity(ctx, product.ID, "medium"); err != nil {
			t.Fatal(err)
		}
		now, shipped, minimum = read(t)
		if minimum != "medium" || now.Total != 1 || now.Low != 0 || shipped == nil || shipped.Total != 1 {
			t.Errorf("from medium up, now %+v against shipped %+v counted from %q, want the low left out",
				now, shipped, minimum)
		}
	})
}
