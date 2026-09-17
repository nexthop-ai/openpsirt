package httpapi_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// TestReadinessSaysWhatIsBlocking is the list behind the count.
//
// "8 criticals now, v2.4.1 shipped with 4" is read at the moment there is no
// time to go and assemble what the 8 are, and the answer carried no list at
// all — so the one screen a release conversation happens in sent everybody
// back to the findings list to rebuild the same narrowing by hand.
func TestReadinessSaysWhatIsBlocking(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		const at = "/v1/products/mine/streams/master/variants/broadcom/readiness"
		ready := func(t *testing.T) struct {
			Blockers int `json:"blockers"`
			Blocking []struct {
				Vulnerability string `json:"vulnerability"`
				State         string `json:"state"`
				Places        int    `json:"places"`
			} `json:"blocking"`
		} {
			t.Helper()
			var out struct {
				Blockers int `json:"blockers"`
				Blocking []struct {
					Vulnerability string `json:"vulnerability"`
					State         string `json:"state"`
					Places        int    `json:"places"`
				} `json:"blocking"`
			}
			read(t, r, "private-triage", at, &out)
			return out
		}

		first := ready(t)
		if first.Blockers != 2 || len(first.Blocking) != 2 {
			t.Fatalf("nothing is decided and the blocker list holds %d of %d",
				len(first.Blocking), first.Blockers)
		}
		if first.Blocking[0].State != "undecided" || first.Blocking[0].Places == 0 {
			t.Errorf("a blocker reads as %+v", first.Blocking[0])
		}

		// Agreeing to ship with something is the decision this list is about,
		// so it leaves: a row somebody agreed to is not standing between the
		// branch and the release.
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code >= 300 {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}
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

// scannedOneIssueAtTwoVersions files one issue on one component name at two
// versions, which is two folds and so two rows of the blocking list.
//
// The shape a build has when it ships a library twice: the same source package
// at two versions, both vulnerable to the same issue.
func (r *reach) scannedOneIssueAtTwoVersions(t *testing.T) {
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
		TargetID: target.ID, ContentHash: "one-issue-two-versions", BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}

	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	older := graph.Described{
		Purl: "pkg:golang/golang.org/x/crypto@0.14.0", Name: "golang.org/x/crypto",
		Version: "0.14.0", UpstreamName: "golang.org/x/crypto", UpstreamVersion: "0.14.0",
	}
	newer := graph.Described{
		Purl: "pkg:golang/golang.org/x/crypto@0.17.0", Name: "golang.org/x/crypto",
		Version: "0.17.0", UpstreamName: "golang.org/x/crypto", UpstreamVersion: "0.17.0",
	}
	shipped := []graph.Described{older, newer}
	edges := make([]graph.Dependency, 0, len(shipped))
	for _, one := range shipped {
		edges = append(edges, graph.Dependency{Parent: product, Child: one})
	}
	if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root: product, Components: shipped, Dependencies: edges,
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
	var reported []finding.Reported
	for _, at := range shipped {
		reported = append(reported, finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-46595", Severity: "critical"},
			Component: at, FixState: finding.FixedUpstream, FixedIn: "0.31.0",
		})
	}
	if _, err := findings.Apply(ctx, target.ID, run.ID, reported); err != nil {
		t.Fatal(err)
	}
}

// TestBlockingRowsOfOneComponentAreToldApart pins the version on the row.
//
// A group is keyed on the issue and the fold, and a fold is the source package
// at the version it was built at — so one issue on one component at two
// versions is two rows. Named by component alone they arrive identical: the
// panel drew the same line twice, under the same React key, and a reader had
// no way to tell which of the two a row was about.
func TestBlockingRowsOfOneComponentAreToldApart(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedOneIssueAtTwoVersions(t)

		var out struct {
			Blocking []struct {
				Vulnerability string `json:"vulnerability"`
				Component     string `json:"component"`
				Version       string `json:"version"`
			} `json:"blocking"`
		}
		read(t, r, "private-triage",
			"/v1/products/mine/streams/master/variants/broadcom/readiness", &out)

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
