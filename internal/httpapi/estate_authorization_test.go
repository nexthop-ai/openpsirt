package httpapi_test

import (
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

// seedTheirs puts one disclosed and one undisclosed finding behind "theirs",
// the product nobody names in a per-product grant.
//
// An export over an empty result set is 200 whether the narrowing ran or not,
// so a test that only reads status codes passes against an estate grant that
// dropped the visibility predicate entirely — which is the disclosure this
// whole shape is written around.
//
// The undisclosed one is written straight to the column. Recording a flaw by
// hand is the path that mints one in a deployment, and standing it up here
// would test that path rather than this one.
func seedTheirs(t *testing.T, r *reach) (disclosed, undisclosed string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.db.DB)
	located, err := names.Locate(ctx, "theirs", "master", "mellanox")
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	scan, outcome, err := ingest.NewStore(r.db.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "estate-theirs",
		BuiltAt: time.Now().UTC(), ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	root := graph.Described{Purl: "pkg:deb/debian/theirs@1.0", Name: "theirs", Version: "1.0"}
	lib := graph.Described{Purl: "pkg:deb/debian/libestate@2.1", Name: "libestate", Version: "2.1"}
	if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root: root, Components: []graph.Described{lib},
		Dependencies: []graph.Dependency{{Parent: root, Child: lib}},
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
	disclosed, undisclosed = "CVE-2026-9001", "CVE-2026-9002"
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{
		{Issue: finding.Named{Identifier: disclosed, Severity: "high"},
			Component: lib, FixState: finding.NoFix},
		{Issue: finding.Named{Identifier: undisclosed, Severity: "high"},
			Component: lib, FixState: finding.NoFix},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.DB.NewUpdate().Table("finding").
		Set("visibility = ?", access.Private).
		Where(`vulnerability_id IN (SELECT id FROM "vulnerability" WHERE identifier = ?)`,
			undisclosed).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return disclosed, undisclosed
}

// A role held across every product reaches every product, including the one
// nobody granted it against by name — and reaches it at its own visibility and
// no further.
//
// The second half is the one worth pinning. The queries already carry a flag
// meaning "every product", and it means *no narrowing at all*: visibility
// included. An estate grant that set it would have handed somebody granted
// disclosed reading every undisclosed finding in the deployment (REQ-43).
func TestARoleHeldEverywhereReachesEveryProductAtItsOwnVisibility(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		// Both products, where a per-product reader reaches only the one they
		// were granted. "theirs" is the product nobody named in their grant.
		for _, product := range []string{"mine", "theirs"} {
			if got := r.as(t, "estate-reader", http.MethodGet,
				"/v1/products/"+product+"/streams"); got != http.StatusOK {
				t.Errorf("a role held everywhere reads %q as %d, not 200", product, got)
			}
			// The per-product reader is the contrast: granted on "mine" alone,
			// so "theirs" is invisible rather than merely unreadable.
			want := http.StatusOK
			if product == "theirs" {
				want = http.StatusNotFound
			}
			if got := r.as(t, "reader", http.MethodGet,
				"/v1/products/"+product+"/streams"); got != want {
				t.Errorf("a per-product reader reads %q as %d, not %d", product, got, want)
			}
		}

		// Exports are named by REQ-43 because they are what gets missed: a
		// list narrowed correctly and an export that was not is a disclosure
		// nothing on the screen reports. Asserted on the body, because a 200
		// over an empty result set says nothing at all.
		disclosed, undisclosed := seedTheirs(t, r)
		for _, path := range []string{
			"/v1/findings.csv",
			"/v1/products/theirs/findings.csv",
		} {
			body := asPerson(t, r, "estate-reader", http.MethodGet, path, "")
			if body.Code != http.StatusOK {
				t.Errorf("a role held everywhere reads %s as %d, not 200", path, body.Code)
				continue
			}
			if !strings.Contains(body.Body.String(), disclosed) {
				t.Errorf("%s omits the disclosed finding the estate role reaches", path)
			}
			if strings.Contains(body.Body.String(), undisclosed) {
				t.Errorf("%s exported an undisclosed finding to a role granted disclosed reading only", path)
			}
		}
	})
}
