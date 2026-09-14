package advisory_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/database"
	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
)

// issuer is a deployment that has been told who it publishes as.
var issuer = publisher.Named{Name: "Example Networks", Namespace: "https://example.test"}

type fixture struct {
	db      *database.DB
	store   *advisory.Store
	finds   *finding.Store
	graph   *graph.Store
	scans   *ingest.Store
	product int64
	// master is the branch and v2.4.1 the tagged release, so an advisory has
	// more than one release to name. With one, the list cannot be told from
	// "whichever build was asked from".
	master, tagged int64
	who            access.Subject
	seq            int
	built          time.Time
}

var (
	root    = graph.Described{Purl: "pkg:deb/debian/sonic@1.0", Name: "sonic", Version: "1.0"}
	carrier = graph.Described{
		Purl: "pkg:deb/debian/libswsscommon@1.0.0", Name: "libswsscommon", Version: "1.0.0",
	}
)

func each(t *testing.T, fn func(t *testing.T, f *fixture)) {
	t.Helper()
	fixtures.Each(t, func(t *testing.T, w *fixtures.World) {
		// The branch is the seeded target; the tag needs one of its own,
		// because what an advisory says about a release that never moves is
		// half of what this store answers.
		tagged := w.TargetFor(w.Tag, w.Customer)
		f := &fixture{
			db: w.DB, store: advisory.NewStore(w.DB.DB), finds: finding.NewStore(w.DB.DB),
			graph: graph.NewStore(w.DB.DB), scans: ingest.NewStore(w.DB.DB),
			product: w.Product.ID, master: w.Target.ID, tagged: tagged.ID,
			who: access.NewPerson(w.Person.ID, w.Person.Identity, false, map[int64][]access.Role{
				w.Product.ID: {access.PublicRead, access.PrivateRead, access.PrivateTriage},
			}, 0),
			built: time.Now().UTC().Add(-72 * time.Hour),
		}
		f.shipped(t, f.master)
		f.shipped(t, f.tagged)
		fn(t, f)
	})
}

// shipped stores a graph against one build.
func (f *fixture) shipped(t *testing.T, target int64) {
	t.Helper()
	ctx := t.Context()
	f.seq++
	f.built = f.built.Add(time.Hour)
	scan, outcome, err := f.scans.Record(ctx, ingest.Arriving{
		TargetID: target, ContentHash: fmt.Sprintf("hash-%d", f.seq), BuiltAt: f.built,
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if _, err := f.graph.Apply(ctx, target, scan.ID, graph.Snapshot{
		Root: root, Components: []graph.Described{carrier},
		Dependencies: []graph.Dependency{{Parent: root, Child: carrier}},
	}); err != nil {
		t.Fatalf("apply graph: %v", err)
	}
}

// recorded enters a flaw against one build and returns what it was filed as.
func (f *fixture) recorded(t *testing.T, target int64) string {
	t.Helper()
	_, identifier, err := f.finds.Enter(t.Context(), f.who, finding.Entering{
		TargetIDs: []int64{target}, Component: carrier.Name, Severity: "high",
		Summary: "The management socket answers before anyone authenticated.",
	})
	if err != nil {
		t.Fatalf("recording a flaw: %v", err)
	}
	return identifier
}

func TestAnAdvisoryNamesEveryReleaseHoldingTheFlawAndNamesEachInTheTree(t *testing.T) {
	// A reader of an advisory is asking "am I affected", and the answer is
	// a release rather than a dependency path. Two releases, because a
	// document with one cannot show that the list follows the findings
	// rather than the build somebody happened to ask from.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		identifier := f.recorded(t, f.master)
		// The same issue in the tagged release. Recording again would mint a
		// second identifier, so the row is filed against the issue that
		// already exists — which is what one flaw in two releases is.
		f.alsoIn(t, identifier, f.tagged)

		doc, err := f.store.For(ctx, f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		if len(doc.Vulnerabilities) != 1 {
			t.Fatalf("the document carries %d vulnerabilities", len(doc.Vulnerabilities))
		}
		affected := doc.Vulnerabilities[0].Status.KnownAffected
		// Named by stream and variant together, never by one of them: the same
		// branch built two ways is two builds, and naming only the branch
		// would claim something about hardware nobody built for. In name
		// order, which is what a reader of the document sees.
		want := []string{
			"sonic:" + fixtures.BranchName + ":broadcom",
			"sonic:" + fixtures.TagName + ":broadcom",
		}
		slices.Sort(want)
		if len(affected) != len(want) {
			t.Fatalf("affected: %v, want %v", affected, want)
		}
		for i := range want {
			if affected[i] != want[i] {
				t.Errorf("affected[%d] is %q, want %q", i, affected[i], want[i])
			}
		}

		// Every release a status names is named in the tree, or the document
		// makes a statement about something it never introduced.
		named := map[string]bool{}
		for _, vendor := range doc.ProductTree.Branches {
			for _, product := range vendor.Branches {
				for _, release := range product.Branches {
					named[release.Product.ID] = true
				}
			}
		}
		for _, id := range affected {
			if !named[id] {
				t.Errorf("the product tree does not name %q", id)
			}
		}
	})
}

func TestAReleaseThatFixedTheFlawIsNamedAsFixedRatherThanLeftOut(t *testing.T) {
	// The answer a reader of an advisory is hoping for. A release that held
	// the flaw and no longer does is the one to upgrade to, and leaving it out
	// of the document reads identically to a release that never shipped the
	// thing at all.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		identifier := f.recorded(t, f.master)
		f.alsoIn(t, identifier, f.tagged)

		issueID, err := finding.NewVulnerabilities(f.db.DB).ByName(ctx, identifier)
		if err != nil {
			t.Fatal(err)
		}
		done, err := f.finds.Resolve(ctx, f.who, f.tagged, issueID,
			"Shipped in v2.4.1, which carries the patch.")
		if err != nil {
			t.Fatalf("closing it in the tagged release: %v", err)
		}
		if done.Closed != 1 {
			t.Errorf("closed %d locations, want the one the release holds", done.Closed)
		}

		doc, err := f.store.For(ctx, f.who, issuer, "sonic", identifier)
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		status := doc.Vulnerabilities[0].Status
		if len(status.KnownAffected) != 1 || status.KnownAffected[0] != "sonic:master:broadcom" {
			t.Errorf("affected: %v, want the branch alone", status.KnownAffected)
		}
		if len(status.Fixed) != 1 || status.Fixed[0] != "sonic:"+fixtures.TagName+":broadcom" {
			t.Errorf("fixed: %v, want the release it left", status.Fixed)
		}
	})
}

func TestAnAdvisoryIsRefusedWhereNobodyHasSaidWhoPublishesIt(t *testing.T) {
	// A CSAF document requires a publisher, so one generated without a
	// configured identity would fail validation wherever somebody took it
	// next — after they had already sent it. Refused here instead, saying
	// which part is missing.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		_, err := f.store.For(t.Context(), f.who, publisher.Named{}, "sonic", identifier)
		if !errors.Is(err, advisory.ErrNoPublisher) {
			t.Errorf("an unconfigured deployment generated a document: %v", err)
		}
		if !strings.Contains(err.Error(), "PUBLISHER_NAME") ||
			!strings.Contains(err.Error(), "PUBLISHER_NAMESPACE") {
			t.Errorf("the refusal does not say what to set: %v", err)
		}
		// A name with no namespace is the same gap: both fields are required.
		// The message names the half that is missing, and only that half —
		// whoever reads it cannot fix it, and the operator who can is reading
		// it relayed rather than sitting at the process.
		_, err = f.store.For(t.Context(), f.who,
			publisher.Named{Name: "Example Networks"}, "sonic", identifier)
		if !errors.Is(err, advisory.ErrNoPublisher) {
			t.Errorf("a publisher with no namespace was accepted: %v", err)
		}
		if !strings.Contains(err.Error(), "PUBLISHER_NAMESPACE") ||
			strings.Contains(err.Error(), "PUBLISHER_NAME ") {
			t.Errorf("the refusal does not name the missing half: %v", err)
		}
	})
}

// alsoIn files the same issue against a second build.
//
// Recording it again would mint a second identifier, which is a second flaw.
// One flaw present in two releases is one issue with a finding in each, and
// that is what an advisory aggregates.
func (f *fixture) alsoIn(t *testing.T, identifier string, target int64) {
	t.Helper()
	ctx := t.Context()
	issueID, err := finding.NewVulnerabilities(f.db.DB).ByName(ctx, identifier)
	if err != nil {
		t.Fatal(err)
	}
	var componentID int64
	if err := f.db.DB.NewSelect().
		TableExpr("graph_node AS n").
		Join("JOIN component AS c ON c.id = n.component_id").
		ColumnExpr("c.id").
		Where("n.target_id = ?", target).
		Where("c.name = ?", carrier.Name).
		Limit(1).Scan(ctx, &componentID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := &finding.Finding{
		TargetID: target, Kind: finding.Entered, Visibility: access.Private,
		VulnerabilityID: issueID, ComponentID: componentID,
		PlaceIdentity: finding.PlaceIdentity(carrier.Name, ""),
		LastChangedAt: now, OpenedAt: now,
	}
	if _, err := f.db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
		t.Fatal(err)
	}
}
