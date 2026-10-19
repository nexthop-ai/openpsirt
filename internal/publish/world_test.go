// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package publish_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/publish"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

// base is the address the deployment under test is reached at.
const base = "https://psirt.example.test"

// who is the publisher every document names.
var who = publisher.Named{
	Name: "Example Networks", Namespace: "https://example.test", Category: "vendor",
	Prefix: "EXN", Served: base + publish.DirectoryPath,
}

// The components a build ships, by what its inventory calls them.
var (
	openssl = graph.Described{Purl: "pkg:deb/debian/openssl@3.0.11-1", Name: "openssl", Version: "3.0.11-1"}
	libnl   = graph.Described{Purl: "pkg:deb/debian/libnl-3-200@3.7.0", Name: "libnl-3-200", Version: "3.7.0"}
	zlib    = graph.Described{Purl: "pkg:deb/debian/zlib1g@1.2.13", Name: "zlib1g", Version: "1.2.13"}
	swss    = graph.Described{Purl: "pkg:deb/sonic/swss@1.0.0", Name: "swss", Version: "1.0.0"}
)

// world is the seeded catalog, a proposer and an approver who hold every role
// on every product named, and what writes the published documents.
type world struct {
	*fixture.World
	t         *testing.T
	findings  *finding.Store
	decisions *triage.Store
	documents *publish.Store
	pass      *publish.Pass
	built     time.Time
	roles     map[int64][]access.Role
	proposer  access.Subject
	approver  access.Subject
}

// newWorld seeds a world over the fixture's.
func newWorld(t *testing.T, w *fixture.World) *world {
	t.Helper()
	db := w.DB.DB
	out := &world{
		World: w, t: t, findings: finding.NewStore(db), decisions: triage.NewStore(db),
		documents: publish.NewStore(db),
		pass: publish.NewPass(db, publish.NewGenerator(db, who, base), "test",
			slog.New(slog.NewTextHandler(os.Stderr, nil))),
		built: time.Now().UTC().Add(-48 * time.Hour),
		roles: map[int64][]access.Role{},
	}
	out.hold(w.Product)
	return out
}

// hold gives the proposer and the approver every role on a product.
func (w *world) hold(product *catalog.Product) {
	w.t.Helper()
	w.roles[product.ID] = []access.Role{access.PublicRead, access.PublicTriage,
		access.PrivateRead, access.PrivateTriage, access.Approver}
	person := func(identity string) access.Subject {
		account, err := w.Access.Ensure(context.Background(), identity, identity, new(false), nil)
		if err != nil {
			w.t.Fatal(err)
		}
		return access.NewPerson(account.ID, identity, false, w.roles, 0)
	}
	w.proposer, w.approver = person("ana@example.com"), person("ben@example.com")
}

// edge is one component pulling in another.
type edge struct{ parent, child graph.Described }

// ship records a scan of a build: its root and what hangs beneath it.
func (w *world) ship(target *catalog.Target, root graph.Described, edges ...edge) {
	w.t.Helper()
	ctx := w.t.Context()
	w.built = w.built.Add(time.Minute)
	scan, outcome, err := ingest.NewStore(w.DB.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "hash-" + w.built.Format(time.RFC3339Nano),
		BuiltAt: w.built, ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		w.t.Fatalf("record a scan: %v %v", outcome, err)
	}
	snap := graph.Snapshot{Root: root}
	seen := map[string]bool{}
	for _, one := range edges {
		for _, part := range []graph.Described{one.parent, one.child} {
			if part != root && !seen[part.Purl] {
				seen[part.Purl] = true
				snap.Components = append(snap.Components, part)
			}
		}
		snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: one.parent, Child: one.child})
	}
	if _, err := fixture.ApplyGraph(ctx, w.DB.DB, target.ID, scan.ID, snap); err != nil {
		w.t.Fatal(err)
	}
	if root.Purl != "" {
		if _, err := w.DB.DB.NewUpdate().TableExpr(`"scan"`).
			Set(`"root_identifier" = ?`, root.Purl).
			Where(`"id" = ?`, scan.ID).Exec(ctx); err != nil {
			w.t.Fatal(err)
		}
	}
}

// reported is one issue a scanner reported in one component.
type reported struct {
	issue     string
	component graph.Described
}

// report runs a scanner over a build, reporting these and nothing else.
func (w *world) report(target *catalog.Target, found ...reported) {
	w.t.Helper()
	ctx := w.t.Context()
	run, err := w.findings.Begin(ctx, finding.Run{TargetID: target.ID, Scanner: "grype", RanHere: true})
	if err != nil {
		w.t.Fatal(err)
	}
	var rows []finding.Reported
	for _, one := range found {
		rows = append(rows, finding.Reported{
			Issue: finding.Named{Identifier: one.issue, Severity: "high",
				Description: "What " + one.issue + " is."},
			Component: one.component,
		})
	}
	if _, err := w.findings.Apply(ctx, target.ID, run.ID, rows); err != nil {
		w.t.Fatal(err)
	}
}

// claim is what one claim says.
type claim struct {
	outcome       triage.Outcome
	justification triage.Justification
	mitigation    string
	scope         triage.Scope
	fixedVersion  string
	committedTo   *time.Time
	deferredUntil *time.Time
	// waiting leaves a claim that needs a second person without one.
	waiting bool
}

// decide records a claim at every open place of an issue in one component of
// a build, and has the second person agree to it where it needs one.
func (w *world) decide(target *catalog.Target, issue string, component graph.Described, said claim) {
	w.t.Helper()
	ctx := w.t.Context()
	vulnerability, err := finding.NewVulnerabilities(w.DB.DB).ByName(ctx, issue)
	if err != nil {
		w.t.Fatal(err)
	}
	var open []finding.Finding
	if err := w.DB.DB.NewSelect().Model(&open).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Where(`"f"."target_id" = ?`, target.ID).
		Where(`"f"."vulnerability_id" = ?`, vulnerability).
		Where(`"c"."name" = ?`, component.Name).
		Where(`"f"."closed_at" IS NULL`).
		Scan(ctx); err != nil || len(open) == 0 {
		w.t.Fatalf("%s is open at %d places of %s: %v", issue, len(open), component.Name, err)
	}
	var proposals []triage.Proposal
	placed := map[string]bool{}
	for _, one := range open {
		// One place holds every version of a name it ever shipped, so two
		// findings of one issue may share it.
		if placed[one.PlaceIdentity] {
			continue
		}
		placed[one.PlaceIdentity] = true
		at, err := w.findings.PlaceFor(ctx, w.proposer, target.ID, vulnerability, one.PlaceIdentity)
		if err != nil {
			w.t.Fatal(err)
		}
		proposals = append(proposals, triage.Proposal{
			Place: triage.Place{
				ProductID: at.ProductID, VulnerabilityID: at.VulnerabilityID,
				PlaceIdentity: at.PlaceIdentity, Visibility: at.Visibility,
				ComponentUpstream: at.ComponentUpstream, ConsumerUpstream: at.ConsumerUpstream,
				OnTag: at.OnTag,
			},
			Outcome: said.outcome, Justification: said.justification, Mitigation: said.mitigation,
			Scope: said.scope, FixedVersion: said.fixedVersion, CommittedTo: said.committedTo,
			DeferredUntil: said.deferredUntil,
			Reasoning:     "Read the code.", By: w.proposer.ID, MadeOn: []int64{target.ID},
			BindingAcross: []int64{target.ID},
		})
	}
	recorded, err := w.decisions.ProposeMany(ctx, w.proposer, proposals)
	if err != nil {
		w.t.Fatal(err)
	}
	if recorded[0].NeedsApproval && !said.waiting {
		if _, err := w.decisions.ApproveClaim(ctx, w.approver, recorded[0].ClaimID, "", nil, ""); err != nil {
			w.t.Fatal(err)
		}
	}
}

// publishes turns a product's documents on or off.
func (w *world) publishes(product *catalog.Product, on bool) {
	w.t.Helper()
	if err := w.Catalog.SetPublishes(w.t.Context(), product.ID, on); err != nil {
		w.t.Fatal(err)
	}
}

// write runs the pass once.
func (w *world) write() publish.Wrote {
	w.t.Helper()
	wrote, err := w.pass.Once(w.t.Context())
	if err != nil {
		w.t.Fatal(err)
	}
	if wrote.Skipped > 0 {
		w.t.Fatalf("the pass could not work out %d products", wrote.Skipped)
	}
	return wrote
}

// anybody is anybody at all, as the published surface builds them.
func (w *world) anybody() access.Subject {
	w.t.Helper()
	products, err := w.Catalog.Publishing(w.t.Context())
	if err != nil {
		w.t.Fatal(err)
	}
	return access.Published(products)
}

// listed is every document anybody may be handed now.
func (w *world) listed(statuses string) []publish.Listing {
	w.t.Helper()
	out, err := w.documents.Listed(w.t.Context(), w.anybody(), statuses)
	if err != nil {
		w.t.Fatal(err)
	}
	return out
}

// csafAbout is the CSAF VEX document about an issue in a product, as anybody
// is handed it, or nil where none is.
func (w *world) csafAbout(product *catalog.Product, issue string) *advisory.Document {
	w.t.Helper()
	for _, one := range w.listed("all") {
		if one.Kind == publish.CSAFVEX && one.TrackingID == "VEX-"+product.Name+"-"+issue {
			doc, err := w.documents.At(w.t.Context(), w.anybody(), one.Path, "all")
			if err != nil {
				w.t.Fatal(err)
			}
			var out advisory.Document
			if err := json.Unmarshal([]byte(doc.Body), &out); err != nil {
				w.t.Fatal(err)
			}
			return &out
		}
	}
	return nil
}

// openVEXAbout is the OpenVEX document about a branch or tag of a product,
// or nil where none is.
func (w *world) openVEXAbout(product *catalog.Product, stream string) *vex.Statements {
	w.t.Helper()
	path := publish.OpenVEXPath + product.Name + "/" + stream + ".json"
	doc, err := w.documents.At(w.t.Context(), w.anybody(), path, "all")
	if err != nil {
		return nil
	}
	var out vex.Statements
	if err := json.Unmarshal([]byte(doc.Body), &out); err != nil {
		w.t.Fatal(err)
	}
	return &out
}

// everything is every byte anybody may be handed, documents and lists alike,
// as one string to search.
func (w *world) everything() string {
	w.t.Helper()
	var all strings.Builder
	for _, one := range w.listed("all") {
		all.WriteString(one.Path + " " + one.TrackingID + " " + one.Title + "\n")
		doc, err := w.documents.At(w.t.Context(), w.anybody(), one.Path, "all")
		if err != nil {
			w.t.Fatal(err)
		}
		all.WriteString(doc.Body + "\n")
	}
	return all.String()
}

// issued records a flaw of ours in the default build, disclosed or not, names
// it on an advisory, has the second person agree, and records that the
// advisory went out. It answers the advisory's name and the flaw's.
func (w *world) issued(disclosed bool) (advisoryName, flaw string) {
	w.t.Helper()
	ctx := w.t.Context()
	_, flaw, err := w.findings.Enter(ctx, w.proposer, finding.Entering{
		TargetIDs: []int64{w.Target.ID}, Component: swss.Name, Severity: "high",
		Summary:   "The management socket answers before anyone authenticated.",
		Disclosed: disclosed, Told: finding.Told{FoundHere: true},
	})
	if err != nil {
		w.t.Fatal(err)
	}
	advisories := advisory.NewStore(w.DB.DB)
	made, err := advisories.Mint(ctx, w.proposer, who, "The management socket")
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := advisories.Add(ctx, w.proposer, made.Identifier, w.Product.Name, flaw); err != nil {
		w.t.Fatal(err)
	}
	if _, err := advisories.Approve(ctx, w.approver, made.Identifier); err != nil {
		w.t.Fatal(err)
	}
	if _, err := advisories.Issued(ctx, w.proposer, who, made.Identifier, "Published."); err != nil {
		w.t.Fatal(err)
	}
	return made.Identifier, flaw
}
