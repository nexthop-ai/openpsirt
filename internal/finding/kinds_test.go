// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

var (
	// A Go module beside the Debian packages, so a scope holds two kinds.
	gomod = graph.Described{
		Purl: "pkg:golang/github.com/vishvananda/netlink@v1.1.0", Name: "netlink", Version: "v1.1.0",
	}
	// A component a producer gave no package identifier.
	unnamed = graph.Described{Name: "vendor-blob", Version: "7"}
)

// kinded is twoConsumers with a Go module and a component of no kind in it.
func kinded() graph.Snapshot {
	snap := twoConsumers()
	snap.Components = append(snap.Components, gomod, unnamed)
	snap.Dependencies = append(snap.Dependencies,
		graph.Dependency{Parent: swss, Child: gomod},
		graph.Dependency{Parent: teamd, Child: unnamed})
	return snap
}

// said is a list of kinds as one string, for comparing against what was wanted.
func said(kinds []finding.PackageKind) string {
	out := ""
	for _, one := range kinds {
		out += fmt.Sprintf("%s=%d ", one.Kind, one.Open)
	}
	return out
}

// hideIssue makes every finding of one issue undisclosed.
func (f *fixture) hideIssue(t *testing.T, identifier string) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().TableExpr(`"finding"`).
		Set("visibility = ?", access.Private).
		Where("vulnerability_id = ?", f.issueID(t, identifier)).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestPackageKindsAreCountedOverWhatTheReaderMaySee(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, kinded())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			// Two issues at a Debian package that sits at two places: two
			// rows on the list, and four findings.
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
			// A Debian package and a Go module nobody has disclosed anything
			// about.
			found("CVE-2026-3", swss), found("CVE-2026-3", gomod),
			// Something at a component with no kind to offer.
			found("CVE-2026-4", unnamed),
		}); err != nil {
			t.Fatal(err)
		}
		f.hideIssue(t, "CVE-2026-3")

		for _, c := range []struct {
			what   string
			who    access.Subject
			want   string
			denied bool
		}{
			{"a public reader", f.holding(t, access.PublicRead), "deb=2 ", false},
			// Undisclosed reading alone reads nothing disclosed, and a kind
			// present only there is offered to nobody else.
			{"a private reader", f.holding(t, access.PrivateRead), "deb=1 golang=1 ", false},
			{"a reader of both", f.holding(t, access.PublicRead, access.PrivateRead),
				"deb=3 golang=1 ", false},
			{"an approver alone", f.holding(t), "", true},
			{"an administrator granted nothing", access.NewPerson(1, "admin", true, nil, 0), "", true},
			{"a pipeline", access.NewPipeline(1, "nightly", access.Scope{ProductID: f.productID}), "", true},
		} {
			got, err := f.store.PackageKinds(t.Context(), c.who, f.scope)
			switch {
			case c.denied && !errors.Is(err, access.ErrDenied):
				t.Errorf("%s was not refused: %s %v", c.what, said(got), err)
			case c.denied:
			case err != nil:
				t.Errorf("%s: %v", c.what, err)
			case said(got) != c.want:
				t.Errorf("%s was offered %q, want %q", c.what, said(got), c.want)
			}
		}
	})
}

func TestPackageKindsCountEachIssueAtAComponentOnceAcrossBuilds(t *testing.T) {
	// The list counts one issue at one component as one row however many
	// builds of the selection hold it, and a count beside a kind that said
	// otherwise would promise rows the list does not have.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, kinded())
		reported := []finding.Reported{found("CVE-2026-1", libnl), found("CVE-2026-2", gomod)}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), reported); err != nil {
			t.Fatal(err)
		}
		other := f.anotherBranch(t, "2026.06")
		f.shippedTo(t, other, kinded())
		if _, err := f.store.Apply(t.Context(), other, f.runOn(t, other), reported); err != nil {
			t.Fatal(err)
		}

		whole := finding.Scope{ProductID: &f.productID}
		got, err := f.store.PackageKinds(t.Context(), f.holding(t, access.PublicRead), whole)
		if err != nil {
			t.Fatal(err)
		}
		if said(got) != "deb=1 golang=1 " {
			t.Errorf("across two builds holding the same two rows: %q", said(got))
		}
	})
}

func TestPackageKindsLeaveOutWhatHasClosed(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, kinded())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", gomod),
		}); err != nil {
			t.Fatal(err)
		}
		// The next run reports the Go module's issue alone, which closes the
		// Debian package's.
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-2", gomod),
		}); err != nil {
			t.Fatal(err)
		}
		got, err := f.store.PackageKinds(t.Context(), f.holding(t, access.PublicRead), f.scope)
		if err != nil {
			t.Fatal(err)
		}
		if said(got) != "golang=1 " {
			t.Errorf("after the Debian issue closed: %q", said(got))
		}
	})
}

func TestPackageKindsAcrossProductsReachOnlyTheProductsSomebodyReads(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, kinded())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		cat := catalog.NewStore(f.db.DB)
		other, err := cat.DeclareProduct(ctx, "edge-router", "Edge")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cat.DeclareVariant(ctx, other.ID, "broadcom", true); err != nil {
			t.Fatal(err)
		}
		elsewhere := f.anotherBranchOf(t, other.ID, "main")
		f.shippedTo(t, elsewhere, kinded())
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", gomod), found("CVE-2026-3", gomod),
		}); err != nil {
			t.Fatal(err)
		}
		// The other product's second Go issue is undisclosed.
		f.hideIssue(t, "CVE-2026-3")

		for _, c := range []struct {
			what   string
			who    access.Subject
			want   string
			denied bool
		}{
			{"a reader of this product", f.holding(t, access.PublicRead), "deb=1 ", false},
			// The same issue at the same package in two products is a row in
			// each.
			{"a public reader of both", f.holdingIn(t, []int64{f.productID, other.ID}, access.PublicRead),
				"deb=2 golang=1 ", false},
			{"a reader of both at both visibilities",
				f.holdingIn(t, []int64{f.productID, other.ID}, access.PublicRead, access.PrivateRead),
				"deb=2 golang=2 ", false},
			{"somebody holding nothing", access.NewPerson(1, "nobody", false, nil, 0), "", false},
			{"a pipeline", access.NewPipeline(1, "nightly", access.Scope{ProductID: f.productID}), "", true},
		} {
			got, err := f.store.PackageKindsAnywhere(ctx, c.who)
			switch {
			case c.denied && !errors.Is(err, access.ErrDenied):
				t.Errorf("%s was not refused: %s %v", c.what, said(got), err)
			case c.denied:
			case err != nil:
				t.Errorf("%s: %v", c.what, err)
			case said(got) != c.want:
				t.Errorf("%s was offered %q, want %q", c.what, said(got), c.want)
			}
		}
	})
}
