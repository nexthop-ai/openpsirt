// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

var (
	// swssSource is a source repository as a SONiC inventory names one,
	// named by its producer as something other than its repository.
	swssSource = graph.Described{Purl: "pkg:github/sonic-net/sonic-swss@2126d2752826", Name: "swss", Version: "1.0.0"}
	vendored   = graph.Described{Purl: "pkg:cargo/addr2line@0.25.1", Name: "addr2line", Version: "0.25.1"}
	swssDeb    = at("swss", "1.0.0")
)

// sourceShapes are the two ways a SONiC inventory places a source repository:
// pulled in by nothing, and hung off the package built from it.
func sourceShapes() map[string]graph.Snapshot {
	return map[string]graph.Snapshot{
		"pulled in by nothing": {
			Root:       root,
			Components: []graph.Described{swssDeb, swssSource, vendored},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swssDeb}, {Parent: swssSource, Child: vendored},
			},
		},
		"under its package": {
			Root:       root,
			Components: []graph.Described{swssDeb, swssSource, vendored},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swssDeb}, {Parent: swssDeb, Child: swssSource},
				{Parent: swssSource, Child: vendored},
			},
		},
	}
}

func TestARepositoryRowCountsWhatIsBeneathItWhereverTheInventoryPlacesIt(t *testing.T) {
	for shape, snap := range sourceShapes() {
		t.Run(shape, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				f.scannedAt(t, snap, ago(10), found("CVE-2026-1", vendored), found("CVE-2026-2", vendored),
					found("CVE-2026-3", swssDeb))
				f.closeIt(t, "CVE-2026-2", finding.Upgraded, ago(5))

				rows, err := f.store.Grouped(t.Context(), f.holding(t, access.PublicRead), f.build,
					finding.ByRepository, "")
				if err != nil {
					t.Fatal(err)
				}
				if len(rows) != 1 {
					t.Fatalf("listed %+v, want the one repository", rows)
				}
				got := rows[0]
				if got.Key != "pkg:github/sonic-net/sonic-swss" || got.Open != 1 || got.Fixed != 1 ||
					len(got.Versions) != 1 || got.Versions[0] != "2126d2752826" || got.One == nil || got.One.Name != "swss" {
					t.Errorf("the repository reads %+v, want one open and one fixed beneath it at the commit it ships", got)
				}
			})
		})
	}
}

func TestAnEcosystemRowCountsWhatIsAtItsOwnComponents(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.scannedAt(t, sourceShapes()["pulled in by nothing"], ago(10),
			found("CVE-2026-1", vendored), found("CVE-2026-3", swssDeb), found("CVE-2026-4", swssDeb))
		who := f.holding(t, access.PublicRead)

		rows, err := f.store.Grouped(t.Context(), who, f.build, finding.ByEcosystem, "")
		if err != nil {
			t.Fatal(err)
		}
		open := map[string]int{}
		for _, r := range rows {
			open[r.Key] = r.Open
		}
		// The root is the build, never a row; the deb fixture holds the
		// tree's two other packages as well.
		if open["deb"] != 2 || open["cargo"] != 1 || open["github"] != 0 || rows[0].Key != "deb" {
			t.Errorf("by ecosystem reads %+v, want deb with two first, cargo one, github none", rows)
		}
		packages, err := f.store.Grouped(t.Context(), who, f.build, finding.ByEcosystem, "cargo")
		if err != nil {
			t.Fatal(err)
		}
		if len(packages) != 1 || packages[0].Key != "pkg:cargo/addr2line" || packages[0].Open != 1 {
			t.Errorf("cargo's packages read %+v, want addr2line with one open", packages)
		}
	})
}

func TestAGroupedListCountsOnlyWhatTheReaderMaySee(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.scannedAt(t, sourceShapes()["under its package"], ago(10),
			found("CVE-2026-1", vendored), found("CVE-2026-3", vendored))
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set(`"visibility" = ?`, access.Private).
			Where(`"vulnerability_id" = ?`, f.issueID(t, "CVE-2026-3")).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			who  access.Subject
			want int
		}{
			{f.holding(t, access.PublicRead), 1},
			{f.holding(t, access.PublicRead, access.PrivateRead), 2},
		} {
			rows, err := f.store.Grouped(t.Context(), c.who, f.build, finding.ByRepository, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0].Open != c.want {
				t.Errorf("the repository says %+v, want %d open", rows, c.want)
			}
		}
		outsider := f.holdingIn(t, []int64{f.productID + 1000}, access.PublicRead)
		if _, err := f.store.Grouped(t.Context(), outsider, f.build, finding.ByRepository, ""); !errors.Is(err, access.ErrDenied) {
			t.Errorf("somebody reading another product was answered %v, want refused", err)
		}
	})
}
