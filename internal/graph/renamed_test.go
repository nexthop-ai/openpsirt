// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"strings"
	"testing"

	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// A package named after its own version is renamed by every upgrade. The
// inventory's changes, a comparison of two builds and the walk beneath a
// replaced version read the rename as the one package moving.

// kernelAt is the four Debian kernel packages SONiC ships, named after the
// kernel's version, as one build describes them.
func kernelAt(version string) []graph.Described {
	names := []string{
		"linux-image-" + version + "+deb13-sonic-amd64-unsigned",
		"linux-headers-" + version + "+deb13-sonic-amd64",
		"linux-headers-" + version + "+deb13-common-sonic",
		"linux-kbuild-" + version + "+deb13",
	}
	out := make([]graph.Described, 0, len(names))
	for _, name := range names {
		out = append(out, graph.Described{
			Purl: "pkg:deb/debian/" + strings.ReplaceAll(name, "+", "%2B") + "@" + version + "-1" +
				"?arch=amd64&distro=debian-13&upstream=linux",
			Name: name, Version: version + "-1",
		})
	}
	return out
}

func TestAPackageRenamedByItsUpgradeIsListedAsChanged(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, holding(append(kernelAt("6.12.41"), openssl)...))
		scanID := applied(t, f, holding(append(kernelAt("6.12.94"), openssl)...))

		got := spelled(changes(t, f, scanID))
		want := []string{
			"changed linux-headers-6.12.94+deb13-common-sonic [6.12.41-1] -> [6.12.94-1]",
			"changed linux-headers-6.12.94+deb13-sonic-amd64 [6.12.41-1] -> [6.12.94-1]",
			"changed linux-image-6.12.94+deb13-sonic-amd64-unsigned [6.12.41-1] -> [6.12.94-1]",
			"changed linux-kbuild-6.12.94+deb13 [6.12.41-1] -> [6.12.94-1]",
		}
		if strings.Join(got, "; ") != strings.Join(want, "; ") {
			t.Errorf("the listing reads\n%v\nwant\n%v", got, want)
		}
		if counted := delta(t, f, scanID); counted != (graph.Delta{Changed: 4}) {
			t.Errorf("the upgrade counts %+v, want four changed", counted)
		}
	})
}

func TestTwoBuildsOfARenamedPackageDifferByItsVersion(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		tagged := taggedBuild(t, f)
		appliedTo(t, f, f.buildID, holding(kernelAt("6.12.41")[0]))
		appliedTo(t, f, tagged, holding(kernelAt("6.12.94")[0]))

		got := spelled(between(t, f, f.buildID, tagged))
		want := "changed linux-image-6.12.94+deb13-sonic-amd64-unsigned [6.12.41-1] -> [6.12.94-1]"
		if len(got) != 1 || got[0] != want {
			t.Errorf("the comparison reads %v, want %q", got, want)
		}
	})
}

func TestAVersionARenameReplacedIsPairedWithTheRenamedPackage(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		before, after := kernelAt("6.12.41")[0], kernelAt("6.12.94")[0]
		if _, err := fixtures.ApplyGraph(ctx, f.db, f.buildID, f.scan(t), holding(before)); err != nil {
			t.Fatal(err)
		}
		if _, err := fixtures.ApplyGraph(ctx, f.db, f.buildID, f.scan(t), holding(after)); err != nil {
			t.Fatal(err)
		}
		ids, err := graph.NewComponents(f.db.DB).Intern(ctx, []graph.Described{before, after})
		if err != nil {
			t.Fatal(err)
		}
		replaced, err := graph.Replaced(ctx, f.db, f.buildID)
		if err != nil {
			t.Fatal(err)
		}
		if got := replaced[ids[before.Identity()]]; len(got) != 1 || got[0] != ids[after.Identity()] {
			t.Errorf("the kernel the build moved off is replaced by %v, want the renamed one (%d)",
				got, ids[after.Identity()])
		}
	})
}
