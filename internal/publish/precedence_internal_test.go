// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package publish

import (
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

// The document's rule for a product identifier named twice: it is listed once,
// under the more cautious status, whichever fact is read first. The facts here
// are built by hand, two builds stating one component beneath one consumer,
// whose identifier names no build; this pins the rule, not a path by which the
// store hands over that input.
func TestAnIdentifierNamedTwiceIsListedOnceUnderTheMoreCautiousStatus(t *testing.T) {
	const component, consumer = "pkg:deb/debian/openssl@3.0.11-1", "pkg:deb/sonic/swss@1.0.0"
	product := &catalog.Product{ID: 1, Name: "sonic", DisplayName: "SONiC"}
	fact := func(status, justification string) vex.Fact {
		return vex.Fact{Issue: "CVE-2026-1001", Component: "openssl", Purl: component,
			Within: consumer, Status: status, Justification: justification}
	}
	ours := &built{branchOrTag: "master", branchOrTagShown: "Master", variant: "broadcom", variantShown: "Broadcom"}
	theirs := &built{branchOrTag: "master", branchOrTagShown: "Master", variant: "lab", variantShown: "Lab"}
	id := component + "|" + consumer
	for _, c := range []struct {
		name   string
		first  vex.Fact
		second vex.Fact
		want   string
	}{
		{"affected read first", fact(vex.Affected, ""), fact(vex.NotAffected, "vulnerable_code_not_present"), vex.Affected},
		{"affected read last", fact(vex.NotAffected, "vulnerable_code_not_present"), fact(vex.Affected, ""), vex.Affected},
		{"fixed against not affected", fact(vex.NotAffected, "vulnerable_code_not_present"), fact(vex.Fixed, ""), vex.Fixed},
		{"fixed against affected", fact(vex.Affected, ""), fact(vex.Fixed, ""), vex.Affected},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, named := (&Generator{}).treeFor(product, []placed{{ours, c.first}, {theirs, c.second}})
			listed := map[string][]string{
				vex.Affected:    named.status.KnownAffected,
				vex.Fixed:       named.status.Fixed,
				vex.NotAffected: named.status.KnownNotAffected,
			}
			for status, ids := range listed {
				want := 0
				if status == c.want {
					want = 1
				}
				if n := len(slices.DeleteFunc(slices.Clone(ids), func(s string) bool { return s != id })); n != want {
					t.Errorf("%s is listed %d times as %s, want %d: %+v", id, n, status, want, named.status)
				}
			}
			if flags := named.flags(); c.want != vex.NotAffected && len(flags) != 0 {
				t.Errorf("an identifier listed as %s carries the reason it is not affected: %+v", c.want, flags)
			}
		})
	}
}
