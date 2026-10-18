// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Anybody at all reads disclosed work in the products that publish and
// nothing else: not undisclosed work there, not a product that does not
// publish, and no role, case, team or hold over the deployment anywhere.
func TestAnybodyReadsOnlyDisclosedWorkWhereItIsPublished(t *testing.T) {
	const published, other = 7, 8
	anybody := access.Published([]int64{published})
	if !anybody.Reads(access.Public, published) {
		t.Error("anybody does not read disclosed work in a product that publishes")
	}
	for _, refused := range []struct {
		what    string
		answers bool
	}{
		{"undisclosed work where it is published", anybody.Reads(access.Private, published)},
		{"disclosed work in a product that does not publish", anybody.Reads(access.Public, other)},
		{"that a product that does not publish exists", anybody.Sees(other)},
		{"a role", anybody.Holds(access.PublicRead, published)},
		{"triage", anybody.Triages(access.Public, published)},
		{"a role anywhere", anybody.HoldsAnywhere(access.Roles()...)},
		{"the deployment's own records", anybody.ReadsTheDeployment()},
		{"a case", anybody.OnCase(published, 1)},
		{"everything", anybody.Unnarrowed()},
	} {
		if refused.answers {
			t.Errorf("anybody holds %s", refused.what)
		}
	}
	if err := anybody.Administering("anything"); err == nil {
		t.Error("anybody administers")
	}
	if products, all := anybody.Products(); all || !slices.Equal(products, []int64{published}) {
		t.Errorf("anybody reads products %v (all %v), want the one that publishes", products, all)
	}
	if mine := anybody.Mine(); len(mine) != 0 {
		t.Errorf("anybody holds work as %v", mine)
	}
	if nobody := access.Published(nil); nobody.Reads(access.Public, published) {
		t.Error("anybody reads a product where nothing publishes")
	}
}
