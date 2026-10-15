// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

func TestAGrantSetAsideIsNotHeldWhenThePeopleListIsNarrowed(t *testing.T) {
	// Group-bound mode sets a person's own grants aside. Narrowed to who
	// approves on a product, the list leaves out somebody whose only grant
	// there is set aside, and keeps somebody whose grant is in force.
	named := map[int64]core.Named{7: {Address: "sonic"}}
	grant := HeldBody{Product: "sonic", Role: core.Role("approver"), Effective: true}
	if !holding([]HeldBody{grant}, 7, named, "approver") {
		t.Fatal("a grant in force is not held, so this checks nothing")
	}
	grant.Effective = false
	if holding([]HeldBody{grant}, 7, named, "approver") {
		t.Error("a grant set aside is held")
	}
	grant.Everywhere, grant.Product = true, ""
	if holding([]HeldBody{grant}, 7, named, "approver") {
		t.Error("a grant across every product set aside is held")
	}
}
