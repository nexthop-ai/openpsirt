// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestTheFindingPackageNamesTheSameDismissalsAsTriage(t *testing.T) {
	// A duplicate may only point at work still open, and a place dismissed
	// is not open. The finding package cannot import this one, so it spells
	// the list; an outcome added here and not there would count a dismissed
	// place as open.
	var owned []string
	for _, each := range triage.OutcomesDismissing() {
		owned = append(owned, string(each))
	}
	if len(owned) == 0 {
		t.Fatal("triage names no dismissal, so this checked nothing")
	}
	spelled := slices.Clone(finding.Dismissing)
	slices.Sort(owned)
	slices.Sort(spelled)
	if !slices.Equal(owned, spelled) {
		t.Errorf("triage dismisses %v and the finding package spells %v", owned, spelled)
	}
}
