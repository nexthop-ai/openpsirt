// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// The findings package spells the outcomes it asks about itself, because it
// cannot import this one. Spelled differently, a supplier's statement closes a
// finding somebody marked affected, and a wrong match lapses on a version.
func TestTheOutcomesTheFindingsPackageAsksAboutAreSpelledAsHere(t *testing.T) {
	for _, tc := range []struct {
		there string
		here  triage.Outcome
	}{
		{finding.AffectedOutcome, triage.Affected},
		{finding.Mismatched, triage.Mismatched},
	} {
		if tc.there != string(tc.here) {
			t.Errorf("the findings package spells %q as %q", tc.here, tc.there)
		}
	}
}
