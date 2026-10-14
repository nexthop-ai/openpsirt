// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

func TestTheDeploymentReadsEverythingAndActsOnNothing(t *testing.T) {
	// The deployment's own subject holds no role, so it triages, approves and
	// decides nothing; only a reading rule takes the every-product shortcut.
	everything := access.Everything("a background pass")
	if where, _ := notApprovableWhere(everything, "de"); where != "1 = 1" {
		t.Errorf("every decision reads as approvable by the deployment: %q", where)
	}
	if where, _ := notDecidableWhere(everything, "de"); where != "1 = 1" {
		t.Errorf("every decision reads as decidable by the deployment: %q", where)
	}
	if !unnarrowedMay(everything, readable) {
		t.Error("the deployment does not read everything")
	}
	for name, rule := range map[string]func(access.Subject, int64, access.Visibility) bool{
		"approve": mayApprove, "decide": mayDecide,
	} {
		if unnarrowedMay(everything, rule) {
			t.Errorf("the deployment may %s everything", name)
		}
	}
}
