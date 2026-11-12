// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// A waiting claim that stopped being readable between the list and what
// agreeing would do is left off the page and out of the total, so a client
// paging by the total never asks past the end.
func TestAnAssessmentLeftOffThePageIsLeftOutOfItsTotal(t *testing.T) {
	waiting := func(id int64) finding.Assessment {
		return finding.Assessment{ID: id, State: finding.AssessmentProposed, NeedsApproval: true}
	}
	decisions := []finding.Assessment{waiting(1), waiting(2), {ID: 3, State: finding.AssessmentLive}}
	would := map[int64]finding.Consequence{1: {Findings: 4}}
	items, total := assessmentPage(decisions, 7, would, func(a finding.Assessment) AssessmentBody {
		return AssessmentBody{ID: a.ID}
	})
	if len(items) != 2 || items[0].ID != 1 || items[1].ID != 3 {
		t.Fatalf("the page holds %+v; want the answered claim and the one in force", items)
	}
	if items[0].Open != 4 {
		t.Errorf("the answered claim opens %d findings; want 4", items[0].Open)
	}
	if total != 6 {
		t.Errorf("the total is %d with one of seven left off; want 6", total)
	}
}
