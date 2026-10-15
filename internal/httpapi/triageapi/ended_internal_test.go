// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// A part of a claim that stopped without saying when leaves the moment out,
// and one that says when states it in UTC.
func TestAnEndedPartWithNoMomentLeavesItOut(t *testing.T) {
	west := time.Date(2026, time.March, 4, 20, 30, 0, 0, time.FixedZone("west", -10*60*60))
	parts := endedReach([]triage.EndedPart{{Rows: 1}, {Rows: 1, At: west}})
	unknown, err := json.Marshal(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unknown), `"at"`) {
		t.Errorf("a part with no moment reads %s", unknown)
	}
	known, err := json.Marshal(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(known), `"at":"2026-03-05T06:30:00Z"`) {
		t.Errorf("a part that says when reads %s", known)
	}
}
