// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"strings"
	"testing"
	"time"
)

// A refused date is named as its UTC day, whatever zone the moment arrived in.
// The moment below is the evening of the first of January ten hours west of
// UTC, which is the second of January in UTC.
func TestARefusedDateIsNamedAsItsUTCDay(t *testing.T) {
	west := time.Date(2020, time.January, 1, 20, 0, 0, 0, time.FixedZone("west", -10*60*60))
	now := time.Date(2026, time.October, 15, 12, 0, 0, 0, time.UTC)
	for _, each := range []Proposal{
		{Outcome: Deferred, DeferredUntil: &west},
		{Outcome: PatchNeeded, CommittedTo: &west},
	} {
		t.Run(string(each.Outcome), func(t *testing.T) {
			each.Reasoning = "Looked at it."
			each.By = 1
			err := each.valid(now)
			if err == nil {
				t.Fatal("a date in the past was accepted")
			}
			if !strings.Contains(err.Error(), "2020-01-02 has passed") {
				t.Errorf("the refusal reads %q, want the UTC day 2020-01-02", err)
			}
		})
	}
}
