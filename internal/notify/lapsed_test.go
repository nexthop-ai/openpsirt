// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// A lapse counts occurrence rows, and one decision reaches many of them, so the
// count is said as occurrences: "forty-four decisions" would claim forty-four
// decisions where one decision lapsed at forty-four places.
func TestALapseCountsTheOccurrencesItReachedAsOccurrences(t *testing.T) {
	got := Lapse(triage.ForPerson{PersonID: 1, Rows: 44}).Body
	if !strings.HasPrefix(got, "Your decisions at 44 occurrences stopped applying") {
		t.Errorf("a lapse at 44 occurrences says %q; want the count said as occurrences", got)
	}
	if one := Lapse(triage.ForPerson{PersonID: 1, Rows: 1}).Body; !strings.HasPrefix(one, "A decision of yours stopped applying") {
		t.Errorf("a lapse at one occurrence says %q; want one decision", one)
	}
}
