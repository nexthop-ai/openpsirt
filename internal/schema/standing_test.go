// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// A serving instance serves a schema at its own version that nothing is
// changing, pauses for one being changed or left with its record standing,
// stops for one behind it that nothing is changing, and never serves one a
// later release applied, even while that release is still changing it.
func TestAStandingFollowsTheLeaseAndTheVersion(t *testing.T) {
	for _, c := range []struct {
		changing         migrate.Change
		applied, carried int64
		want             Standing
	}{
		{migrate.Unchanged, 47, 47, Serves},
		{migrate.Held, 47, 47, Changes},
		{migrate.Recorded, 47, 47, Stranded},
		{migrate.Unchanged, 46, 47, Behind},
		{migrate.Held, 46, 47, Changes},
		{migrate.Recorded, 46, 47, Stranded},
		{migrate.Unchanged, 48, 47, Superseded},
		{migrate.Held, 48, 47, Superseded},
		{migrate.Recorded, 48, 47, Superseded},
	} {
		if got := stands(c.changing, c.applied, c.carried); got != c.want {
			t.Errorf("changing %v at %d, carrying %d: %v, want %v", c.changing, c.applied, c.carried, got, c.want)
		}
	}
}

// A look whose question about a change failed still stops an instance whose
// schema a later release applied, since that release may have reshaped what
// the question reads; at any other version the failure is answered.
func TestAVersionAheadStopsAnInstanceWhoseLookFailed(t *testing.T) {
	failed := errors.New("the record of schema changes is gone")
	if got, err := looked(migrate.Unchanged, 48, 47, failed); got != Superseded || err != nil {
		t.Errorf("a version ahead with a failed look: %v, %v; want Superseded and no error", got, err)
	}
	if _, err := looked(migrate.Unchanged, 47, 47, failed); !errors.Is(err, failed) {
		t.Errorf("a failed look at this build's version answered %v, not the failure", err)
	}
}
