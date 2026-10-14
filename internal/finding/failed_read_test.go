// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// A disclosure movement that could not be read is not one that is not there.
// Answered as absent inside the transaction, a lost race is never taken again
// and an outage tells the person agreeing that there is nothing to agree to.
func TestAMovementThatCouldNotBeReadIsNotOneThatIsNotThere(t *testing.T) {
	handle := dbtest.Without(t, "disclosure_movement")
	who := access.NewPerson(1, "approver", false, nil, 101)
	_, err := finding.NewStore(handle.DB).AgreeToMovement(t.Context(), who, 1)
	if err == nil {
		t.Fatal("agreeing to a movement read from a table that is not there succeeded")
	}
	if errors.Is(err, finding.ErrNotEmbargoed) {
		t.Errorf("a read that failed was answered as nothing to agree to: %v", err)
	}
}
