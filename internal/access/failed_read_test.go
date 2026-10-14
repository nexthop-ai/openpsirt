// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// A sign-in whose match could not be read is a fault. Taken for somebody
// unknown, an outage refuses everybody arriving as though nothing authorized
// them, and nothing is logged.
func TestASignInWhoseMatchCouldNotBeReadIsAFaultNotAStranger(t *testing.T) {
	handle := dbtest.Without(t, "person_identity")
	_, err := access.NewStore(handle.DB).AdmitByGroups(t.Context(),
		access.Arrival{ViaProxy: true, Username: "someone"}, nil)
	if err == nil {
		t.Fatal("a sign-in over a lookup that failed was admitted")
	}
	if errors.Is(err, access.ErrDenied) {
		t.Errorf("a lookup that failed was answered as somebody nothing authorized: %v", err)
	}
}
