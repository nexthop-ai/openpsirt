// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// A scan that could not be read is not a scan that is not there. Answered as
// absent, an outage reads to a caller as an upload that was never received.
func TestAScanThatCouldNotBeReadIsNotOneThatIsNotThere(t *testing.T) {
	handle := dbtest.Without(t, "scan")
	_, err := ingest.NewStore(handle.DB).ByID(t.Context(), 1)
	if err == nil {
		t.Fatal("a scan read from a table that is not there came back")
	}
	if errors.Is(err, ingest.ErrNoScan) {
		t.Errorf("a read that failed was answered as no such scan: %v", err)
	}
}
