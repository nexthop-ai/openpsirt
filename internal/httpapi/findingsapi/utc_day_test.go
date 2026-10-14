// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// One instant is one day whatever zone the server's clock read it in. Pinned
// against a time in another zone, because the process zone cannot be moved
// under a running server.
func TestAFindingsDayIsTheUTCDayOfItsMoment(t *testing.T) {
	west := time.FixedZone("west", -7*3600)
	due := time.Date(2026, 10, 14, 23, 0, 0, 0, west)
	opened := time.Date(2026, 9, 30, 22, 30, 0, 0, west)
	row := findingBody(finding.Group{DueAt: &due, OpenedAt: opened, DiscloseAt: &due}, due)
	if row.Due != "2026-10-15" || row.DiscloseAt != "2026-10-15" || row.Opened != "2026-10-01" {
		t.Errorf("the row reads due %s, disclosed %s, opened %s; want the UTC days 2026-10-15, 2026-10-15, 2026-10-01",
			row.Due, row.DiscloseAt, row.Opened)
	}
	if moved := core.InUTC(&due); moved.Location() != time.UTC || !moved.Equal(due) {
		t.Errorf("a moment answered as a time is %v, want the same instant in UTC", moved)
	}
	if core.InUTC(nil) != nil {
		t.Error("no moment is answered as one")
	}
}
