// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"testing"
	"time"
)

// Notification text names a moment in UTC, whatever zone it arrived in. The
// moment is the evening of the first of January ten hours west of UTC, which
// is the morning of the second in UTC.
func TestNotificationTextNamesAMomentInUTC(t *testing.T) {
	west := time.Date(2026, time.January, 1, 20, 30, 0, 0, time.FixedZone("west", -10*60*60))
	if got, want := day(west), "2026-01-02"; got != want {
		t.Errorf("the day reads %q, want %q", got, want)
	}
	if got, want := minute(west), "2026-01-02 06:30 UTC"; got != want {
		t.Errorf("the minute reads %q, want %q", got, want)
	}
}
