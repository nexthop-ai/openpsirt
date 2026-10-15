// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import "time"

// day is the UTC calendar day a moment falls on, as notification text names
// it. One moment is one day to every reader, whatever zone the server's clock
// is in.
func day(at time.Time) string { return at.UTC().Format(time.DateOnly) }

// minute is a moment to the minute in UTC, named as UTC, as notification text
// names a deadline that falls within a day.
func minute(at time.Time) string { return at.UTC().Format("2006-01-02 15:04 UTC") }
