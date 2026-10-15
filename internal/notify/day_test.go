// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// zoned matches a moment formatted in whatever zone it carries: a Format call
// not reached through UTC.
var zoned = regexp.MustCompile(`\.Format\(`)

// formattedInItsOwnZone is every line of source formatting a moment without
// converting it to UTC first, by line number.
func formattedInItsOwnZone(source string) []int {
	var found []int
	for i, line := range strings.Split(source, "\n") {
		for _, at := range zoned.FindAllStringIndex(line, -1) {
			if !strings.HasSuffix(line[:at[0]], ".UTC()") {
				found = append(found, i+1)
			}
		}
	}
	return found
}

func TestAMomentFormattedInItsOwnZoneIsReported(t *testing.T) {
	if got := formattedInItsOwnZone("x\nbody := row.DiscloseAt.Format(time.DateOnly)"); len(got) != 1 || got[0] != 2 {
		t.Errorf("a date formatted in its own zone was reported as %v", got)
	}
	if got := formattedInItsOwnZone("at.UTC().Format(time.DateOnly)\nday(row.DiscloseAt)"); len(got) != 0 {
		t.Errorf("a UTC date and a date through day were reported as %v", got)
	}
}

// Every notice names a moment through day or minute, or converts it to UTC
// where it formats it, so no notice names a day in the server's zone.
func TestEveryNoticeNamesAMomentInUTC(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	examined := 0
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		examined++
		source, err := os.ReadFile(path) //nolint:gosec // G304: this package's own source
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range formattedInItsOwnZone(string(source)) {
			t.Errorf("%s:%d formats a moment in the zone it carries; name it through day or minute", path, line)
		}
	}
	if examined == 0 {
		t.Fatal("no source was found, so this checked nothing")
	}
}
