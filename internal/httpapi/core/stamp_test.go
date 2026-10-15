// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// An unknown moment renders as nothing, which an optional field leaves out,
// and a known one in UTC whatever zone the driver handed it back in.
func TestAnUnknownMomentIsStatedAsNothingAndAKnownOneInUTC(t *testing.T) {
	east := time.FixedZone("east", 5*60*60)
	known := time.Date(2026, 3, 4, 10, 30, 0, 0, east)
	for _, c := range []struct {
		name string
		got  string
		want string
	}{
		{"a zero time", core.Stamp(time.Time{}), ""},
		{"no time at all", core.StampAt(nil), ""},
		{"a pointer to a zero time", core.StampAt(&time.Time{}), ""},
		{"a known time", core.Stamp(known), "2026-03-04T05:30:00Z"},
		{"a pointer to a known time", core.StampAt(&known), "2026-03-04T05:30:00Z"},
	} {
		if c.got != c.want {
			t.Errorf("%s rendered %q, want %q", c.name, c.got, c.want)
		}
	}
}

// timeField matches a struct field of type time.Time that JSON encodes, which
// it writes in the zone the value carries and to the nanosecond.
var timeField = regexp.MustCompile("\\*?time\\.Time\\s+`json:\"([a-z_]+)")

// sealed is the one time.Time field JSON encodes that is not a response: the
// moment a sign-in in progress was sealed into its cookie.
const sealed = "minted"

// unstamped is every way a source file states a moment without Stamp.
func unstamped(source string) []string {
	var why []string
	if strings.Contains(source, "Format(time.RFC3339") || strings.Contains(source, `"2006-01-02T15:04:05`) {
		why = append(why, "formats a moment by hand")
	}
	for _, match := range timeField.FindAllStringSubmatch(source, -1) {
		if match[1] != sealed {
			why = append(why, "encodes "+match[1]+" as a time.Time")
		}
	}
	return why
}

func TestAMomentEncodedAsATimeIsReported(t *testing.T) {
	if got := unstamped("\tStoppedAt time.Time `json:\"stopped_at\"`\n\tUntil *time.Time `json:\"until,omitempty\"`"); len(got) != 2 {
		t.Errorf("two encoded times were reported as %v", got)
	}
	if got := unstamped("\tStoppedAt string `json:\"stopped_at\"`\n\tMinted time.Time `json:\"minted\"`"); len(got) != 0 {
		t.Errorf("a stamped moment and the sealed sign-in were reported as %v", got)
	}
}

// A response states a moment through Stamp alone. Formatted by hand, a zero
// time answers as the year 1 where the renderer would leave it out.
func TestEveryMomentAResponseStatesGoesThroughStamp(t *testing.T) {
	examined := 0
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "httpapitest" {
			// Builds the documents a test sends, which are not responses.
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
			filepath.ToSlash(path) == "../core/period.go" {
			return nil
		}
		examined++
		source, err := os.ReadFile(path) //nolint:gosec // G304: this repository's own source
		if err != nil {
			return err
		}
		for _, why := range unstamped(string(source)) {
			t.Errorf("%s %s; state it through core.Stamp or core.StampAt", path, why)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if examined == 0 {
		t.Fatal("no source was found, so this checked nothing")
	}
}
