// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core_test

import (
	"io/fs"
	"os"
	"path/filepath"
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
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(source), "Format(time.RFC3339") ||
			strings.Contains(string(source), `"2006-01-02T15:04:05`) {
			t.Errorf("%s formats a moment by hand; state it through core.Stamp or core.StampAt", path)
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
