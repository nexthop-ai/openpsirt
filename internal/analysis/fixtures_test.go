// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/sarif"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

// toolOutput reads one of the reader's real tool outputs.
func toolOutput(t *testing.T, name string) sarif.Log {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "sarif", "testdata", name)) //nolint:gosec // G304: a path under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	log, err := sarif.NewUpload(sarif.DefaultLimits()).Read(f)
	if err != nil {
		t.Fatal(err)
	}
	return log
}

// The comparability each real producer's plain output gets with nothing
// stated beside it: CodeQL lists every query it ran, so its rule set is
// read from the output; clang-tidy states nothing about its coverage.
func TestAPlainRunIsComparableOnlyWhereItsOutputStatesItsCoverage(t *testing.T) {
	for _, c := range []struct {
		file, root    string
		extractedNone bool
		comparable    bool
		reason        series.Reason
	}{
		{"codeql2150-cpp.sarif", "/src", false, true, ""},
		// CodeQL states its run successful with every compilation failed,
		// and its coverage notifications are what say so.
		{"codeql2150-cpp.sarif", "/src", true, false, series.FailureSignal},
		{"clangtidy-artemis.sarif", "/var/tmp/testing-dir/assignment", false, false, series.NoCoverage},
	} {
		name := c.file
		if c.extractedNone {
			name += " extracting nothing"
		}
		t.Run(name, func(t *testing.T) {
			logs := []sarif.Log{toolOutput(t, c.file)}
			if c.extractedNone {
				logs[0].Runs[0].Invocations[0].Extracted = 0
			}
			stated := Describe(logs, Stated{Series: "s"})
			placed, err := Place(logs, c.root, 1<<30, func(string) bool { return false })
			if err != nil {
				t.Fatal(err)
			}
			ok, reason := series.Comparability(stated.Params, nil, placed.Signals)
			if ok != c.comparable || reason != c.reason {
				t.Errorf("comparable %v for %q; want %v for %q", ok, reason, c.comparable, c.reason)
			}
		})
	}
}
