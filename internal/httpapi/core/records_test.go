// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core_test

import (
	"encoding/json"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/cverecord"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// The lines a scan writes are the lines a register reads back. Written the way
// the scan writes them, from the record's own type, so a field renamed on one
// side fails here rather than leaving the register's evidence blank.
func TestTheLinesAScanRecordsAreTheLinesARegisterReads(t *testing.T) {
	stated := []cverecord.Stated{
		{Entry: "Linux Linux", Line: cverecord.Line{Version: "6.18.27", Status: "unaffected",
			LessThanOrEqual: "6.18.*", VersionType: "semver"}},
		{Entry: "zlib zlib", Line: cverecord.Line{Version: "1.3", Status: "UNAFFECTED",
			LessThan: "2.0"}},
		{Entry: "curl curl", Line: cverecord.Line{Version: "8.1.0", Status: "unaffected"}},
	}
	stored, err := json.Marshal(stated)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := core.RecordLines(string(stored))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"Linux Linux unaffected from 6.18.27 to 6.18.*",
		"zlib zlib unaffected from 1.3 before 2.0",
		"curl curl unaffected at 8.1.0",
	}
	if len(lines) != len(want) {
		t.Fatalf("read %d lines, want %d", len(lines), len(want))
	}
	for i, line := range lines {
		if got := line.Said(); got != want[i] {
			t.Errorf("line %d reads %q, want %q", i, got, want[i])
		}
	}
}

// Lines recorded and unreadable are an error, so the row can say so rather
// than show a closure with no evidence.
func TestLinesThatCannotBeReadAreAnErrorNotNone(t *testing.T) {
	if _, err := core.RecordLines(`{"entry": 7}`); err == nil {
		t.Error("lines that cannot be read were read as none")
	}
	if lines, err := core.RecordLines(""); err != nil || lines != nil {
		t.Errorf("no lines read as %v, %v", lines, err)
	}
}
