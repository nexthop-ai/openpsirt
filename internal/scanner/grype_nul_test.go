// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/scanner"
)

// A NUL in what the scanner reports is dropped as it is read: every string a
// match carries may reach the database, and the query builder refuses one on
// two of the engines.
func TestANULInAMatchIsDroppedAsItIsRead(t *testing.T) {
	raw, err := os.ReadFile("testdata/grype-output.json")
	if err != nil {
		t.Fatal(err)
	}
	carrying := strings.ReplaceAll(string(raw), `"description": "`, `"description": "\u0000`)
	result, err := scanner.ParseGrype(strings.NewReader(carrying), scanner.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Reported) == 0 {
		t.Fatal("nothing was read, so this checked nothing")
	}
	if said := fmt.Sprintf("%+v", result.Reported); strings.Contains(said, "\x00") {
		t.Errorf("a match was read with a NUL in it")
	}
}
