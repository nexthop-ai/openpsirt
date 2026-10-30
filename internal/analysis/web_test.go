// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/sarif"
)

// webRun is one run of a web scanner reporting a result at each address, a
// path placed in the checkout where an address is one.
func webRun(addresses ...string) string {
	results := make([]string, 0, len(addresses))
	for _, at := range addresses {
		results = append(results, `{"ruleId":"10038","message":{"text":"header not set"},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"`+at+`"},"region":{"startLine":1}}}]}`)
	}
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ZAP","rules":[{"id":"10038"}]}},` +
		`"results":[` + strings.Join(results, ",") + `]}]}`
}

func placeWeb(t *testing.T, doc string) (Placed, error) {
	t.Helper()
	log, err := sarif.NewUpload(sarif.DefaultLimits()).Read(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	return Place([]sarif.Log{log}, "", sarif.DefaultLimits().MaxBytes, nil)
}

func TestARunWhoseResultsAreAllAtWebAddressesIsRefused(t *testing.T) {
	_, err := placeWeb(t, webRun("https://shop.example/login", "HTTP://shop.example/cart"))
	if !refusal.In(err) || !strings.Contains(err.Error(), "web scanner results are not supported") {
		t.Errorf("a run of web addresses alone answered %v; want a refusal saying web scanner results are not supported", err)
	}
}

func TestAWebAddressBesideAFileIsDroppedAndCounted(t *testing.T) {
	placed, err := placeWeb(t, webRun("https://shop.example/login", "src/server.c"))
	if err != nil {
		t.Fatalf("a run placing a result in a file was refused: %v", err)
	}
	if len(placed.Results) != 1 || placed.Results[0].Path != "src/server.c" {
		t.Errorf("placed %+v; want the result in the file alone", placed.Results)
	}
	if got := placed.Receipt.Dropped[DroppedWeb]; got != 1 {
		t.Errorf("the receipt drops %d at a web address (%v); want 1", got, placed.Receipt.Dropped)
	}
	if got := placed.Receipt.Dropped[DroppedOutside]; got != 0 {
		t.Errorf("the receipt drops %d outside the checkout; want the web address counted as one", got)
	}
}

func TestARunPlacingNothingAtAWebAddressIsNotRefusedAsOne(t *testing.T) {
	// A file address outside the checkout is dropped, never read as a web
	// scanner's.
	placed, err := placeWeb(t, webRun("file:///elsewhere/server.c"))
	if err != nil {
		t.Fatalf("a run outside the checkout was refused: %v", err)
	}
	if got := placed.Receipt.Dropped[DroppedOutside]; got != 1 {
		t.Errorf("the receipt drops %d outside the checkout; want 1", got)
	}
}
