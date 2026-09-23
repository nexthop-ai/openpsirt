// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestARatingIsPublishedWithTheSchemeItIsOn(t *testing.T) {
	// A number alone is not readable across schemes. A report that stated no
	// version still has a generation, which is what is published in its place.
	got := ratingBodies([]finding.CVSS{
		{Generation: 4, ScoreCenti: 710, Vector: "CVSS:4.0/AV:N", Version: "4.0", Source: "cna", Kind: "Secondary"},
		{Generation: 3, ScoreCenti: 820, Vector: "CVSS:3.1/AV:N"},
	})
	if len(got) != 2 {
		t.Fatalf("published %d ratings, want 2", len(got))
	}
	if got[0] != (RatingBody{Version: "4.0", Score: 7.1, Vector: "CVSS:4.0/AV:N", Source: "cna", Kind: "Secondary"}) {
		t.Errorf("the first rating reads %+v", got[0])
	}
	if got[1].Version != "3" || got[1].Score != 8.2 {
		t.Errorf("a rating stating no version reads %+v, want its generation", got[1])
	}
	if ratingBodies(nil) != nil {
		t.Error("an issue with no ratings publishes an empty list rather than none")
	}
}
