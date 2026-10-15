// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// Each band's count lands in its own place, worst first, and a word that is
// not a band is counted in none of them.
func TestEachBandsCountLandsInItsOwnPlace(t *testing.T) {
	critical, high, medium, low := core.BandCounts(map[string]int{
		"critical": 1, "high": 2, "medium": 3, "low": 4, "negligible": 5,
	})
	if critical != 1 || high != 2 || medium != 3 || low != 4 {
		t.Errorf("read %d, %d, %d, %d, want 1, 2, 3, 4", critical, high, medium, low)
	}
}
