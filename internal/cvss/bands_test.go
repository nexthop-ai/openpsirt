// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package cvss

import (
	"slices"
	"testing"
)

// The words a score is banded into are the words the list offers, every one
// of them reached and nothing else answered. The API offers the list as the
// band a score falls in, so a word the scorer answers and the list leaves out
// is a response its own document says cannot happen.
func TestEveryBandAScoreFallsInIsOneTheListOffers(t *testing.T) {
	reached := map[string]bool{}
	for tenths := 0; tenths <= 100; tenths++ {
		word := bandOf(float64(tenths) / 10)
		if !slices.Contains(Bands(), word) {
			t.Errorf("a score of %.1f falls in %q, which the list does not offer", float64(tenths)/10, word)
		}
		reached[word] = true
	}
	for _, word := range Bands() {
		if !reached[word] {
			t.Errorf("no score falls in %q", word)
		}
	}
}
