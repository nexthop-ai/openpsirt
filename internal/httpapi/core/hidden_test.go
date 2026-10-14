// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import "testing"

func TestNothingHeldInAProductNobodySeesAnswersAsNoSuchProduct(t *testing.T) {
	if err := HiddenIfEmpty(0, "theirs", false); err == nil || err.Error() != NoSuchProduct().Error() {
		t.Errorf("an empty answer about a product nobody sees reads as %v", err)
	}
	for _, c := range []struct {
		rows    int
		product string
		sees    bool
	}{
		{1, "theirs", false},
		{0, "", false},
		{0, "mine", true},
	} {
		if err := HiddenIfEmpty(c.rows, c.product, c.sees); err != nil {
			t.Errorf("%+v was refused: %v", c, err)
		}
	}
}
