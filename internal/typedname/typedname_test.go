// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package typedname_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/typedname"
)

func TestOnlyANameABrowserResolvesAsADotSegmentIsUnaddressable(t *testing.T) {
	for _, name := range []string{".", "..", " .. "} {
		if typedname.Addressable("a name", name) == nil {
			t.Errorf("%q was accepted", name)
		}
	}
	// A browser sends these as written.
	for _, name := range []string{"...", ".hidden", "release-2.4", "a..b"} {
		if err := typedname.Addressable("a name", name); err != nil {
			t.Errorf("%q was refused: %v", name, err)
		}
	}
}
