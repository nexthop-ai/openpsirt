// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package publish

import "testing"

// A client resolves "." and ".." alone as a path segment, and sends more dots
// as written, so only the two are escaped further.
func TestOnlyADotSegmentIsEscapedFurther(t *testing.T) {
	for name, want := range map[string]string{
		".":    "%2E",
		"..":   "%2E%2E",
		"...":  "...",
		"v1.0": "v1.0",
		"a/b":  "a%2Fb",
	} {
		if got := segment(name); got != want {
			t.Errorf("%q became %q, want %q", name, got, want)
		}
	}
}
