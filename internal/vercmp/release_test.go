// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vercmp_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/vercmp"
)

func TestAReleaseIsTheVersionWithoutWhatItsDistributionAdds(t *testing.T) {
	for _, c := range []struct {
		ecosystem, version, want string
	}{
		{"deb", "6.12.41-1", "6.12.41"},
		{"deb", "1:2.3.2-2+b1", "2.3.2"},
		{"deb", "4.12.1", "4.12.1"},
		{"deb", "2.41.5-0+deb13u1", "2.41.5"},
		{"deb", "1.0-beta-2", "1.0-beta"},
		{"deb", "unfixed", "unfixed"},
		{"deb", "x:1.0-1", "x:1.0-1"},
		{"rpm", "2:5.14.0-427.el9", "5.14.0"},
		{"apk", "1.37.0-r31", "1.37.0"},
		{"apk", "1.37.0", "1.37.0"},
		{"apk", "1.0-rc", "1.0-rc"},
		{"pypi", "2.1.0+cu121", "2.1.0"},
		{"pypi", "1!2.0", "1!2.0"},
		{"npm", "1.0.0-rc.1", "1.0.0-rc.1"},
		{"golang", "v1.2.3-0.20240101000000-abcdef123456", "v1.2.3-0.20240101000000-abcdef123456"},
		{"maven", "1.0-SNAPSHOT", "1.0-SNAPSHOT"},
		{"github", "6.12.41-1", "6.12.41"},
		{"", "6.12.41-1", "6.12.41"},
		{"generic", "UNKNOWN", "UNKNOWN"},
		{"deb", " 6.12.41-1 ", "6.12.41"},
	} {
		if got := vercmp.Release(vercmp.SchemeOf(c.ecosystem), c.version); got != c.want {
			t.Errorf("%s %q releases %q, want %q", c.ecosystem, c.version, got, c.want)
		}
	}
}
