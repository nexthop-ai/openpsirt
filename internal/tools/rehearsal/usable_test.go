// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// The release and the engine name a directory the rehearsal removes, so each
// is refused before it is joined into a path unless it is one.
func TestARehearsalRefusesWhatIsNotAReleaseOrAnEngine(t *testing.T) {
	for _, c := range []struct {
		from, engine string
		usable       bool
	}{
		{"v0.2.0", "postgres", true},
		{"v0.3.0-rc.1", "sqlite", true},
		{"../../../other/proj", "sqlite", false},
		{"v0.2.0/../../x", "mysql", false},
		{"v0.2.0", "../x", false},
		{"v0.2.0", "oracle", false},
	} {
		if err := usable(c.from, c.engine); (err == nil) != c.usable {
			t.Errorf("-from %q -engine %q: usable = %v (%v), want %v", c.from, c.engine, err == nil, err, c.usable)
		}
	}
}
