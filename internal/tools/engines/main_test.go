// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"testing"
)

func TestEachListIsReadFromTheEnumeration(t *testing.T) {
	for _, c := range []struct {
		which string
		want  string
	}{
		{"", "[postgres mysql mariadb sqlite]"},
		{"servers", "[postgres mysql mariadb]"},
		{"partial", "[mysql mariadb]"},
	} {
		got, err := listed(c.which)
		if err != nil {
			t.Fatalf("%q: %v", c.which, err)
		}
		if fmt.Sprint(got) != c.want {
			t.Errorf("%q listed %v, want %v", c.which, got, c.want)
		}
	}
}

func TestAListThisDoesNotKnowIsRefused(t *testing.T) {
	if got, err := listed("sevrers"); err == nil {
		t.Errorf("a misspelled list printed %v, which a makefile loop would read as every engine", got)
	}
}
