// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package uribase

import "testing"

func TestAnAddressResolvesToWhatItsChainEndsAt(t *testing.T) {
	bases := map[string][2]string{
		"ABS":     {"file:///build/sonic/", ""},
		"UNDER":   {"src/", "ABS"},
		"FRR":     {"src/sonic-frr/", "SRCROOT"},
		"WORK":    {"out/", ""},
		"EMPTY":   {"", ""},
		"LOOP":    {"a/", "LOOPED"},
		"LOOPED":  {"b/", "LOOP"},
		"ELSEWHR": {"x/", "NOWHERE"},
	}
	defined := func(name string) (string, string, bool) {
		b, ok := bases[name]
		return b[0], b[1], ok && b[0] != ""
	}
	for _, c := range []struct {
		name, uri, base string
		start           Start
		want            string
		ok              bool
	}{
		{"an absolute path", "/usr/include/x.h", "", Absolute, "/usr/include/x.h", true},
		{"a file address", "file:///build/sonic/a.c", "", Absolute, "/build/sonic/a.c", true},
		{"a chain to an absolute address", "x.c", "UNDER", Absolute, "/build/sonic/src/x.c", true},
		{"the root's undefined name", "a.c", "SRCROOT", FromRoot, "a.c", true},
		{"the root's other name", "a.c", "%SRCROOT%", FromRoot, "a.c", true},
		{"a chain to the root's undefined name", "bgpd/a.c", "FRR", FromRoot, "src/sonic-frr/bgpd/a.c", true},
		{"no starting point", "a.c", "", FromWork, "a.c", true},
		{"a chain to no starting point", "a.c", "WORK", FromWork, "out/a.c", true},
		{"a name defined with no address", "a.c", "EMPTY", Absolute, "", false},
		{"a chain to another undefined name", "a.c", "ELSEWHR", Absolute, "", false},
		{"a chain that loops", "a.c", "LOOP", Absolute, "", false},
		{"another scheme", "https://example.com/a.c", "", Absolute, "", false},
	} {
		got, start, ok := Resolve(c.uri, c.base, defined, len(bases))
		if ok != c.ok || ok && (got != c.want || start != c.start) {
			t.Errorf("%s: resolved %q from %d, %v; want %q from %d, %v", c.name, got, start, ok, c.want, c.start, c.ok)
		}
	}
}

func TestAChainLongerThanItsBoundIsRefused(t *testing.T) {
	defined := func(name string) (string, string, bool) {
		switch name {
		case "A":
			return "a/", "B", true
		case "B":
			return "b/", "", true
		}
		return "", "", false
	}
	if _, _, ok := Resolve("x.c", "A", defined, 2); !ok {
		t.Error("a chain within its bound was refused")
	}
	if _, _, ok := Resolve("x.c", "A", defined, 1); ok {
		t.Error("a chain past its bound was followed")
	}
}
