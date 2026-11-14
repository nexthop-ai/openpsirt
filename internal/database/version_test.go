// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database

import "testing"

func TestParseVersionHandlesEachServersShape(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want Version
	}{
		// PostgreSQL numbers releases as series.patch, so what it reports is
		// two parts and the second of them is the patch level. Read as
		// {16, 15, 0}, it compares correctly against every other {16, n}.
		{"PostgreSQL 16.15 on x86_64-pc-linux-musl, compiled by gcc", Version{16, 15, 0}},
		{"8.4.11", Version{8, 4, 11}},
		{"10.11.6-MariaDB-1:10.11.6+maria~ubu2204", Version{10, 11, 6}},
		{"11.4.13-MariaDB-ubu2404", Version{11, 4, 13}},
		{"3.53.3", Version{3, 53, 3}},
	} {
		got, err := parseVersion(tc.raw)
		if err != nil {
			t.Errorf("parseVersion(%q): %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseVersion(%q) = %s, want %s", tc.raw, got, tc.want)
		}
	}
}

func TestParseVersionRejectsNonsense(t *testing.T) {
	for _, raw := range []string{"", "unknown", "version"} {
		if _, err := parseVersion(raw); err == nil {
			t.Errorf("parseVersion(%q) was accepted", raw)
		}
	}
}

func TestVersionComparison(t *testing.T) {
	for _, tc := range []struct {
		have, floor Version
		ok          bool
	}{
		{Version{16, 0, 0}, Version{14, 0, 0}, true},
		{Version{14, 0, 0}, Version{14, 0, 0}, true},
		{Version{13, 9, 0}, Version{14, 0, 0}, false},
		{Version{10, 6, 0}, Version{10, 6, 0}, true},
		{Version{10, 5, 0}, Version{10, 6, 0}, false},
		// A larger minor must not rescue a smaller major.
		{Version{9, 99, 0}, Version{10, 6, 0}, false},
		// Nor a larger patch a smaller minor, and a patch level decides only
		// when the two above it are equal.
		{Version{10, 5, 99}, Version{10, 6, 0}, false},
		{Version{8, 0, 36}, Version{8, 0, 40}, false},
		{Version{8, 0, 40}, Version{8, 0, 40}, true},
		{Version{8, 0, 41}, Version{8, 0, 40}, true},
		{Version{8, 1, 0}, Version{8, 0, 40}, true},
	} {
		if got := tc.have.AtLeast(tc.floor); got != tc.ok {
			t.Errorf("%s.AtLeast(%s) = %v, want %v", tc.have, tc.floor, got, tc.ok)
		}
	}
}

func TestEveryEngineHasAFloor(t *testing.T) {
	// A missing floor would silently accept any version of that engine.
	if len(Engines()) == 0 {
		t.Fatal("no engines were listed, so this checked nothing")
	}
	for _, e := range Engines() {
		if _, ok := minimum[e]; !ok {
			t.Errorf("%s has no minimum version", e)
		}
	}
}

func TestAVersionIsWrittenTheWayItsServerReportsIt(t *testing.T) {
	// A patch level appended to a version that never had one reads as a
	// precision nobody reported: PostgreSQL says "16.15" and means a series
	// and its patch, so "16.15.0" invents a third part it does not have.
	for _, tc := range []struct {
		have Version
		want string
	}{
		{Version{16, 15, 0}, "16.15"},
		{Version{8, 4, 11}, "8.4.11"},
		{Version{10, 6, 0}, "10.6"},
	} {
		if got := tc.have.String(); got != tc.want {
			t.Errorf("%#v printed as %q, want %q", tc.have, got, tc.want)
		}
	}
}

func TestAPostgreSQLVersionIsReadFromItsNumber(t *testing.T) {
	// A pre-release names its version with no dot, and the first dotted
	// number in what version() says is then the compiler's.
	for _, tc := range []struct {
		number string
		want   Version
	}{
		{"180000", Version{18, 0, 0}},
		{"160015", Version{16, 15, 0}},
		{"140001", Version{14, 1, 0}},
		{"130022", Version{13, 22, 0}},
	} {
		got, err := postgresVersion(tc.number)
		if err != nil {
			t.Errorf("postgresVersion(%q): %v", tc.number, err)
			continue
		}
		if got != tc.want {
			t.Errorf("postgresVersion(%q) = %s, want %s", tc.number, got, tc.want)
		}
	}
	for _, number := range []string{"", "18beta1", "0", "-1"} {
		if _, err := postgresVersion(number); err == nil {
			t.Errorf("postgresVersion(%q) was accepted", number)
		}
	}
}
