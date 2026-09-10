package database

import "testing"

func TestParseVersionHandlesEachServersShape(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want Version
	}{
		{"PostgreSQL 16.15 on x86_64-pc-linux-musl, compiled by gcc", Version{16, 15}},
		{"8.4.11", Version{8, 4}},
		{"10.11.6-MariaDB-1:10.11.6+maria~ubu2204", Version{10, 11}},
		{"11.4.13-MariaDB-ubu2404", Version{11, 4}},
		{"3.53.3", Version{3, 53}},
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
		{Version{16, 0}, Version{14, 0}, true},
		{Version{14, 0}, Version{14, 0}, true},
		{Version{13, 9}, Version{14, 0}, false},
		{Version{10, 6}, Version{10, 6}, true},
		{Version{10, 5}, Version{10, 6}, false},
		// A larger minor must not rescue a smaller major.
		{Version{9, 99}, Version{10, 6}, false},
	} {
		if got := tc.have.AtLeast(tc.floor); got != tc.ok {
			t.Errorf("%s.AtLeast(%s) = %v, want %v", tc.have, tc.floor, got, tc.ok)
		}
	}
}

func TestEveryEngineHasAFloor(t *testing.T) {
	// A missing floor would silently accept any version of that engine.
	for _, e := range []Engine{Postgres, MySQL, MariaDB, SQLite} {
		if _, ok := minimum[e]; !ok {
			t.Errorf("%s has no minimum version", e)
		}
	}
}
