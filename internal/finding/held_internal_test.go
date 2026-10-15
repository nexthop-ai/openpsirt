// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"database/sql"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
)

// Two findings share an update statement only where every value it writes to
// every row is the same, and differ in their key wherever one value differs.
// A column the update writes and the key leaves out would hand one finding
// another's values; a column the update does not write and the key holds only
// splits a statement in two. The order is the one column written from each
// row's own value, so findings differing in it share a statement.
func TestFindingsShareAnUpdateOnlyWhereEveryValueWrittenIsTheSame(t *testing.T) {
	on := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	later := on.Add(time.Hour)
	one, two := int64(1), int64(2)
	base := func() moving {
		at := on
		return moving{f: Finding{
			FixState: FixedUpstream, FixedIn: "1.0", FixedAt: &at,
			Matched: "exact", MatchedFrom: "a", MatchedIn: "b", MatchedRange: "< 1.0",
			SuppressedBy: &one, StatedBy: &one, ClaimedBy: &one,
			Urgency: 10, RankExploited: false, RankShipped: false, DueAt: &at,
		}, learned: &at}
	}
	// Each case changes the one column it names and nothing else.
	cases := []struct {
		column string
		// gate is the flag the update writes the column under, or perRow
		// where it writes it from each row's own value.
		gate   string
		change func(m *moving)
	}{
		{"fix_state", "described", func(m *moving) { m.f.FixState = "" }},
		{"fixed_in", "described", func(m *moving) { m.f.FixedIn = "2.0" }},
		{"fixed_at", "described", func(m *moving) { m.f.FixedAt = &later }},
		{"matched", "described", func(m *moving) { m.f.Matched = "upstream" }},
		{"matched_from", "described", func(m *moving) { m.f.MatchedFrom = "c" }},
		{"matched_in", "described", func(m *moving) { m.f.MatchedIn = "d" }},
		{"matched_range", "described", func(m *moving) { m.f.MatchedRange = "< 2.0" }},
		{"suppressed_by", "described", func(m *moving) { m.f.SuppressedBy = &two }},
		{"suppressed_by", "described", func(m *moving) { m.f.SuppressedBy = nil }},
		{"stated_by", "described", func(m *moving) { m.f.StatedBy = &two }},
		{"stated_by", "described", func(m *moving) { m.f.StatedBy = nil }},
		{"claimed_by", "described", func(m *moving) { m.f.ClaimedBy = &two }},
		{"claimed_by", "described", func(m *moving) { m.f.ClaimedBy = nil }},
		{"urgency", "perRow", func(m *moving) { m.f.Urgency = 20 }},
		{"urgency_exploited", "moved", func(m *moving) { m.f.RankExploited = true }},
		{"urgency_shipped", "moved", func(m *moving) { m.f.RankShipped = true }},
		{"exploited_learned_at", "exploitationMoved", func(m *moving) { m.learned = &later }},
		{"due_at", "clockMoved", func(m *moving) { m.f.DueAt = &later }},
	}
	flags := map[string]func(m *moving, on bool){
		"described":         func(m *moving, on bool) { m.described = on },
		"moved":             func(m *moving, on bool) { m.moved = on },
		"exploitationMoved": func(m *moving, on bool) { m.exploitationMoved = on },
		"clockMoved":        func(m *moving, on bool) { m.clockMoved = on },
	}
	covered := map[string]bool{}
	for _, c := range cases {
		covered[c.column] = true
		for _, written := range []bool{true, false} {
			a, b := base(), base()
			if c.gate == "perRow" {
				flags["moved"](&a, written)
				flags["moved"](&b, written)
				c.change(&b)
				if a.key() != b.key() {
					t.Errorf("%s, written per row, split the statement", c.column)
				}
				continue
			}
			flags[c.gate](&a, written)
			flags[c.gate](&b, written)
			c.change(&b)
			if differ := a.key() != b.key(); differ != written {
				t.Errorf("%s under %q set %v: keys differ %v, want %v", c.column, c.gate, written, differ, written)
			}
		}
	}

	// The cases name every column the update writes with every flag set,
	// and nothing it does not.
	db := bun.NewDB(sql.OpenDB(unconnected{}), sqlitedialect.New())
	all := base()
	for _, set := range flags {
		set(&all, true)
	}
	all.add(1, all.f.Urgency)
	statement := all.update(db, 0, 1).String()
	var written []string
	for _, m := range regexp.MustCompile(`(?:SET |, )"?([a-z_]+)"? = `).FindAllStringSubmatch(statement, -1) {
		written = append(written, m[1])
	}
	if len(written) == 0 {
		t.Fatalf("no column was found in %s, so this checked nothing", statement)
	}
	for _, column := range written {
		if !covered[column] {
			t.Errorf("the update writes %s and no case changes it", column)
		}
		delete(covered, column)
	}
	var stray []string
	for column := range covered {
		stray = append(stray, column)
	}
	sort.Strings(stray)
	if len(stray) > 0 {
		t.Errorf("cases name %s, which the update does not write", strings.Join(stray, ", "))
	}
}
