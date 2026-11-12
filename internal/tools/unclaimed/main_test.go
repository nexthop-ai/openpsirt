// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"slices"
	"strings"
	"testing"
)

// A decision no design document names is a defect, built or not. This gate is
// what AGENTS.md means by "the other direction is checked by the gate".

func has(named map[string]bool, want ...string) bool {
	for _, id := range want {
		if !named[canonical(id)] {
			return false
		}
	}
	return true
}

func TestWhatADocumentNames(t *testing.T) {
	for _, c := range []struct {
		what     string
		text     string
		named    []string
		notNamed []string
	}{
		{
			"one identifier in prose",
			"Visibility is enforced in the data layer (REQ-42).",
			[]string{"REQ-42"}, []string{"REQ-41", "REQ-43"},
		},
		{
			"a Satisfies line listing several",
			"Satisfies: REQ-08, REQ-17, REQ-25",
			[]string{"REQ-08", "REQ-17", "REQ-25"}, []string{"REQ-09", "REQ-18"},
		},
		{
			// The form the documents state a run in. A decision claimed by a
			// range alone has this expansion for its whole audit trail.
			"a range, which names everything between",
			"an explanation and an approval, REQ-23 to REQ-25",
			[]string{"REQ-23", "REQ-24", "REQ-25"}, []string{"REQ-22", "REQ-26"},
		},
		{
			"a range of one",
			"REQ-30 to REQ-30",
			[]string{"REQ-30"}, []string{"REQ-29", "REQ-31"},
		},
		{
			// Two identifiers in a sentence rather than a run. Expanded, this
			// would claim every number between them under one prefix — which
			// is a document claiming decisions it never mentions.
			"a range across two areas, which is not a range",
			"from REQ-70 to SEC-02 the rule holds",
			[]string{"REQ-70", "SEC-02"}, []string{"REQ-71", "SEC-01"},
		},
		{
			"prose naming nothing",
			"The trail records who changed what, and when.",
			nil, []string{"REQ-22"},
		},
	} {
		named := identifiersIn(c.text)
		if !has(named, c.named...) {
			t.Errorf("%s: %q named %v, want all of %v", c.what, c.text, keys(named), c.named)
		}
		for _, id := range c.notNamed {
			if named[canonical(id)] {
				t.Errorf("%s: %q was read as naming %s", c.what, c.text, id)
			}
		}
	}
}

func TestARangeNamesItsRequirementsWhateverWidthTheyAreWrittenAt(t *testing.T) {
	// Requirements are matched by number. A two-digit range in an area that
	// has reached three digits still names the two-digit requirements inside
	// it, and nothing outside it.
	named := identifiersIn("REQ-08 to REQ-10")
	for _, id := range []string{"REQ-08", "REQ-09", "REQ-10", "REQ-009"} {
		if !named[canonical(id)] {
			t.Errorf("a range expanded to %v, which misses %s", keys(named), id)
		}
	}
	for _, wrong := range []string{"REQ-07", "REQ-11", "REQ-100"} {
		if named[canonical(wrong)] {
			t.Errorf("a range expanded to %s, which is outside it", wrong)
		}
	}
}

func TestTheRequirementsTableIsReadAsRows(t *testing.T) {
	// The pattern that finds a requirement and what it says. A row shape it
	// stops matching is a requirement this gate stops asking about, which
	// looks exactly like a requirement a document names. A withdrawn decision
	// is history rather than an obligation, and the marker is what tells them
	// apart.
	text := strings.Join([]string{
		"## 3. Requirements",
		"| REQ-01 | Apache 2.0 | Somebody else runs it |",
		"| REQ-02 | **Withdrawn** — replaced by REQ-03 |",
		"not a row at all",
		"| SEC-10 | Keys are hashed at rest |",
		"## 4. Out of scope",
		"| REQ-99 | Out of scope |",
	}, "\n")
	want, err := requirementsIn(text)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(want, []string{"REQ-01", "SEC-10"}) {
		t.Errorf("read %v, want the two in force and in the section", want)
	}
}

func TestASectionHoldingNoRequirementChecksNothingAndIsRefused(t *testing.T) {
	for _, text := range []string{
		"## 3. Requirements\nprose only\n## 4. Out of scope\n",
		"no sections at all",
	} {
		if _, err := requirementsIn(text); err == nil {
			t.Errorf("%q was read as a list of requirements", text)
		}
	}
}

func keys(named map[string]bool) []string {
	out := make([]string, 0, len(named))
	for id := range named {
		out = append(out, id)
	}
	return out
}
