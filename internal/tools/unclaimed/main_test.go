// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// A decision no design document names is a defect, built or not. This gate is
// what AGENTS.md means by "the other direction is checked by the gate", and it
// had no test — so the step that decides whether a hundred and thirty-two
// decisions are claimed by a document or merely near one had an exit code for
// its evidence.

// twoDigits is the width the requirements are written at, which is what a
// range expands against.
var twoDigits = map[string]int{"REQ": 2, "SEC": 2}

func has(named map[string]bool, want ...string) bool {
	for _, id := range want {
		if !named[id] {
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
			// The form the documents state a run in. A hundred and thirty-two
			// decisions are claimed by a range endpoint and nothing else,
			// so what this expands to is the whole of their audit trail.
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
		named := identifiersIn(c.text, twoDigits)
		if !has(named, c.named...) {
			t.Errorf("%s: %q named %v, want all of %v", c.what, c.text, keys(named), c.named)
		}
		for _, id := range c.notNamed {
			if named[id] {
				t.Errorf("%s: %q was read as naming %s", c.what, c.text, id)
			}
		}
	}
}

func TestARangeIsWrittenAtTheWidthTheRequirementsUse(t *testing.T) {
	// The identifiers are zero-padded, so a range expanded at the wrong width
	// produces names no requirement has — and every one of them then reads as
	// a decision nothing claims.
	named := identifiersIn("REQ-08 to REQ-10", map[string]int{"REQ": 2})
	if !has(named, "REQ-08", "REQ-09", "REQ-10") {
		t.Errorf("a padded range expanded to %v", keys(named))
	}
	for _, wrong := range []string{"REQ-8", "REQ-9", "REQ-008"} {
		if named[wrong] {
			t.Errorf("a range expanded to %s, which is no requirement's name", wrong)
		}
	}
}

func TestTheRequirementsTableIsReadAsRows(t *testing.T) {
	// The pattern that finds a requirement and what it says. A row shape it
	// stops matching is a requirement this gate stops asking about, which
	// looks exactly like a requirement a document names.
	table := strings.Join([]string{
		"| REQ-01 | Apache 2.0 | Somebody else runs it |",
		"| REQ-02 | **Withdrawn** — replaced by REQ-03 |",
		"not a row at all",
		"| SEC-10 | Keys are hashed at rest |",
	}, "\n")

	got := map[string]string{}
	for _, match := range row.FindAllStringSubmatch(table, -1) {
		got[match[1]] = match[2]
	}
	for _, want := range []string{"REQ-01", "REQ-02", "SEC-10"} {
		if _, found := got[want]; !found {
			t.Errorf("%s was not read as a row", want)
		}
	}
	if len(got) != 3 {
		t.Errorf("read %d rows from a table holding three", len(got))
	}
	// A withdrawn decision is history rather than an obligation, and the
	// marker is what tells them apart.
	if !strings.HasPrefix(strings.TrimSpace(strings.TrimLeft(got["REQ-02"], "*")), "Withdrawn") {
		t.Errorf("a withdrawn row read as %q, which nothing would skip", got["REQ-02"])
	}
}

func keys(named map[string]bool) []string {
	out := make([]string, 0, len(named))
	for id := range named {
		out = append(out, id)
	}
	return out
}
