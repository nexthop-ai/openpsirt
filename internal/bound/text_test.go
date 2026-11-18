// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package bound_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/bound"
)

func TestTextDropsNULAndReplacesInvalidBytes(t *testing.T) {
	if got := bound.Text("caf\xe9 \x00and on"); got != "caf� and on" {
		t.Errorf("repaired as %q", got)
	}
	if got := bound.Text("already text"); got != "already text" {
		t.Errorf("text that needed nothing came back as %q", got)
	}
	// A run of invalid bytes is one replacement.
	if got := bound.Text("a\xff\xfeb"); got != "a\uFFFDb" {
		t.Errorf("a run of two invalid bytes came back as %q", got)
	}
	// A NUL is dropped after invalid bytes are replaced, so it never joins
	// the bytes either side into a character.
	if got := bound.Text("\xc3\x00\xa9"); got != "\uFFFD\uFFFD" {
		t.Errorf("bytes either side of a NUL came back as %q", got)
	}
}

func TestLineIsOneLineOfPrintableText(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"  Intel Boot Agent\n\n  v1.5.89\t(x86)  ", "Intel Boot Agent v1.5.89 (x86)"},
		{"bell\a and \x1b[31mred\x1b[0m", "bell and [31mred[0m"},
		{"caf\xe9\x00 au lait", "caf� au lait"},
		{"next\u0085line", "next line"},
		{" \n\t ", ""},
	} {
		if got := bound.Line(c.in); got != c.want {
			t.Errorf("Line(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The cut counts characters, so a description in a script taking three bytes a
// character keeps as many characters as one in ASCII, and none is split.
func TestLineCutsAtMostLineCharacters(t *testing.T) {
	for _, unit := range []string{"a", "界"} {
		got := bound.Line(strings.Repeat(unit, bound.MostLine+50))
		if n := utf8.RuneCountInString(got); n != bound.MostLine {
			t.Errorf("a long run of %q kept %d characters, want %d", unit, n, bound.MostLine)
		}
		if !utf8.ValidString(got) {
			t.Errorf("a long run of %q was cut inside a character", unit)
		}
	}
	// A space where the cut lands is not kept at the end.
	if got := bound.Line(strings.Repeat("a", bound.MostLine-1) + " b"); got != strings.Repeat("a", bound.MostLine-1) {
		t.Errorf("a cut on a space kept %q at the end", got[len(got)-2:])
	}
}

// A key is repaired as its value is, so a repaired value still finds its entry:
// a release named by one field and looked up in a map keyed by it.
func TestTextInRepairsMapKeys(t *testing.T) {
	doc := struct {
		Latest string
		Times  map[string]string
	}{
		Latest: "1.0\x00",
		Times:  map[string]string{"1.0\x00": "2026-01-01", "2.0": "2026-02-01"},
	}
	bound.TextIn(&doc)
	if got := doc.Times[doc.Latest]; got != "2026-01-01" {
		t.Errorf("the repaired version %q finds %q in %v", doc.Latest, got, doc.Times)
	}
	if len(doc.Times) != 2 {
		t.Errorf("the map holds %v", doc.Times)
	}

	// A key already valid keeps its value over one that repairs to it.
	clash := map[string]string{"k": "kept", "k\x00": "repaired", "k\x00\x00": "also repaired"}
	bound.TextIn(&clash)
	if len(clash) != 1 || clash["k"] != "kept" {
		t.Errorf("a valid key lost its value: %v", clash)
	}
	// Among keys that repair alike, the last in byte order wins.
	repairs := map[string]string{"j\x00": "first", "j\x00\x00": "second"}
	bound.TextIn(&repairs)
	if len(repairs) != 1 || repairs["j"] != "second" {
		t.Errorf("keys repairing alike kept %v", repairs)
	}
}

func TestTextInReachesEveryStringADecodedDocumentHolds(t *testing.T) {
	type inner struct{ Name string }
	doc := struct {
		Name   string
		Many   []string
		Nested []inner
		Ptr    *inner
		Map    map[string]string
		Any    map[string]any
		hidden map[string]string
	}{
		Name: "a\x00", Many: []string{"c\x00"}, Nested: []inner{{"d\x00"}}, Ptr: &inner{"e\x00"},
		Map:    map[string]string{"k": "f\x00"},
		Any:    map[string]any{"s": "g\x00", "list": []any{"h\x00", map[string]any{"deep": "i\x00"}}},
		hidden: map[string]string{"k": "j\x00"},
	}
	bound.TextIn(&doc)
	list := doc.Any["list"].([]any)
	for name, got := range map[string]string{
		"a field": doc.Name, "a slice element": doc.Many[0], "a struct in a slice": doc.Nested[0].Name,
		"a pointer": doc.Ptr.Name, "a map value": doc.Map["k"], "an interface in a map": doc.Any["s"].(string),
		"an interface in a slice": list[0].(string), "a map inside an interface": list[1].(map[string]any)["deep"].(string),
	} {
		if len(got) != 1 {
			t.Errorf("%s came back as %q", name, got)
		}
	}
	// A map behind an unexported field is passed over: reflection may read
	// it and never write it, so writing it would panic.
	if doc.hidden["k"] != "j\x00" {
		t.Errorf("an unexported field was reached: %q", doc.hidden)
	}
}
