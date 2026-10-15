// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package bound_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/bound"
)

func TestTextDropsNULAndReplacesInvalidBytes(t *testing.T) {
	if got := bound.Text("caf\xe9 \x00and on"); got != "caf� and on" {
		t.Errorf("repaired as %q", got)
	}
	if got := bound.Text("already text"); got != "already text" {
		t.Errorf("text that needed nothing came back as %q", got)
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
		hidden string
	}{
		Name: "a\x00", Many: []string{"c\x00"}, Nested: []inner{{"d\x00"}}, Ptr: &inner{"e\x00"},
		Map:    map[string]string{"k": "f\x00"},
		Any:    map[string]any{"s": "g\x00", "list": []any{"h\x00", map[string]any{"deep": "i\x00"}}},
		hidden: "j\x00",
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
	if doc.hidden != "j\x00" {
		t.Errorf("an unexported field was reached: %q", doc.hidden)
	}
}
