// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// TestEveryTrailKindConstantIsListed pins that Kinds() names every kind the
// trail package declares, and nothing else.
//
// Every place a caller may filter by offers Kinds(), so a kind reaching the
// constants without reaching that list is one nothing can be filtered by —
// which fails as an empty screen rather than as an error.
//
// The truth is the constants, read from the source. Taken from Kinds(), this
// would pass for a kind declared and left out of Kinds() as well.
func TestEveryTrailKindConstantIsListed(t *testing.T) {
	t.Parallel()

	declared := trailKindConstants(t)
	if len(declared) == 0 {
		t.Fatal("no kind constants were found in the source, so this checked nothing")
	}
	listed := map[string]bool{}
	for _, kind := range trail.Kinds() {
		listed[string(kind)] = true
	}
	for name, value := range declared {
		if !listed[value] {
			t.Errorf("the constant %s is %q, which Kinds() does not list", name, value)
		}
	}
	for value := range listed {
		if !slices.Contains(slices.Collect(maps.Values(declared)), value) {
			t.Errorf("Kinds() lists %q, which no constant declares", value)
		}
	}
}

// trailKindConstants is every Kind constant the trail package declares, by
// the constant's own name.
//
// Read from the source, for the reason the test above gives. The shape is the
// one internal/notify/message_test.go uses over its own enumeration.
func trailKindConstants(t *testing.T) map[string]string {
	t.Helper()

	path := filepath.Join("..", "trail", "trail.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	found := map[string]string{}
	for _, decl := range file.Decls {
		group, ok := decl.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, spec := range group.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			named, ok := value.Type.(*ast.Ident)
			if !ok || named.Name != "Kind" || len(value.Values) != len(value.Names) {
				continue
			}
			for i, name := range value.Names {
				literal, ok := value.Values[i].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				word, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatalf("read the value of %s: %v", name.Name, err)
				}
				found[name.Name] = word
			}
		}
	}
	return found
}
