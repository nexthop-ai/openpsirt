// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// TestEveryTrailKindIsOffered pins that the kinds an administrative change can
// have and the kinds a caller may filter by are the same set.
//
// Every place a caller may filter by spells the list out as a struct tag, and
// a kind reaching the constants without reaching all of them is one nothing
// can be filtered by — which fails as an empty screen rather than as an error.
//
// The truth is the constants, read from the source. Taken from Kinds(), this
// would pass for a kind declared and left out of Kinds() as well, which is the
// same accident one step further back and makes Kinds() another hand-kept copy
// rather than the one place the set is named.
func TestEveryTrailKindIsOffered(t *testing.T) {
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

	tags := trailKindEnums(t)
	if len(tags) == 0 {
		t.Fatal("no enum tags over a trail kind were found, so this checked nothing")
	}

	for where, offered := range tags {
		offeredSet := map[string]bool{}
		for _, one := range offered {
			offeredSet[one] = true
			if !listed[one] {
				t.Errorf("%s offers %q, which no kind in the trail package declares", where, one)
			}
		}
		for _, one := range declared {
			if !offeredSet[one] {
				t.Errorf("%s does not offer %q, so nobody can filter by it", where, one)
			}
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

// trailKindEnums reads every enum tag on a field named Kind in this package,
// keyed by where it was found.
//
// Read from the source rather than from a value, because most of them sit on a
// struct declared inside a function and no type of this package's own reaches
// them.
func trailKindEnums(t *testing.T) map[string][]string {
	t.Helper()

	found := map[string][]string{}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read this package: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			field, ok := node.(*ast.Field)
			if !ok || field.Tag == nil || len(field.Names) != 1 || field.Names[0].Name != "Kind" {
				return true
			}
			raw, err := strconv.Unquote(field.Tag.Value)
			if err != nil {
				return true
			}
			offered := reflect.StructTag(raw).Get("enum")
			if offered == "" || !strings.Contains(offered, "setting") {
				return true
			}
			at := filepath.Join(name, strconv.Itoa(fset.Position(field.Pos()).Line))
			parts := strings.Split(offered, ",")
			sort.Strings(parts)
			found[at] = parts
			return true
		})
	}
	return found
}
