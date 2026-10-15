// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/currency"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

// module is the import path every package here sits under.
const module = "github.com/nexthop-ai/openpsirt/"

// vocabulary is one closed list a package states, with where its type is
// declared and the constants it leaves out on purpose.
type vocabulary struct {
	pkg, typ string
	words    []string
	apart    []string
}

// listed is a typed list as a vocabulary, its type found from the list itself.
// apart names constants of the type that are not words the list offers.
func listed[T ~string](all []T, apart ...string) vocabulary {
	typ := reflect.TypeFor[T]()
	out := vocabulary{pkg: strings.TrimPrefix(typ.PkgPath(), module), typ: typ.Name(), apart: apart}
	for _, each := range all {
		out.words = append(out.words, string(each))
	}
	return out
}

// TestEveryVocabularyListsEveryConstantOfItsType holds each list a route
// offers to the constants its package declares of that type.
//
// A route offers the list, so a constant the store writes and the list leaves
// out is a word the route refuses. The truth is the constants, read from the
// source: taken from the list, this would pass for a constant left out of it.
func TestEveryVocabularyListsEveryConstantOfItsType(t *testing.T) {
	t.Parallel()

	for _, each := range []vocabulary{
		listed(triage.Outcomes()),
		listed(triage.Justifications()),
		listed(triage.WhatHappenedAll()),
		listed(triage.States()),
		listed(triage.QueueReasons()),
		listed(triage.ClaimKinds()),
		listed(access.Roles()),
		listed(access.OverTheDeployment()),
		listed(access.Modes()),
		listed(access.Sources()),
		listed(access.EmailSources(), "NobodySaid"),
		listed(access.PartyKinds()),
		listed(access.Visibilities()),
		listed(catalog.Kinds()),
		listed(finding.Acts()),
		listed(finding.Dispositions()),
		listed(finding.ClaimStandings()),
		listed(finding.Origins()),
		listed(finding.FixStates()),
		listed(finding.NoDeadlines()),
		listed(finding.UpgradeStates()),
		listed(finding.MatchRoutes()),
		listed(finding.ReferenceKinds()),
		listed(finding.RulingStates()),
		listed(finding.SortKeys()),
		listed(finding.BundleSortKeys()),
		listed(finding.Closures()),
		listed(finding.VariantSpreads(), "AnyVariants"),
		listed(graph.Reasons),
		listed(graph.ChangeKinds()),
		listed(notify.Kinds()),
		listed(notify.Lifetimes()),
		listed(ingest.Progresses()),
		listed(ingest.Kinds()),
		listed(patchbranch.States()),
		listed(patchbranch.Steps()),
		listed(currency.Whys()),
		listed(trail.Kinds()),
		listed(trail.Actors()),
		listed(setting.Kinds()),
		listed(setting.Sections()),
		listed(vex.Kinds()),
	} {
		t.Run(each.pkg+"."+each.typ, func(t *testing.T) {
			t.Parallel()
			declared := constantsOf(t, filepath.Join("..", "..", each.pkg), each.typ)
			if len(declared) == 0 {
				t.Fatalf("no %s constants were found in %s, so this checked nothing", each.typ, each.pkg)
			}
			values := map[string]bool{}
			for name, value := range declared {
				values[value] = true
				if !slices.Contains(each.words, value) && !slices.Contains(each.apart, name) {
					t.Errorf("the constant %s is %q, which the list does not offer", name, value)
				}
			}
			for _, word := range each.words {
				if !values[word] {
					t.Errorf("the list offers %q, which no %s constant declares", word, each.typ)
				}
			}
			for _, name := range each.apart {
				if _, held := declared[name]; !held {
					t.Errorf("%s is set apart from the list and no constant has that name", name)
				}
			}
		})
	}
}

// constantsOf is every constant of a named type a package's source declares,
// by the constant's own name.
func constantsOf(t *testing.T, dir, typ string) map[string]string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
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
				if !ok || named.Name != typ || len(value.Values) != len(value.Names) {
					continue
				}
				for i, constant := range value.Names {
					if word, ok := stringValue(t, file, value.Values[i]); ok {
						found[constant.Name] = word
					}
				}
			}
		}
	}
	return found
}

// stringValue is the string a constant's value spells: a literal, or a
// constant of another package of this module named by its selector, which is
// how a vocabulary declared from another package's spelling reads.
func stringValue(t *testing.T, file *ast.File, value ast.Expr) (string, bool) {
	t.Helper()

	switch value := value.(type) {
	case *ast.BasicLit:
		if value.Kind != token.STRING {
			return "", false
		}
		word, err := strconv.Unquote(value.Value)
		if err != nil {
			t.Fatalf("read the value %s: %v", value.Value, err)
		}
		return word, true
	case *ast.SelectorExpr:
		pkg, ok := value.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		for _, imported := range file.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil || !strings.HasPrefix(path, module) || filepath.Base(path) != pkg.Name {
				continue
			}
			word, ok := untypedConstantsOf(t, filepath.Join("..", "..", strings.TrimPrefix(path, module)))[value.Sel.Name]
			return word, ok
		}
	}
	return "", false
}

// untypedConstantsOf is every constant a package's source declares as a string
// literal with no type, by the constant's own name.
func untypedConstantsOf(t *testing.T, dir string) map[string]string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			group, ok := decl.(*ast.GenDecl)
			if !ok || group.Tok != token.CONST {
				continue
			}
			for _, spec := range group.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok || value.Type != nil || len(value.Values) != len(value.Names) {
					continue
				}
				for i, constant := range value.Names {
					if literal, ok := value.Values[i].(*ast.BasicLit); ok && literal.Kind == token.STRING {
						if word, err := strconv.Unquote(literal.Value); err == nil {
							found[constant.Name] = word
						}
					}
				}
			}
		}
	}
	return found
}
