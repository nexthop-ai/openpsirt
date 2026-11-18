// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The reasons a list a route offers is not held to the constants of a type.
const (
	plainStrings = "a list of plain strings, whose words no type declares"
	someOutcomes = "a part of triage.Outcomes, which is checked whole"
	someReasons  = "a part of triage.Justifications, which is checked whole"
)

// listsApart is every list a route offers that is not held to the constants of
// its type, with the reason it is not.
var listsApart = map[string]string{
	"advisory.ReleaseStatuses":        plainStrings,
	"advisory.Statuses":               plainStrings,
	"analysis.CodeFindingAssignees":   plainStrings,
	"analysis.Methods":                plainStrings,
	"cvss.Bands":                      plainStrings,
	"finding.AssessmentStates":        plainStrings,
	"finding.Assignees":               plainStrings,
	"finding.Bands":                   plainStrings,
	"finding.BuildSayings":            plainStrings,
	"finding.LeastFirst":              plainStrings,
	"finding.MinimumSeverities":       plainStrings,
	"finding.OutcomesOffered":         plainStrings,
	"finding.Recordable":              plainStrings,
	"finding.Sources":                 plainStrings,
	"finding.Supports":                plainStrings,
	"finding.VexStatuses":             plainStrings,
	"incident.Malice":                 plainStrings,
	"notify.Platforms":                plainStrings,
	"sbom.Scopes":                     plainStrings,
	"triage.CodeFindingOutcomes":      someOutcomes,
	"triage.JustificationsCorrecting": someReasons,
	"triage.OutcomesInBulk":           someOutcomes,
	"triage.OutcomesOneAtATime":       someOutcomes,
	"triage.OutcomesThatHideRisk":     someOutcomes,
	"triage.VulnerabilityOutcomes":    someOutcomes,
}

// TestEveryOfferedVocabularyIsCheckedOrSetApart holds the lists the routes
// offer, read from the source, to the lists the constants test checks and the
// lists set apart from it, in both directions.
func TestEveryOfferedVocabularyIsCheckedOrSetApart(t *testing.T) {
	t.Parallel()

	offered := map[string]string{}
	if err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		for _, name := range offeredLists(parsed(t, path)) {
			offered[name] = path
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(offered) == 0 {
		t.Fatal("no route offers a list, so this checked nothing")
	}
	checked := checkedLists(parsed(t, "vocabulary_constants_test.go"))
	if len(checked) == 0 {
		t.Fatal("the constants test checks no list, so this checked nothing")
	}

	for name, path := range offered {
		_, apart := listsApart[name]
		if !slices.Contains(checked, name) && !apart {
			t.Errorf("%s offers %s, which is neither checked against its constants nor set apart", path, name)
		}
	}
	for name := range listsApart {
		if _, held := offered[name]; !held {
			t.Errorf("%s is set apart, and no route offers it", name)
		}
		if slices.Contains(checked, name) {
			t.Errorf("%s is set apart and checked as well", name)
		}
	}
	for _, name := range checked {
		if _, held := offered[name]; !held {
			t.Errorf("%s is checked against its constants, and no route offers it", name)
		}
	}
}

// TestTheOfferedListsAreFoundInEitherForm holds the detection to one source
// offering a list each way it is offered, and to the lists it reads that are
// not offered.
func TestTheOfferedListsAreFoundInEitherForm(t *testing.T) {
	t.Parallel()

	const source = `package core

import (
	"github.com/danielgtaylor/huma/v2"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	tri "github.com/nexthop-ai/openpsirt/internal/triage"
)

func (Handed) Schema(huma.Registry) *huma.Schema { return words(finding.Origins()) }

func (Built) Schema(huma.Registry) *huma.Schema {
	offered := []any{}
	for _, each := range kind.Families() {
		offered = append(offered, string(each))
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}

func (Aliased) Schema(huma.Registry) *huma.Schema { return words(tri.States()) }

func (Joined) Schema(huma.Registry) *huma.Schema {
	return words(append(plainly(tri.Roles()), plainly(finding.Others())...))
}

func (Held) Schema(huma.Registry) *huma.Schema { return words(finding.Reasons) }

func (Narrowed) Schema(huma.Registry) *huma.Schema {
	return words(append(Which(tri.Outcomes(), tri.Outcome.Hides), tri.Several))
}

func (Spelled) Schema(huma.Registry) *huma.Schema {
	return words([]string{string(finding.Planned), string(finding.Unplanned)})
}

func counted() int {
	n := 0
	for range finding.Acts() {
		n++
	}
	return n
}

func (Local) Schema(huma.Registry) *huma.Schema { return words(local()) }
`
	file, err := parser.ParseFile(token.NewFileSet(), "offered.go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	got := offeredLists(file)
	want := []string{"finding.Origins", "finding.Others", "finding.Reasons", "finding/kind.Families",
		"triage.Outcomes", "triage.Roles", "triage.States"}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("the source offers %q, want %q", got, want)
	}
}

// parsed is one source file of this package's tree.
func parsed(t *testing.T, path string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return file
}

// offeredLists is every list a file offers a route as a closed set of words,
// named by its package's path within the module and its function or
// variable: a list read in what is handed to words, and a list a function
// building a schema's enumeration calls for.
func offeredLists(file *ast.File) []string {
	named := listNamer(file)
	found := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if fn, ok := n.Fun.(*ast.Ident); !ok || fn.Name != "words" || len(n.Args) != 1 {
				return true
			}
			// A variable handed whole, and every list the argument calls for,
			// since one is offered joined to another or narrowed.
			if name, ok := named(n.Args[0], true); ok {
				found[name] = true
			}
			ast.Inspect(n.Args[0], func(inner ast.Node) bool {
				if e, ok := inner.(*ast.CallExpr); ok {
					if name, ok := named(e, false); ok {
						found[name] = true
					}
				}
				return true
			})
		case *ast.FuncDecl:
			if n.Body == nil || !buildsEnum(n.Body) {
				return true
			}
			ast.Inspect(n.Body, func(inner ast.Node) bool {
				if e, ok := inner.(*ast.CallExpr); ok {
					if name, ok := named(e, false); ok {
						found[name] = true
					}
				}
				return true
			})
		}
		return true
	})
	out := make([]string, 0, len(found))
	for name := range found {
		out = append(out, name)
	}
	return out
}

// checkedLists is every list the constants test hands to listed, named as
// offeredLists names it.
func checkedLists(file *ast.File) []string {
	named := listNamer(file)
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		if fn, ok := call.Fun.(*ast.Ident); !ok || fn.Name != "listed" {
			return true
		}
		if name, ok := named(call.Args[0], true); ok {
			out = append(out, name)
		}
		return true
	})
	return out
}

// listNamer names a list a file reads from a package of this module: a call
// of one of its functions taking nothing, or, where variables is set, one of
// its variables.
func listNamer(file *ast.File) func(e ast.Expr, variables bool) (string, bool) {
	ours := map[string]string{}
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil || !strings.HasPrefix(path, module) {
			continue
		}
		within := strings.TrimPrefix(strings.TrimPrefix(path, module), "internal/")
		name := filepath.Base(path)
		if imported.Name != nil {
			name = imported.Name.Name
		}
		ours[name] = within
	}
	return func(e ast.Expr, variables bool) (string, bool) {
		if call, ok := e.(*ast.CallExpr); ok {
			if len(call.Args) != 0 {
				return "", false
			}
			e = call.Fun
		} else if !variables {
			return "", false
		}
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		within, ours := ours[pkg.Name]
		if !ours {
			return "", false
		}
		return within + "." + sel.Sel.Name, true
	}
}

// buildsEnum reports whether a function body sets a schema's enumeration.
func buildsEnum(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if kv, ok := n.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Enum" {
				found = true
			}
		}
		return !found
	})
	return found
}
