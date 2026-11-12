// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// figuresIn is every exported function in these Go sources that asks whether
// a subject may count code findings: single is each one calling MayCount or a
// scope's mayCount, across each one calling a scope's mayCount, which is the
// form a scope across products is checked through.
func figuresIn(sources map[string][]byte) (single, across []string, err error) {
	fset := token.NewFileSet()
	for name, source := range sources {
		file, err := parser.ParseFile(fset, name, source, 0)
		if err != nil {
			return nil, nil, err
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil || !fn.Name.IsExported() {
				continue
			}
			direct, scoped := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch callee := call.Fun.(type) {
				case *ast.Ident:
					direct = direct || callee.Name == "MayCount"
				case *ast.SelectorExpr:
					scoped = scoped || callee.Sel.Name == "mayCount"
				}
				return true
			})
			if direct || scoped {
				single = append(single, fn.Name.Name)
			}
			if scoped {
				across = append(across, fn.Name.Name)
			}
		}
	}
	slices.Sort(single)
	slices.Sort(across)
	return single, across, nil
}

// figures is every figure this package's source asks MayCount of.
func figures(t *testing.T) (single, across []string) {
	t.Helper()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string][]byte{}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name) //nolint:gosec // this package's own source
		if err != nil {
			t.Fatal(err)
		}
		sources[name] = source
	}
	single, across, err = figuresIn(sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(single) == 0 || len(across) == 0 {
		t.Fatal("no figure asks whether it may count, so this checked nothing")
	}
	return single, across
}

// checkedAre fails for every figure the source holds and the test does not
// ask, and every one the test asks that the source no longer holds.
func checkedAre(t *testing.T, what string, found []string, asked map[string]func() error) {
	t.Helper()
	for _, name := range found {
		if _, ok := asked[name]; !ok {
			t.Errorf("%s asks whether it may count and is not asked here%s", name, what)
		}
	}
	for name := range asked {
		if !slices.Contains(found, name) {
			t.Errorf("%s is asked here%s and no longer asks whether it may count", name, what)
		}
	}
}

func TestAFigureAskingWhetherItMayCountIsFound(t *testing.T) {
	single, across, err := figuresIn(map[string][]byte{"a.go": []byte(`package analysis
func Direct(s Subject) error { return MayCount(s, 1, "x") }
func Scoped(scope Scope, s Subject) error { return scope.mayCount(s, "x") }
func Plain() error { return nil }
func unexported(s Subject) error { return MayCount(s, 1, "x") }
`)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(single, []string{"Direct", "Scoped"}) || !slices.Equal(across, []string{"Scoped"}) {
		t.Errorf("found %v and %v across, want [Direct Scoped] and [Scoped]", single, across)
	}
}

// Every security testing figure refuses a reader of the product who does not
// read security testing material in it, in the data layer and before the
// database is asked anything, so a handler that forgot to check still counts
// nothing. The database is nil: a figure reaching it fails another way.
func TestEverySecurityTestingFigureRefusesAReaderOfDependencyWorkAlone(t *testing.T) {
	reader := access.NewPerson(1, "reader", false, map[int64][]access.Role{7: {access.PublicRead, access.PrivateRead}}, 0)
	scope := Scope{ProductID: 7}
	now := time.Now()
	single, _ := figures(t)
	asked := map[string]func() error{
		"CodeFindingCountsOf": func() error {
			_, err := CodeFindingCountsOf(t.Context(), nil, reader, scope)
			return err
		},
		"Trend": func() error {
			_, err := Trend(t.Context(), nil, reader, scope, now, time.Hour, 1)
			return err
		},
		"TimeToJudge": func() error {
			_, err := TimeToJudge(t.Context(), nil, reader, scope, now, now, now)
			return err
		},
		"TimeToFix": func() error {
			_, err := TimeToFix(t.Context(), nil, reader, scope, now, now)
			return err
		},
		"PrecisionOf": func() error {
			_, err := PrecisionOf(t.Context(), nil, reader, scope)
			return err
		},
		"CoverageOf": func() error {
			_, err := CoverageOf(t.Context(), nil, reader, scope, now, now, now)
			return err
		},
		"ByRelease": func() error {
			_, err := ByRelease(t.Context(), nil, reader, scope, 1)
			return err
		},
		"CountsBySeries": func() error {
			_, err := CountsBySeries(t.Context(), nil, reader, 7)
			return err
		},
		"CountsOfComponent": func() error {
			_, err := CountsOfComponent(t.Context(), nil, reader, scope)
			return err
		},
		"OpenOn": func() error {
			_, err := OpenOn(t.Context(), nil, reader, 7, 1, nil)
			return err
		},
		// A match in a product the reader does not count in has no entry, and
		// the rest of the answer stands.
		"OpenOfMatches": func() error {
			got, err := OpenOfMatches(t.Context(), nil, reader, []finding.SourceMatch{
				{ProductID: 7, Folded: "zlib", Builds: []int64{1}},
			})
			if err == nil && len(got) == 0 {
				return access.ErrDenied
			}
			return err
		},
	}
	checkedAre(t, "", single, asked)
	for name, figure := range asked {
		if err := refusedOrReached(figure); !errors.Is(err, access.ErrDenied) {
			t.Errorf("%s answered %v to a reader of dependency work alone; want a refusal", name, err)
		}
	}
}

// refusedOrReached is what a figure answers, or that it reached the database,
// which here is nil.
func refusedOrReached(figure func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("it reached the database")
		}
	}()
	return figure()
}

// Every security testing figure across products refuses a scope naming a
// product where the reader does not read security testing material, in the
// data layer and before the database is asked anything, though they read it
// in another product of the scope: each product is checked, never the first.
func TestEverySecurityTestingFigureAcrossProductsRefusesAProductNotReadAtSecurityTesting(t *testing.T) {
	reader := access.NewPerson(1, "reader", false, map[int64][]access.Role{
		7: {access.SecurityTestingRead},
		8: {access.PublicRead, access.PrivateRead},
	}, 0)
	scope := Scope{Across: []int64{7, 8}}
	now := time.Now()
	_, across := figures(t)
	asked := map[string]func() error{
		"CodeFindingCountsOf": func() error {
			_, err := CodeFindingCountsOf(t.Context(), nil, reader, scope)
			return err
		},
		"Trend": func() error {
			_, err := Trend(t.Context(), nil, reader, scope, now, time.Hour, 1)
			return err
		},
		"TimeToJudge": func() error {
			_, err := TimeToJudge(t.Context(), nil, reader, scope, now, now, now)
			return err
		},
		"CoverageOf": func() error {
			_, err := CoverageOf(t.Context(), nil, reader, scope, now, now, now)
			return err
		},
	}
	checkedAre(t, " across products", across, asked)
	for name, figure := range asked {
		if err := refusedOrReached(figure); !errors.Is(err, access.ErrDenied) {
			t.Errorf("%s across products answered %v with a product read for dependency work alone; want a refusal", name, err)
		}
	}
}

// The code finding queue across products keeps the products where the reader
// reads security testing work, whatever the caller names, and refuses
// anybody but a person before the database is asked anything.
func TestTheQueueAcrossProductsKeepsOnlyProductsReadAtSecurityTesting(t *testing.T) {
	reader := access.NewPerson(1, "reader", false, map[int64][]access.Role{
		7: {access.SecurityTestingRead},
		8: {access.PublicRead, access.PrivateRead},
	}, 0)
	scope, err := Scope{Across: []int64{7, 8}}.readAcross(reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(scope.Across) != 1 || scope.Across[0] != 7 {
		t.Errorf("the queue across products reads %v, want the product read at security testing alone", scope.Across)
	}
	none, err := Scope{Across: []int64{8}}.readAcross(reader)
	if err != nil || none.Across == nil || len(none.Across) != 0 {
		t.Errorf("a reader of security testing work in none of them reads %v and %v, want an empty scope across",
			none.Across, err)
	}
	for name, who := range map[string]access.Subject{
		"a key":   access.NewPipeline(2, "ci", access.Scope{ProductID: 7}),
		"anybody": access.Published([]int64{7}),
	} {
		err := refusedOrReached(func() error {
			_, err := CodeFindingsOf(t.Context(), nil, who, Scope{Across: []int64{7}}, "", 10, 0)
			return err
		})
		if !errors.Is(err, access.ErrDenied) {
			t.Errorf("%s reading the queue across products answered %v, want a refusal", name, err)
		}
	}
}
