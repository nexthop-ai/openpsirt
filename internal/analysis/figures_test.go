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

// figuresIn is every exported function in these Go sources that reads with
// a subject: single is each one taking an access.Subject, across each of
// those also taking a Scope, which a caller may set across products. What
// makes a function one is its parameters, never the check it is held to, so
// a new one that forgets the check is still found.
func figuresIn(sources map[string][]byte) (single, across []string, err error) {
	fset := token.NewFileSet()
	for name, source := range sources {
		file, err := parser.ParseFile(fset, name, source, 0)
		if err != nil {
			return nil, nil, err
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() {
				continue
			}
			subject, scoped := false, false
			for _, field := range fn.Type.Params.List {
				switch typ := field.Type.(type) {
				case *ast.SelectorExpr:
					if pkg, ok := typ.X.(*ast.Ident); ok && pkg.Name == "access" && typ.Sel.Name == "Subject" {
						subject = true
					}
				case *ast.Ident:
					scoped = scoped || typ.Name == "Scope"
				}
			}
			if subject {
				single = append(single, fn.Name.Name)
			}
			if subject && scoped {
				across = append(across, fn.Name.Name)
			}
		}
	}
	slices.Sort(single)
	slices.Sort(across)
	return single, across, nil
}

// figures is every function this package's source reads with a subject.
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
		t.Fatal("no function reads with a subject, so this checked nothing")
	}
	return single, across
}

// checkedAre fails for every function the source holds that is neither asked
// nor exempt, every one asked or exempt that the source no longer holds, and
// every one both asked and exempt.
func checkedAre(t interface {
	Helper()
	Errorf(format string, args ...any)
}, what string, found []string, asked map[string]func() error, exempt map[string]string) {
	t.Helper()
	for _, name := range found {
		_, isAsked := asked[name]
		_, isExempt := exempt[name]
		switch {
		case !isAsked && !isExempt:
			t.Errorf("%s reads with a subject%s and is neither asked here nor exempt", name, what)
		case isAsked && isExempt:
			t.Errorf("%s is both asked here%s and exempt", name, what)
		}
	}
	for name := range asked {
		if !slices.Contains(found, name) {
			t.Errorf("%s is asked here%s and no longer reads with a subject", name, what)
		}
	}
	for name := range exempt {
		if !slices.Contains(found, name) {
			t.Errorf("%s is exempt%s and no longer reads with a subject", name, what)
		}
	}
}

func TestAFigureIsAnExportedFunctionTakingASubject(t *testing.T) {
	single, across, err := figuresIn(map[string][]byte{"a.go": []byte(`package analysis
func Direct(s access.Subject) error { return MayCount(s, 1, "x") }
func Forgotten(s access.Subject, id int64) error { return nil }
func Scoped(scope Scope, s access.Subject) error { return scope.mayCount(s, "x") }
func ScopedForgotten(s access.Subject, scope Scope) error { return nil }
func Plain(scope Scope) error { return nil }
func unexported(s access.Subject) error { return MayCount(s, 1, "x") }
func (r Reader) Method(s access.Subject) error { return nil }
`)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(single, []string{"Direct", "Forgotten", "Scoped", "ScopedForgotten"}) ||
		!slices.Equal(across, []string{"Scoped", "ScopedForgotten"}) {
		t.Errorf("found %v and %v across, want [Direct Forgotten Scoped ScopedForgotten] and [Scoped ScopedForgotten]",
			single, across)
	}
}

// recorder counts what checkedAre reports.
type recorder struct{ reported int }

func (r *recorder) Helper() {}

func (r *recorder) Errorf(string, ...any) { r.reported++ }

func TestAFunctionNeitherAskedNorExemptIsReported(t *testing.T) {
	none := func() error { return nil }
	for _, c := range []struct {
		what   string
		found  []string
		asked  map[string]func() error
		exempt map[string]string
		want   bool
	}{
		{"asked", []string{"A"}, map[string]func() error{"A": none}, nil, false},
		{"exempt", []string{"A"}, nil, map[string]string{"A": "why"}, false},
		{"neither", []string{"A"}, nil, nil, true},
		{"both", []string{"A"}, map[string]func() error{"A": none}, map[string]string{"A": "why"}, true},
		{"asked and gone", nil, map[string]func() error{"A": none}, nil, true},
		{"exempt and gone", nil, nil, map[string]string{"A": "why"}, true},
	} {
		r := &recorder{}
		checkedAre(r, "", c.found, c.asked, c.exempt)
		if got := r.reported > 0; got != c.want {
			t.Errorf("%s: reported=%v, want %v", c.what, got, c.want)
		}
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
	checkedAre(t, "", single, asked, map[string]string{
		"MayCount":              "the check itself",
		"MayRecordAsFlaw":       "the check for recording a flaw, which asks triage",
		"Propose":               "a flaw's proposal, behind recording a flaw",
		"RecordAsFlaw":          "records a flaw, behind recording a flaw",
		"UndoRecordAsFlaw":      "undoes a flaw, behind recording a flaw",
		"IncludeInDisclosure":   "edits a flaw, behind recording a flaw",
		"ExcludeFromDisclosure": "edits a flaw, behind recording a flaw",
		"Answerable":            "one code finding, behind its reach",
		"KinOf":                 "one code finding's kin, behind code finding visibility",
		"Unanswered":            "one code finding's group, behind code finding visibility",
		"EvidenceOf":            "one code finding's evidence, behind its reach",
		"OriginOf":              "one flaw's origin, behind code finding visibility",
		"ProposeRule":           "a suppression rule, behind triage of security testing",
		"ApproveRule":           "a suppression rule, behind approval and reading security testing",
		"RetireRule":            "a suppression rule, behind triage of security testing",
		"SuppressionRules":      "the suppression rules, behind reading security testing",
		"CodeFindingsOf":        "the queue's list, behind code finding visibility",
		"CodeFindingPageOf":     "the queue's list, behind code finding visibility",
		"OpenCodeFindingsOf":    "the queue's list, behind code finding visibility",
	})
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
		// A figure of one product counts no scope across products.
		"TimeToFix": func() error {
			_, err := TimeToFix(t.Context(), nil, reader, scope, now, now)
			return err
		},
		"PrecisionOf": func() error {
			_, err := PrecisionOf(t.Context(), nil, reader, scope)
			return err
		},
		"ByRelease": func() error {
			_, err := ByRelease(t.Context(), nil, reader, scope, 1)
			return err
		},
		"CountsOfComponent": func() error {
			_, err := CountsOfComponent(t.Context(), nil, reader, scope)
			return err
		},
	}
	checkedAre(t, " across products", across, asked, map[string]string{
		"CodeFindingsOf": "the queue keeps the products read at security testing; " +
			"TestTheQueueAcrossProductsKeepsOnlyProductsReadAtSecurityTesting",
		"CodeFindingPageOf":  "the queue, as CodeFindingsOf",
		"OpenCodeFindingsOf": "the queue, as CodeFindingsOf",
	})
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
