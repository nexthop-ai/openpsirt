// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/parser"
	"go/token"
	"testing"
)

func TestAStoreMethodQueryingWithNoSubjectIsReported(t *testing.T) {
	source := []byte(`package finding

func (s *Store) Narrowed(ctx context.Context, subject access.Subject, id int64) error {
	return s.db.NewSelect().Where("id = ?", id).Scan(ctx)
}

func (s *Store) Unnarrowed(ctx context.Context, id int64) error {
	return s.db.NewSelect().Where("id = ?", id).Scan(ctx)
}

func (s *Store) ByPointer(ctx context.Context, subject *access.Subject, id int64) error {
	return s.db.NewSelect().Where("id = ?", id).Scan(ctx)
}

func (s *Store) AsTheLast(ctx context.Context, id int64, subjects ...access.Subject) error {
	return s.db.NewSelect().Where("id = ?", id).Scan(ctx)
}

func (v *Vulnerabilities) Raw(ctx context.Context, id int64) error {
	_, err := v.db.NewRaw("SELECT 1").Exec(ctx)
	return err
}

func (s *Store) Arithmetic(a, b int) int { return a + b }

func (s *Store) unexported(ctx context.Context) error {
	return s.db.NewSelect().Scan(ctx)
}

func (o *Other) Elsewhere(ctx context.Context) error {
	return o.db.NewSelect().Scan(ctx)
}

func (w *Watcher) Pass(ctx context.Context) error {
	return w.store.Unnarrowed(ctx, 1)
}

func (d *Delegating) Read(ctx context.Context, db bun.IDB, id int64) error {
	return read(ctx, db, id)
}

func Function(ctx context.Context, db bun.IDB, id int64) error {
	return read(ctx, db, id)
}

func FunctionNarrowed(ctx context.Context, db bun.IDB, subject access.Subject, id int64) error {
	return read(ctx, db, id)
}

func FunctionPure(a int) int { return twice(a) }

func (s *Store) Through(ctx context.Context, id int64) error {
	return s.helper(ctx, id)
}

func (s *Store) helper(ctx context.Context, id int64) error {
	return read(ctx, s.db, id)
}

func read(ctx context.Context, db bun.IDB, id int64) error {
	return db.NewSelect().Where("id = ?", id).Scan(ctx)
}

func (s *Store) Pure(a int) int { return twice(a) }

func twice(a int) int { return a * 2 }
`)
	found, examined, err := inSource("finding", "x.go", source)
	if err != nil {
		t.Fatal(err)
	}
	if examined != 12 {
		t.Errorf("%d store methods and functions were examined, want the ten exported store methods "+
			"and the two exported functions that query", examined)
	}
	reported := map[string]bool{}
	for _, one := range found {
		reported[one.name] = true
	}
	for name, want := range map[string]bool{
		"finding.Store.Narrowed":      false,
		"finding.Store.Unnarrowed":    true,
		"finding.Store.ByPointer":     false,
		"finding.Store.AsTheLast":     false,
		"finding.Vulnerabilities.Raw": true,
		"finding.Store.Arithmetic":    false,
		"finding.Store.unexported":    false,
		"finding.Other.Elsewhere":     true,
		"finding.Watcher.Pass":        false,
		"finding.Delegating.Read":     true,
		"finding.Function":            true,
		"finding.FunctionNarrowed":    false,
		"finding.FunctionPure":        false,
		"finding.read":                false,
		"finding.Store.Through":       true,
		"finding.Store.Pure":          false,
	} {
		if reported[name] != want {
			t.Errorf("%s reported = %v, want %v", name, reported[name], want)
		}
	}
}

func TestACallIntoAnotherPackageIsNotTakenForOneOfThisPackages(t *testing.T) {
	// strings.Replace is not this package's Replace, whatever that does, and
	// a local named as an import could be is still this package's. An exported
	// method of an unexported or generic type is reached from other packages
	// through a constructor or an interface, so it is read.
	source := []byte(`package sourcelink

import (
	"strings"

	text "example.com/typed/v2"
	"example.com/x-store"
)

func (s *Store) Replace(ctx context.Context, id int64) error {
	return s.db.NewUpdate().Where("id = ?", id).Scan(ctx)
}

func Normalize(remote string) string { return strings.Replace(remote, ":", "/", 1) }

func Fold(typed string) string { return text.Replace(typed) }

func Local(ctx context.Context, s *Store) error { return s.Replace(ctx, 1) }

func Shadowed(ctx context.Context, store *Store) error { return store.Replace(ctx, 1) }

func (c *chunks) Read(ctx context.Context) error {
	return c.db.NewSelect().Scan(ctx)
}

func (c *Cache[K, V]) Get(ctx context.Context) error {
	return c.db.NewSelect().Scan(ctx)
}
`)
	found, _, err := inSource("sourcelink", "r.go", source)
	if err != nil {
		t.Fatal(err)
	}
	reported := map[string]bool{}
	for _, one := range found {
		reported[one.name] = true
	}
	for name, want := range map[string]bool{
		"sourcelink.Store.Replace": true,
		"sourcelink.Local":         true,
		"sourcelink.Shadowed":      true,
		"sourcelink.Normalize":     false,
		"sourcelink.Fold":          false,
		"sourcelink.chunks.Read":   true,
		"sourcelink.Cache.Get":     true,
	} {
		if reported[name] != want {
			t.Errorf("%s reported = %v, want %v", name, reported[name], want)
		}
	}
}

func TestAnImportIsKnownByTheNamesItsPathSuggests(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "i.go", `package x

import (
	"strings"
	"gopkg.in/yaml.v3"
	"github.com/jackc/pgx/v5"
	"github.com/example/go-difflib"
	named "example.com/other"
)
`, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	names := importNames(file)
	for _, want := range []string{"strings", "yaml", "pgx", "difflib", "named"} {
		if !names[want] {
			t.Errorf("an import is not known as %s: %v", want, names)
		}
	}
}

func TestASubjectIsNamedAsTheAccessPackageSpellsIt(t *testing.T) {
	// Inside access the type is Subject; anywhere else a type of that name
	// is some other package's own.
	source := func(pkg string) []byte {
		return []byte("package " + pkg + `

func (s *Store) Read(ctx context.Context, subject Subject, id int64) error {
	return s.db.NewSelect().Where("id = ?", id).Scan(ctx)
}
`)
	}
	if found, _, err := inSource("access", "a.go", source("access")); err != nil || len(found) != 0 {
		t.Errorf("a method of access taking a Subject was reported: %v %v", found, err)
	}
	if found, _, err := inSource("elsewhere", "e.go", source("elsewhere")); err != nil || len(found) != 1 {
		t.Errorf("a method taking another package's Subject was reported %v %v, want it reported", found, err)
	}
}

func TestEveryPackageOfTheTreeIsReadButProgramsAndHarnesses(t *testing.T) {
	// The packages are the tree's, never a list: a store added anywhere is
	// read. A program and a test harness, a package importing testing that no
	// program under cmd/ links, are reached by no request, and a package is
	// named by its directory under internal/. A package importing testing that
	// a program links, directly or through another package, is read.
	store := func(pkg string) []byte {
		return []byte("package " + pkg + `

func (s *Store) Unnarrowed(ctx context.Context, id int64) error {
	return s.db.NewSelect().Where("id = ?", id).Scan(ctx)
}
`)
	}
	found, examined, err := inTree(map[string]map[string][]byte{
		"cmd/openpsirt": {"cmd/openpsirt/main.go": []byte(`package main

import (
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/served"
)
`)},
		"internal/series": {"internal/series/s.go": []byte(`package series

import "github.com/nexthop-ai/openpsirt/internal/latest"

func (s *Store) Unnarrowed(ctx context.Context, id int64) error {
	return s.db.NewSelect().Where("id = ?", id).Scan(ctx)
}
`)},
		"internal/latest": {"internal/latest/l.go": []byte(`package latest

import "testing"

func Helped(t *testing.T) {}

func (s *Store) Unnarrowed(ctx context.Context, id int64) error {
	return s.db.NewSelect().Where("id = ?", id).Scan(ctx)
}
`)},
		"internal/httpapi/core": {"internal/httpapi/core/c.go": store("core")},
		"internal/tools/gate":   {"internal/tools/gate/main.go": store("main")},
		"internal/dbtest/fixture": {"internal/dbtest/fixture/f.go": []byte(`package fixture

import "testing"

func Seeded(t *testing.T) {}

func (s *Store) Unnarrowed(ctx context.Context, id int64) error {
	return s.db.NewSelect().Where("id = ?", id).Scan(ctx)
}
`)},
		"internal/attest": {"internal/attest/a.go": store("attest")},
		"internal/served": {
			"internal/served/a.go": store("served"),
			"internal/served/b.go": []byte(`package served

import "testing"

func Benchmarked(b *testing.B) {}
`),
		},
		"internal/kerneltest": {"internal/kerneltest/k.go": store("kerneltest")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if examined != 6 {
		t.Errorf("%d store methods were examined, want the six outside programs and harnesses", examined)
	}
	reported := map[string]bool{}
	for _, one := range found {
		reported[one.name] = true
	}
	for name, want := range map[string]bool{
		"series.Store.Unnarrowed":         true,
		"httpapi/core.Store.Unnarrowed":   true,
		"tools/gate.Store.Unnarrowed":     false,
		"dbtest/fixture.Store.Unnarrowed": false,
		"attest.Store.Unnarrowed":         true,
		"served.Store.Unnarrowed":         true,
		"kerneltest.Store.Unnarrowed":     true,
		"latest.Store.Unnarrowed":         true,
	} {
		if reported[name] != want {
			t.Errorf("%s reported = %v, want %v (reported %v)", name, reported[name], want, reported)
		}
	}
}

func TestAnExemptionNamesItsReason(t *testing.T) {
	if _, err := parseExempt([]byte("finding.Store.Apply\n")); err == nil {
		t.Error("an exemption with no reason was accepted")
	}
	exempt, err := parseExempt([]byte("# a comment\n\nfinding.Store.Apply A background pass.\n"))
	if err != nil {
		t.Fatal(err)
	}
	if exempt["finding.Store.Apply"] != "A background pass." {
		t.Errorf("the exemption reads %v", exempt)
	}
}

func TestATreeWithNoProgramIsRefused(t *testing.T) {
	// With no program, every package importing testing would read as a
	// harness, so the tree is refused rather than read.
	if _, _, err := inTree(map[string]map[string][]byte{
		"internal/series": {"internal/series/s.go": []byte("package series\n\nimport \"testing\"\n\nfunc Helped(t *testing.T) {}\n")},
	}); err == nil {
		t.Error("a tree with no program under cmd/ was read")
	}
}
