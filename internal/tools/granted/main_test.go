// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const module = "github.com/nexthop-ai/openpsirt"

const accessPath = module + "/internal/access"

// accessSources is the access package's source, tests aside, by its path from
// the repository root, so the models are found by their tags the way the
// program finds them.
func accessSources(t *testing.T) map[string][]byte {
	t.Helper()
	source := os.DirFS(filepath.Join("..", "..", "access"))
	paths, err := fs.Glob(source, "*.go")
	if err != nil || len(paths) == 0 {
		t.Fatalf("the access package's source was not found: %v", err)
	}
	sources := map[string][]byte{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		text, err := fs.ReadFile(source, path)
		if err != nil {
			t.Fatal(err)
		}
		sources[filepath.Join("internal", "access", path)] = text
	}
	return sources
}

// judged is what the gate reports in the files given, beside the access
// package's own source, keyed by path and name, the way the program judges the
// tree. The access package's own exemptions are left out of the answer.
func judged(t *testing.T, files map[string]string) map[string]string {
	t.Helper()
	sources := accessSources(t)
	for path, src := range files {
		sources[path] = []byte(src)
	}
	found, err := check(module, sources, halves)
	if err != nil {
		t.Fatal(err)
	}
	for key := range found {
		if _, exempt := inside[key]; exempt {
			delete(found, key)
		}
	}
	return found
}

// The two models are found from their struct tags rather than from a list of
// their names.
func TestTheAccessModelsAreFoundByTheirTags(t *testing.T) {
	known, err := learn(module, accessSources(t))
	if err != nil {
		t.Fatal(err)
	}
	types := known.types[accessPath]
	if r := types["Grant"]; !r.perProduct || r.estate {
		t.Errorf("Grant reaches %+v, want the per-product table alone", r)
	}
	if r := types["EstateGrant"]; r.perProduct || !r.estate {
		t.Errorf("EstateGrant reaches %+v, want the estate table alone", r)
	}
}

// A role is held in two tables — one against a product, one across the estate
// — and a query reaching one alone answers no for somebody who holds exactly
// the grant being asked about. Each shape a query reaches a table in is given
// here, reported where it reaches one alone and not where it reaches both.
func TestReachingOneGrantTableAndNotTheOther(t *testing.T) {
	for _, c := range []struct {
		what string
		src  string
		want map[string]string
	}{
		{
			"both by name, which is the rule",
			`package p
			func f() { q.Join("role_grant").Join("role_grant_all") }`,
			map[string]string{},
		},
		{
			"neither, which is a function about something else",
			`package p
			func f() { q.Join("person").Where("id = ?", id) }`,
			map[string]string{},
		},
		{
			"the per-product table alone, by name",
			`package p
			func f() { q.Join("role_grant").Where("product_id = ?", id) }`,
			map[string]string{"f": "role_grant_all"},
		},
		{
			// The estate name contains the per-product one, so a substring
			// test for "role_grant" is satisfied by "role_grant_all".
			"the estate table alone, by name",
			`package p
			func f() { q.Join("role_grant_all").Where("person_id = ?", id) }`,
			map[string]string{"f": "role_grant"},
		},
		{
			// A model binds its table in a struct tag, so a query built from
			// it never spells the name.
			"the per-product model alone, from another package",
			`package p
			import "github.com/nexthop-ai/openpsirt/internal/access"
			func f() { db.NewSelect().Model((*access.Grant)(nil)).Where("role = ?", r).Exists(ctx) }`,
			map[string]string{"f": "role_grant_all"},
		},
		{
			"both models, from another package",
			`package p
			import "github.com/nexthop-ai/openpsirt/internal/access"
			func f() {
				db.NewSelect().Model((*access.Grant)(nil)).Exists(ctx)
				db.NewSelect().Model((*access.EstateGrant)(nil)).Exists(ctx)
			}`,
			map[string]string{},
		},
		{
			"the estate model alone, inside the access package",
			`package access
			type EstateGrant struct {
				bun.BaseModel ` + "`bun:\"table:role_grant_all,alias:rga\"`" + `
			}
			func f() { var grants []EstateGrant; db.NewSelect().Model(&grants).Scan(ctx) }`,
			map[string]string{"f": "role_grant"},
		},
		{
			// The package is imported under another name, and the model is
			// still the model.
			"the per-product model alone, through an import alias",
			`package p
			import acc "github.com/nexthop-ai/openpsirt/internal/access"
			func f() { db.NewSelect().Model((*acc.Grant)(nil)).Exists(ctx) }`,
			map[string]string{"f": "role_grant_all"},
		},
		{
			// A model is recognized by its tag, so one declared under another
			// name in another package is a model all the same.
			"a model of the per-product table under a name of its own",
			`package p
			type grantRow struct {
				bun.BaseModel ` + "`bun:\"table:role_grant,alias:rg\"`" + `
				PersonID int64
			}
			func f() { var rows []grantRow; db.NewSelect().Model(&rows).Scan(ctx) }`,
			map[string]string{"f": "role_grant_all"},
		},
		{
			// A package named access that is not this one declares nothing
			// this gate knows about.
			"a selector on a package that declares no model",
			`package p
			import access "example.com/elsewhere/access"
			func f() { db.NewSelect().Model((*access.Grant)(nil)).Exists(ctx) }`,
			map[string]string{},
		},
		{
			// A file naming both tables in two functions is two queries that
			// each ask one.
			"one of each in two functions",
			`package p
			func f() { q.Join("role_grant") }
			func g() { q.Join("role_grant_all") }`,
			map[string]string{"f": "role_grant_all", "g": "role_grant"},
		},
		{
			// Each name in a block is judged by its own value, so a block
			// holding one query per table is two names that each ask one.
			"a block of one query per table",
			`package p
			const (
				perProduct = "role_grant"
				estate     = "role_grant_all"
			)`,
			map[string]string{"perProduct": "role_grant_all", "estate": "role_grant"},
		},
		{
			"a function reaching one table through a package-level name",
			`package p
			var perProduct = []string{"role_grant"}
			var estate = []string{"role_grant_all"}
			func f() { q.Join(perProduct[0]) }
			func g() { q.Join(perProduct[0]).Join(estate[0]) }`,
			map[string]string{"perProduct": "role_grant_all", "estate": "role_grant", "f": "role_grant_all"},
		},
		{
			"an alias of the per-product model",
			`package p
			import "github.com/nexthop-ai/openpsirt/internal/access"
			type row = access.Grant
			func f() { var rows []row; db.NewSelect().Model(&rows).Scan(ctx) }`,
			map[string]string{"f": "role_grant_all"},
		},
		{
			// bun's way of extending a model with columns of its own.
			"a struct embedding the per-product model",
			`package p
			import "github.com/nexthop-ai/openpsirt/internal/access"
			type row struct {
				access.Grant ` + "`bun:\",extend\"`" + `
				Name string
			}
			func f() { var rows []row; db.NewSelect().Model(&rows).Scan(ctx) }`,
			map[string]string{"f": "role_grant_all"},
		},
		{
			"a type built from one built from the per-product model",
			`package p
			import "github.com/nexthop-ai/openpsirt/internal/access"
			type outer struct{ *inner }
			type inner = access.Grant
			func f() { var rows []outer; db.NewSelect().Model(&rows).Scan(ctx) }`,
			map[string]string{"f": "role_grant_all"},
		},
		{
			// A query built from the struct does not select from the field's
			// table.
			"a struct holding the model in a named field",
			`package p
			import "github.com/nexthop-ai/openpsirt/internal/access"
			type answer struct{ Held access.Grant }
			func f() { var a answer; _ = a }`,
			map[string]string{},
		},
		{
			// A reader listing one table is half of what somebody holds, and a
			// caller deciding from that half alone answers no for somebody
			// holding the role across the estate.
			"a call to the per-product reader alone",
			`package p
			func f() { held, _ := store.Grants(ctx, id); _ = held }`,
			map[string]string{"f": "role_grant_all"},
		},
		{
			"a call to each half",
			`package p
			func f() {
				held, _ := store.Grants(ctx, id)
				estate, _ := store.EstateGrants(ctx, id)
				_, _ = held, estate
			}`,
			map[string]string{},
		},
		{
			"a call to the estate-wide list alone",
			`package p
			func f() { everywhere, _ := store.EveryEstateGrant(ctx); _ = everywhere }`,
			map[string]string{"f": "role_grant"},
		},
		{
			// Recording one row decides nothing about what somebody holds.
			"a call to a writer of one table",
			`package p
			func f() { _ = store.GrantRole(ctx, person, product, role) }`,
			map[string]string{},
		},
		{
			// Two methods of one name are two functions, so neither is
			// answered for by the other.
			"two methods of one name on different types",
			`package p
			func (s *Store) Withdraw() { q.Join("role_grant").Join("role_grant_all") }
			func (t *Team) Withdraw() { q.Join("role_grant") }`,
			map[string]string{"Team.Withdraw": "role_grant_all"},
		},
		{
			// A field of the same name on something else is not the model.
			"a field that shares the model's name",
			`package p
			func f() { _ = request.Grant }`,
			map[string]string{},
		},
	} {
		got := map[string]string{}
		for key, table := range judged(t, map[string]string{"internal/p/x.go": c.src}) {
			got[strings.TrimPrefix(key, "internal/p/x.go:")] = table
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: reported %v, want %v", c.what, got, c.want)
		}
	}
}

// What another package declares is learned from that package and followed into
// the one importing it: a type built from a model there, and a constant naming
// a table there. A twin asking both tables is not reported, and a file where a
// table may be named alone is not judged.
func TestWhatAnotherPackageDeclaresIsFollowed(t *testing.T) {
	got := judged(t, map[string]string{
		"internal/x/row.go": `package x
			import "github.com/nexthop-ai/openpsirt/internal/access"
			type Row struct {
				access.Grant ` + "`bun:\",extend\"`" + `
				Name string
			}`,
		"internal/tables/tables.go": `package tables
			const PerProduct = "role_grant"`,
		"internal/y/q.go": `package y
			import (
				"github.com/nexthop-ai/openpsirt/internal/access"
				"github.com/nexthop-ai/openpsirt/internal/tables"
				"github.com/nexthop-ai/openpsirt/internal/x"
			)
			func alone() { var rows []x.Row; db.NewSelect().Model(&rows).Scan(ctx) }
			func both() {
				var rows []x.Row
				db.NewSelect().Model(&rows).Scan(ctx)
				db.NewSelect().Model((*access.EstateGrant)(nil)).Scan(ctx)
			}
			func named() { q.Join("? AS rg", bun.Ident(tables.PerProduct)) }
			func namedBoth() { q.Join("? AS rg", bun.Ident(tables.PerProduct)).Join("role_grant_all") }`,
		// A chain across packages, read in no particular order, is followed
		// to its end.
		"internal/c1/c.go": `package c1
			import "github.com/nexthop-ai/openpsirt/internal/x"
			type Row struct{ x.Row }`,
		"internal/c2/c.go": `package c2
			import "github.com/nexthop-ai/openpsirt/internal/c1"
			type Row = c1.Row`,
		"internal/c3/c.go": `package c3
			import "github.com/nexthop-ai/openpsirt/internal/c2"
			type Row struct{ *c2.Row }`,
		"internal/c4/c.go": `package c4
			import "github.com/nexthop-ai/openpsirt/internal/c3"
			type Row = c3.Row`,
		"internal/c5/c.go": `package c5
			import "github.com/nexthop-ai/openpsirt/internal/c4"
			type Row struct{ c4.Row }
			func far() { var rows []Row; db.NewSelect().Model(&rows).Scan(ctx) }`,
		"internal/y/q_test.go": `package y
			func TestRow() { q.Join("role_grant") }`,
		"internal/dbtest/clean.go": `package dbtest
			func f() { q.Join("role_grant") }`,
	})
	want := map[string]string{
		"internal/c5/c.go:far":                 "role_grant_all",
		"internal/tables/tables.go:PerProduct": "role_grant_all",
		"internal/y/q.go:alone":                "role_grant_all",
		"internal/y/q.go:named":                "role_grant_all",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reported %v, want %v", got, want)
	}
}

// A reader passes what it reaches to its callers, and a caller that is itself
// such a reader passes on what it reached through its calls. Reading both
// halves through the exempt readers is reaching both tables.
func TestAReaderCallingBothHalvesReachesBoth(t *testing.T) {
	got := judged(t, map[string]string{
		"internal/p/x.go": `package p
			func everybody() { people, held, _ := store.People(ctx); _, _ = people, held }
			func reaching() {
				people, held, _ := store.People(ctx)
				everywhere, _ := store.EveryEstateGrant(ctx)
				_, _, _ = people, held, everywhere
			}`,
	})
	want := map[string]string{"internal/p/x.go:everybody": "role_grant_all"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reported %v, want %v", got, want)
	}
}

// A half is an exemption, since only a reader the gate otherwise reports is
// one whose reach callers take on.
func TestEveryHalfIsAnExemption(t *testing.T) {
	if len(halves) == 0 {
		t.Fatal("no reader is a half, so no call is followed")
	}
	for _, key := range halves {
		if _, exempt := inside[key]; !exempt {
			t.Errorf("%s is a half and not an exemption", key)
		}
	}
}

// An exemption is used by a match, and one nothing matches is reported, since
// a function of that name added later would be waved through unread.
func TestAnExemptionIsHonoredAndOneNothingMatchesIsReported(t *testing.T) {
	exempt := map[string]string{"a.go:f": "why", "a.go:gone": "why"}
	got := verdict(map[string]string{"a.go:f": "role_grant_all", "a.go:g": "role_grant"}, exempt)
	want := []string{
		"a.go:g: reaches one grant table and not role_grant",
		"a.go:gone: named as reaching one table alone, and nothing there does",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reported %q, want %q", got, want)
	}
}

// Every exemption says why, because an exemption is where the gate stops
// looking.
func TestEveryExemptionSaysWhy(t *testing.T) {
	if len(inside) == 0 {
		t.Fatal("nothing is exempt, so this checks nothing")
	}
	for key, why := range inside {
		if why == "" {
			t.Errorf("%s is exempt and says nothing about why", key)
		}
	}
}

// Two readers calling each other each take on what the other reaches, and the
// repetition settles on one answer.
func TestReadersCallingEachOtherSettle(t *testing.T) {
	sources := accessSources(t)
	sources["internal/q/q.go"] = []byte(`package q
		func a() { db.NewSelect().Join("role_grant"); s.b() }
		func b() { db.NewSelect().Join("role_grant_all"); s.a() }`)
	done := make(chan map[string]string, 1)
	go func() {
		found, err := check(module, sources, []string{"internal/q/q.go:a", "internal/q/q.go:b"})
		if err != nil {
			t.Error(err)
		}
		done <- found
	}()
	select {
	case found := <-done:
		for _, key := range []string{"internal/q/q.go:a", "internal/q/q.go:b"} {
			if table, reported := found[key]; reported {
				t.Errorf("%s reported as reaching %s alone, though it calls the other half", key, table)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the readers' reach never settled")
	}
}
