// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const accessPath = "github.com/nexthop-ai/openpsirt/internal/access"

// accessModels is the types the access package declares, read from its source
// the way the walk reads them, so the models are found by their tags.
func accessModels(t *testing.T) models {
	t.Helper()
	source := os.DirFS(filepath.Join("..", "..", "access"))
	paths, err := fs.Glob(source, "*.go")
	if err != nil || len(paths) == 0 {
		t.Fatalf("the access package's source was not found: %v", err)
	}
	types := map[string]reach{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		text, err := fs.ReadFile(source, path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, text, 0)
		if err != nil {
			t.Fatal(err)
		}
		types = merged(types, typesIn(file, scope{}))
	}
	return models{accessPath: types}
}

// The two models are found from their struct tags rather than from a list of
// their names.
func TestTheAccessModelsAreFoundByTheirTags(t *testing.T) {
	types := accessModels(t)[accessPath]
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
			// A field of the same name on something else is not the model.
			"a field that shares the model's name",
			`package p
			func f() { _ = request.Grant }`,
			map[string]string{},
		},
	} {
		got, err := oneAlone("x.go", []byte(c.src), nil, accessModels(t), nil)
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: reported %v, want %v", c.what, got, c.want)
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
