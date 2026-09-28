// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"testing"
)

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
			func f() { db.NewSelect().Model((*access.Grant)(nil)).Where("role = ?", r).Exists(ctx) }`,
			map[string]string{"f": "role_grant_all"},
		},
		{
			"both models, from another package",
			`package p
			func f() {
				db.NewSelect().Model((*access.Grant)(nil)).Exists(ctx)
				db.NewSelect().Model((*access.EstateGrant)(nil)).Exists(ctx)
			}`,
			map[string]string{},
		},
		{
			"the estate model alone, inside the access package",
			`package access
			func f() { var grants []EstateGrant; db.NewSelect().Model(&grants).Scan(ctx) }`,
			map[string]string{"f": "role_grant"},
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
			// A field of the same name on something else is not the model.
			"a field that shares the model's name",
			`package p
			func f() { _ = request.Grant }`,
			map[string]string{},
		},
	} {
		got, err := oneAlone("x.go", []byte(c.src), nil)
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: reported %v, want %v", c.what, got, c.want)
		}
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
