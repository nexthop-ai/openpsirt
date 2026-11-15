// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// A read narrowed by a product named in its query answers a product the
// asker holds nothing on exactly as it answers a product nobody declared,
// with or without a branch or tag and a variant beside it, declared or not.
// Answered differently, the query is a directory of products, and of their
// branches and variants, one name at a time. The reads are taken from the
// registered operations rather than a list, so a read added later is held
// to the rule the day it is added.
//
// "reader" holds a role on mine alone. "theirs" is declared with a branch
// master and a variant mellanox, so a hidden scope is asked both with names
// it declares and with names it does not.
func TestAProductNamedInAQueryAnswersAlikeHiddenOrUndeclared(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		swept, narrowed := 0, 0
		for path, item := range r.API.OpenAPI().Paths {
			if item.Get == nil {
				continue
			}
			takes := map[string]bool{}
			var required []string
			for _, p := range item.Get.Parameters {
				if p.In != "query" {
					continue
				}
				takes[p.Name] = true
				if p.Required && p.Name != "product" {
					required = append(required, p.Name+"=libnl")
				}
			}
			// A path naming the product scopes by it, and the query's
			// product is not what is asked.
			if !takes["product"] || strings.Contains(path, "{product}") {
				continue
			}
			at := fill(path)
			if strings.Contains(at, "{") {
				t.Errorf("%s has a path parameter this sweep has no value for, so it is not being checked", path)
				continue
			}
			ask := func(query string) *httptestAnswer {
				if len(required) > 0 {
					query += "&" + strings.Join(required, "&")
				}
				got := httpapitest.AsPerson(t, r, "reader", http.MethodGet, at+"?"+query, "")
				return &httptestAnswer{code: got.Code, body: got.Body.String()}
			}
			undeclared := ask("product=nosuch")
			hidden := []string{"product=theirs"}
			if takes["branch_or_tag"] {
				narrowed++
				hidden = append(hidden, "product=theirs&branch_or_tag=master",
					"product=theirs&branch_or_tag=nosuch")
			}
			if takes["variant"] {
				hidden = append(hidden, "product=theirs&variant=mellanox", "product=theirs&variant=nosuch",
					"product=theirs&branch_or_tag=master&variant=nosuch")
			}
			swept++
			for _, query := range hidden {
				if got := ask(query); *got != *undeclared {
					t.Errorf("GET %s?%s answered %d %s, and a product nobody declared %d %s",
						at, query, got.code, got.body, undeclared.code, undeclared.body)
				}
			}
		}
		// A sweep that walks nothing passes, so each class is counted.
		if swept < 20 || narrowed < 10 {
			t.Errorf("only %d reads take a product and %d of them a branch or tag: "+
				"this sweep is not walking them", swept, narrowed)
		}
		t.Logf("swept %d reads taking a product, %d of them a branch or tag", swept, narrowed)
	})
}

// httptestAnswer is the status and body of one answer, compared whole.
type httptestAnswer struct {
	code int
	body string
}
