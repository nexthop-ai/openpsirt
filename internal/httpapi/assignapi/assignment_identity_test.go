// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// identityStandIn is a value the fixture holds for each path parameter beside
// an {identity}. A parameter missing here leaves its operation unasked, and
// the walk reports it.
var identityStandIn = map[string]string{
	"product": "mine", "branch_or_tag": "master", "variant": "broadcom",
	"issue": "CVE-2026-9999", "occurrence": "1", "role": "public-read",
	"name": "theirs", "team": "1",
}

// identityBodies is the body an operation needs for its name to be resolved
// at all; one sent nothing refuses its shape first, for every name alike.
var identityBodies = map[string]string{
	"POST /v1/people/{identity}/assignments/hand-back": `{"to":""}`,
}

// identityTold are the operations and credentials whose caller is let through
// to name a person, and so is told whether the name is held, keyed
// "METHOD path as credential". Each is reported when its answers stop
// differing.
var identityTold = map[string]string{
	"PUT /v1/products/{product}/issues/{issue}/collaborators/{identity} as private-triage": "a triager " +
		"adding a collaborator names somebody who must hold an account, and is told when nobody does, " +
		"as assigning work is",
	"DELETE /v1/products/{product}/issues/{issue}/collaborators/{identity} as private-triage": "a triager " +
		"removing a collaborator is told whether the name is on the case or held by nobody",
	codeFindingCollaborator("PUT"): "an analyst granting a code finding names somebody who must hold an " +
		"account, and is told when nobody does, as a triager adding a case collaborator is",
	codeFindingCollaborator("DELETE"): "an analyst withdrawing a code finding is told whether the name " +
		"holds it or is held by nobody",
}

// codeFindingCollaborator is the told key for one method on a code finding's
// collaborators, as the analyst working it.
func codeFindingCollaborator(method string) string {
	return method + " /v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}" +
		"/code-findings/{occurrence}/collaborators/{identity} as security-testing-triager"
}

// identityOperation is one operation carrying an {identity}.
type identityOperation struct {
	method, path string
}

// identityOperations is every operation in a document's paths whose path
// carries an {identity}, reads before writes, so a write answered to any
// credential changes nothing a later read is asked.
func identityOperations(paths map[string][]string) []identityOperation {
	var found []identityOperation
	for path, methods := range paths {
		if !strings.Contains(path, "{identity}") {
			continue
		}
		for _, method := range methods {
			found = append(found, identityOperation{method, path})
		}
	}
	slices.SortFunc(found, func(a, b identityOperation) int {
		if (a.method == http.MethodGet) != (b.method == http.MethodGet) {
			if a.method == http.MethodGet {
				return -1
			}
			return 1
		}
		return strings.Compare(a.method+" "+a.path, b.method+" "+b.path)
	})
	return found
}

func TestAnIdentityOperationIsFoundInThePaths(t *testing.T) {
	got := identityOperations(map[string][]string{
		"/v1/people/{identity}/sessions": {http.MethodDelete},
		"/v1/people/{identity}":          {http.MethodGet},
		"/v1/products/{product}":         {http.MethodGet},
	})
	want := []identityOperation{
		{http.MethodGet, "/v1/people/{identity}"},
		{http.MethodDelete, "/v1/people/{identity}/sessions"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
}

func TestNoRouteSaysWhetherAnIdentityHasAnAccount(t *testing.T) {
	// The invariant holds across every operation the API document lists
	// with an {identity} in its path, so one added later is asked without
	// anybody listing it.
	//
	// Two ways to satisfy it. A route open to any credential answers a
	// name nobody holds exactly as it answers a name somebody holds whose
	// work the caller cannot see. A route only an administrator may call
	// refuses everybody else *before* the name is resolved, so the refusal
	// carries nothing — an administrator already knows who has an account.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		// A code finding recorded as a flaw, so its collaborators are reached
		// past the role and the occurrence.
		codeFinding, _ := httpapitest.RecordedCodeFinding(t, r, false)

		paths := map[string][]string{}
		for path, item := range r.API.OpenAPI().Paths {
			for method := range httpapitest.Operations(item) {
				paths[path] = append(paths[path], method)
			}
		}
		operations := identityOperations(paths)
		if len(operations) == 0 {
			t.Fatal("no operation carries an {identity}, so this checked nothing")
		}
		for key := range identityBodies {
			method, path, _ := strings.Cut(key, " ")
			if !slices.Contains(operations, identityOperation{method, path}) {
				t.Errorf("%s has a body here and is no operation carrying an {identity}", key)
			}
		}

		stillTold := map[string]bool{}
		for told := range identityTold {
			stillTold[told] = true
		}

		// "reader" holds an account here; the other name has never been seen.
		const held, unheld = "reader", "nobody-has-this-name"

		// Every credential the deployment recognizes, including one holding
		// nothing on any product.
		for _, op := range operations {
			for _, who := range []string{"reader", "triager", "private-triage", "security-testing-triager"} {
				path := strings.Replace(op.path, "/code-findings/{occurrence}", "/code-findings/"+codeFinding, 1)
				for name, value := range identityStandIn {
					path = strings.ReplaceAll(path, "{"+name+"}", value)
				}
				if strings.Count(path, "{") != 1 {
					t.Errorf("%s %s has a path parameter this has no value for", op.method, op.path)
					continue
				}
				body := identityBodies[op.method+" "+op.path]
				known := httpapitest.AsPerson(t, r, who, op.method,
					strings.Replace(path, "{identity}", held, 1), body)
				unknown := httpapitest.AsPerson(t, r, who, op.method,
					strings.Replace(path, "{identity}", unheld, 1), body)

				told := op.method + " " + op.path + " as " + who
				differ := known.Code != unknown.Code || known.Body.String() != unknown.Body.String()
				if _, ok := identityTold[told]; ok {
					if !differ {
						t.Errorf("%s answers a held and an unheld name alike, and is listed as told", told)
					}
					delete(stillTold, told)
					continue
				}
				if known.Code != unknown.Code {
					t.Errorf("%s %s as %s: a name somebody holds answers %d and a name nobody holds %d",
						op.method, op.path, who, known.Code, unknown.Code)
				}
				if known.Body.String() != unknown.Body.String() {
					t.Errorf("%s %s as %s: the two answers read differently\n  held: %s\nunheld: %s",
						op.method, op.path, who, known.Body.String(), unknown.Body.String())
				}
			}
		}
		for told := range stillTold {
			t.Errorf("%s is listed as told and was not asked", told)
		}
		t.Logf("asked %d operations carrying an {identity}", len(operations))
	})
}
