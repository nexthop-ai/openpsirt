// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// The schemas are worked out once per process and every API shares them, but
// the link from an answer to its schema is written into each API's own copy.
// Shared outright, the second API finds the link already present and serves
// its answers without one.
func TestEveryAPIAProcessBuildsLinksItsAnswersToTheirSchema(t *testing.T) {
	var documents []string
	for range 2 {
		h, api := New(nil, nil, core.Deps{})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/sign-in", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("the providers answered %d: %s", rec.Code, rec.Body)
		}
		if !strings.Contains(rec.Body.String(), `"$schema"`) || rec.Header().Get("Link") == "" {
			t.Errorf("an API built after the first answers without its schema link: %s", rec.Body)
		}
		doc, err := json.Marshal(api.OpenAPI())
		if err != nil {
			t.Fatal(err)
		}
		documents = append(documents, string(doc))
	}
	if documents[0] != documents[1] {
		t.Error("two APIs built in one process describe themselves differently")
	}
}

// An alias changes the schema of a type, and the schemas are shared by every
// API in the process, so one API declaring an alias would change the others.
func TestATypeAliasIsRefusedBecauseEveryAPIWouldTakeIt(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a type alias was accepted into the schemas every API shares")
		}
	}()
	newSchemas().RegisterTypeAlias(reflect.TypeFor[string](), reflect.TypeFor[int]())
}
