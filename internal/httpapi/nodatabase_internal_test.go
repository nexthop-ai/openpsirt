// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// A read reached without a database refuses in words rather than panicking on
// the missing handle. The resolver refuses everybody where there is no
// database, so a caller is attached here directly, as the resolver would.
func TestAReadWithNoDatabaseRefusesInWords(t *testing.T) {
	router := chi.NewMux()
	api := humachi.New(router, huma.DefaultConfig("test", "0"))
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		next(huma.WithContext(ctx, access.With(ctx.Context(),
			access.Everything("a test with no database"))))
	})
	in := Deps{}
	registerDue(api, in)
	registerDueExport(api, in)
	registerComparisonExport(api, in)
	registerTrendExport(api, in)

	for _, path := range []string{
		"/v1/running-out",
		"/v1/running-out.csv",
		"/v1/trend.csv",
		"/v1/products/mine/comparison.csv?from=master&from_variant=a&to=master&to_variant=b",
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusInternalServerError ||
			!strings.Contains(rec.Body.String(), "not fully configured") {
			t.Errorf("%s with no database answered %d: %s", path, rec.Code, rec.Body.String())
		}
	}
}
