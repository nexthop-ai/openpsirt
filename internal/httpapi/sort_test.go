package httpapi_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestTheListSortsOnlyByColumnsItNames(t *testing.T) {
	// A placeholder cannot bind a column name, so a sort column is the one
	// query parameter that has to reach the SQL text — the case
	// parameterized values and identifiers from an allowlist name by
	// example, and the live hole in a codebase that parameterizes
	// everything else. What reaches the statement is the allowlist's own
	// expression; a word that is not one of them is not a sort.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		const at = "/v1/products/mine/findings"
		var ordered struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
			} `json:"items"`
			Total int `json:"total"`
		}

		// The named orders answer, and answer the same population.
		for _, by := range []string{"urgency", "age", "deadline", "places", "epss", "severity"} {
			var page struct {
				Items []struct{} `json:"items"`
				Total int        `json:"total"`
			}
			read(t, r, "triager", at+"?sort="+by, &page)
			if page.Total != 2 || len(page.Items) != 2 {
				t.Errorf("sorting by %s answered %d of %d, want both rows",
					by, len(page.Items), page.Total)
			}
		}

		// And it actually orders: the high sits above the low by severity, and
		// under it the other way.
		read(t, r, "triager", at+"?sort=severity", &ordered)
		if len(ordered.Items) != 2 || ordered.Items[0].Vulnerability != "CVE-2026-9999" {
			t.Errorf("by severity the worst is not first: %+v", ordered.Items)
		}
		read(t, r, "triager", at+"?sort=severity&asc=true", &ordered)
		if len(ordered.Items) != 2 || ordered.Items[0].Vulnerability != "CVE-2026-1000" {
			t.Errorf("asked the other way the worst is still first: %+v", ordered.Items)
		}

		// Anything that is not one of the named orders is not a sort. Refused
		// by the schema where it can be, and harmless where it cannot: what a
		// caller sends never becomes the expression.
		for _, hostile := range []string{
			"id",
			"urgency DESC, (SELECT secret FROM person)",
			"places; DROP TABLE finding",
			"1",
			"f.assigned_to",
		} {
			got := asPerson(t, r, "triager", http.MethodGet,
				at+"?sort="+url.QueryEscape(hostile), "")
			switch got.Code {
			case http.StatusUnprocessableEntity, http.StatusBadRequest:
				// Refused by the enum, which is the ordinary answer.
			case http.StatusOK:
				// Or answered in the list's own order, having reached nothing.
				var page struct {
					Total int `json:"total"`
				}
				read(t, r, "triager", at+"?sort="+url.QueryEscape(hostile), &page)
				if page.Total != 2 {
					t.Errorf("%q changed what the list answers: %d rows", hostile, page.Total)
				}
			default:
				t.Errorf("%q answered %d: %s", hostile, got.Code, got.Body.String())
			}
		}
	})
}

func TestEveryOrderTheDocumentOffersIsOneTheStoreSortsBy(t *testing.T) {
	// The enums are built from the store's own lists, so asking whether those
	// match is asking whether a list equals itself. What is worth checking
	// here is that every order the document offers answers over HTTP at all
	// — whether the store has an expression for each is asked in the package
	// that holds the expressions.
	//
	// Asked of each route with its own vocabulary rather than of one route
	// with everybody's: a bump has an issue count and a build count that a
	// finding has not, so the two lists offer different words and a check
	// that sent one list's words to the other route would be asking the
	// wrong question.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		declared := map[string][]string{}
		for path, item := range r.api.OpenAPI().Paths {
			if item.Get == nil {
				continue
			}
			for _, param := range item.Get.Parameters {
				if param.Name != "sort" || param.Schema == nil {
					continue
				}
				offered := make([]string, 0, len(param.Schema.Enum))
				for _, one := range param.Schema.Enum {
					word, ok := one.(string)
					if !ok {
						t.Fatalf("%s offers a sort order that is not a word: %v", path, one)
					}
					offered = append(offered, word)
				}
				declared[path] = offered
			}
		}
		if len(declared) == 0 {
			t.Fatal("no endpoint declares a sort order, so this proves nothing")
		}

		// The fixture's own build, which is what the placeholders in a path
		// stand for.
		named := strings.NewReplacer(
			"{product}", "mine", "{stream}", "master", "{variant}", "broadcom",
			"{format}", "json")
		asked := 0
		for path, words := range declared {
			for _, word := range words {
				at := named.Replace(path) + "?sort=" + word
				if strings.Contains(at, "{") {
					t.Fatalf("%s names something this test cannot stand in for", path)
				}
				got := asPerson(t, r, "triager", http.MethodGet, at, "")
				if got.Code != http.StatusOK {
					t.Errorf("%s sorted by %q answered %d: %s",
						path, word, got.Code, got.Body.String())
				}
				asked++
			}
		}
		if asked == 0 {
			t.Fatal("no order was asked for, so this checked nothing")
		}
	})
}
