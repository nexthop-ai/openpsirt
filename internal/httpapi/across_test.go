// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/csv"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

const acrossQueue = "/v1/code-findings"

// acrossListed is the code finding queue across products as these tests read
// it.
type acrossListed struct {
	Items []struct {
		Product    string `json:"product"`
		Occurrence string `json:"occurrence"`
		Rule       string `json:"rule"`
	} `json:"items"`
	Total   int            `json:"total"`
	States  map[string]int `json:"states"`
	Waiting int            `json:"waiting"`
	Ruled   int            `json:"ruled"`
	Ended   int            `json:"past_end_of_life"`
}

// rows is each listed row as product and rule, sorted.
func (l acrossListed) rows() []string {
	out := make([]string, 0, len(l.Items))
	for _, each := range l.Items {
		out = append(out, each.Product+" "+each.Rule)
	}
	sort.Strings(out)
	return out
}

// readsSecurityTestingIn grants one of the cast security testing reading in a
// product.
func readsSecurityTestingIn(t *testing.T, r *httpapitest.Reach, who, product string) {
	t.Helper()
	ctx := t.Context()
	person, err := r.Rights.ByIdentity(ctx, who)
	if err != nil {
		t.Fatal(err)
	}
	named, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, product)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Rights.GrantRole(ctx, person.ID, named.ID, access.SecurityTestingRead); err != nil {
		t.Fatal(err)
	}
}

// The queue across products lists each product's code findings the reader
// reads security testing work in, one row per code finding in a product, and
// counts as one product's queue counts: a rule at the same place in two
// products is two code findings.
func TestTheQueueAcrossProductsListsEveryProductReadAsItsOwnQueueDoes(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.CodeFindingsInBothProducts(t, r)
		readsSecurityTestingIn(t, r, "security-testing-reader", "theirs")
		both := []string{"mine clang-tidy/leak", "mine cppcheck/bad", "mine semgrep/bad", "theirs clang-tidy/leak"}
		for _, c := range []struct {
			who, query string
			want       []string
		}{
			{"security-testing-reader", "", both},
			{"security-testing-reader", "?assigned=nobody", both},
			{"security-testing-reader", "?method=sast", both},
			{"security-testing-reader", "?series=CLANG-TIDY/default", []string{"mine clang-tidy/leak", "theirs clang-tidy/leak"}},
			{"security-testing-reader", "?component=mine-src", []string{"mine clang-tidy/leak"}},
			{"security-testing-reader", "?component=theirs-image", []string{"theirs clang-tidy/leak"}},
			{"security-testing-reader", "?state=fixed", nil},
			// Reading security testing work in one product, that product alone.
			{"security-testing-triager", "", both[:3]},
			// Reading none, nothing: a product read at another visibility
			// contributes no code finding.
			{"reader", "", nil},
			{"outsider", "", nil},
			{"approver", "", nil},
		} {
			var got acrossListed
			httpapitest.Read(t, r, c.who, acrossQueue+c.query, &got)
			if !slices.Equal(got.rows(), c.want) || got.Total != len(c.want) {
				t.Errorf("%s reads %s as %v, %d in all; want %v", c.who, c.query, got.rows(), got.Total, c.want)
			}
			if c.query == "" && got.States["open"] != len(c.want) {
				t.Errorf("%s counts %d open across products; want %d", c.who, got.States["open"], len(c.want))
			}
		}

		// Every count is the sum of each product's own queue's.
		var across, mine, theirs acrossListed
		httpapitest.Read(t, r, "security-testing-reader", acrossQueue, &across)
		httpapitest.Read(t, r, "security-testing-reader", "/v1/products/mine/code-findings", &mine)
		httpapitest.Read(t, r, "security-testing-reader", "/v1/products/theirs/code-findings", &theirs)
		for state, n := range across.States {
			if n != mine.States[state]+theirs.States[state] {
				t.Errorf("%d %s across products; the two products count %d and %d", n, state,
					mine.States[state], theirs.States[state])
			}
		}
		if across.Waiting != mine.Waiting+theirs.Waiting || across.Ruled != mine.Ruled+theirs.Ruled ||
			across.Ended != mine.Ended+theirs.Ended {
			t.Errorf("across products waits %d, ruled %d, ended %d; the products sum to %d, %d, %d",
				across.Waiting, across.Ruled, across.Ended, mine.Waiting+theirs.Waiting,
				mine.Ruled+theirs.Ruled, mine.Ended+theirs.Ended)
		}

		// Paged as one list: two pages of two hold all four, none twice.
		var first, second acrossListed
		httpapitest.Read(t, r, "security-testing-reader", acrossQueue+"?limit=2", &first)
		httpapitest.Read(t, r, "security-testing-reader", acrossQueue+"?limit=2&offset=2", &second)
		paged := append(first.rows(), second.rows()...)
		sort.Strings(paged)
		if !slices.Equal(paged, both) {
			t.Errorf("two pages list %v; want %v", paged, both)
		}

		// The file holds the list's rows, each naming its product last.
		file := httpapitest.AsPerson(t, r, "security-testing-reader", http.MethodGet, acrossQueue+".csv", "")
		records, err := csv.NewReader(strings.NewReader(file.Body.String())).ReadAll()
		if file.Code != http.StatusOK || err != nil {
			t.Fatalf("the file across products answered %d: %v\n%s", file.Code, err, file.Body.String())
		}
		var filed []string
		for _, record := range records {
			if len(record) > 1 && record[0] != "rule" && !strings.HasPrefix(record[0], "#") {
				filed = append(filed, record[len(record)-1]+" "+record[0])
			}
		}
		sort.Strings(filed)
		if !slices.Equal(filed, both) {
			t.Errorf("the file across products holds %v; want %v", filed, both)
		}
	})
}

// Who may ask the queue across products, and that a subtree, which is one
// build's, is refused there as the findings list across products refuses it.
func TestWhoMayListCodeFindingsAcrossProducts(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.CodeFindingsInBothProducts(t, r)
		for _, c := range []struct {
			who, path string
			want      int
		}{
			{"", acrossQueue, http.StatusUnauthorized},
			{"", acrossQueue + ".csv", http.StatusUnauthorized},
			{"security-testing-reader", acrossQueue, http.StatusOK},
			{"security-testing-reader", acrossQueue + ".json", http.StatusOK},
			{"reader", acrossQueue, http.StatusOK},
			{"approver", acrossQueue, http.StatusOK},
			{"auditor", acrossQueue, http.StatusOK},
			{"security-testing-reader", acrossQueue + "?beneath=libmine1", http.StatusUnprocessableEntity},
			{"security-testing-reader", acrossQueue + ".csv?beneath=libmine1", http.StatusUnprocessableEntity},
			{"security-testing-reader", acrossQueue + "?state=nosuch", http.StatusUnprocessableEntity},
		} {
			if got := httpapitest.AsPerson(t, r, c.who, http.MethodGet, c.path, ""); got.Code != c.want {
				t.Errorf("%q GET %s = %d, want %d: %s", c.who, c.path, got.Code, c.want, got.Body.String())
			}
		}
		if got := r.WithKey(t, r.Key, http.MethodGet, acrossQueue); got.Code != http.StatusForbidden {
			t.Errorf("a pipeline key read the code findings across products: %d %s", got.Code, got.Text)
		}
	})
}
