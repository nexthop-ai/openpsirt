// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
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

// summed reads the queue across products as the security testing reader,
// with the query given, and holds it to the rows wanted, and its waiting and
// ruled counts to those wanted and to the sum of each product's own.
func summed(t *testing.T, r *httpapitest.Reach, want []string, query string, waiting, ruled int) {
	t.Helper()
	var across, mine, theirs acrossListed
	httpapitest.Read(t, r, "security-testing-reader", acrossQueue+query, &across)
	httpapitest.Read(t, r, "security-testing-reader", "/v1/products/mine/code-findings"+query, &mine)
	httpapitest.Read(t, r, "security-testing-reader", "/v1/products/theirs/code-findings"+query, &theirs)
	if !slices.Equal(across.rows(), want) {
		t.Errorf("across products %s lists %v; want %v", query, across.rows(), want)
	}
	if across.Waiting != waiting || across.Ruled != ruled ||
		across.Waiting != mine.Waiting+theirs.Waiting || across.Ruled != mine.Ruled+theirs.Ruled {
		t.Errorf("across products %s waits %d and ruled %d; want %d and %d, and the products sum to %d and %d",
			query, across.Waiting, across.Ruled, waiting, ruled, mine.Waiting+theirs.Waiting, mine.Ruled+theirs.Ruled)
	}
	for state, n := range across.States {
		if n != mine.States[state]+theirs.States[state] {
			t.Errorf("%d %s across products %s; the two products count %d and %d", n, state, query,
				mine.States[state], theirs.States[state])
		}
	}
}

// readsSecurityTestingIn grants one of the cast security testing reading in a
// product.
func readsSecurityTestingIn(t *testing.T, r *httpapitest.Reach, who, product string) {
	t.Helper()
	grantIn(t, r, who, product, access.SecurityTestingRead)
}

// grantIn grants one of the cast a role in a product.
func grantIn(t *testing.T, r *httpapitest.Reach, who, product string, role access.Role) {
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
	if err := r.Rights.GrantRole(ctx, person.ID, named.ID, role); err != nil {
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

		// Each row's state, wait and rule are its own product's. The same
		// rule at the same place is a code finding in each product, so a
		// decision or a rule read in the wrong product moves the other's row,
		// or leaves its own where it was. Each step has a decision or rule in
		// one product the other lacks, in both directions.
		leaks := map[string]string{}
		for _, each := range across.Items {
			if each.Rule == "clang-tidy/leak" {
				leaks[each.Product] = each.Occurrence
			}
		}
		if len(leaks) != 2 {
			t.Fatalf("the queue across products lists the leak in %v; want mine and theirs", leaks)
		}
		grantIn(t, r, "security-testing-triager", "theirs", access.SecurityTestingTriage)
		grantIn(t, r, "security-testing-reviewer", "theirs", access.SecurityTestingRead)
		grantIn(t, r, "security-testing-reviewer", "theirs", access.Approver)
		dismiss := func(product, at string) int64 {
			t.Helper()
			got := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost,
				"/v1/products/"+product+"/branches-and-tags/master/variants/"+at+"/code-findings/"+leaks[product]+"/decision",
				`{"outcome":"dismissed","reason":"false_positive","reasoning":"checked a line above"}`)
			var decided struct {
				DecisionID int64 `json:"decision_id"`
			}
			if got.Code != http.StatusCreated || json.Unmarshal(got.Body.Bytes(), &decided) != nil {
				t.Fatalf("the dismissal in %s answered %d: %s", product, got.Code, got.Body)
			}
			return decided.DecisionID
		}
		rest := []string{"mine cppcheck/bad", "mine semgrep/bad"}

		dismiss("mine", "broadcom")
		summed(t, r, append(rest, "theirs clang-tidy/leak"), "", 1, 0)
		waiting := dismiss("theirs", "mellanox")
		summed(t, r, rest, "", 2, 0)
		if got := httpapitest.AsPerson(t, r, "security-testing-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", waiting), `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving the dismissal in theirs answered %d: %s", got.Code, got.Body)
		}
		summed(t, r, rest, "", 1, 0)
		summed(t, r, []string{"theirs clang-tidy/leak"}, "?state=dismissed", 1, 0)

		rule := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost,
			"/v1/products/mine/suppression-rules",
			`{"rule":"clang-tidy/leak","prefix":"src/a.c","reason":"false_positive","reasoning":"every allocation here is pooled"}`)
		var proposed struct {
			ID int64 `json:"id"`
		}
		if rule.Code != http.StatusCreated || json.Unmarshal(rule.Body.Bytes(), &proposed) != nil {
			t.Fatalf("proposing the rule answered %d: %s", rule.Code, rule.Body)
		}
		if got := httpapitest.AsPerson(t, r, "security-testing-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/products/mine/suppression-rules/%d/approval", proposed.ID), `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving the rule answered %d: %s", got.Code, got.Body)
		}
		summed(t, r, rest, "", 0, 1)
		summed(t, r, []string{"mine clang-tidy/leak", "theirs clang-tidy/leak"}, "?state=dismissed", 0, 1)
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
