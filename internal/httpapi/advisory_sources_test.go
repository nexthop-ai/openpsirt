// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// named configures a supplier for a product, or asks for one to be withdrawn.
func (r *reach) named(t *testing.T, who, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if who != "" {
		req.Header.Set(testHeader, who)
	}
	fromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return rec
}

// The address of a publisher's description of what they publish.
const publishedAt = `{"name":"ExampleDistribution",` +
	`"url":"https://distribution.example.test/.well-known/csaf/provider-metadata.json"}`

func TestOnlyAnAdministratorNamesASupplierToReadAdvisoriesFrom(t *testing.T) {
	// Naming one admits a third party's judgment into this deployment's
	// evidence and points it at an address of their choosing. It is a
	// deployment decision rather than a product one, so holding triage on the
	// product is not enough.
	//
	// Three things refuse here and any one of them alone leaves this green: the
	// scope on the operation's own declaration, which runs before any handler;
	// the handler; and the store, which refuses a subject that administers
	// nothing. That is what the declaration is for, and it is why this is
	// verified by taking all three out rather than one.
	twoReach(t, func(t *testing.T, r *reach) {
		const sources = "/v1/products/mine/advisory-sources"

		for _, c := range []struct {
			who    string
			method string
			path   string
			body   string
			want   int
		}{
			// Nobody at all, refused before anything about the request is
			// examined.
			{"", http.MethodGet, sources, "", http.StatusUnauthorized},
			{"", http.MethodPost, sources, publishedAt, http.StatusUnauthorized},

			// Every role on the product, none of which administers the
			// deployment.
			{"reader", http.MethodGet, sources, "", http.StatusForbidden},
			{"triager", http.MethodPost, sources, publishedAt, http.StatusForbidden},
			{"private-triage", http.MethodPost, sources, publishedAt, http.StatusForbidden},
			{"approver", http.MethodPost, sources, publishedAt, http.StatusForbidden},
			{"triager", http.MethodDelete, sources + "/ExampleDistribution", "",
				http.StatusForbidden},

			// Reading the deployment's own records is not changing them.
			{"auditor", http.MethodPost, sources, publishedAt, http.StatusForbidden},

			// And the administrator, who may.
			{"admin", http.MethodPost, sources, publishedAt, http.StatusCreated},
			{"admin", http.MethodGet, sources, "", http.StatusOK},
			{"admin", http.MethodDelete, sources + "/ExampleDistribution", "",
				http.StatusNoContent},
		} {
			if got := r.named(t, c.who, c.method, c.path, c.body).Code; got != c.want {
				t.Errorf("%s %s as %q answered %d, want %d",
					c.method, c.path, c.who, got, c.want)
			}
		}
	})
}

func TestASupplierIsNamedListedAndWithdrawn(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		const sources = "/v1/products/mine/advisory-sources"

		if got := r.named(t, "admin", http.MethodPost, sources, publishedAt).Code; got != http.StatusCreated {
			t.Fatalf("naming a supplier answered %d", got)
		}
		listed := r.suppliers(t, sources)
		if len(listed) != 1 || listed[0].Name != "ExampleDistribution" {
			t.Fatalf("the product reads as configured with %+v", listed)
		}
		// Never tried, so there is no moment of either kind and no reason.
		if listed[0].Tried != nil || listed[0].Read != nil || listed[0].Because != "" {
			t.Errorf("a supplier nothing has read reads as %+v", listed[0])
		}

		if got := r.named(t, "admin", http.MethodDelete,
			sources+"/ExampleDistribution", "").Code; got != http.StatusNoContent {
			t.Fatalf("withdrawing a supplier answered %d", got)
		}
		if listed := r.suppliers(t, sources); len(listed) != 0 {
			t.Errorf("a withdrawn supplier is still listed: %+v", listed)
		}
		// And withdrawing it twice says so rather than answering as though it
		// had worked: a supplier believed withdrawn that was not goes on being
		// reached.
		if got := r.named(t, "admin", http.MethodDelete,
			sources+"/ExampleDistribution", "").Code; got != http.StatusNotFound {
			t.Errorf("withdrawing a supplier that is not configured answered %d", got)
		}
	})
}

func TestASupplierAddedTwiceUnderOneNameIsAnAnswerRatherThanAFault(t *testing.T) {
	// A double-click answered 500 and put a fault in the log for a rule
	// working exactly as written: the row it collides with is one the caller
	// can see.
	twoReach(t, func(t *testing.T, r *reach) {
		const sources = "/v1/products/mine/advisory-sources"

		if got := r.named(t, "admin", http.MethodPost, sources, publishedAt).Code; got != http.StatusCreated {
			t.Fatalf("naming a supplier answered %d", got)
		}
		rec := r.named(t, "admin", http.MethodPost, sources, publishedAt)
		if rec.Code != http.StatusConflict {
			t.Errorf("naming it again answered %d, want 409: %s", rec.Code, rec.Body.String())
		}
		// And under another spelling of the same name, because a name people
		// type is matched without regard to capitals.
		again := `{"name":"exampledistribution",` +
			`"url":"https://distribution.example.test/.well-known/csaf/provider-metadata.json"}`
		if got := r.named(t, "admin", http.MethodPost, sources, again).Code; got != http.StatusConflict {
			t.Errorf("another spelling of the same name answered %d, want 409", got)
		}
	})
}

func TestAWithdrawalMatchesTheNameWithoutRegardToCapitals(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		const sources = "/v1/products/mine/advisory-sources"

		if got := r.named(t, "admin", http.MethodPost, sources, publishedAt).Code; got != http.StatusCreated {
			t.Fatalf("naming a supplier answered %d", got)
		}
		if got := r.named(t, "admin", http.MethodDelete,
			sources+"/exampledistribution", "").Code; got != http.StatusNoContent {
			t.Errorf("withdrawing it by another spelling answered %d", got)
		}
		if listed := r.suppliers(t, sources); len(listed) != 0 {
			t.Errorf("it is still listed: %+v", listed)
		}
	})
}

func TestAnAddressThatIsNotAPublishersDirectoryIsRefusedAtTheRequest(t *testing.T) {
	// Refused where somebody is typing rather than on a cycle hours later,
	// which is the only place the message reaches the person who made the
	// mistake.
	twoReach(t, func(t *testing.T, r *reach) {
		const sources = "/v1/products/mine/advisory-sources"

		for _, body := range []string{
			`{"name":"Plain","url":"http://distribution.example.test/provider-metadata.json"}`,
			`{"name":"Credentialed","url":"https://a:b@distribution.example.test/x.json"}`,
			`{"name":"Relative","url":"/provider-metadata.json"}`,
		} {
			rec := r.named(t, "admin", http.MethodPost, sources, body)
			if rec.Code == http.StatusCreated {
				t.Errorf("%s was stored", body)
			}
		}
		if listed := r.suppliers(t, sources); len(listed) != 0 {
			t.Errorf("a refused address was stored anyway: %+v", listed)
		}
	})
}

func TestASupplierIsNamedAgainstOneProductAndNotTheOther(t *testing.T) {
	// A claim is recorded against a product, so a supplier feeding two is two
	// rows — and withdrawing one leaves the other standing.
	twoReach(t, func(t *testing.T, r *reach) {
		const mine = "/v1/products/mine/advisory-sources"
		const theirs = "/v1/products/theirs/advisory-sources"

		if got := r.named(t, "admin", http.MethodPost, mine, publishedAt).Code; got != http.StatusCreated {
			t.Fatalf("naming a supplier answered %d", got)
		}
		if listed := r.suppliers(t, theirs); len(listed) != 0 {
			t.Errorf("the other product reads as configured with %+v", listed)
		}
		if got := r.named(t, "admin", http.MethodPost, theirs, publishedAt).Code; got != http.StatusCreated {
			t.Fatalf("naming the same supplier for a second product answered %d", got)
		}
		if got := r.named(t, "admin", http.MethodDelete,
			mine+"/ExampleDistribution", "").Code; got != http.StatusNoContent {
			t.Fatalf("withdrawing it answered %d", got)
		}
		if listed := r.suppliers(t, theirs); len(listed) != 1 {
			t.Errorf("withdrawing it from one product took it from the other: %+v", listed)
		}
	})
}

// supplierRow is one row of the list, as the API returns it.
type supplierRow struct {
	Name    string  `json:"name"`
	URL     string  `json:"url"`
	Tried   *string `json:"tried"`
	Read    *string `json:"read"`
	Because string  `json:"because"`
}

// suppliers is what the list endpoint answers for a product.
func (r *reach) suppliers(t *testing.T, path string) []supplierRow {
	t.Helper()
	rec := r.named(t, "admin", http.MethodGet, path, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("listing suppliers answered %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Items []supplierRow `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Items
}
