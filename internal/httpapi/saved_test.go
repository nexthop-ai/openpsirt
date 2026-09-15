package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
)

func TestASavedFilterIsPersonalAndReplacesItsOwnName(t *testing.T) {
	// Nothing is shared: no ownership, no permissions, and no arguing
	// about whose filter is authoritative. "Personal" has to hold at the
	// query rather than only on the screen, or an identifier is a way to
	// reach somebody else's.
	eachReach(t, func(t *testing.T, r *reach) {
		keep := func(t *testing.T, who, name, query string) int {
			t.Helper()
			return asPerson(t, r, who, http.MethodPut, "/v1/products/mine/saved-filters/"+name,
				`{"query":"`+query+`"}`).Code
		}
		if code := keep(t, "triager", "overdue-kernel", "overdue=true&component=linux"); code != http.StatusNoContent {
			t.Fatalf("keeping a filter answered %d", code)
		}
		if code := keep(t, "reader", "overdue-kernel", "q=openssl"); code != http.StatusNoContent {
			t.Fatalf("somebody else keeping the same name answered %d", code)
		}

		mine := func(t *testing.T, who string) []struct {
			Name  string `json:"name"`
			Query string `json:"query"`
		} {
			t.Helper()
			var out struct {
				Items []struct {
					Name  string `json:"name"`
					Query string `json:"query"`
				} `json:"items"`
			}
			read(t, r, who, "/v1/products/mine/saved-filters", &out)
			return out.Items
		}

		// Two people, one name, two filters, and neither sees the other's.
		theirs := mine(t, "triager")
		if len(theirs) != 1 || theirs[0].Query != "overdue=true&component=linux" {
			t.Fatalf("a triager's own filters are %+v", theirs)
		}
		others := mine(t, "reader")
		if len(others) != 1 || others[0].Query != "q=openssl" {
			t.Fatalf("somebody else's filters are %+v", others)
		}

		// Saving over a name replaces it rather than refusing: the act is
		// deciding what that name means.
		if code := keep(t, "triager", "OVERDUE-KERNEL", "overdue=true"); code != http.StatusNoContent {
			t.Fatalf("saving over a name answered %d", code)
		}
		theirs = mine(t, "triager")
		if len(theirs) != 1 || theirs[0].Query != "overdue=true" {
			t.Errorf("saving over a name left %+v", theirs)
		}

		// And forgetting reaches only your own: somebody else's name is not
		// there, which is what a name nobody kept answers too.
		if got := asPerson(t, r, "reader", http.MethodDelete,
			"/v1/products/mine/saved-filters/overdue-kernel", ""); got.Code != http.StatusNoContent {
			t.Fatalf("forgetting your own answered %d", got.Code)
		}
		if len(mine(t, "triager")) != 1 {
			t.Error("forgetting their own took somebody else's")
		}
		if got := asPerson(t, r, "reader", http.MethodDelete,
			"/v1/products/mine/saved-filters/overdue-kernel", ""); got.Code != http.StatusNotFound {
			t.Errorf("forgetting a name nobody kept answered %d", got.Code)
		}
	})
}

// A rule prepares a claim; a person proposes it.
//
// The wider form — a rule proposing its own pending claim — was refused
// because it leaves the approver as the only human judgment on it. What is
// kept here is a prefill, and what has to hold is that it is a prefill: it
// carries the words somebody will put their name to, and it never proposes
// anything by itself.
func TestASavedFilterCanPrepareAClaimAndNeverProposesOne(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		keep := func(t *testing.T, name, body string) (int, string) {
			t.Helper()
			got := asPerson(t, r, "triager", http.MethodPut, "/v1/products/mine/saved-filters/"+name, body)
			return got.Code, got.Body.String()
		}
		type prepared struct {
			Outcome       string `json:"outcome"`
			Justification string `json:"justification"`
			Reasoning     string `json:"reasoning"`
			DeferDays     int    `json:"defer_days"`
		}
		mine := func(t *testing.T) []struct {
			Name     string    `json:"name"`
			Query    string    `json:"query"`
			Prepares *prepared `json:"prepares"`
		} {
			t.Helper()
			var out struct {
				Items []struct {
					Name     string    `json:"name"`
					Query    string    `json:"query"`
					Prepares *prepared `json:"prepares"`
				} `json:"items"`
			}
			read(t, r, "triager", "/v1/products/mine/saved-filters", &out)
			return out.Items
		}

		// The reasoning is what somebody will be putting their name to, so a
		// prefill without it is refused: a button that proposes a dismissal
		// saying nothing is the shape this decision exists to avoid.
		if code, said := keep(t, "kernel-modules", `{"query":"component=linux-image",
			"prepares":{"outcome":"not-applicable","justification":"vulnerable_code_not_present"}}`); code < 400 {
			t.Errorf("a prefill with no reasoning was kept: %d %s", code, said)
		}

		if code, said := keep(t, "kernel-modules", `{"query":"component=linux-image",
			"prepares":{"outcome":"not-applicable",
			"justification":"vulnerable_code_not_present",
			"reasoning":"The driver is not built for this image."}}`); code != http.StatusNoContent {
			t.Fatalf("keeping a filter that prepares a claim answered %d: %s", code, said)
		}
		kept := mine(t)
		if len(kept) != 1 || kept[0].Prepares == nil {
			t.Fatalf("the saved filter reads %+v", kept)
		}
		if kept[0].Prepares.Outcome != "not-applicable" ||
			kept[0].Prepares.Reasoning != "The driver is not built for this image." {
			t.Errorf("it prepares %+v", kept[0].Prepares)
		}

		// **It proposes nothing by itself.** Keeping it left no claim behind:
		// a person submits it, which is the whole of why the narrow form was
		// chosen over a rule that files its own.
		var queue struct {
			Total int `json:"total"`
		}
		read(t, r, "reviewer", "/v1/review-queue", &queue)
		if queue.Total != 0 {
			t.Errorf("saving a filter that prepares a claim proposed %d of them", queue.Total)
		}

		// Saving over the name without a prefill takes the prefill off. The
		// act is deciding what that name means now, and a prefill that
		// survived would fire on a filter somebody had made ordinary.
		if code, said := keep(t, "kernel-modules",
			`{"query":"component=linux-image"}`); code != http.StatusNoContent {
			t.Fatalf("saving over it answered %d: %s", code, said)
		}
		kept = mine(t)
		if len(kept) != 1 || kept[0].Prepares != nil {
			t.Errorf("after saving over it without a prefill, it reads %+v", kept)
		}
	})
}

func TestASavedFilterBelongsToTheProductItNarrows(t *testing.T) {
	// A filter's query names branches and variants, which belong to one
	// product and usually exist in no other. Offered everywhere, one saved on
	// a product with a branch called master narrowed a product that has none
	// — a filter that matches nothing, chosen from a list that gave no reason
	// why. Picking it also replaces what is on screen, so the wrong narrowing
	// is applied rather than merely offered.
	eachReach(t, func(t *testing.T, r *reach) {
		// The same person can see a second product, so what is being measured
		// is the filter's scope rather than what they may reach.
		person, err := r.rights.Ensure(t.Context(), "triager", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		theirs, err := catalog.NewStore(r.db.DB).ProductByName(t.Context(), "theirs")
		if err != nil {
			t.Fatal(err)
		}
		if err := r.rights.GrantRole(t.Context(), person.ID, theirs.ID,
			access.PublicRead); err != nil {
			t.Fatal(err)
		}

		if kept := asPerson(t, r, "triager", http.MethodPut,
			"/v1/products/mine/saved-filters/overdue-kernel",
			`{"query":"stream=master&severity=critical"}`); kept.Code != http.StatusNoContent {
			t.Fatalf("keeping a filter answered %d: %s", kept.Code, kept.Body.String())
		}

		named := func(t *testing.T, product string) []string {
			t.Helper()
			var out struct {
				Items []struct {
					Name string `json:"name"`
				} `json:"items"`
			}
			read(t, r, "triager", "/v1/products/"+product+"/saved-filters", &out)
			names := make([]string, 0, len(out.Items))
			for _, one := range out.Items {
				names = append(names, one.Name)
			}
			return names
		}

		if got := named(t, "mine"); len(got) != 1 || got[0] != "overdue-kernel" {
			t.Errorf("the product it was saved on lists %v", got)
		}
		if got := named(t, "theirs"); len(got) != 0 {
			t.Errorf("a filter saved on one product is offered on another: %v", got)
		}
	})
}
