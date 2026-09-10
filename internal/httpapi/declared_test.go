package httpapi_test

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
)

// asked is what an operation declares it needs, read back off the document the
// server builds from its own registrations.
//
// Declared in the test rather than shared with the package under test: what is
// being checked is that the *published* shape means something, so reading it
// the way a client generator would is the honest way to read it.
type asked struct {
	Scope string   `json:"scope"`
	AnyOf []string `json:"any_of"`
	// Narrowed says the roles decide what comes back rather than whether the
	// operation answers at all — an empty list to a stranger is the right
	// answer there, so those are not gates and this sweep is not about them.
	Narrowed bool `json:"narrowed"`
}

// standIn is a value for each path parameter that the fixture actually has,
// where it has one. What an arbitrary identifier gets is a 404, which is
// still not an answer — so a parameter missing from here weakens the check for
// that operation without breaking it.
var standIn = map[string]string{
	"product": "mine", "stream": "master", "variant": "broadcom",
	"vulnerability": "CVE-2026-9999", "component": "libnl-3-200",
	"identity": "reader", "name": "master", "format": "json",
	"role": "public-read", "kind": "branch", "alias": "CVE-2026-1000",
	"id": "1", "place": "1", "batch": "1", "team": "1", "scan": "1",
	"run": "1", "document": "1", "token": "1", "tag": "one",
}

func TestAnOperationRefusesSomebodyHoldingNoneOfTheRolesItDeclares(t *testing.T) {
	// telling at the finding's visibility and the honest sentence on the
	// privileges page: the declaration is not the check, the check is a
	// line in each handler, and the two drifted apart three times before
	// this review and three times during it — the routing preview, the tag
	// list and the reporter's contact details all answered somebody the
	// declaration said could not ask.
	//
	// Every one of those was found by reading the two against each other.
	// This is the floor underneath that reading: whatever else an
	// operation declaring a role on a product does, it does not answer 2xx
	// to somebody who holds none of them. It cannot prove the check is the
	// right one — only that there is one — and a refusal for the wrong
	// reason (an identifier the fixture does not have) passes it. That is
	// why it is a floor and not the ceiling.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)

		// Counted by class, because a sweep that quietly stops walking is
		// worse than no sweep: the numbers it checks are the only evidence
		// it is still looking at the API, and a class emptying is invisible
		// in one total.
		var onProduct, deployment, anywhere, notAGate, narrowed, noValue int
		for path, item := range r.api.OpenAPI().Paths {
			for method, op := range operations(item) {
				want, ok := op.Extensions[requiresExtensionName]
				if !ok {
					t.Errorf("%s %s declares nothing at all: every operation "+
						"goes through requiring()", method, path)
					continue
				}
				var needs asked
				raw, err := json.Marshal(want)
				if err != nil {
					t.Fatalf("%s %s: %v", method, path, err)
				}
				if err := json.Unmarshal(raw, &needs); err != nil {
					t.Fatalf("%s %s: %v", method, path, err)
				}
				if needs.Narrowed {
					narrowed++
					continue
				}
				// Who is a stranger to this operation depends on what it
				// asks for. The scope was read as "a scope alone is
				// satisfied by anybody holding anything", which is true of
				// the credential scopes and false of the two that name a
				// standing nobody holds by default — so every
				// administrator-only operation and every any-product one
				// went unswept, which is most of the ones a mistake would
				// be worst on.
				var who string
				switch {
				case needs.Scope == "product" && len(needs.AnyOf) > 0:
					onProduct++
					who = strangerTo(needs.AnyOf)
				case needs.Scope == "deployment":
					deployment++
					// Somebody who holds a role on the product and does not
					// administer the deployment. A subject who reaches
					// nothing would be refused before the gate was consulted.
					who = "reader"
				case needs.Scope == "any-product":
					anywhere++
					// Somebody recognized who holds no role on any product,
					// which is what this scope asks for.
					who = "nothing"
				default:
					notAGate++
					continue
				}

				asking := fill(path)
				if strings.Contains(asking, "{") {
					noValue++
					t.Errorf("%s %s has a path parameter this sweep has no value "+
						"for, so it is not being checked", method, path)
					continue
				}
				if got := r.as(t, who, method, asking); got >= 200 && got < 300 {
					t.Errorf("%s %s answered %q with %d, and %q satisfies none of "+
						"what it declares (%s)", method, asking, who, got, who,
						describe(needs))
				}
			}
		}
		// A sweep that walks nothing passes. Said out loud per class, at
		// numbers the API cannot fall below without somebody having deleted
		// most of it — and per class, because one total hides a class that
		// has quietly emptied.
		if onProduct < 30 {
			t.Errorf("only %d operations are gated by a role on a product: "+
				"this sweep is not walking them", onProduct)
		}
		if deployment < 20 {
			t.Errorf("only %d operations are gated on administering the deployment: "+
				"this sweep is not walking them", deployment)
		}
		if anywhere < 3 {
			t.Errorf("only %d operations are gated on a role anywhere: "+
				"this sweep is not walking them", anywhere)
		}
		t.Logf("swept %d on a product, %d deployment-wide, %d on any product "+
			"(%d ask only for a credential, %d are narrowed rather than gated, "+
			"%d have no value here)",
			onProduct, deployment, anywhere, notAGate, narrowed, noValue)
	})
}

// describe says what an operation asks for, for a failure message.
func describe(needs asked) string {
	if len(needs.AnyOf) > 0 {
		return strings.Join(needs.AnyOf, " or ") + " (" + needs.Scope + ")"
	}
	return needs.Scope
}

// requiresExtensionName is the key the operation carries. Spelled out here
// because a test reading the published document reads what was published.
const requiresExtensionName = "x-openpsirt-requires"

// strangerTo picks somebody from the fixture's cast who holds none of these
// roles and does hold something on the product, because a subject who reaches
// nothing is refused before any role is consulted — which would make the
// check pass without ever reaching the handler.
func strangerTo(roles []string) string {
	held := map[string]bool{}
	for _, role := range roles {
		held[role] = true
	}
	switch {
	case !held["public-read"]:
		return "reader"
	case !held["private-read"]:
		return "private"
	default:
		// Both read roles satisfy it, so anybody who can see the
		// product can ask. What is left is the capability held bare,
		// which reaches nothing at all — a weaker case, and the only
		// one left.
		return "assigner-only"
	}
}

// fill puts the fixture's own names into a path template.
func fill(path string) string {
	for name, value := range standIn {
		path = strings.ReplaceAll(path, "{"+name+"}", value)
	}
	return path
}

// operations is the methods one path answers, in a fixed order so a failure
// reads the same twice.
func operations(item *huma.PathItem) map[string]*huma.Operation {
	all := map[string]*huma.Operation{
		http.MethodGet: item.Get, http.MethodPost: item.Post,
		http.MethodPut: item.Put, http.MethodPatch: item.Patch,
		http.MethodDelete: item.Delete,
	}
	out := map[string]*huma.Operation{}
	names := make([]string, 0, len(all))
	for method := range all {
		names = append(names, method)
	}
	sort.Strings(names)
	for _, method := range names {
		if all[method] != nil {
			out[method] = all[method]
		}
	}
	return out
}
