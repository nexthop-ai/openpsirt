package httpapi_test

import (
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"
)

func TestEverySettingSomethingReadsIsOneSomebodyCanSet(t *testing.T) {
	// The rule this codebase states is that a setting nothing reads must not
	// be offered. The three disclosure periods were the inverse and nobody had
	// named the inverse: each is read and wired into behavior — when an
	// embargo's date falls, how much it may be moved by before a second person
	// agrees, how long before that date the people who could still move it are
	// told — and none was in the list of what may be set. Two design documents
	// described all three as settings. A deployment whose coordinated
	// disclosure policy is not ninety days read that it could configure one
	// and could not.
	twoReach(t, func(t *testing.T, r *reach) {
		var offered struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
		}
		read(t, r, "admin", "/v1/settings", &offered)
		has := map[string]bool{}
		for _, each := range offered.Items {
			has[each.Name] = true
		}

		for _, name := range []string{
			"disclosure.after",
			"disclosure.extension-threshold",
			"disclosure.lead-time",
		} {
			if !has[name] {
				t.Errorf("%s is read by the application and cannot be set", name)
				continue
			}
			// And settable in fact, not only listed: an allowlist that names a
			// key the write path refuses is the same defect one step along.
			if got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/"+name,
				`{"value":"720h"}`); got.Code >= 300 {
				t.Errorf("setting %s answered %d: %s", name, got.Code, got.Body.String())
			}
		}
	})
}

func TestNothingOfferedComesBackWithoutAValue(t *testing.T) {
	// `default: true` with an empty value is the screen saying "nobody has set
	// this" and then not saying what applies instead. Three settings did: the
	// disclosure periods reported blank while 90 days, 30 days and 14 days
	// were what the deployment enforced, because the switch behind the shipped
	// value had 22 arms and the list had 27 names.
	twoReach(t, func(t *testing.T, r *reach) {
		var offered struct {
			Items []struct {
				Name    string `json:"name"`
				Value   string `json:"value"`
				Default bool   `json:"default"`
			} `json:"items"`
		}
		read(t, r, "admin", "/v1/settings", &offered)
		if len(offered.Items) < 20 {
			t.Fatalf("%d settings came back, so this checked almost nothing", len(offered.Items))
		}
		for _, each := range offered.Items {
			if strings.TrimSpace(each.Value) == "" {
				t.Errorf("%s came back with no value (default=%v), which reads as "+
					"nothing applying", each.Name, each.Default)
			}
		}
		// And the three that were blank carry what the readers actually use.
		want := map[string]string{
			"disclosure.after":               "2160h0m0s",
			"disclosure.extension-threshold": "720h0m0s",
			"disclosure.lead-time":           "336h0m0s",
		}
		for _, each := range offered.Items {
			if expected, named := want[each.Name]; named && each.Value != expected {
				t.Errorf("%s reports %q, and its readers fall back to %q",
					each.Name, each.Value, expected)
			}
		}
	})
}

func TestWhatTheDocumentSaysAFindingWithNoDeadlineCarries(t *testing.T) {
	// Two response bodies published the same field with different words. The
	// evidence body declared `past-end-of-life`, which nothing in the tree
	// produces, and omitted `out-of-support`, which the store emits on every
	// finding whose release is past end of life — so a consumer validating
	// against the published document rejected the body it was actually sent,
	// and a TypeScript one could not narrow on the value.
	//
	// Read from the document the server builds, because that is what a
	// consumer is held to.
	twoReach(t, func(t *testing.T, r *reach) {
		declared := map[string][]string{}
		for name, schema := range r.api.OpenAPI().Components.Schemas.Map() {
			for field, property := range schema.Properties {
				if field != "no_deadline" || len(property.Enum) == 0 {
					continue
				}
				said := make([]string, 0, len(property.Enum))
				for _, one := range property.Enum {
					said = append(said, fmt.Sprint(one))
				}
				sort.Strings(said)
				declared[name] = said
			}
		}
		if len(declared) == 0 {
			t.Fatal("no published body declares why a finding has no deadline")
		}
		// The two the store emits, and nothing else. Named here rather than
		// read from internal/finding so that a word added there without being
		// published fails this rather than passing it.
		want := []string{"below-the-line", "out-of-support"}
		for body, said := range declared {
			if !slices.Equal(said, want) {
				t.Errorf("%s declares %v, and the store emits %v", body, said, want)
			}
		}
	})
}
