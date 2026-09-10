package httpapi_test

import (
	"net/http"
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
