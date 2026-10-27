// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// asked is one request about a code finding recorded as a flaw and the answer it gets.
type asked struct {
	who, method, path, body string
	want                    int
}

// answered sends each request about the code finding at an occurrence in turn.
func answered(t *testing.T, r *httpapitest.Reach, occurrence string, cases []asked) {
	t.Helper()
	for _, c := range cases {
		got := httpapitest.AsPerson(t, r, c.who, c.method, codeFindingAt(occurrence)+c.path, c.body)
		if got.Code != c.want {
			t.Errorf("%s %s %s answered %d, want %d: %s", c.who, c.method, c.path, got.Code, c.want, got.Body)
		}
	}
}

// recordAsFlawNamingNoBuild is a flaw record whose body names a build nobody made,
// which a caller without the rights is refused before it is looked up.
const recordAsFlawNamingNoBuild = `{"builds":[{"stream":"nosuch","variant":"broadcom"}],"summary":"p leaks"}`

func TestRecordingAsAFlawAndIncludingInDisclosureTakeBothTriageRoles(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, _ := httpapitest.RecordedCodeFinding(t, r, false)
		var cases []asked
		// Internal triage alone, private triage alone, and internal reading.
		for _, who := range []string{"internal-triager", "embargo-triager", "internal-reader"} {
			cases = append(cases,
				asked{who, http.MethodGet, "/flaw", "", http.StatusForbidden},
				asked{who, http.MethodPost, "/flaw", recordAsFlawNamingNoBuild, http.StatusForbidden},
				asked{who, http.MethodPut, "/flaw/disclosure", "", http.StatusForbidden},
				asked{who, http.MethodDelete, "/flaw/disclosure", "", http.StatusForbidden},
			)
		}
		cases = append(cases,
			asked{"code-finding-handler", http.MethodGet, "/flaw", "", http.StatusOK},
			asked{"code-finding-handler", http.MethodDelete, "/flaw/disclosure", "", http.StatusConflict},
		)
		answered(t, r, occurrence, cases)
	})
}

func TestAnInternalOnlyCodeFindingsCollaboratorsAreManagedByItsInternalReaders(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, _ := httpapitest.RecordedCodeFinding(t, r, false)
		answered(t, r, occurrence, []asked{
			{"internal-reader", http.MethodGet, "/collaborators", "", http.StatusOK},
			{"internal-reader", http.MethodPut, "/collaborators/outsider", "", http.StatusNoContent},
			{"internal-triager", http.MethodDelete, "/collaborators/outsider", "", http.StatusNoContent},
			// Undisclosed work alone does not read the internal code finding.
			{"embargo-triager", http.MethodGet, "/collaborators", "", http.StatusNotFound},
			{"embargo-triager", http.MethodPut, "/collaborators/outsider", "", http.StatusNotFound},
		})
	})
}

func TestAnIncludedCodeFindingsCollaboratorsAreManagedByItsInternalReaders(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, _ := httpapitest.RecordedCodeFinding(t, r, true)
		answered(t, r, occurrence, []asked{
			{"internal-reader", http.MethodGet, "/collaborators", "", http.StatusOK},
			{"internal-reader", http.MethodPut, "/collaborators/outsider", "", http.StatusNoContent},
			// The flaw's readers read the included code finding, and do not decide
			// who else does.
			{"embargo-reader", http.MethodGet, "", "", http.StatusOK},
			{"embargo-reader", http.MethodGet, "/collaborators", "", http.StatusNotFound},
			{"embargo-reader", http.MethodPut, "/collaborators/reader", "", http.StatusNotFound},
			// Somebody granted the code finding reads it, and does not decide who
			// else does.
			{"outsider", http.MethodGet, "", "", http.StatusOK},
			{"outsider", http.MethodGet, "/collaborators", "", http.StatusNotFound},
		})
	})
}

func TestNoGrantOfACodeFindingChangesOnceItsFlawIsDisclosed(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, true)
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut,
			codeFindingAt(occurrence)+"/collaborators/outsider", ""); got.Code != http.StatusNoContent {
			t.Fatalf("granting the code finding answered %d: %s", got.Code, got.Body)
		}
		disclosed(t, r, flaw)
		answered(t, r, occurrence, []asked{
			// Reading the disclosed code finding is not managing who was granted it.
			{"reader", http.MethodGet, "/collaborators", "", http.StatusNotFound},
			{"reader", http.MethodPut, "/collaborators/private", "", http.StatusNotFound},
			{"reader", http.MethodDelete, "/collaborators/outsider", "", http.StatusNotFound},
			{"code-finding-handler", http.MethodGet, "/collaborators", "", http.StatusOK},
			{"code-finding-handler", http.MethodPut, "/collaborators/private", "", http.StatusConflict},
			{"code-finding-handler", http.MethodDelete, "/collaborators/outsider", "", http.StatusConflict},
		})
	})
}
