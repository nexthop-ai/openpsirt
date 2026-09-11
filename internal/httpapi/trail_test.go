package httpapi_test

import (
	"net/http"
	"testing"
)

// changed is the trail as an administrator reads it.
type changed struct {
	Items []struct {
		By      string `json:"by"`
		Kind    string `json:"kind"`
		About   string `json:"about"`
		Was     string `json:"was"`
		Became  string `json:"became"`
		Unset   bool   `json:"unset"`
		Cleared bool   `json:"cleared"`
	} `json:"items"`
	Total int `json:"total"`
}

func TestEveryAdministrativeChangeIsRecorded(t *testing.T) {
	// Three of the things here silently rewrite what this tool reports —
	// the deadline windows, the triage floor, and a support date — and
	// none of them recorded who moved it. For a tool whose whole output is
	// evidence, that is the evidence being movable with nothing saying
	// that anybody moved it.
	//
	// Walked as a table rather than asserted one act at a time, because the
	// recording happens where the actor is known rather than in the store
	// underneath: what this guards against is a new administrative route
	// forgetting.
	eachReach(t, func(t *testing.T, r *reach) {
		for _, act := range []struct {
			what   string
			method string
			path   string
			body   string
			kind   string
			about  string
		}{
			{
				what: "a setting", method: http.MethodPut,
				path: "/v1/settings/triage.floor", body: `{"value":"medium"}`,
				kind: "setting", about: "triage.floor",
			},
			{
				what: "an account", method: http.MethodPost, path: "/v1/people",
				body: `{"identity":"newcomer"}`,
				kind: "account", about: "newcomer",
			},
			{
				what: "a role granted", method: http.MethodPost, path: "/v1/people",
				body: `{"identity":"newcomer",` +
					`"holds":[{"product":"mine","role":"public-read"}]}`,
				kind: "role", about: "newcomer on mine",
			},
			{
				what: "a role withdrawn", method: http.MethodDelete,
				path: "/v1/people/newcomer/roles/mine/public-read",
				kind: "role", about: "newcomer on mine",
			},
			{
				what: "a support date", method: http.MethodPut,
				path: "/v1/products/mine/end-of-life", body: `{"on":"2027-01-01"}`,
				kind: "support", about: "mine",
			},
			{
				what: "a release's support date", method: http.MethodPut,
				path: "/v1/products/mine/streams/master/end-of-life", body: `{"on":"2027-01-01"}`,
				kind: "support", about: "mine master",
			},
			{
				what: "a team", method: http.MethodPost, path: "/v1/teams",
				body: `{"name":"kernel"}`, kind: "team", about: "kernel",
			},
			{
				// Declared with somebody on it, which is a second way onto a
				// team and was the way that recorded nothing.
				what: "a team declared with a member", method: http.MethodPost,
				path: "/v1/teams", body: `{"name":"kernel","members":["newcomer"]}`,
				kind: "team", about: "kernel · newcomer",
			},
			{
				what: "somebody taken off at declaration", method: http.MethodDelete,
				path: "/v1/teams/kernel/members/newcomer",
				kind: "team", about: "kernel · newcomer",
			},
			{
				what: "somebody put on a team", method: http.MethodPut,
				path: "/v1/teams/kernel/members/newcomer",
				kind: "team", about: "kernel · newcomer",
			},
			{
				what: "somebody taken off a team", method: http.MethodDelete,
				path: "/v1/teams/kernel/members/newcomer",
				kind: "team", about: "kernel · newcomer",
			},
			{
				what: "a team retired", method: http.MethodDelete, path: "/v1/teams/kernel",
				kind: "team", about: "kernel",
			},
		} {
			got := asPerson(t, r, "admin", act.method, act.path, act.body)
			if got.Code >= 300 {
				t.Fatalf("%s answered %d: %s", act.what, got.Code, got.Body.String())
			}
			var trail changed
			read(t, r, "admin", "/v1/administration/changes?limit=1", &trail)
			if len(trail.Items) == 0 {
				t.Fatalf("%s left no record of who changed it", act.what)
			}
			newest := trail.Items[0]
			if newest.Kind != act.kind || newest.About != act.about {
				t.Errorf("%s recorded %q/%q, want %q/%q",
					act.what, newest.Kind, newest.About, act.kind, act.about)
			}
			if newest.By != "admin" {
				t.Errorf("%s was recorded against %q rather than whoever made it",
					act.what, newest.By)
			}
		}

		// What it held before is kept, because "who raised the floor to
		// critical" is half the question and the other half is what it was.
		if got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.floor",
			`{"value":"critical"}`); got.Code >= 300 {
			t.Fatalf("raising the floor answered %d: %s", got.Code, got.Body.String())
		}
		var trail changed
		read(t, r, "admin", "/v1/administration/changes?kind=setting&limit=1", &trail)
		if len(trail.Items) == 0 || trail.Items[0].Was != "medium" ||
			trail.Items[0].Became != "critical" {
			t.Errorf("raising the floor recorded %+v, want medium becoming critical",
				trail.Items)
		}
		// And the first time it was set, nobody had: an absent before is not
		// the same as an empty one.
		read(t, r, "admin", "/v1/administration/changes?kind=setting&limit=50", &trail)
		first := trail.Items[len(trail.Items)-1]
		if !first.Unset {
			t.Errorf("the first setting of a value reports a previous one: %+v", first)
		}
	})
}

func TestTheTrailIsAnAdministratorsToRead(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		for _, who := range []string{"triager", "private-triage", "approver"} {
			got := asPerson(t, r, who, http.MethodGet, "/v1/administration/changes", "")
			if got.Code != http.StatusForbidden && got.Code != http.StatusNotFound {
				t.Errorf("%s read the administration trail, answering %d", who, got.Code)
			}
		}
	})
}
