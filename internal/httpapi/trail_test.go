package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
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

// seeded is what an act needs that the fixture does not already hold: an issue
// to name, and the identifier of a rule an earlier act made.
type seeded struct {
	issue string
	rule  string
}

// fill puts what has been seeded into a path, a body or an expected name.
func (s *seeded) fill(text string) string {
	text = strings.ReplaceAll(text, "{issue}", s.issue)
	return strings.ReplaceAll(text, "{rule}", s.rule)
}

// trailedAct is one registered write that must leave a row in the
// administrative trail, with what it takes to drive it and what the row has to
// say.
type trailedAct struct {
	// id is the operation this drives, which is what ties the table to the
	// registered routes rather than to a list somebody maintains.
	id   string
	what string
	// who makes it, empty for the administrator.
	who    string
	method string
	path   string
	body   string
	kind   string
	about  string
	// drive replaces the ordinary request, for the one act that is a file
	// upload rather than a JSON body.
	drive func(t *testing.T, r *reach, seen *seeded) *httptest.ResponseRecorder
	// keep takes what the act answered, for an act below it that needs it.
	keep func(t *testing.T, seen *seeded, answered []byte)
}

// administrativeActs is every registered write that must leave a trail row.
//
// Ordered, because most of them act on what the one above made: a role is
// granted to somebody who was recorded, a rule routes to a team that was
// declared, a credential is withdrawn after it was minted.
//
// The identifiers are what tie this to the server rather than to a list: the
// walk below fails on a registered write that is in neither this table nor
// outsideTheTrail, so a new administrative route is classified rather than
// forgotten. That is the whole point of it. A list of acts somebody maintains
// by hand is a list that goes short, and the routes it goes short by are the
// ones recording nothing with the suite green.
var administrativeActs = []trailedAct{
	{
		id: "set-setting", what: "a setting", method: http.MethodPut,
		path: "/v1/settings/triage.floor", body: `{"value":"medium"}`,
		kind: "setting", about: "triage.floor",
	},
	{
		id: "set-role-mode", what: "where roles come from", method: http.MethodPut,
		path: "/v1/roles/mode", body: `{"mode":"direct"}`,
		kind: "setting", about: "roles.mode",
	},
	{
		id: "record-person", what: "an account", method: http.MethodPost,
		path: "/v1/people", body: `{"identity":"newcomer"}`,
		kind: "account", about: "newcomer",
	},
	{
		id: "record-person", what: "a role granted", method: http.MethodPost,
		path: "/v1/people",
		body: `{"identity":"newcomer",` +
			`"holds":[{"product":"mine","role":"public-read"}]}`,
		kind: "role", about: "newcomer on mine",
	},
	{
		id: "withdraw-role", what: "a role withdrawn", method: http.MethodDelete,
		path: "/v1/people/newcomer/roles/mine/public-read",
		kind: "role", about: "newcomer on mine",
	},
	{
		id: "record-person", what: "a role granted across the estate",
		method: http.MethodPost, path: "/v1/people",
		body: `{"identity":"newcomer",` +
			`"holds":[{"role":"public-read","everywhere":true}]}`,
		kind: "role", about: "newcomer on every product",
	},
	{
		id: "withdraw-estate-role", what: "a role withdrawn across the estate",
		method: http.MethodDelete, path: "/v1/people/newcomer/roles/public-read",
		kind: "role", about: "newcomer on every product",
	},
	{
		id: "unbind-identifier", what: "how somebody signs in, unpinned",
		method: http.MethodDelete, path: "/v1/people/newcomer/identifier",
		kind: "account", about: "newcomer",
	},
	{
		// A group bound to a role grants it to everybody in that group from
		// their next sign-in, which is the widest grant anybody here makes
		// and the one the trail had no record of at all.
		id: "bind-group", what: "a group bound to a role", method: http.MethodPost,
		path: "/v1/roles/bindings",
		body: `{"group":"Security","product":"mine","role":"public-read"}`,
		kind: "role", about: "Security on mine",
	},
	{
		id: "unbind-group", what: "a group unbound from a role", method: http.MethodDelete,
		path: "/v1/roles/bindings?group=Security&product=mine&role=public-read",
		kind: "role", about: "Security on mine",
	},
	{
		id: "bind-group", what: "a group bound to administration", method: http.MethodPost,
		path: "/v1/roles/bindings", body: `{"group":"Owners","role":"admin"}`,
		kind: "role", about: "Owners over this deployment",
	},
	{
		id: "unbind-group", what: "a group unbound from administration",
		method: http.MethodDelete, path: "/v1/roles/bindings?group=Owners&role=admin",
		kind: "role", about: "Owners over this deployment",
	},
	{
		// The other thing held over the deployment. It goes down the same
		// route and is recorded the same way, which is the point of there
		// being one route.
		id: "bind-group", what: "a group bound to auditing", method: http.MethodPost,
		path: "/v1/roles/bindings", body: `{"group":"Auditors","role":"audit"}`,
		kind: "role", about: "Auditors over this deployment",
	},
	{
		id: "unbind-group", what: "a group unbound from auditing",
		method: http.MethodDelete, path: "/v1/roles/bindings?group=Auditors&role=audit",
		kind: "role", about: "Auditors over this deployment",
	},
	{
		// The one act that hands out a new way into the deployment, and the
		// one the trail recorded the withdrawal of without the grant.
		id: "create-key", what: "a pipeline credential minted", method: http.MethodPost,
		path: "/v1/keys", body: `{"name":"builder","product":"mine","stream":"master"}`,
		kind: "credential", about: "builder",
	},
	{
		id: "revoke-key", what: "a pipeline credential withdrawn", method: http.MethodDelete,
		path: "/v1/keys/builder", kind: "credential", about: "builder",
	},
	{
		id: "mint-token", what: "somebody's own credential minted", method: http.MethodPost,
		path: "/v1/tokens", body: `{"name":"script","lifetime":"24h"}`,
		kind: "credential", about: "admin · script",
	},
	{
		id: "revoke-my-token", what: "somebody's own credential withdrawn",
		method: http.MethodDelete, path: "/v1/tokens/script",
		kind: "credential", about: "admin · script",
	},
	{
		// Minted by its owner so that the act below withdraws somebody
		// else's, which is the administrative one.
		id: "mint-token", what: "another person's credential minted", who: "reader",
		method: http.MethodPost, path: "/v1/tokens",
		body: `{"name":"theirs","lifetime":"24h"}`,
		kind: "credential", about: "reader · theirs",
	},
	{
		id: "revoke-anyones-token", what: "another person's credential withdrawn",
		method: http.MethodDelete, path: "/v1/people/reader/tokens/theirs",
		kind: "credential", about: "reader · theirs",
	},
	{
		id: "set-product-triage-floor", what: "the line a product triages at",
		method: http.MethodPut, path: "/v1/products/mine/triage-floor",
		body: `{"floor":"high"}`, kind: "setting", about: "triage floor of mine",
	},
	{
		id: "set-product-end-of-life", what: "a support date", method: http.MethodPut,
		path: "/v1/products/mine/end-of-life", body: `{"on":"2027-01-01"}`,
		kind: "support", about: "mine",
	},
	{
		id: "set-stream-end-of-life", what: "a release's support date",
		method: http.MethodPut, path: "/v1/products/mine/streams/master/end-of-life",
		body: `{"on":"2027-01-01"}`, kind: "support", about: "mine master",
	},
	{
		id: "set-release-details", what: "when a release went out", method: http.MethodPut,
		path: "/v1/products/mine/streams/master/release",
		body: `{"released_on":"2026-03-31"}`, kind: "release", about: "mine master",
	},
	{
		id: "record-team", what: "a team", method: http.MethodPost, path: "/v1/teams",
		body: `{"name":"kernel"}`, kind: "team", about: "kernel",
	},
	{
		// Declared with somebody on it, which is a second way onto a team and
		// was the way that recorded nothing.
		id: "record-team", what: "a team declared with a member", method: http.MethodPost,
		path: "/v1/teams", body: `{"name":"kernel","members":["newcomer"]}`,
		kind: "team", about: "kernel · newcomer",
	},
	{
		id: "remove-from-team", what: "somebody taken off at declaration",
		method: http.MethodDelete, path: "/v1/teams/kernel/members/newcomer",
		kind: "team", about: "kernel · newcomer",
	},
	{
		id: "add-to-team", what: "somebody put on a team", method: http.MethodPut,
		path: "/v1/teams/kernel/members/newcomer", kind: "team", about: "kernel · newcomer",
	},
	{
		id: "remove-from-team", what: "somebody taken off a team", method: http.MethodDelete,
		path: "/v1/teams/kernel/members/newcomer", kind: "team", about: "kernel · newcomer",
	},
	{
		// Routing is neither a grant nor a withdrawal and is not held against
		// a person, so it carries a kind of its own rather than being read as
		// a role change by anybody filtering the trail.
		id: "add-routing-rule", what: "a routing rule", who: "assigner",
		method: http.MethodPost, path: "/v1/products/mine/routing-rules",
		body: `{"name":"kernel things","team":"kernel","beneath":"libnl-3-200"}`,
		kind: "routing", about: "mine · kernel things",
		keep: func(t *testing.T, seen *seeded, answered []byte) {
			var rule struct {
				ID int64 `json:"id"`
			}
			if err := json.Unmarshal(answered, &rule); err != nil {
				t.Fatal(err)
			}
			seen.rule = strconv.FormatInt(rule.ID, 10)
		},
	},
	{
		id: "retire-routing-rule", what: "a routing rule retired", who: "assigner",
		method: http.MethodDelete, path: "/v1/products/mine/routing-rules/{rule}",
		kind: "routing", about: "mine · {rule}",
	},
	{
		id: "retire-team", what: "a team retired", method: http.MethodDelete,
		path: "/v1/teams/kernel", kind: "team", about: "kernel",
	},
	{
		id: "add-outbound", what: "somewhere to send notifications", method: http.MethodPost,
		path: "/v1/outbound",
		body: `{"name":"ops","kind":"*","url":"https://hooks.example.test/t/abc",` +
			`"secret":"sixteen-characters-at-least"}`,
		kind: "setting", about: "outbound · ops · *",
	},
	{
		id: "retire-outbound", what: "a destination retired", method: http.MethodDelete,
		path: "/v1/outbound/ops/*", kind: "setting", about: "outbound · ops · *",
	},
	{
		id: "add-collaborator", what: "somebody brought into a case", who: "private-triage",
		method: http.MethodPut,
		path:   "/v1/products/mine/issues/{issue}/collaborators/reader",
		kind:   "case", about: "mine · {issue} · reader",
	},
	{
		id: "remove-collaborator", what: "somebody taken off a case", who: "private-triage",
		method: http.MethodDelete,
		path:   "/v1/products/mine/issues/{issue}/collaborators/reader",
		kind:   "case", about: "mine · {issue} · reader",
	},
	{
		// Deployment-wide and permanent: from here on a scan of any product
		// reporting that name resolves to this issue.
		id: "add-alias", what: "another name for an issue", who: "private-triage",
		method: http.MethodPut,
		path:   "/v1/products/mine/issues/{issue}/aliases/CVE-2026-40001",
		kind:   "alias", about: "{issue}",
	},
	{
		id: "upload-vex-statements", what: "what a publisher says about a component",
		kind: "setting", about: "VEX statements from example",
		drive: func(t *testing.T, r *reach, _ *seeded) *httptest.ResponseRecorder {
			return r.vexed(t, "admin", "example",
				said("not_affected", "vulnerable_code_not_present", ""))
		},
	},
	{
		id: "end-sessions", what: "somebody cut off now", method: http.MethodDelete,
		path: "/v1/people/newcomer/sessions", kind: "account", about: "newcomer",
	},
	{
		id: "deactivate-person", what: "somebody deactivated", method: http.MethodPut,
		path: "/v1/people/newcomer/deactivation", kind: "account", about: "newcomer",
	},
	{
		id: "reactivate-person", what: "somebody reactivated", method: http.MethodDelete,
		path: "/v1/people/newcomer/deactivation", kind: "account", about: "newcomer",
	},
}

// outsideTheTrail is every registered write that leaves no row, and why.
//
// The trail is the layer above the triage record rather than part of it: the
// settings, grants and dates that decide what the record says. So a judgment
// about a finding is not one of these, and neither is an act whose actor and
// moment are already written on the thing it changed.
//
// A reason here is a decision, not a note. Absorbing a route that should be
// trailed is the failure this whole table exists to make visible, and the way
// it would happen is somebody adding a line rather than a call.
var outsideTheTrail = map[string]string{
	// The decision record (REQ-22). Every one of these is a triage judgment
	// or an argument about one, kept beside the decision it belongs to with
	// who made it and when.
	"agree-assessment":       "the decision record",
	"agree-to-extension":     "the decision record",
	"approve-claim":          "the decision record",
	"assess-issue":           "the decision record",
	"assign-finding":         "the decision record",
	"carry-decisions":        "the decision record",
	"comment-on-claim":       "the decision record",
	"decide":                 "the decision record",
	"decide-finding":         "the decision record",
	"decide-together":        "the decision record",
	"edit-comment":           "the decision record",
	"edit-issue-note":        "the decision record",
	"extend-disclosure":      "the decision record",
	"note-on-issue":          "the decision record",
	"plan-upgrade":           "the decision record",
	"point-claim-elsewhere":  "the decision record",
	"reaffirm-claim":         "the decision record",
	"reaffirm-decision":      "the decision record",
	"record-advisory-issued": "the decision record",
	"record-finding":         "the decision record",
	"repromise-upgrade":      "the decision record",
	"resolve-finding":        "the decision record",
	"revise-claim":           "the decision record",
	"send-claim-back":        "the decision record",
	"set-affected-builds":    "the decision record",
	"split-claim":            "the decision record",
	"tag-finding":            "the decision record",
	"undo-batch":             "the decision record",
	"untag-finding":          "the decision record",
	"withdraw-assessment":    "the decision record",
	"withdraw-claim":         "the decision record",

	// Recorded on the thing it changed, with who and when. A second row in
	// the trail would be a copy that can disagree with it.
	"acknowledge-report": "recorded on the report, which names who answered it and when",
	"redact-attachment":  "recorded on the attachment",
	"upload-attachment":  "recorded on the attachment, which names who uploaded it",
	"upload-scan":        "recorded as the scan's provenance",

	// One person's own, and nothing anybody else reads changes.
	"acknowledge-all-notifications": "their own notifications",
	"acknowledge-notification":      "their own notifications",
	"forget-filter":                 "their own saved filters",
	"save-filter":                   "their own saved filters",
	"set-digest":                    "their own mail",
	"sign-out":                      "their own session",

	// The catalog says what exists. Declaring something new changes nothing
	// about what the record already says of what was there.
	"declare-product": "the catalog",
	"declare-stream":  "the catalog",
	"declare-variant": "the catalog",

	// Work moving, which is recorded where work is.
	"hand-back-assignments": "recorded in the assignment history",

	// Running the tool rather than changing it: a job that was set aside is
	// asked to run again, and nothing about what anybody may do moves.
	"retry-set-aside-work": "operating the queue",
}

// TestEveryRegisteredWriteIsEitherTrailedOrDeliberatelyNot walks the document
// the server builds and fails on a write that nobody has classified.
//
// This is the half that catches the next route rather than the last one. A
// literal of twelve acts walks nothing, whatever the comment at
// internal/httpapi/trail.go claims, and leaves nine administrative writes
// recording nothing with the suite green.
func TestEveryRegisteredWriteIsEitherTrailedOrDeliberatelyNot(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		trailed := map[string]bool{}
		for _, act := range administrativeActs {
			trailed[act.id] = true
		}

		registered := map[string]bool{}
		for _, item := range r.api.OpenAPI().Paths {
			for _, operation := range []*huma.Operation{
				item.Post, item.Put, item.Patch, item.Delete,
			} {
				if operation == nil {
					continue
				}
				registered[operation.OperationID] = true
				switch {
				case trailed[operation.OperationID] && outsideTheTrail[operation.OperationID] != "":
					t.Errorf("%s is both driven as a trailed act and listed as outside the trail",
						operation.OperationID)
				case trailed[operation.OperationID], outsideTheTrail[operation.OperationID] != "":
				default:
					t.Errorf("%s %s (%s) is neither trailed nor deliberately outside the trail: "+
						"record it with noteChange, or say in outsideTheTrail why it leaves no row",
						operation.Method, operation.Path, operation.OperationID)
				}
			}
		}

		// The other direction, so a route that is renamed or removed takes
		// its classification with it rather than leaving a line that reads as
		// coverage of something that is not there.
		for id := range trailed {
			if !registered[id] {
				t.Errorf("%s is driven as a trailed act and no longer registered", id)
			}
		}
		for id, why := range outsideTheTrail {
			if !registered[id] {
				t.Errorf("%s is listed as outside the trail (%s) and no longer registered", id, why)
			}
		}

		// A walk that reached nothing looks exactly like a walk that found
		// nothing wrong.
		if len(registered) < 70 {
			t.Errorf("only %d writes were reached, so this proves little", len(registered))
		}
	})
}

// TestEveryAdministrativeChangeIsRecorded drives each of them and reads the
// row back.
//
// Three of the things here silently rewrite what this tool reports — the
// deadline windows, the triage floor, and a support date — and none of them
// recorded who moved it. For a tool whose whole output is evidence, that is
// the evidence being movable with nothing saying that anybody moved it.
//
// The classification above is what catches a route nobody thought about; this
// is what catches a call that was written and does not do what it says.
func TestEveryAdministrativeChangeIsRecorded(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		seen := &seeded{issue: r.embargoed(t)}

		for _, act := range administrativeActs {
			who := act.who
			if who == "" {
				who = "admin"
			}
			got := act.drive
			if got == nil {
				got = func(t *testing.T, r *reach, seen *seeded) *httptest.ResponseRecorder {
					return asPerson(t, r, who, act.method, seen.fill(act.path),
						seen.fill(act.body))
				}
			}
			// Counted before and after, not read off the top.
			//
			// Reading only the newest row lets an act pass with its own write
			// deleted wherever the act above it left a row saying the same
			// three things — which is true of unbinding a group, of
			// withdrawing one's own token, and of taking somebody off a team
			// twice.
			var before changed
			read(t, r, "admin", "/v1/administration/changes?limit=1", &before)

			answered := got(t, r, seen)
			if answered.Code >= 300 {
				t.Fatalf("%s (%s) answered %d: %s",
					act.what, act.id, answered.Code, answered.Body.String())
			}
			if act.keep != nil {
				act.keep(t, seen, answered.Body.Bytes())
			}

			var trail changed
			read(t, r, "admin", "/v1/administration/changes?limit=1", &trail)
			if trail.Total != before.Total+1 {
				t.Fatalf("%s (%s) left %d rows, want 1",
					act.what, act.id, trail.Total-before.Total)
			}
			if len(trail.Items) == 0 {
				t.Fatalf("%s (%s) left no record of who changed it", act.what, act.id)
			}
			newest := trail.Items[0]
			if newest.Kind != act.kind || newest.About != seen.fill(act.about) {
				t.Errorf("%s (%s) recorded %q/%q, want %q/%q", act.what, act.id,
					newest.Kind, newest.About, act.kind, seen.fill(act.about))
			}
			if newest.By != who {
				t.Errorf("%s (%s) was recorded against %q rather than whoever made it",
					act.what, act.id, newest.By)
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
		read(t, r, "admin", "/v1/administration/changes?kind=setting&limit=200", &trail)
		first := trail.Items[len(trail.Items)-1]
		if !first.Unset {
			t.Errorf("the first setting of a value reports a previous one: %+v", first)
		}
	})
}

// TestADeactivationIsRecordedEvenWhenTheRestOfTheActFails pins the order the
// note is written in.
//
// Deactivating somebody ends their sessions and hands their work back, and
// both of those can answer 500 with the deactivation already written. Recorded
// afterwards, that left a person who cannot sign in and nothing saying who
// stopped them — permanently, because the second attempt finds nothing to move
// and returns before reaching the note at all.
func TestADeactivationIsRecordedEvenWhenTheRestOfTheActFails(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		if got := asPerson(t, r, "admin", http.MethodPost, "/v1/people",
			`{"identity":"leaver"}`); got.Code >= 300 {
			t.Fatalf("recording somebody answered %d: %s", got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "admin", http.MethodPut,
			"/v1/people/leaver/deactivation", ""); got.Code >= 300 {
			t.Fatalf("deactivating answered %d: %s", got.Code, got.Body.String())
		}

		// Again: nothing moves, and nothing is recorded a second time. A row
		// per attempt would say somebody was deactivated twice.
		if got := asPerson(t, r, "admin", http.MethodPut,
			"/v1/people/leaver/deactivation", ""); got.Code >= 300 {
			t.Fatalf("deactivating again answered %d: %s", got.Code, got.Body.String())
		}

		var trail changed
		read(t, r, "admin", "/v1/administration/changes?kind=account&limit=200", &trail)
		deactivations := 0
		for _, row := range trail.Items {
			if row.About == "leaver" && row.Became == "deactivated" {
				deactivations++
			}
		}
		if deactivations != 1 {
			t.Errorf("deactivating twice recorded %d rows, want 1", deactivations)
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

// TestAChangeThatCannotBeRecordedIsNotMade pins the act and its record as one
// transaction.
//
// Written after the change with its failure logged, the record lets a setting
// move with nothing saying who moved it — the state REQ-22 says the record
// exists to prevent, reachable without anybody attacking anything.
//
// The trail table is taken away for the length of the act, which is the one
// way to make the record fail without making the change fail first.
func TestAChangeThatCannotBeRecordedIsNotMade(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		if got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.floor",
			`{"value":"medium"}`); got.Code >= 300 {
			t.Fatalf("setting the floor answered %d: %s", got.Code, got.Body.String())
		}

		hide := func(from, to string) {
			t.Helper()
			if _, err := r.db.ExecContext(ctx,
				`ALTER TABLE "`+from+`" RENAME TO "`+to+`"`); err != nil {
				t.Fatalf("cannot rename %q to %q: %v", from, to, err)
			}
		}
		hide("admin_change", "admin_change_hidden")
		got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.floor",
			`{"value":"critical"}`)
		hide("admin_change_hidden", "admin_change")

		if got.Code < 500 {
			t.Errorf("a change nothing could record answered %d, want a refusal", got.Code)
		}
		// The whole of the point: the setting is what it was.
		var offered struct {
			Items []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"items"`
		}
		read(t, r, "admin", "/v1/settings", &offered)
		for _, item := range offered.Items {
			if item.Name != "triage.floor" {
				continue
			}
			if item.Value != "medium" {
				t.Errorf("the floor is %q after a change nothing recorded, want medium",
					item.Value)
			}
			return
		}
		t.Error("the triage floor is not among the settings offered")
	})
}

// TestTheAuditPermissionReadsTheDeploymentAndNoProduct pins both halves of
// what it grants.
//
// The record proving nobody moved the goalposts was readable only by the
// people who can move them: an auditor could read every decision and not the
// deadline policy those decisions were measured against, who held which role
// when they were made, or whether any of it changed.
func TestTheAuditPermissionReadsTheDeploymentAndNoProduct(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		// The deployment's own records, which is the whole of the grant.
		for _, path := range []string{
			"/v1/administration/changes", "/v1/administration/changes.csv",
			"/v1/settings", "/v1/people",
			"/v1/people/admin", "/v1/roles/bindings", "/v1/roles/mode",
		} {
			if got := asPerson(t, r, "auditor", http.MethodGet, path, ""); got.Code != http.StatusOK {
				t.Errorf("an auditor reading %s answered %d: %s",
					path, got.Code, got.Body.String())
			}
		}

		// And no product, and nothing that is not one of those records. What a
		// worker reported quotes what its job was about, and a destination's
		// address is the credential for two of the services it names — so
		// neither is read by the grant that reads the records.
		for _, path := range []string{
			"/v1/products/mine/findings", "/v1/products/mine/builds",
			"/v1/work/set-aside", "/v1/outbound",
		} {
			got := asPerson(t, r, "auditor", http.MethodGet, path, "")
			if got.Code != http.StatusForbidden && got.Code != http.StatusNotFound {
				t.Errorf("an auditor reading %s answered %d, want a refusal: %s",
					path, got.Code, got.Body.String())
			}
		}

		// Every write over those same records stays with the administrator.
		for _, act := range []struct {
			method, path, body string
		}{
			{http.MethodPut, "/v1/settings/triage.floor", `{"value":"high"}`},
			{http.MethodPost, "/v1/people", `{"identity":"someone-else"}`},
			{http.MethodPost, "/v1/roles/bindings", `{"group":"Owners","role":"admin"}`},
			{http.MethodPut, "/v1/roles/mode", `{"mode":"direct"}`},
		} {
			got := asPerson(t, r, "auditor", act.method, act.path, act.body)
			if got.Code != http.StatusForbidden {
				t.Errorf("an auditor sending %s %s answered %d, want 403: %s",
					act.method, act.path, got.Code, got.Body.String())
			}
		}
	})
}

// TestBothThingsHeldOverTheDeploymentAreRecorded pins the record against the
// two grants it is read by.
//
// Written as arms of one switch, a request granting both recorded one of them,
// and the audit permission's arm never ran at all — so the one grant that
// opens the change log was the change that log did not hold. The table above
// classifies by operation, and both of these are a *field* on a route already
// listed as trailed, which is why neither had coverage.
func TestBothThingsHeldOverTheDeploymentAreRecorded(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		if got := asPerson(t, r, "admin", http.MethodPost, "/v1/people",
			`{"identity":"ada"}`); got.Code >= 300 {
			t.Fatalf("recording somebody answered %d: %s", got.Code, got.Body.String())
		}
		// Both at once, against somebody who already exists, which is the
		// request that recorded one of the two.
		if got := asPerson(t, r, "admin", http.MethodPost, "/v1/people",
			`{"identity":"ada","admin":true,"audits":true}`); got.Code >= 300 {
			t.Fatalf("granting both answered %d: %s", got.Code, got.Body.String())
		}

		var trail changed
		read(t, r, "admin", "/v1/administration/changes?kind=account&limit=200", &trail)
		for _, want := range []struct{ was, became string }{
			{"", "administrator"},
			{"", "auditor"},
		} {
			found := false
			for _, row := range trail.Items {
				if row.About == "ada" && row.Became == want.became && row.Unset == (want.was == "") {
					found = true
				}
			}
			if !found {
				t.Errorf("nothing records ada becoming %s: %+v", want.became, trail.Items)
			}
		}

		// And taking one back is recorded with what it was, which is the half
		// an access review reads.
		if got := asPerson(t, r, "admin", http.MethodPost, "/v1/people",
			`{"identity":"ada","audits":false}`); got.Code >= 300 {
			t.Fatalf("withdrawing it answered %d: %s", got.Code, got.Body.String())
		}
		read(t, r, "admin", "/v1/administration/changes?kind=account&limit=200", &trail)
		withdrawn := false
		for _, row := range trail.Items {
			if row.About == "ada" && row.Was == "auditor" && row.Cleared {
				withdrawn = true
			}
		}
		if !withdrawn {
			t.Errorf("nothing records ada ceasing to audit: %+v", trail.Items)
		}
	})
}

// TestNoActHandsItsRecordsFailureToTheCaller walks every trailed route with
// the trail table taken away.
//
// Ten of the forty sites returned the recorder's error straight out of the
// closure, so a failed trail write handed the caller the driver's own message
// — the statement text, and for a connection failure the address and the user
// it tried. That is what `wentWrong` exists to stop, and the way it comes back
// is a new trailed route written in the shape those ten had.
func TestNoActHandsItsRecordsFailureToTheCaller(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		r.scannedWithEvidence(t)
		seen := &seeded{issue: r.embargoed(t)}

		hide := func(from, to string) {
			t.Helper()
			if _, err := r.db.ExecContext(ctx,
				`ALTER TABLE "`+from+`" RENAME TO "`+to+`"`); err != nil {
				t.Fatalf("cannot rename %q to %q: %v", from, to, err)
			}
		}

		examined := 0
		for _, act := range administrativeActs {
			who := act.who
			if who == "" {
				who = "admin"
			}
			hide("admin_change", "admin_change_hidden")
			var got *httptest.ResponseRecorder
			if act.drive != nil {
				got = act.drive(t, r, seen)
			} else {
				got = asPerson(t, r, who, act.method, seen.fill(act.path), seen.fill(act.body))
			}
			hide("admin_change_hidden", "admin_change")
			examined++

			// Whatever the act would otherwise have answered, what it must
			// not answer is anything a driver wrote. Checked by what a
			// failure reads like rather than by the status: some of these
			// refuse before they reach the recorder at all, which is fine.
			body := got.Body.String()
			for _, leaked := range []string{
				"admin_change", "SQL", "no such table", "syntax", "sqlite", "pq:", "Error 1",
			} {
				if strings.Contains(body, leaked) {
					t.Errorf("%s (%s) answered %d with the database's own words: %s",
						act.what, act.id, got.Code, body)
					break
				}
			}
		}
		if examined == 0 {
			t.Fatal("no administrative act was driven, so this checked nothing")
		}
		t.Logf("drove %d administrative acts with the trail table taken away", examined)
	})
}

// TestACaseIsRecordedByTheNamesItResolvedTo pins what a record is composed
// from.
//
// Widening the column does not cover what actually lands in it: a path segment
// carries no length on any route here, and an issue is looked up through a
// normalization that keeps only its first 191 runes — so what resolved and
// what was typed are not the same string, and a record composed from what was
// typed is unbounded. Now that the record is written inside the act, that is
// the act refused rather than a row quietly missing.
//
// Shown with capitals, which is the small case of the same thing: the lookup
// folds them and the stored name does not have them.
func TestACaseIsRecordedByTheNamesItResolvedTo(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		issue := r.embargoed(t)
		typed := strings.ToLower(issue)
		if typed == issue {
			t.Fatalf("the fixture's issue %q is already folded, so this shows nothing", issue)
		}

		at := "/v1/products/mine/issues/" + url.PathEscape(typed) + "/collaborators/reader"
		if got := asPerson(t, r, "private-triage", http.MethodPut, at, ""); got.Code >= 300 {
			t.Fatalf("bringing somebody in answered %d: %s", got.Code, got.Body.String())
		}

		var trail changed
		read(t, r, "admin", "/v1/administration/changes?kind=case&limit=50", &trail)
		if len(trail.Items) == 0 {
			t.Fatal("bringing somebody into a case recorded nothing")
		}
		newest := trail.Items[0]
		if want := "mine · " + issue + " · reader"; newest.About != want {
			t.Errorf("the record says %q, want %q — the names it resolved to", newest.About, want)
		}
	})
}
