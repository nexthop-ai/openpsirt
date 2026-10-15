// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

func TestTheNewEndpointsAnswerRatherThanExist(t *testing.T) {
	// Each of these was added to close a gap the interface work found, and
	// each one is the kind of thing that can be registered, return an empty
	// shape, and look finished. This drives them against a build that has
	// something in it.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)

		// Walking the graph, one step at a time.
		var top struct {
			Items []struct {
				Component string `json:"component"`
				Findings  int    `json:"findings"`
				Children  int    `json:"children"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "reader", "/v1/products/mine/streams/master/variants/broadcom/components", &top)
		if len(top.Items) == 0 {
			t.Fatal("the build reports pulling nothing in")
		}
		var around struct {
			Above []struct {
				Component string `json:"component"`
			} `json:"above"`
			Below []struct {
				Component string `json:"component"`
			} `json:"below"`
		}
		httpapitest.Read(t, r, "reader", "/v1/products/mine/streams/master/variants/broadcom"+
			"/components/libnl-3-200/around", &around)
		if len(around.Above) == 0 {
			t.Errorf("nothing pulls libnl-3-200 in, which cannot be true: %+v", around)
		}

		// The issues at a component, which is what a bulk claim narrows.
		var issues struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
				Severity      string `json:"severity"`
				Places        int    `json:"places"`
				FixedIn       string `json:"fixed_in"`
			} `json:"items"`
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
			"/components/libnl-3-200/issues", &issues)
		if issues.Total != 1 || len(issues.Items) != 1 {
			t.Fatalf("%d issues at the component, want 1", issues.Total)
		}
		// The list a person picks from carries what they need to pick: how bad
		// it is, how much of the build it sits in, and whether there is
		// anywhere to go.
		if issues.Items[0].Severity == "" || issues.Items[0].FixedIn == "" ||
			issues.Items[0].Places == 0 {
			t.Errorf("the list to choose from says nothing to choose on: %+v", issues.Items[0])
		}

		// One claim across a named set.
		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/components/libnl-3-200/decisions",
			`{"vulnerabilities":["CVE-2026-9999"],"outcome":"not-applicable",`+
				`"justification":"vulnerable_code_not_in_execute_path",`+
				`"selected_by":"searched the reports for \"driver\"",`+
				`"reasoning":"These are in drivers absent from our kernel config."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("deciding a set together answered %d: %s", got.Code, got.Body.String())
		}
		var recorded struct {
			Recorded int     `json:"recorded"`
			IDs      []int64 `json:"ids"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		// One per *place*, not one per name. A decision is keyed on a place,
		// so a claim built from one of them would silence one consumer and
		// leave the rest open while reporting that it had covered them.
		var places int
		for _, each := range issues.Items {
			places += each.Places
		}
		if recorded.Recorded != places {
			t.Errorf("recorded %d decisions for %d places, want one each",
				recorded.Recorded, places)
		}

		// And how the set was narrowed is on the record, because "how were
		// these chosen" is the question asked of a bulk judgment later.
		var made struct {
			Decision struct {
				SelectedBy string `json:"selected_by"`
			} `json:"decision"`
		}
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/decisions/%d", recorded.IDs[0]), &made)
		if made.Decision.SelectedBy == "" {
			t.Error("a claim recorded as one of many does not say how the set was narrowed")
		}

		// A deferral with nowhere to say until when is refused rather than
		// recorded as a postponement with no end.
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/components/libnl-3-200/decisions",
			`{"vulnerabilities":["CVE-2026-9999"],"outcome":"deferred",`+
				`"selected_by":"the same search","reasoning":"Not this release."}`,
		); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("deferring with no date answered %d: %s", got.Code, got.Body.String())
		}

		// A name nobody here knows says which name, so a person who pasted a
		// list can fix the list rather than bisect it.
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/components/libnl-3-200/decisions",
			`{"vulnerabilities":["CVE-2026-9999","CVE-1999-0001"],"outcome":"wont-fix",`+
				`"selected_by":"a list somebody pasted","reasoning":"Not worth it."}`,
		); got.Code != http.StatusNotFound ||
			!strings.Contains(got.Body.String(), "CVE-1999-0001") {
			t.Errorf("an unknown issue answered %d without naming it: %s",
				got.Code, got.Body.String())
		}

		// The trend, worked out rather than stored.
		var trend struct {
			Items []struct {
				At   string `json:"at"`
				Open int    `json:"open"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "reader", "/v1/trend?weeks=4", &trend)
		if len(trend.Items) != 4 {
			t.Errorf("asked for four weeks and got %d points", len(trend.Items))
		}
		if trend.Items[len(trend.Items)-1].Open == 0 {
			t.Error("the trend ends with nothing open, but something is")
		}

		// Settings are listed, and one is set.
		var settings struct {
			Items []struct {
				Name    string `json:"name"`
				Value   string `json:"value"`
				Default bool   `json:"default"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "admin", "/v1/settings", &settings)
		if len(settings.Items) == 0 {
			t.Fatal("no settings are listed")
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut,
			"/v1/settings/remediation.due.critical",
			`{"value":"48h"}`); got.Code != http.StatusNoContent {
			t.Errorf("setting a deadline answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestNobodyLearnsWhoHasAnAccountByBeingRefused(t *testing.T) {
	// A name nobody holds and a name somebody holds must come back the same
	// way to anybody not authorized to act on either, or the refusal is a
	// directory of the organization readable by every account.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)

		// Handing back somebody's work is administrative. A reader asking
		// about a real account and a made-up one gets one answer.
		real := httpapitest.AsPerson(t, r, "reader", http.MethodPost,
			"/v1/people/triager/assignments/hand-back", `{}`)
		invented := httpapitest.AsPerson(t, r, "reader", http.MethodPost,
			"/v1/people/nobody-at-all/assignments/hand-back", `{}`)
		if real.Code != invented.Code {
			t.Errorf("releasing a real person's work answered %d and an invented one %d",
				real.Code, invented.Code)
		}
		if real.Code != http.StatusForbidden {
			t.Errorf("a reader releasing somebody's work answered %d, want 403", real.Code)
		}

		// Assigning is the same shape: reading a product is not being able to
		// hand its findings around, so the name is never resolved first.
		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"
		known := httpapitest.AsPerson(t, r, "reader", http.MethodPut, at, `{"person":"triager"}`)
		unknown := httpapitest.AsPerson(t, r, "reader", http.MethodPut, at, `{"person":"nobody-at-all"}`)
		if known.Code != unknown.Code || known.Body.String() != unknown.Body.String() {
			t.Errorf("assigning to a real person answered %d %s and to an invented one %d %s",
				known.Code, known.Body.String(), unknown.Code, unknown.Body.String())
		}
	})
}

func TestASettingThatWouldReadAsUnsetIsRefused(t *testing.T) {
	// Every reader treats zero and negative as unset and falls back to the
	// shipped value, so storing one produces a setting that looks set on the
	// administration screen and does nothing at all.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, value := range []string{"0h", "-48h", "nonsense"} {
			if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut,
				"/v1/settings/remediation.due.critical",
				`{"value":"`+value+`"}`); got.Code != http.StatusUnprocessableEntity {
				t.Errorf("%q was accepted as a deadline: %d %s",
					value, got.Code, got.Body.String())
			}
		}

		// The one setting that is a count rather than a duration is checked as
		// a count. A duration there would be stored and then ignored.
		cap := "/v1/settings/triage.together-cap"
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, cap,
			`{"value":"48h"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a duration was accepted as a count: %d %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, cap,
			`{"value":"0"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a cap of nothing was accepted: %d %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, cap,
			`{"value":"5"}`); got.Code != http.StatusNoContent {
			t.Errorf("setting the cap answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestAnAttachmentSizeAboveItsCeilingIsRefused(t *testing.T) {
	// Every upload is written to scratch space whole as it arrives, and the
	// space is sized for the largest request a route takes.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		at := "/v1/settings/attachment.max-size"
		over := strconv.Itoa(setting.MostAttachmentMaxSize + 1)
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, at,
			`{"value":"`+over+`"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a size past the ceiling was accepted: %d %s", got.Code, got.Body.String())
		}
		most := strconv.Itoa(setting.MostAttachmentMaxSize)
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, at,
			`{"value":"`+most+`"}`); got.Code != http.StatusNoContent {
			t.Errorf("a size at the ceiling answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestTheCallerIsToldWhatTheyMayDoRatherThanFindingOut(t *testing.T) {
	// A screen has to know whether to offer an action before it draws one.
	// Without this the client either offers everything and lets people walk
	// into a refusal, or re-implements the mapping from roles to capabilities
	// and drifts from the one the server actually enforces.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		type can struct {
			Product      string `json:"product"`
			MaySee       bool   `json:"may_see"`
			ReadsPublic  bool   `json:"reads_public"`
			ReadsPrivate bool   `json:"reads_private"`
			MayTriage    bool   `json:"may_triage"`
			MayHide      bool   `json:"may_hide"`
			MayAgree     bool   `json:"may_agree"`
		}
		type who struct {
			Identity string `json:"identity"`
			Name     string `json:"name"`
			Admin    bool   `json:"admin"`
			Kind     string `json:"kind"`
			Reach    []can  `json:"reach"`
		}

		var reader who
		httpapitest.Read(t, r, "reader", "/v1/session/me", &reader)
		if reader.Identity != "reader" || reader.Kind != "person" {
			t.Errorf("a reader is described as %+v", reader)
		}
		if reader.Name == "" {
			t.Error("nothing to show in a header")
		}
		if reader.Admin {
			t.Error("a reader is reported as an administrator")
		}
		if len(reader.Reach) == 0 {
			t.Fatal("a reader reaches no product at all")
		}
		for _, each := range reader.Reach {
			if !each.MaySee || !each.ReadsPublic {
				t.Errorf("%s is listed but cannot be seen", each.Product)
			}
			// Reading what is disclosed is not reading what is not, and it is
			// certainly not deciding. This is the assertion that catches a
			// capability widened by accident.
			if each.ReadsPrivate || each.MayTriage || each.MayHide || each.MayAgree {
				t.Errorf("a reader is offered more than reading in %s: %+v", each.Product, each)
			}
		}

		var triager who
		httpapitest.Read(t, r, "triager", "/v1/session/me", &triager)
		for _, each := range triager.Reach {
			if !each.MayTriage {
				t.Errorf("a triager may not triage %s", each.Product)
			}
			if each.MayHide {
				t.Errorf("a public triager is offered undisclosed findings in %s", each.Product)
			}
		}

		// An administrator reaches everything, which is the one role not held
		// against a product.
		var admin who
		httpapitest.Read(t, r, "admin", "/v1/session/me", &admin)
		if !admin.Admin {
			t.Error("the administrator is not described as one")
		}
		if len(admin.Reach) < len(reader.Reach) {
			t.Errorf("an administrator reaches %d products where a reader reaches %d",
				len(admin.Reach), len(reader.Reach))
		}
	})
}
