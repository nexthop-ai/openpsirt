// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

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
		at := "/v1/products/mine/branches-and-tags/master/variants/broadcom" +
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
		cap := "/v1/settings/triage.bulk-decision-cap"
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
