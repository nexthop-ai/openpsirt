// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"strings"
	"testing"
)

// A person page is an administrator's surface. Every other read of somebody's
// notifications is somebody reading their own, and this one is the exception
// that exists so a leak can be investigated — so anybody who is not an
// administrator is refused, whatever else they hold.
func TestOnlyAnAdministratorReadsAPersonWhole(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		for _, who := range []string{"reader", "triager", "approver", ""} {
			got := r.body(t, who, http.MethodGet, "/v1/people/admin")
			// Refused, and refused as a refusal. "not 200" would be
			// satisfied by a fault, and a control that answers 500 is one
			// nobody can tell from a broken deployment.
			if who == "" {
				if got.code != http.StatusUnauthorized {
					t.Errorf("a request from nobody answered %d, want 401", got.code)
				}
				continue
			}
			if got.code != http.StatusForbidden {
				t.Errorf("%q reading a person page answered %d, want 403: %s",
					who, got.code, got.text)
			}
		}
		var body map[string]any
		read(t, r, "admin", "/v1/people/triager", &body)
		if body["identity"] != "triager" {
			t.Errorf("the page is about %v, want triager", body["identity"])
		}
	})
}

// The record of what somebody was told is not narrowed by what they may read
// now — that is the whole point of asking — but it is still only an
// administrator who may ask. The narrowing that does apply is on the area they
// read themselves, which is pinned in the notify package.
func TestAPersonPageCarriesWhatTheyHoldAndWhatTheyWereTold(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		var body struct {
			Identity  string `json:"identity"`
			ToldTotal int    `json:"told_total"`
			HeldTotal int    `json:"held_total"`
			Holds     []struct {
				Product   string `json:"product"`
				Role      string `json:"role"`
				Effective bool   `json:"effective"`
			} `json:"holds"`
			Record struct {
				Proposed  int `json:"proposed"`
				Approved  int `json:"approved"`
				Withdrawn int `json:"withdrawn"`
			} `json:"record"`
		}
		read(t, r, "admin", "/v1/people/triager", &body)
		if len(body.Holds) == 0 {
			t.Error("somebody who holds a role reads as holding nothing")
		}
		// The counts are answerable even where nothing has been proposed;
		// zero and absent are different answers and this one is a number.
		if body.Record.Proposed < 0 || body.Record.Approved < 0 || body.Record.Withdrawn < 0 {
			t.Errorf("the record reads as %+v", body.Record)
		}
		if body.ToldTotal < 0 || body.HeldTotal < 0 {
			t.Errorf("a total came back negative: told %d, held %d", body.ToldTotal, body.HeldTotal)
		}
	})
}

// A name nobody holds answers the same way as a name somebody holds that the
// caller may not reach: 404. Resolving first and refusing after would make the
// refusal informative, which turns a lookup into a directory.
func TestAPersonPageSaysNothingAboutWhoExists(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		missing := r.body(t, "admin", http.MethodGet, "/v1/people/nobody-at-all")
		if missing.code != http.StatusNotFound {
			t.Errorf("a name nobody holds answered %d, want 404", missing.code)
		}
		// And to somebody who may not ask at all, a name that does exist and a
		// name that does not answer alike.
		real1 := r.body(t, "triager", http.MethodGet, "/v1/people/admin")
		fake := r.body(t, "triager", http.MethodGet, "/v1/people/nobody-at-all")
		if real1.code != fake.code {
			t.Errorf("a real name answered %d and an invented one %d, which tells them apart",
				real1.code, fake.code)
		}
	})
}

// Leaving is an administrator's act, it is immediate, and it is not a
// deletion. The one refusal that is not about roles is deactivating yourself:
// an administrator who does it leaves nobody able to undo it.
func TestLeavingIsRecordedAndCannotLockOutWhoeverRecordsIt(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		// Their own account. Refused before anything is written, so the
		// deployment still has somebody who can administer it.
		self := r.body(t, "admin", http.MethodPut, "/v1/people/admin/deactivation")
		if self.code != http.StatusConflict {
			t.Errorf("an administrator deactivated themselves: %d %s", self.code, self.text)
		}

		// Somebody else, twice. The second says so and does not move the date.
		first := r.body(t, "admin", http.MethodPut, "/v1/people/triager/deactivation")
		if first.code != http.StatusOK {
			t.Fatalf("deactivating somebody answered %d: %s", first.code, first.text)
		}
		if strings.Contains(first.text, `"already":true`) {
			t.Error("the first deactivation reported that they had already left")
		}
		again := r.body(t, "admin", http.MethodPut, "/v1/people/triager/deactivation")
		if again.code != http.StatusOK || !strings.Contains(again.text, `"already":true`) {
			t.Errorf("deactivating twice answered %d: %s", again.code, again.text)
		}

		// And they are out, at once, on the path a browser uses.
		gone := r.body(t, "triager", http.MethodGet, "/v1/findings")
		if gone.code == http.StatusOK {
			t.Error("somebody who has left still reads findings")
		}

		// Not a deletion: they are still a person, and still named by the
		// record. The page about them still answers.
		var body map[string]any
		read(t, r, "admin", "/v1/people/triager", &body)
		if body["identity"] != "triager" {
			t.Errorf("somebody who left is no longer readable: %v", body)
		}

		// Back again, with what they still hold.
		back := r.body(t, "admin", http.MethodDelete, "/v1/people/triager/deactivation")
		if back.code != http.StatusNoContent {
			t.Fatalf("reactivating answered %d: %s", back.code, back.text)
		}
		if returned := r.body(t, "triager", http.MethodGet, "/v1/findings"); returned.code != http.StatusOK {
			t.Errorf("somebody brought back answered %d: %s", returned.code, returned.text)
		}
	})
}

// Only an administrator may record that somebody left. Anybody else asking is
// refused as a refusal rather than as a fault.
func TestOnlyAnAdministratorRecordsThatSomebodyLeft(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		for _, who := range []string{"reader", "triager", "approver"} {
			got := r.body(t, who, http.MethodPut, "/v1/people/reader/deactivation")
			if got.code != http.StatusForbidden {
				t.Errorf("%q deactivated somebody: %d %s", who, got.code, got.text)
			}
		}
	})
}
