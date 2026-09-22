package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// shelf is the obligation list as one person reads it.
type shelf struct {
	Items []struct {
		ID            int64  `json:"id"`
		Vulnerability string `json:"vulnerability"`
		Product       string `json:"product"`
		Windows       []struct {
			Window struct {
				Name string `json:"name"`
			} `json:"window"`
			EndsAt   string `json:"ends_at"`
			Passed   bool   `json:"passed"`
			Answered bool   `json:"answered"`
		} `json:"windows"`
		Told []struct {
			Recipient string `json:"recipient"`
			WindowID  int64  `json:"window_id"`
			Window    string `json:"window"`
		} `json:"told"`
	} `json:"items"`
}

// attackedAt records that "mine" was exploited through the scanned issue, as
// having become known at a moment, and returns the record.
func (r *reach) attackedAt(t *testing.T, known time.Time) int64 {
	t.Helper()
	got := asPerson(t, r, "private-triage", http.MethodPost,
		"/v1/products/mine/issues/CVE-2026-9999/exploited-here",
		`{"known_at":"`+known.UTC().Format(time.RFC3339)+`",`+
			`"grounds":"A customer sent packet captures."}`)
	if got.Code != http.StatusCreated {
		t.Fatalf("recording answered %d: %s", got.Code, got.Body.String())
	}
	var kept struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &kept); err != nil {
		t.Fatal(err)
	}
	return kept.ID
}

// declared adds a window as the administrator and returns its identifier.
func (r *reach) declared(t *testing.T, name string, hours int) int64 {
	t.Helper()
	got := asPerson(t, r, "admin", http.MethodPost, "/v1/obligation-windows",
		fmt.Sprintf(`{"name":%q,"hours":%d}`, name, hours))
	if got.Code != http.StatusCreated {
		t.Fatalf("declaring a window answered %d: %s", got.Code, got.Body.String())
	}
	var window struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &window); err != nil {
		t.Fatal(err)
	}
	return window.ID
}

func TestAWindowAfterAnAttackIsWatchedUntilSomebodyOutsideIsRecordedAsTold(t *testing.T) {
	// The shelf and the condition it raises: running from the moment the
	// attack became known, said to whoever may act on the product, and
	// cleared by a notice that names the window rather than by anybody
	// dismissing it.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		early := r.declared(t, "Early warning", 24)
		r.declared(t, "Final report", 24*14)
		record := r.attackedAt(t, time.Now().UTC().Add(-2*time.Hour))

		var seen shelf
		read(t, r, "private-triage", "/v1/obligations", &seen)
		if len(seen.Items) != 1 || len(seen.Items[0].Windows) != 2 {
			t.Fatalf("the shelf holds %+v, want one incident with two windows", seen)
		}
		if seen.Items[0].Windows[0].Passed || seen.Items[0].Windows[0].Answered {
			t.Errorf("a window two hours into a day reads as %+v", seen.Items[0].Windows[0])
		}

		if open := r.alerts(t, "private-triage", "obligation-open"); len(open) != 2 {
			t.Fatalf("two running windows raised %d notices: %v", len(open), open)
		}
		// Nobody who may not act on the product hears of it.
		if open := r.alerts(t, "outsider", "obligation-open"); len(open) != 0 {
			t.Errorf("somebody with nothing on the product was told: %v", open)
		}

		if got := asPerson(t, r, "private-triage", http.MethodPost,
			fmt.Sprintf("/v1/exploited-here/%d/told", record),
			fmt.Sprintf(`{"recipient":"ENISA","told_at":%q,"said":"An attack.","window":%d}`,
				time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), early),
		); got.Code != http.StatusCreated {
			t.Fatalf("recording a notice answered %d: %s", got.Code, got.Body.String())
		}
		open := r.alerts(t, "private-triage", "obligation-open")
		if len(open) != 1 || !contains(open[0], "Final report") {
			t.Errorf("after the early warning was answered, the running ones are %v", open)
		}

		read(t, r, "private-triage", "/v1/obligations", &seen)
		if !seen.Items[0].Windows[0].Answered {
			t.Error("the answered window does not read as answered on the shelf")
		}
		if len(seen.Items[0].Told) != 1 || seen.Items[0].Told[0].Window != "Early warning" ||
			seen.Items[0].Told[0].WindowID != early {
			t.Errorf("the notice is not on the shelf with its window: %+v", seen.Items[0].Told)
		}
	})
}

func TestAWindowThatEndedWithNobodyToldIsSaidAsPassed(t *testing.T) {
	// The two conditions clear differently, so the running one closes when
	// the end arrives and the passed one opens.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		r.declared(t, "Early warning", 24)
		r.attackedAt(t, time.Now().UTC().Add(-30*time.Hour))

		if open := r.alerts(t, "private-triage", "obligation-open"); len(open) != 0 {
			t.Errorf("a window that has ended is still said to be running: %v", open)
		}
		if passed := r.alerts(t, "private-triage", "obligation-passed"); len(passed) != 1 {
			t.Errorf("a window that ended with nobody told raised %d notices", len(passed))
		}
	})
}

func TestNoWindowIsWatchedUntilADeploymentDeclaresOne(t *testing.T) {
	// None ships. A deployment under no obligation declares none and hears
	// nothing; the record still stands on the shelf.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		r.attackedAt(t, time.Now().UTC().Add(-30*time.Hour))

		var seen shelf
		read(t, r, "private-triage", "/v1/obligations", &seen)
		if len(seen.Items) != 1 || len(seen.Items[0].Windows) != 0 {
			t.Errorf("with no window declared the shelf holds %+v", seen)
		}
		for _, kind := range []string{"obligation-open", "obligation-passed"} {
			if told := r.alerts(t, "private-triage", kind); len(told) != 0 {
				t.Errorf("with no window declared, %s said %v", kind, told)
			}
		}
	})
}

func TestTheShelfIsNotReadBySomebodyWhoMayNotBeToldOfTheIssue(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		r.attackedAt(t, time.Now().UTC().Add(-time.Hour))

		var seen shelf
		read(t, r, "outsider", "/v1/obligations", &seen)
		if len(seen.Items) != 0 {
			t.Errorf("somebody with nothing on the product was shown %+v", seen)
		}
	})
}

// undisclosed makes every finding the fixture scanned undisclosed.
func (r *reach) undisclosed(t *testing.T) {
	t.Helper()
	if _, err := r.db.DB.NewUpdate().Table("finding").
		Set("visibility = ?", "private").Where("1 = 1").Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestAnAttackThroughAnUndisclosedIssueReachesOnlyWhoMayReadIt(t *testing.T) {
	// Somebody who triages the product's public findings may not be told an
	// undisclosed issue exists, on the shelf or in a notification. The
	// notification is a second place the rule has to hold, and the one a
	// reader does not go looking for.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		r.undisclosed(t)
		r.declared(t, "Early warning", 24)
		r.attackedAt(t, time.Now().UTC().Add(-time.Hour))

		var seen shelf
		read(t, r, "triager", "/v1/obligations", &seen)
		if len(seen.Items) != 0 {
			t.Errorf("a public triager was shown an undisclosed attack: %+v", seen)
		}
		read(t, r, "private-triage", "/v1/obligations", &seen)
		if len(seen.Items) != 1 {
			t.Errorf("a private triager was shown %d incidents, want the one", len(seen.Items))
		}

		if told := r.alerts(t, "triager", "obligation-open"); len(told) != 0 {
			t.Errorf("a public triager was told of an undisclosed attack: %v", told)
		}
		// Not written for them at all. Every read of the notifications
		// narrows again, so the list above would stay empty if the sweep
		// wrote one; what leaves this deployment by mail or webhook is
		// composed from the row.
		written, err := r.db.DB.NewSelect().TableExpr(`"notification" AS "n"`).
			Join(`JOIN "person" AS "p" ON p.id = n.person_id`).
			Where("p.identity = ?", "triager").
			Where("n.kind = ?", "obligation-open").
			Where("n.cleared_at IS NULL").
			Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if written != 0 {
			t.Errorf("the sweep wrote %d notices of an undisclosed attack for a public triager",
				written)
		}
		if told := r.alerts(t, "private-triage", "obligation-open"); len(told) != 1 {
			t.Errorf("a private triager was told %d times, want once", len(told))
		}
	})
}

func TestARunningWindowStopsBeingSaidWhenItsWindowOrItsRecordGoes(t *testing.T) {
	// Every way a running window ends that is not a notice: the window is
	// retired, or the record it counts from is cleared. Nobody dismisses it.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		early := r.declared(t, "Early warning", 24)
		r.declared(t, "Notification", 72)
		record := r.attackedAt(t, time.Now().UTC().Add(-time.Hour))
		if open := r.alerts(t, "private-triage", "obligation-open"); len(open) != 2 {
			t.Fatalf("two running windows raised %d notices", len(open))
		}

		if got := asPerson(t, r, "admin", http.MethodDelete,
			fmt.Sprintf("/v1/obligation-windows/%d", early), ""); got.Code != http.StatusNoContent {
			t.Fatalf("retiring answered %d: %s", got.Code, got.Body.String())
		}
		open := r.alerts(t, "private-triage", "obligation-open")
		if len(open) != 1 || !contains(open[0], "Notification") {
			t.Errorf("after retiring the early warning, the running ones are %v", open)
		}

		if got := asPerson(t, r, "private-triage", http.MethodDelete,
			fmt.Sprintf("/v1/exploited-here/%d", record),
			`{"because":"The captures were of a different deployment."}`,
		); got.Code != http.StatusNoContent {
			t.Fatalf("clearing answered %d: %s", got.Code, got.Body.String())
		}
		if open := r.alerts(t, "private-triage", "obligation-open"); len(open) != 0 {
			t.Errorf("a cleared record still has a running window: %v", open)
		}
	})
}

func TestANoticeNamingAPassedWindowClearsIt(t *testing.T) {
	// A notice given late is still a notice, and the window it names stops
	// being said as passed with nobody told.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		early := r.declared(t, "Early warning", 24)
		record := r.attackedAt(t, time.Now().UTC().Add(-30*time.Hour))
		if passed := r.alerts(t, "private-triage", "obligation-passed"); len(passed) != 1 {
			t.Fatalf("a passed window raised %d notices", len(passed))
		}

		if got := asPerson(t, r, "private-triage", http.MethodPost,
			fmt.Sprintf("/v1/exploited-here/%d/told", record),
			fmt.Sprintf(`{"recipient":"ENISA","told_at":%q,"said":"An attack.","window":%d}`,
				time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), early),
		); got.Code != http.StatusCreated {
			t.Fatalf("recording a notice answered %d: %s", got.Code, got.Body.String())
		}
		if passed := r.alerts(t, "private-triage", "obligation-passed"); len(passed) != 0 {
			t.Errorf("a passed window a notice names is still said: %v", passed)
		}
	})
}

func TestTheListABulkJudgmentIsPickedFromMarksAnAttackedIssue(t *testing.T) {
	// A judgment over a selection reaching an attacked issue is refused
	// whole, so the list it is picked from says which issue that is.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/components/libnl-3-200/issues"
		var picked struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
				ExploitedHere bool   `json:"exploited_here"`
			} `json:"items"`
		}
		read(t, r, "private-triage", at, &picked)
		if len(picked.Items) == 0 || picked.Items[0].ExploitedHere {
			t.Fatalf("before any record the list reads %+v", picked)
		}
		r.attackedAt(t, time.Now().UTC().Add(-time.Hour))
		read(t, r, "private-triage", at, &picked)
		if !picked.Items[0].ExploitedHere {
			t.Errorf("after the record the list reads %+v", picked)
		}
	})
}

func TestTheWindowsInForceAreReadByAnybodySignedIn(t *testing.T) {
	// Whoever records a notice names a window, so they have to be able to
	// read which windows there are without administering anything.
	twoReach(t, func(t *testing.T, r *reach) {
		r.declared(t, "Notification", 72)
		r.declared(t, "Early warning", 24)
		var windows struct {
			Items []struct {
				Name  string `json:"name"`
				Hours int    `json:"hours"`
			} `json:"items"`
		}
		read(t, r, "triager", "/v1/obligation-windows", &windows)
		if len(windows.Items) != 2 || windows.Items[0].Name != "Early warning" {
			t.Errorf("the windows read as %+v, want both, shortest first", windows.Items)
		}
	})
}

func TestAWindowOrANoticeRefusedSaysWhy(t *testing.T) {
	// Each refusal as a caller meets it: which request, and what status.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		r.declared(t, "Early warning", 24)
		record := r.attackedAt(t, time.Now().UTC().Add(-time.Hour))
		told := fmt.Sprintf("/v1/exploited-here/%d/told", record)
		now := time.Now().UTC().Format(time.RFC3339)

		for _, tc := range []struct {
			what, who, method, path, body string
			want                          int
		}{
			{"a second window under one name", "admin", http.MethodPost, "/v1/obligation-windows",
				`{"name":"EARLY WARNING","hours":48}`, http.StatusConflict},
			{"a window nobody declared changed", "admin", http.MethodPut,
				"/v1/obligation-windows/9999", `{"name":"Late","hours":48}`, http.StatusNotFound},
			{"a window nobody declared retired", "admin", http.MethodDelete,
				"/v1/obligation-windows/9999", "", http.StatusNotFound},
			{"a triager declaring a window", "private-triage", http.MethodPost,
				"/v1/obligation-windows", `{"name":"Mine","hours":48}`, http.StatusForbidden},
			{"a notice naming no window in force", "private-triage", http.MethodPost, told,
				`{"recipient":"ENISA","told_at":"` + now + `","said":"An attack.","window":9999}`,
				http.StatusUnprocessableEntity},
			{"a notice about a record nobody kept", "private-triage", http.MethodPost,
				"/v1/exploited-here/9999/told",
				`{"recipient":"ENISA","told_at":"` + now + `","said":"An attack."}`,
				http.StatusNotFound},
			{"a notice with no moment", "private-triage", http.MethodPost, told,
				`{"recipient":"ENISA","told_at":"yesterday","said":"An attack."}`,
				http.StatusUnprocessableEntity},
		} {
			if got := asPerson(t, r, tc.who, tc.method, tc.path, tc.body); got.Code != tc.want {
				t.Errorf("%s answered %d, want %d: %s", tc.what, got.Code, tc.want, got.Body.String())
			}
		}
	})
}
