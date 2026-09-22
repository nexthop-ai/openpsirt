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
		if len(seen.Items[0].Told) != 1 || seen.Items[0].Told[0].Window != "Early warning" {
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
