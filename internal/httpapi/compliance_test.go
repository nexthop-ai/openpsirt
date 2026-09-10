package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestADeferralIsNotCountedAsAFailure(t *testing.T) {
	// A rate that counted an approved deferral as a failure would punish
	// the deliberate act the deferral mechanism exists to make possible,
	// and within a quarter people stop deferring and start letting things
	// run late silently.
	twoReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)

		rate := func(t *testing.T, word string) struct {
			Closed   int `json:"closed"`
			Met      int `json:"met"`
			Late     int `json:"late"`
			Deferred int `json:"deferred"`
			Overdue  int `json:"overdue"`
		} {
			t.Helper()
			var out struct {
				Items []struct {
					Severity string `json:"severity"`
					Closed   int    `json:"closed"`
					Met      int    `json:"met"`
					Late     int    `json:"late"`
					Deferred int    `json:"deferred"`
					Overdue  int    `json:"overdue"`
				} `json:"items"`
			}
			read(t, r, "triager", "/v1/compliance?product=mine", &out)
			// Every band is present even where it is empty: a rate table with
			// rows missing reads as one that has been narrowed.
			if len(out.Items) != 4 {
				t.Fatalf("the rate reports %d bands, want the four", len(out.Items))
			}
			for _, each := range out.Items {
				if each.Severity == word {
					return struct {
						Closed   int `json:"closed"`
						Met      int `json:"met"`
						Late     int `json:"late"`
						Deferred int `json:"deferred"`
						Overdue  int `json:"overdue"`
					}{each.Closed, each.Met, each.Late, each.Deferred, each.Overdue}
				}
			}
			t.Fatalf("no band called %q", word)
			return struct {
				Closed   int `json:"closed"`
				Met      int `json:"met"`
				Late     int `json:"late"`
				Deferred int `json:"deferred"`
				Overdue  int `json:"overdue"`
			}{}
		}

		// Past its deadline and nobody has said anything: plainly late.
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("due_at = ?", time.Now().UTC().AddDate(0, 0, -3)).
			Where("1 = 1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := rate(t, "high"); got.Overdue != 1 || got.Deferred != 0 {
			t.Errorf("something late with nothing said reports %+v, want one overdue", got)
		}

		// Somebody proposes a deferral long enough to need a second person.
		// Until they agree it is not in force, so it neither counts as
		// deferred nor stops the finding being late — otherwise the rate
		// hides lateness on nothing more than somebody having typed a
		// proposal, and one person takes their own work off the report.
		until := time.Now().UTC().AddDate(0, 0, 300).Format(time.DateOnly)
		made := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/places/"+place+"/decision",
			`{"outcome":"deferred","deferred_until":"`+until+
				`","reasoning":"Scheduled for the next release."}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("deferring answered %d: %s", made.Code, made.Body.String())
		}
		var proposed struct {
			ClaimID       int64 `json:"claim_id"`
			NeedsApproval bool  `json:"needs_approval"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &proposed); err != nil {
			t.Fatalf("decode: %v (%s)", err, made.Body.String())
		}
		if !proposed.NeedsApproval {
			t.Fatalf("a thirty-day deferral stood on its own, so this test " +
				"cannot tell an agreed one from a proposed one")
		}
		if got := rate(t, "high"); got.Deferred != 0 || got.Overdue != 1 {
			t.Errorf("a deferral nobody has agreed to reports %+v, want it "+
				"still overdue and not yet deferred", got)
		}

		// Agreed. Now it stops being late and becomes its own number — not a
		// success, not a failure, and visible.
		if ok := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", proposed.ClaimID),
			`{}`); ok.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", ok.Code, ok.Body.String())
		}
		got := rate(t, "high")
		if got.Deferred != 1 {
			t.Errorf("a standing deferral reports %+v, want it counted as deferred", got)
		}
		if got.Overdue != 0 {
			t.Errorf("a deferral is still being counted as late: %+v", got)
		}
	})
}

func TestTheListFiltersOnWhenThingsHappened(t *testing.T) {
	// An operational convenience with no compliance claim attached, which
	// is the honest description: it is what an as_of view was really being
	// reached for, at a fraction of the cost.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		count := func(t *testing.T, query string) int {
			t.Helper()
			var page struct {
				Total int `json:"total"`
			}
			read(t, r, "triager", "/v1/products/mine/findings?"+query, &page)
			return page.Total
		}
		yesterday := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
		tomorrow := time.Now().UTC().AddDate(0, 0, 1).Format(time.DateOnly)

		if got := count(t, "opened_after="+yesterday); got != 1 {
			t.Errorf("opened since yesterday is %d rows, want the one seeded now", got)
		}
		if got := count(t, "opened_after="+tomorrow); got != 0 {
			t.Errorf("opened after tomorrow is %d rows", got)
		}
		// Nothing has been claimed about, so nothing was proposed after
		// anything.
		if got := count(t, "proposed_after="+yesterday); got != 0 {
			t.Errorf("proposed since yesterday is %d rows in a fixture nobody decided", got)
		}
		// And a date nothing can read is refused rather than ignored.
		if got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/findings?opened_after=last+week", ""); got.Code < 400 {
			t.Errorf("a date nothing can read answered %d", got.Code)
		}
	})
}

func TestTheRateRefusesAMissingProductRatherThanFailing(t *testing.T) {
	// Its own description says a product is required. The store said so with a
	// plain error nothing recognized, which fell through to the answer given
	// for a write that broke — so a caller who left out a parameter was told
	// the server had failed, on a read-only endpoint, in a sentence about
	// something not being recorded. Every other endpoint taking the same
	// selection answers 200 without a product, so this one has to say why it
	// is different rather than break.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		got := asPerson(t, r, "triager", http.MethodGet, "/v1/compliance", "")
		if got.Code != http.StatusUnprocessableEntity {
			t.Errorf("asking for a rate with no product answered %d, want 422: %s",
				got.Code, got.Body.String())
		}
		if ok := asPerson(t, r, "triager", http.MethodGet,
			"/v1/compliance?product=mine", ""); ok.Code != http.StatusOK {
			t.Errorf("asking for a rate about a product answered %d: %s",
				ok.Code, ok.Body.String())
		}
	})
}

func TestTheRateCountsTheSameThingTheListDoes(t *testing.T) {
	// Counted per row, one flaw in one library that two packages pull in
	// was two late things here and one late thing on the findings list
	// beside it, and both numbers carry the same name. On a real kernel
	// the two were about thirty-seven apart. The unit of work is what
	// somebody decides about — one issue at one component — so that is
	// what the rate counts.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedAtTwoPlaces(t)

		var listed struct {
			Total int `json:"total"`
			Items []struct {
				Places int `json:"places"`
			} `json:"items"`
		}
		read(t, r, "triager", "/v1/products/mine/findings", &listed)
		if listed.Total != 1 {
			t.Fatalf("the findings list reports %d rows for one issue in one "+
				"component, want one", listed.Total)
		}
		if listed.Items[0].Places != 2 {
			t.Fatalf("the fixture put the issue at %d places, want two, so this "+
				"test cannot tell a place from a thing decided about",
				listed.Items[0].Places)
		}

		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("due_at = ?", time.Now().UTC().AddDate(0, 0, -3)).
			Where("1 = 1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		var out struct {
			Items []struct {
				Severity string `json:"severity"`
				Overdue  int    `json:"overdue"`
			} `json:"items"`
		}
		read(t, r, "triager", "/v1/compliance?product=mine", &out)
		for _, band := range out.Items {
			if band.Severity != "high" {
				continue
			}
			if band.Overdue != listed.Total {
				t.Errorf("the rate reports %d overdue where the list beside it "+
					"reports %d rows: the two are counting different things",
					band.Overdue, listed.Total)
			}
			return
		}
		t.Fatal("no band called \"high\"")
	})
}
