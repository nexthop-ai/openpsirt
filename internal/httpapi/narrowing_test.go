package httpapi_test

import (
	"net/http"
	"testing"
)

// previewAs is the routing preview read as somebody in particular, because
// what it answers is supposed to depend on that.
func (r *reach) previewAs(t *testing.T, who, query string) caught {
	t.Helper()
	var out caught
	read(t, r, who, "/v1/products/mine/routing-rules/preview?"+query, &out)
	return out
}

func TestTheRoutingPreviewCountsOnlyWhatTheAskerMayRead(t *testing.T) {
	// counts, aggregates and searches are narrowed like rows. A preview is
	// all three at once — three numbers and a list of component names —
	// and the difference between what it says and what the same person's
	// findings list says is the size of what they may not see.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		open := r.previewAs(t, "triager", "beneath=libnl-3-200")
		if open.Work == 0 {
			t.Fatalf("the preview matched nothing before an embargo existed: %+v", open)
		}

		r.embargoed(t)

		if got := r.previewAs(t, "triager", "beneath=libnl-3-200"); got.Work != open.Work {
			t.Errorf("a public-only reader's preview moved from %d to %d when an "+
				"undisclosed finding was recorded", open.Work, got.Work)
		}
		if got := r.previewAs(t, "private-triage", "beneath=libnl-3-200"); got.Work <= open.Work {
			t.Errorf("somebody who may read undisclosed findings previews %d, "+
				"want more than the %d a public-only reader sees", got.Work, open.Work)
		}
	})
}

func TestTheWordsInUseAreOnlyThoseOnFindingsTheAskerMayRead(t *testing.T) {
	// A tag is free text somebody typed while triaging. On an embargo it says
	// what the embargo is about, and the tag row carries no visibility of its
	// own — it is keyed on the issue and the component, either of which names
	// an undisclosed finding as readily as a public one.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		hidden := r.embargoed(t)

		if put := asPerson(t, r, "private-triage", http.MethodPut,
			findingAt(hidden)+"/tags/waiting-on-reporter", ""); put.Code != http.StatusNoContent {
			t.Fatalf("marking the embargo answered %d: %s", put.Code, put.Body.String())
		}

		words := func(t *testing.T, who string) []string {
			t.Helper()
			var out struct {
				Items []string `json:"items"`
			}
			read(t, r, who, "/v1/products/mine/tags", &out)
			return out.Items
		}
		for _, word := range words(t, "triager") {
			if word == "waiting-on-reporter" {
				t.Errorf("a public-only reader is offered a word written on an "+
					"undisclosed finding: %v", words(t, "triager"))
			}
		}
		var found bool
		for _, word := range words(t, "private-triage") {
			if word == "waiting-on-reporter" {
				found = true
			}
		}
		if !found {
			t.Errorf("somebody who may read the finding is not offered its own word: %v",
				words(t, "private-triage"))
		}
	})
}

func TestAProductSomebodyHoldsNothingOnIsNotDeclaredAsFarAsTheyKnow(t *testing.T) {
	// Resolving the name and narrowing the rows afterwards answers 200
	// with nothing for a product somebody holds nothing on and 404 for a
	// name nobody ever declared, which reads the deployment's product list
	// one guess at a time.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		hidden := asPerson(t, r, "triager", http.MethodGet, "/v1/decisions?product=theirs", "")
		missing := asPerson(t, r, "triager", http.MethodGet, "/v1/decisions?product=nosuch", "")
		if hidden.Code != missing.Code {
			t.Errorf("a product held by somebody else answers %d and a name nobody "+
				"declared answers %d", hidden.Code, missing.Code)
		}
		if hidden.Code != http.StatusNotFound {
			t.Errorf("a product this caller holds nothing on answered %d, want 404: %s",
				hidden.Code, hidden.Body.String())
		}
	})
}

func TestAFilterAskedTwiceAsksForBoth(t *testing.T) {
	// "Undecided or waiting" is a question one value cannot ask, so the
	// state and outcome filters take a list. What makes that work is the
	// wire form: the generated client repeats the parameter, and a
	// parameter the server reads as one comma-separated value would
	// silently keep only the first word — narrowing to less than was asked
	// for, which looks like an answer rather than like a mistake.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		r.claimed(t, "triager", "CVE-2026-9999", "linux-image",
			`{"outcome":"not-applicable",`+
				`"justification":"vulnerable_code_not_in_execute_path",`+
				`"reasoning":"The tracker is compiled out of this kernel."}`)

		total := func(t *testing.T, query string) int {
			t.Helper()
			var page struct {
				Total int `json:"total"`
			}
			read(t, r, "triager", "/v1/products/mine/findings?"+query, &page)
			return page.Total
		}
		waiting := total(t, "state=waiting")
		undecided := total(t, "state=undecided")
		if waiting != 1 || undecided != 1 {
			t.Fatalf("one decided of two reads as %d waiting and %d undecided",
				waiting, undecided)
		}
		if both := total(t, "state=undecided&state=waiting"); both != 2 {
			t.Errorf("asking for both states returned %d rows, want the two; "+
				"only the first word reached the server", both)
		}
	})
}
