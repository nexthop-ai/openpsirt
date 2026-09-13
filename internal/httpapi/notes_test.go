package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// The routes a note is reached by, as one table so a role that reaches a
// thread by one and not the other cannot hide between two tests.
const (
	notesHere  = "/v1/products/mine/issues/CVE-2026-9999/notes"
	notesThere = "/v1/products/theirs/issues/CVE-2026-9999/notes"
)

func TestReadingAProductDoesNotCarryWritingANoteInIt(t *testing.T) {
	// A note records no judgment, which is the whole of what it is for — and
	// writing one is still saying something on the record about work. So the
	// matrix is the same shape as every other write here: reading the product
	// is not enough, and triage on it is.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		const note = `{"body":"Upstream says a patch lands next week."}`

		for _, each := range []struct {
			who  string
			want int
		}{
			// Triage here, which is what writing asks for.
			{"triager", http.StatusCreated},
			{"private-triage", http.StatusCreated},
			// Reading here, which is not.
			{"reader", http.StatusForbidden},
			{"private", http.StatusForbidden},
			// The capability with no triage right under it.
			{"approver", http.StatusNotFound},
			// Nobody at all.
			{"", http.StatusUnauthorized},
		} {
			got := asPerson(t, r, each.who, http.MethodPost, notesHere, note)
			if got.Code != each.want {
				t.Errorf("%q writing a note answered %d, want %d: %s",
					each.who, got.Code, each.want, got.Body.String())
			}
		}
	})
}

func TestANoteInAProductYouHoldNothingOnReadsAsNotThere(t *testing.T) {
	// A note carries what somebody wrote about an issue, so "you may not read
	// this" about a product somebody holds nothing on says the issue is there.
	// A product nobody holds and a product that does not exist answer alike.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)

		for _, path := range []string{notesThere, "/v1/products/nobodys/issues/CVE-2026-9999/notes"} {
			got := asPerson(t, r, "triager", http.MethodGet, path, "")
			if got.Code != http.StatusNotFound {
				t.Errorf("reading %s answered %d, want the words an undeclared product gets: %s",
					path, got.Code, got.Body.String())
			}
			wrote := asPerson(t, r, "triager", http.MethodPost, path,
				`{"body":"Probing."}`)
			if wrote.Code != http.StatusNotFound {
				t.Errorf("writing into %s answered %d, want the same: %s",
					path, wrote.Code, wrote.Body.String())
			}
		}
	})
}

func TestANoteIsReadBackInTheProductItWasWrittenIn(t *testing.T) {
	// The round trip, and the boundary in one: what is written in one product
	// is read back there and nowhere else. The reader here holds both products
	// so the empty answer is a boundary rather than a refusal.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		made := asPerson(t, r, "triager", http.MethodPost, notesHere,
			`{"body":"Upstream says a patch lands next week."}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("writing a note answered %d: %s", made.Code, made.Body.String())
		}

		var page struct {
			Items []struct {
				ID        int64  `json:"id"`
				Body      string `json:"body"`
				WrittenBy string `json:"written_by"`
			} `json:"items"`
		}
		got := asPerson(t, r, "triager", http.MethodGet, notesHere, "")
		if got.Code != http.StatusOK {
			t.Fatalf("reading the notes answered %d: %s", got.Code, got.Body.String())
		}
		if err := json.Unmarshal(got.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 1 || page.Items[0].Body == "" {
			t.Fatalf("the thread came back as %+v, want the note that was written", page.Items)
		}
		if page.Items[0].WrittenBy != "triager" {
			t.Errorf("the note is attributed to %q", page.Items[0].WrittenBy)
		}

		// And not from the other product, asked by somebody holding every
		// product: the issue does not sit there, so the thread answers as an
		// issue that is not there rather than carrying what was written next
		// door.
		elsewhere := asPerson(t, r, "estate-reader", http.MethodGet, notesThere, "")
		if elsewhere.Code != http.StatusNotFound {
			t.Errorf("a reader of every product reached the other product's thread with %d: %s",
				elsewhere.Code, elsewhere.Body.String())
		}
	})
}

func TestOnlyTheAuthorEditsANoteThroughTheApi(t *testing.T) {
	// An edit another person could make is not a correction, and the record
	// keeps what it said before either way.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		made := asPerson(t, r, "triager", http.MethodPost, notesHere,
			`{"body":"First thought."}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("writing a note answered %d: %s", made.Code, made.Body.String())
		}
		var wrote struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &wrote); err != nil {
			t.Fatal(err)
		}
		at := "/v1/notes/" + itoa(wrote.ID)

		// Somebody else who holds triage here.
		if got := asPerson(t, r, "private-triage", http.MethodPut, at,
			`{"body":"Somebody else's words."}`); got.Code < 400 {
			t.Errorf("another triager rewrote somebody's note: %d %s", got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "triager", http.MethodPut, at,
			`{"body":"Second thought."}`); got.Code != http.StatusOK {
			t.Fatalf("the author could not change their own note: %d %s",
				got.Code, got.Body.String())
		}

		var history struct {
			Items []struct {
				Version int    `json:"version"`
				Body    string `json:"body"`
			} `json:"items"`
		}
		got := asPerson(t, r, "triager", http.MethodGet, at+"/history", "")
		if got.Code != http.StatusOK {
			t.Fatalf("reading what it said before answered %d: %s", got.Code, got.Body.String())
		}
		if err := json.Unmarshal(got.Body.Bytes(), &history); err != nil {
			t.Fatal(err)
		}
		if len(history.Items) != 1 || history.Items[0].Body != "First thought." {
			t.Errorf("the history is %+v, want the one version that was replaced", history.Items)
		}
	})
}
