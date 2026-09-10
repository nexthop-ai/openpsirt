package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestASecondAdvisoryIsARevisionOfTheFirst(t *testing.T) {
	// Without a record of the act, a second advisory for the same flaw
	// cannot carry a revision history or a higher version — and both are
	// things CSAF validators check, so a document that fails validation is
	// one a customer's tooling drops.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		flaw := r.embargoed(t)
		at := "/v1/products/mine/issues/" + flaw + "/advisory"

		var first struct {
			Document struct {
				Tracking struct {
					Version string `json:"version"`
					History []struct {
						Number  string `json:"number"`
						Summary string `json:"summary"`
					} `json:"revision_history"`
				} `json:"tracking"`
			} `json:"document"`
		}
		read(t, r, "private-triage", at, &first)
		if first.Document.Tracking.Version != "1" {
			t.Fatalf("a document nobody has issued is version %q",
				first.Document.Tracking.Version)
		}
		if len(first.Document.Tracking.History) != 1 {
			t.Errorf("its history reads as %+v", first.Document.Tracking.History)
		}

		// Somebody publishes it, and says so.
		got := asPerson(t, r, "private-triage", http.MethodPost, at+"/issuance",
			`{"summary":"Initial publication"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording that it went out answered %d: %s", got.Code, got.Body.String())
		}
		var recorded struct {
			Version int    `json:"version"`
			Digest  string `json:"digest"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		if recorded.Version != 1 || len(recorded.Digest) != 64 {
			t.Errorf("what was recorded reads as %+v", recorded)
		}

		// The next document is a revision of it, and says what changed.
		var second struct {
			Document struct {
				Tracking struct {
					Version string `json:"version"`
					History []struct {
						Number  string `json:"number"`
						Summary string `json:"summary"`
					} `json:"revision_history"`
				} `json:"tracking"`
			} `json:"document"`
		}
		read(t, r, "private-triage", at, &second)
		if second.Document.Tracking.Version != "2" {
			t.Errorf("the next document is version %q, want 2",
				second.Document.Tracking.Version)
		}
		if len(second.Document.Tracking.History) != 3 {
			t.Fatalf("its history reads as %+v", second.Document.Tracking.History)
		}
		if second.Document.Tracking.History[1].Summary != "Initial publication" {
			t.Errorf("the history does not say what the issuance said: %+v",
				second.Document.Tracking.History)
		}

		// Issuing again is a second revision rather than a replacement: what
		// was published on a date cannot be worked out again afterwards.
		if got := asPerson(t, r, "private-triage", http.MethodPost, at+"/issuance",
			`{"summary":"Added the fixed release"}`); got.Code != http.StatusCreated {
			t.Fatalf("recording a second issuance answered %d: %s", got.Code, got.Body.String())
		}
		read(t, r, "private-triage", at, &second)
		if second.Document.Tracking.Version != "3" {
			t.Errorf("after two issuances the document is version %q",
				second.Document.Tracking.Version)
		}

		// The digest is of what we generate rather than of anything sent, so
		// two issuances of an unchanged document agree.
		got = asPerson(t, r, "private-triage", http.MethodPost, at+"/issuance", `{}`)
		var third struct {
			Digest string `json:"digest"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &third); err != nil {
			t.Fatal(err)
		}
		if third.Digest != recorded.Digest {
			t.Errorf("an unchanged document hashed differently: %q then %q",
				recorded.Digest, third.Digest)
		}
	})
}
