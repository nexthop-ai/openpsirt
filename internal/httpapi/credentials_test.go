package httpapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// An ingest key belongs to no person, so it is the credential a build pipeline
// holds. Creating one was implemented and reachable only by calling the API by
// hand: nothing in the interface ever posted to it (REQ-44).
func TestAnIngestKeyIsCreatedWithItsScope(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		// The product is always required; the branch and the variant are
		// independent, and either, both or neither may pin it.
		made := asPerson(t, r, "admin", http.MethodPost, "/v1/keys",
			`{"name":"nightly-mine","product":"mine"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("creating a key answered %d: %s", made.Code, made.Body.String())
		}
		var issued struct {
			Item struct {
				Name    string `json:"name"`
				Product string `json:"product"`
				Secret  string `json:"secret"`
			} `json:"item"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &issued); err != nil {
			t.Fatalf("decode: %v (%s)", err, made.Body.String())
		}
		// Shown once, at creation. A store that can hand back what it holds
		// gives up every pipeline's key with a copy of the database.
		if issued.Item.Secret == "" {
			t.Error("the secret was not returned, so the key cannot be used")
		}
		if issued.Item.Name != "nightly-mine" || issued.Item.Product != "mine" {
			t.Errorf("the reply describes %+v", issued.Item)
		}

		// Read back without the secret, because what is stored is a digest.
		listed := asPerson(t, r, "admin", http.MethodGet, "/v1/keys", "")
		if listed.Code != http.StatusOK {
			t.Fatalf("listing keys answered %d", listed.Code)
		}
		if strings.Contains(listed.Body.String(), issued.Item.Secret) {
			t.Error("the listing carries the secret")
		}

		// A name is what an upload records as its sender and what a
		// revocation names, so two keys may not share one.
		again := asPerson(t, r, "admin", http.MethodPost, "/v1/keys",
			`{"name":"nightly-mine","product":"mine"}`)
		if again.Code == http.StatusCreated {
			t.Error("two keys were created under one name")
		}
	})
}

// Administration is global rather than granted against a product, and had no
// control in the interface at all — the API took it and the screens only ever
// displayed it (REQ-42).
func TestAdministrationIsGrantedAndWithdrawn(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		// Somebody who exists and administers nothing. Reaching an
		// administrative endpoint is the test of whether the flag took.
		if got := r.as(t, "reader", http.MethodGet, "/v1/people"); got != http.StatusForbidden {
			t.Fatalf("somebody who administers nothing lists people as %d", got)
		}

		promoted := asPerson(t, r, "admin", http.MethodPost, "/v1/people",
			`{"identity":"reader","admin":true}`)
		// 200 rather than 201: they already existed, and recording somebody
		// again confirms them rather than creating a second.
		if promoted.Code != http.StatusOK {
			t.Fatalf("granting administration answered %d: %s", promoted.Code, promoted.Body.String())
		}
		if got := r.as(t, "reader", http.MethodGet, "/v1/people"); got != http.StatusOK {
			t.Errorf("somebody just made an administrator lists people as %d", got)
		}

		// And back. Withdrawing it is the same act with the other answer,
		// rather than a second endpoint that could disagree.
		withdrawn := asPerson(t, r, "admin", http.MethodPost, "/v1/people",
			`{"identity":"reader","admin":false}`)
		if withdrawn.Code != http.StatusOK {
			t.Fatalf("withdrawing administration answered %d: %s",
				withdrawn.Code, withdrawn.Body.String())
		}
		if got := r.as(t, "reader", http.MethodGet, "/v1/people"); got != http.StatusForbidden {
			t.Errorf("administration was not withdrawn: %d", got)
		}
	})
}
