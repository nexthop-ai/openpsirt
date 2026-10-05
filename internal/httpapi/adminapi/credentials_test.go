// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// An ingest key belongs to no person, so it is the credential a build pipeline
// holds (REQ-44).
func TestAnIngestKeyIsCreatedWithItsScope(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		// The product is always required; the branch and the variant are
		// independent, and either, both or neither may pin it.
		made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/keys",
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
		listed := httpapitest.AsPerson(t, r, "admin", http.MethodGet, "/v1/keys", "")
		if listed.Code != http.StatusOK {
			t.Fatalf("listing keys answered %d", listed.Code)
		}
		if strings.Contains(listed.Body.String(), issued.Item.Secret) {
			t.Error("the listing carries the secret")
		}

		// A revocation names a key, so two in force may not share a name.
		// Refused as the conflict it is, not as a fault at our end.
		again := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/keys",
			`{"name":"nightly-mine","product":"mine"}`)
		if again.Code != http.StatusConflict {
			t.Errorf("a second key under one name answered %d: %s", again.Code, again.Body.String())
		}
	})
}

// A key's name is typed by an administrator to make it and again to withdraw
// it, so it is one name in any capitals: stored folded, refused as taken in
// other capitals, and withdrawn by any spelling of it.
func TestAKeyNameIsMatchedWithoutRegardToCapitals(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/keys",
			`{"name":" Nightly-Mine ","product":"mine"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("creating a key answered %d: %s", made.Code, made.Body.String())
		}
		var issued struct {
			Item struct {
				Name string `json:"name"`
			} `json:"item"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &issued); err != nil {
			t.Fatalf("decode: %v (%s)", err, made.Body.String())
		}
		if issued.Item.Name != "nightly-mine" {
			t.Errorf("the key is named %q, want it folded", issued.Item.Name)
		}

		again := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/keys",
			`{"name":"NIGHTLY-mine","product":"mine"}`)
		if again.Code != http.StatusConflict {
			t.Errorf("the same name in other capitals answered %d: %s", again.Code, again.Body.String())
		}
		blank := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/keys",
			`{"name":"   ","product":"mine"}`)
		if blank.Code != http.StatusUnprocessableEntity {
			t.Errorf("a name of spaces answered %d: %s", blank.Code, blank.Body.String())
		}

		withdrawn := httpapitest.AsPerson(t, r, "admin", http.MethodDelete, "/v1/keys/NIGHTLY-MINE", "")
		if withdrawn.Code != http.StatusNoContent {
			t.Errorf("withdrawing by another spelling answered %d: %s",
				withdrawn.Code, withdrawn.Body.String())
		}
	})
}

// A personal token's name is typed by its owner to mint it and again to
// withdraw it, so it is one name in any capitals: stored folded, refused as
// taken in other capitals, and withdrawn by any spelling of it.
func TestATokenNameIsMatchedWithoutRegardToCapitals(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		made := httpapitest.AsPerson(t, r, "private", http.MethodPost, "/v1/tokens",
			`{"name":" Laptop ","lifetime":"24h"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("minting a token answered %d: %s", made.Code, made.Body.String())
		}
		var minted struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &minted); err != nil {
			t.Fatalf("decode: %v (%s)", err, made.Body.String())
		}
		if minted.Name != "laptop" {
			t.Errorf("the token is named %q, want it folded", minted.Name)
		}

		again := httpapitest.AsPerson(t, r, "private", http.MethodPost, "/v1/tokens",
			`{"name":"LAPTOP","lifetime":"24h"}`)
		if again.Code != http.StatusConflict {
			t.Errorf("the same name in other capitals answered %d: %s", again.Code, again.Body.String())
		}

		withdrawn := httpapitest.AsPerson(t, r, "private", http.MethodDelete, "/v1/tokens/LapTop", "")
		if withdrawn.Code != http.StatusNoContent {
			t.Errorf("withdrawing by another spelling answered %d: %s",
				withdrawn.Code, withdrawn.Body.String())
		}
	})
}

// A key pinned to one release and one variant is listed with both. Listed
// without them it reads as a key for the whole product, which is a different
// credential and the wrong one to withdraw.
func TestAKeyIsListedWithTheReleaseAndVariantItIsPinnedTo(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/keys",
			`{"name":"pinned","product":"mine","stream":"master","variant":"broadcom"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("creating a key answered %d: %s", made.Code, made.Body.String())
		}
		listed := httpapitest.AsPerson(t, r, "admin", http.MethodGet, "/v1/keys", "")
		if listed.Code != http.StatusOK {
			t.Fatalf("listing keys answered %d", listed.Code)
		}
		var out struct {
			Items []struct {
				Name    string `json:"name"`
				Stream  string `json:"stream"`
				Variant string `json:"variant"`
			} `json:"items"`
		}
		if err := json.Unmarshal(listed.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, listed.Body.String())
		}
		for _, key := range out.Items {
			if key.Name != "pinned" {
				continue
			}
			if key.Stream != "master" || key.Variant != "broadcom" {
				t.Errorf("the pinned key is listed with release %q and variant %q", key.Stream, key.Variant)
			}
			return
		}
		t.Errorf("the pinned key is not listed: %s", listed.Body.String())
	})
}

// Administration is global rather than granted against a product (REQ-42).
func TestAdministrationIsGrantedAndWithdrawn(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		// Somebody who exists and administers nothing. Reaching an
		// administrative endpoint is the test of whether the flag took.
		if got := r.As(t, "reader", http.MethodGet, "/v1/people"); got != http.StatusForbidden {
			t.Fatalf("somebody who administers nothing lists people as %d", got)
		}

		promoted := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/people",
			`{"identity":"reader","admin":true}`)
		// 200 rather than 201: they already existed, and recording somebody
		// again confirms them rather than creating a second.
		if promoted.Code != http.StatusOK {
			t.Fatalf("granting administration answered %d: %s", promoted.Code, promoted.Body.String())
		}
		if got := r.As(t, "reader", http.MethodGet, "/v1/people"); got != http.StatusOK {
			t.Errorf("somebody just made an administrator lists people as %d", got)
		}

		// And back. Withdrawing it is the same act with the other answer,
		// rather than a second endpoint that could disagree.
		withdrawn := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/people",
			`{"identity":"reader","admin":false}`)
		if withdrawn.Code != http.StatusOK {
			t.Fatalf("withdrawing administration answered %d: %s",
				withdrawn.Code, withdrawn.Body.String())
		}
		if got := r.As(t, "reader", http.MethodGet, "/v1/people"); got != http.StatusForbidden {
			t.Errorf("administration was not withdrawn: %d", got)
		}
	})
}

// A withdrawn key's name may be given to a new key, and withdrawing by the
// name then reaches the new one. Both stay listed.
func TestAWithdrawnKeysNameIsGivenToANewKey(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for round := 1; round <= 2; round++ {
			made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/keys",
				`{"name":"reused","product":"mine"}`)
			if made.Code != http.StatusCreated {
				t.Fatalf("round %d: creating the key answered %d: %s", round, made.Code, made.Body.String())
			}
			withdrawn := httpapitest.AsPerson(t, r, "admin", http.MethodDelete, "/v1/keys/reused", "")
			if withdrawn.Code != http.StatusNoContent {
				t.Fatalf("round %d: withdrawing it answered %d: %s", round, withdrawn.Code, withdrawn.Body.String())
			}
		}
		again := httpapitest.AsPerson(t, r, "admin", http.MethodDelete, "/v1/keys/reused", "")
		if again.Code != http.StatusNotFound {
			t.Errorf("withdrawing a name with none in force answered %d: %s", again.Code, again.Body.String())
		}
		var listed struct {
			Items []struct {
				Name      string `json:"name"`
				Withdrawn bool   `json:"withdrawn"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "admin", "/v1/keys", &listed)
		count := 0
		for _, key := range listed.Items {
			if key.Name == "reused" {
				count++
				if !key.Withdrawn {
					t.Errorf("a key withdrawn twice over is listed in force: %+v", key)
				}
			}
		}
		if count != 2 {
			t.Errorf("the list holds %d keys named reused, want both", count)
		}
	})
}
