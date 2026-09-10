package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestGrantingARoleDoesNotAskWhetherItWorks holds the line that a grant is
// written with what the caller decides and read back with what the server
// knows.
//
// "effective" is the server's answer: an assignment set aside by a change of
// role-assignment mode is kept so the change can be undone, and it grants
// nothing while it sits there. Required on the way in, it made granting a role
// mean stating whether the role you are granting works — so everything that
// granted one sent "effective": true to be allowed to, and a caller that told
// the truth and left it out was refused with "expected required property
// effective to be present".
func TestGrantingARoleDoesNotAskWhetherItWorks(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		recorded := asPerson(t, r, "admin", http.MethodPost, "/v1/people",
			`{"identity":"ana","display_name":"Ana","provider":"proxy","username":"ana",`+
				`"holds":[{"product":"mine","role":"public-read"}]}`)
		if recorded.Code != http.StatusCreated {
			t.Fatalf("recording somebody with a role answered %d: %s",
				recorded.Code, recorded.Body.String())
		}

		// And the reply describes the record. It used to be the request handed
		// back, so whatever the caller said about a grant came back as though
		// the deployment had confirmed it.
		var made struct {
			Item struct {
				Holds []struct {
					Effective bool   `json:"effective"`
					Source    string `json:"source"`
				} `json:"holds"`
				SignsInBy []struct {
					Provider string `json:"provider"`
				} `json:"signs_in_by"`
			} `json:"item"`
		}
		if err := json.Unmarshal(recorded.Body.Bytes(), &made); err != nil {
			t.Fatalf("decode: %v (%s)", err, recorded.Body.String())
		}
		if len(made.Item.Holds) != 1 {
			t.Fatalf("recording answered with %d roles, not the one granted: %s",
				len(made.Item.Holds), recorded.Body.String())
		}
		if !made.Item.Holds[0].Effective || made.Item.Holds[0].Source != "assigned" {
			t.Errorf("the reply describes the grant as %+v, which is not what was recorded",
				made.Item.Holds[0])
		}
		if len(made.Item.SignsInBy) != 1 || made.Item.SignsInBy[0].Provider != "proxy" {
			t.Errorf("the reply does not say how she can arrive: %s", recorded.Body.String())
		}

		// And the role is a real one, not a body that merely parsed: she can
		// reach the product it was held against, and nothing else.
		if got := r.as(t, "ana", http.MethodGet, "/v1/products/mine/streams"); got != http.StatusOK {
			t.Fatalf("the person just granted a role on mine reads it as %d", got)
		}
		if got := r.as(t, "ana", http.MethodGet, "/v1/products/theirs/streams"); got != http.StatusNotFound {
			t.Fatalf("she reads a product she holds nothing on as %d, not 404", got)
		}

		// Read back, the answer the request did not have to state is there.
		listed := asPerson(t, r, "admin", http.MethodGet, "/v1/people", "")
		if listed.Code != http.StatusOK {
			t.Fatalf("listing people answered %d: %s", listed.Code, listed.Body.String())
		}
		var out struct {
			Items []struct {
				Identity string `json:"identity"`
				Holds    []struct {
					Product   string `json:"product"`
					Role      string `json:"role"`
					Effective bool   `json:"effective"`
					Source    string `json:"source"`
				} `json:"holds"`
			} `json:"items"`
		}
		if err := json.Unmarshal(listed.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, listed.Body.String())
		}
		var found bool
		for _, person := range out.Items {
			if person.Identity != "ana" {
				continue
			}
			for _, hold := range person.Holds {
				if hold.Role != "public-read" {
					continue
				}
				found = true
				if !hold.Effective {
					t.Errorf("the role she was granted is read back as granting nothing")
				}
				if hold.Source != "assigned" {
					t.Errorf("a role an administrator granted came back sourced %q", hold.Source)
				}
			}
		}
		if !found {
			t.Fatalf("the role recorded with her is not read back: %s", listed.Body.String())
		}
	})
}

func TestATokenCannotMintACredentialThatOutlivesIt(t *testing.T) {
	// "A credential cannot mint another" held for a token issuing a
	// token, and was got around by what an administrator's token could make
	// instead: a person — an administrator, even — and a pipeline key. Both
	// outlive the token and neither is bounded by it, so the narrow credential
	// could always ask for a wide one.
	twoReach(t, func(t *testing.T, r *reach) {
		// A personal token belonging to somebody who administers this
		// deployment, which is the credential the escalation used.
		person, err := r.rights.ByIdentity(t.Context(), "admin")
		if err != nil {
			t.Fatal(err)
		}
		_, secret, err := r.rights.NewToken(t.Context(), person.ID, "theirs", nil, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}

		for _, act := range []struct {
			what string
			path string
			body string
		}{
			{"record a person", "/v1/people",
				`{"identity":"made-by-token","display_name":"Made","provider":"proxy",` +
					`"username":"made-by-token","admin":true}`},
			{"create a key", "/v1/keys",
				`{"name":"made-by-token","product":"mine"}`},
		} {
			req := httptest.NewRequest(http.MethodPost, act.path, strings.NewReader(act.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+secret)
			got := httptest.NewRecorder()
			r.handler.ServeHTTP(got, req)
			if got.Code != http.StatusForbidden {
				t.Errorf("a token could %s: %d %s", act.what, got.Code, got.Body.String())
			}
		}

		// The same acts still work for the same person when they have signed
		// in, so what is refused is the credential rather than the right.
		if got := asPerson(t, r, "admin", http.MethodPost, "/v1/people",
			`{"identity":"made-by-session","display_name":"Made","provider":"proxy",`+
				`"username":"made-by-session"}`); got.Code != http.StatusCreated {
			t.Errorf("an administrator signing in could not record a person: %d %s",
				got.Code, got.Body.String())
		}
	})
}
