package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRecordingARoleReadsTheModeBeforeItOpensTheWrite pins that where roles
// come from is read before the transaction recording somebody opens, rather
// than from inside it.
//
// Read from inside, it reached the settings store, which holds the root
// database handle. SQLite lends one connection, so the read waited for the
// connection the transaction was already holding and the request never
// answered at all: nobody could be given a role, and everything else touching
// the database queued behind it for as long as the caller waited. The other
// engines answered, through a second connection, which is the same read outside
// the transaction with the symptom removed.
//
// Both arms, because the guard has two and neither ran anywhere: nothing else
// in this package wires the mode, so the nil check short-circuited and a
// running deployment was the only thing that executed the line.
func TestRecordingARoleReadsTheModeBeforeItOpensTheWrite(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		for _, c := range []struct {
			what   string
			groups bool
			want   int
		}{
			{"assigned directly", false, http.StatusCreated},
			{"derived from groups", true, http.StatusConflict},
		} {
			t.Run(c.what, func(t *testing.T) {
				on := deriving(t, r, c.groups)
				body := `{"identity":"` + strings.ReplaceAll(c.what, " ", "-") + `",` +
					`"holds":[{"product":"mine","role":"public-read"}]}`

				// The request carries a deadline, because the failure this
				// pins is one that never answers. A caller giving up is what
				// releases it — the read inside the write fails, the write
				// rolls back, and the connection comes back — so a deadline
				// here is what a browser or a seeding script does, and it
				// turns a suite that hangs until the binary panics into one
				// failing line. Without it the goroutine holding the
				// transaction outlives the test and blocks the fixture's own
				// cleanup.
				ctx, stop := context.WithTimeout(t.Context(), 10*time.Second)
				defer stop()
				req := httptest.NewRequest(http.MethodPost, "/v1/people",
					strings.NewReader(body)).WithContext(ctx)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set(testHeader, "admin")
				fromOurOwnPage(req)
				rec := httptest.NewRecorder()
				on.handler.ServeHTTP(rec, req)

				if ctx.Err() != nil {
					t.Fatalf("recording somebody with a role, %s, never answered: "+
						"the write is holding the connection something inside it is waiting for",
						c.what)
				}
				if rec.Code != c.want {
					t.Errorf("recording somebody with a role, %s, answered %d, wanted %d: %s",
						c.what, rec.Code, c.want, rec.Body.String())
				}
			})
		}
	})
}

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
			`{"identity":"ana","display_name":"Ana",`+
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
					Username string `json:"username"`
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
		// Recording somebody records the way they arrive, without being asked
		// for it: an identity is the username, whichever path it comes down.
		if len(made.Item.SignsInBy) != 1 || made.Item.SignsInBy[0].Username != "ana" {
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
		_, secret, err := r.rights.NewToken(t.Context(), person.ID, "theirs", nil, nil, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}

		for _, act := range []struct {
			what string
			path string
			body string
		}{
			{"record a person", "/v1/people",
				`{"identity":"made-by-token","display_name":"Made","admin":true}`},
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
			`{"identity":"made-by-session","display_name":"Made"}`); got.Code != http.StatusCreated {
			t.Errorf("an administrator signing in could not record a person: %d %s",
				got.Code, got.Body.String())
		}
	})
}

// TestRecordingSomebodyAgainLeavesAdministrationAlone pins what an omitted
// field means.
//
// Administration was decided from a read taken before the write: a request
// that said nothing about it passed back whatever the read had returned. Two
// requests at once, one granting it and one adding a role, and the second
// wrote back the value it saw before the first — and because the request
// stated nothing, no trail row said anybody had done it.
//
// The read failing was the same shape and worse: it answered "nobody is
// recorded as this", so the handler took an existing administrator to be new
// and recorded them without it.
func TestRecordingSomebodyAgainLeavesAdministrationAlone(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		if got := asPerson(t, r, "admin", http.MethodPost, "/v1/people",
			`{"identity":"deputy","admin":true}`); got.Code >= 300 {
			t.Fatalf("recording an administrator answered %d: %s", got.Code, got.Body.String())
		}

		// A request about something else entirely, saying nothing about
		// administration.
		if got := asPerson(t, r, "admin", http.MethodPost, "/v1/people",
			`{"identity":"deputy","holds":[{"product":"mine","role":"public-read"}]}`,
		); got.Code >= 300 {
			t.Fatalf("granting them a role answered %d: %s", got.Code, got.Body.String())
		}

		var person struct {
			Admin bool `json:"admin"`
		}
		read(t, r, "admin", "/v1/people/deputy", &person)
		if !person.Admin {
			t.Error("granting a role withdrew administration from somebody who held it")
		}

		// And nothing claimed it moved. A row per request would make the
		// trail say administration changed on every edit to somebody's roles.
		var trail changed
		read(t, r, "admin", "/v1/administration/changes?kind=account&limit=200", &trail)
		for _, row := range trail.Items {
			if row.About == "deputy" && row.Became == "administrator" {
				t.Errorf("a request saying nothing about administration recorded %+v", row)
			}
		}
	})
}

func TestWithdrawingSomethingNobodyHoldsRecordsNothingAndReleasesNothing(t *testing.T) {
	// The write bound only the error from its statement and never read how
	// many rows it matched, so a role somebody does not hold — or a word that
	// is not a role at all — answered as withdrawn. The caller then wrote a
	// trail row saying the role was withdrawn, and asked whether the person
	// still held anything there: for a role they never had the answer was no,
	// and everything they were dealing with in that product went back to the
	// unassigned list.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)

		// A role this person does not hold on a product that exists.
		got := asPerson(t, r, "admin", http.MethodDelete,
			"/v1/people/triager/roles/mine/private-read", "")
		if got.Code != http.StatusNotFound {
			t.Errorf("withdrawing a role nobody holds answered %d: %s",
				got.Code, got.Body.String())
		}
		// A word that is not a role at all.
		got = asPerson(t, r, "admin", http.MethodDelete,
			"/v1/people/triager/roles/mine/not-a-role", "")
		if got.Code != http.StatusUnprocessableEntity {
			t.Errorf("withdrawing a word that is not a role answered %d: %s",
				got.Code, got.Body.String())
		}

		// And nothing was recorded as having happened.
		var trail changed
		read(t, r, "admin", "/v1/administration/changes?kind=role&limit=200", &trail)
		for _, row := range trail.Items {
			if strings.Contains(row.About, "triager") {
				t.Errorf("a withdrawal that withdrew nothing recorded %+v", row)
			}
		}
	})
}
