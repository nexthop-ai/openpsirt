package httpapi_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

func TestASecondAdvisoryIsARevisionOfTheFirst(t *testing.T) {
	// Without a record of the act, a second advisory for the same flaw
	// cannot carry a revision history or a higher version — and both are
	// things CSAF validators check, so a document that fails validation is
	// one a customer's tooling drops.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		flaw := r.embargoed(t)
		named := advisoryOver(t, r, "private-triage", "mine", flaw)
		at := "/v1/advisories/" + named

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
		read(t, r, "private-triage", at+"/document", &first)
		if first.Document.Tracking.Version != "1" {
			t.Fatalf("a document nobody has issued is version %q",
				first.Document.Tracking.Version)
		}
		if len(first.Document.Tracking.History) != 1 {
			t.Errorf("its history reads as %+v", first.Document.Tracking.History)
		}

		// Somebody publishes it, and says so. A second person agrees to what
		// it says first, which is what an issuance asks for.
		agreedTo(t, r, at)
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
		read(t, r, "private-triage", at+"/document", &second)
		// Three entries — the flaw recorded, the issuance, and this document
		// being generated — so the version is 3. Counted separately from the
		// history it said 2, and a CSAF validator compares the two.
		if len(second.Document.Tracking.History) != 3 {
			t.Fatalf("its history reads as %+v", second.Document.Tracking.History)
		}
		if newest := second.Document.Tracking.History[2].Number; second.Document.Tracking.Version != newest {
			t.Errorf("the next document is version %q and its history ends at %q",
				second.Document.Tracking.Version, newest)
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
		read(t, r, "private-triage", at+"/document", &second)
		if len(second.Document.Tracking.History) != 4 {
			t.Fatalf("after two issuances its history reads as %+v",
				second.Document.Tracking.History)
		}
		if newest := second.Document.Tracking.History[3].Number; second.Document.Tracking.Version != newest {
			t.Errorf("after two issuances the document is version %q and its history ends at %q",
				second.Document.Tracking.Version, newest)
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

// agreedTo has a second person agree to what the advisory at this path says,
// which is what an issuance asks for.
//
// private-dispatcher holds private triage on the one product and did not start
// any of these advisories, which is the pair of things agreeing asks of
// somebody.
func agreedTo(t *testing.T, r *reach, at string) {
	t.Helper()
	if got := asPerson(t, r, "private-dispatcher", http.MethodPost,
		at+"/approval", ""); got.Code != http.StatusCreated {
		t.Fatalf("agreeing to the advisory at %s answered %d: %s",
			at, got.Code, got.Body.String())
	}
}

// TestAWriteOnAnAdvisoryNeedsTheRoleOnEveryProductItCovers reaches the arm
// that answers an authorization refusal here.
//
// Left to the default arm it answers 422 carrying the denial's own sentence,
// which names the internal product identifier — a number nothing else
// publishes. Deleting the arm leaves the suite green without this.
func TestAWriteOnAnAdvisoryNeedsTheRoleOnEveryProductItCovers(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		r.scannedWithEvidence(t)
		flaw := r.embargoed(t)
		named := advisoryOver(t, r, "private-triage", "mine", flaw)

		// Somebody who triages one product and reads the one this advisory
		// covers. The triage role is what carries them past the route's own
		// requirement, so what refuses them is the rule this pins rather than
		// the middleware above it — and the read is what lets them resolve
		// the advisory, so it is not the answer a name nobody minted gets.
		partly, err := r.rights.Ensure(ctx, "part-triage", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.rights.Claim(ctx, partly.ID, "part-triage"); err != nil {
			t.Fatal(err)
		}
		var mine, theirs int64
		for name, into := range map[string]*int64{"mine": &mine, "theirs": &theirs} {
			if err := r.db.DB.NewSelect().Table("product").Column("id").
				Where("name = ?", name).Scan(ctx, into); err != nil {
				t.Fatal(err)
			}
		}
		for _, held := range []struct {
			product int64
			role    access.Role
		}{
			{theirs, access.PublicTriage},
			{mine, access.PublicRead}, {mine, access.PrivateRead},
		} {
			if err := r.rights.GrantRole(ctx, partly.ID, held.product, held.role); err != nil {
				t.Fatal(err)
			}
		}
		// They may read it, which is what makes the refusal below about the
		// role rather than about the advisory being out of reach.
		if got := asPerson(t, r, "part-triage", http.MethodGet,
			"/v1/advisories/"+named, ""); got.Code != http.StatusOK {
			t.Fatalf("reading an advisory in a product they read answered %d: %s",
				got.Code, got.Body.String())
		}

		refused := asPerson(t, r, "part-triage", http.MethodPatch,
			"/v1/advisories/"+named, `{"title":"Not theirs to call"}`)
		if refused.Code != http.StatusForbidden {
			t.Fatalf("retitling an advisory covering a product they only read answered %d: %s",
				refused.Code, refused.Body.String())
		}
		// And the refusal carries no internal identifier, which is what the
		// arm exists to withhold.
		for _, leaked := range []string{strconv.FormatInt(mine, 10), strconv.FormatInt(theirs, 10)} {
			if strings.Contains(refused.Body.String(), leaked) {
				t.Errorf("the refusal names an internal product identifier: %s",
					refused.Body.String())
			}
		}
	})
}
