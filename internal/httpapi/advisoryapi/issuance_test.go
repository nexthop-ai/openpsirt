// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestASecondAdvisoryIsARevisionOfTheFirst(t *testing.T) {
	// Without a record of the act, a second advisory for the same flaw
	// cannot carry a revision history or a higher version — and both are
	// things CSAF validators check, so a document that fails validation is
	// one a customer's tooling drops.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		flaw := r.Embargoed(t)
		named := httpapitest.AdvisoryOver(t, r, "private-triage", "mine", flaw)
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
		httpapitest.Read(t, r, "private-triage", at+"/document", &first)
		if first.Document.Tracking.Version != "1" {
			t.Fatalf("a document nobody has issued is version %q",
				first.Document.Tracking.Version)
		}
		if len(first.Document.Tracking.History) != 1 {
			t.Errorf("its history reads as %+v", first.Document.Tracking.History)
		}

		// Somebody publishes it, and says so. A second person agrees to what
		// it says first, which is what an issuance asks for.
		httpapitest.AgreedTo(t, r, at)
		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, at+"/issuance",
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
		httpapitest.Read(t, r, "private-triage", at+"/document", &second)
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
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, at+"/issuance",
			`{"summary":"Added the fixed release"}`); got.Code != http.StatusCreated {
			t.Fatalf("recording a second issuance answered %d: %s", got.Code, got.Body.String())
		}
		httpapitest.Read(t, r, "private-triage", at+"/document", &second)
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
		got = httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, at+"/issuance", `{}`)
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

func TestAnAdvisoryNamesWhoAgreesAndSaysWhetherItMovedSinceItWentOut(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		flaw := r.Embargoed(t)
		named := httpapitest.AdvisoryOver(t, r, "private-triage", "mine", flaw)
		at := "/v1/advisories/" + named

		type standing struct {
			AgreedBy []struct {
				Person   string `json:"person"`
				AgreedAt string `json:"agreed_at"`
			} `json:"agreed_by"`
			Changed *bool `json:"changed"`
		}
		var before standing
		httpapitest.Read(t, r, "private-triage", at, &before)
		if len(before.AgreedBy) != 0 || before.Changed != nil {
			t.Errorf("with nobody agreeing and nothing gone out it reads %+v", before)
		}

		httpapitest.AgreedTo(t, r, at)
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, at+"/issuance",
			`{}`); got.Code != http.StatusCreated {
			t.Fatalf("recording that it went out answered %d: %s", got.Code, got.Body.String())
		}
		var sent standing
		httpapitest.Read(t, r, "private-triage", at, &sent)
		if len(sent.AgreedBy) != 1 || sent.AgreedBy[0].Person != "private-dispatcher" ||
			sent.AgreedBy[0].AgreedAt == "" {
			t.Errorf("who agrees reads as %+v", sent.AgreedBy)
		}
		if sent.Changed == nil || *sent.Changed {
			t.Errorf("straight after it went out, changed reads %v", sent.Changed)
		}

		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPatch, at,
			`{"title":"A different title"}`); got.Code != http.StatusOK {
			t.Fatalf("retitling answered %d: %s", got.Code, got.Body.String())
		}
		var moved standing
		httpapitest.Read(t, r, "private-triage", at, &moved)
		if moved.Changed == nil || !*moved.Changed {
			t.Errorf("after a retitle, changed reads %v", moved.Changed)
		}
		if len(moved.AgreedBy) != 0 {
			t.Errorf("an agreement to the old title still names %+v", moved.AgreedBy)
		}
	})
}

// TestAWriteOnAnAdvisoryNeedsTheRoleOnEveryProductItCovers reaches the arm
// that answers an authorization refusal here.
//
// Left to the default arm it answers 422 carrying the denial's own sentence,
// which names the internal product identifier — a number nothing else
// publishes. Deleting the arm leaves the suite green without this.
func TestAWriteOnAnAdvisoryNeedsTheRoleOnEveryProductItCovers(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		r.ScannedWithEvidence(t)
		flaw := r.Embargoed(t)
		named := httpapitest.AdvisoryOver(t, r, "private-triage", "mine", flaw)

		// Somebody who triages one product and reads the one this advisory
		// covers. The triage role is what carries them past the route's own
		// requirement, so what refuses them is the rule this pins rather than
		// the middleware above it — and the read is what lets them resolve
		// the advisory, so it is not the answer a name nobody minted gets.
		partly, err := r.Rights.Ensure(ctx, "part-triage", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Rights.Claim(ctx, partly.ID, "part-triage"); err != nil {
			t.Fatal(err)
		}
		var mine, theirs int64
		for name, into := range map[string]*int64{"mine": &mine, "theirs": &theirs} {
			if err := r.DB.DB.NewSelect().Table("product").Column("id").
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
			if err := r.Rights.GrantRole(ctx, partly.ID, held.product, held.role); err != nil {
				t.Fatal(err)
			}
		}
		// They may read it, which is what makes the refusal below about the
		// role rather than about the advisory being out of reach.
		if got := httpapitest.AsPerson(t, r, "part-triage", http.MethodGet,
			"/v1/advisories/"+named, ""); got.Code != http.StatusOK {
			t.Fatalf("reading an advisory in a product they read answered %d: %s",
				got.Code, got.Body.String())
		}

		refused := httpapitest.AsPerson(t, r, "part-triage", http.MethodPatch,
			"/v1/advisories/"+named, `{"title":"Not theirs to call"}`)
		if refused.Code != http.StatusForbidden {
			t.Fatalf("retitling an advisory covering a product they only read answered %d: %s",
				refused.Code, refused.Body.String())
		}
		// And the refusal carries no internal identifier, which is what the
		// arm exists to withhold. Matched as a whole number: a small
		// identifier is a digit of the status the body also carries.
		for _, leaked := range []int64{mine, theirs} {
			whole := regexp.MustCompile(`\b` + strconv.FormatInt(leaked, 10) + `\b`)
			if whole.MatchString(refused.Body.String()) {
				t.Errorf("the refusal names an internal product identifier: %s",
					refused.Body.String())
			}
		}
	})
}

func TestEveryObjectInACSAFDocumentHasItsKeysInOrder(t *testing.T) {
	// The standard's optional sorting test reads every key at every depth,
	// and a customer's validator reports a document that fails it.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		flaw := r.Embargoed(t)
		named := httpapitest.AdvisoryOver(t, r, "private-triage", "mine", flaw)
		at := "/v1/advisories/" + named

		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodGet, at+"/document", "")
		if got.Code != http.StatusOK {
			t.Fatalf("generating answered %d: %s", got.Code, got.Body.String())
		}
		objects := sortedObjects(t, got.Body.Bytes())

		// And the bytes kept as it went out, which are what a directory serves.
		httpapitest.AgreedTo(t, r, at)
		if sent := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, at+"/issuance",
			`{}`); sent.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", sent.Code, sent.Body.String())
		}
		var kept string
		if err := r.DB.DB.NewSelect().TableExpr(`"advisory_issuance"`).
			Column("document").Limit(1).Scan(t.Context(), &kept); err != nil {
			t.Fatal(err)
		}
		objects += sortedObjects(t, []byte(kept))
		// A walk that reached nothing looks like a walk that found nothing
		// wrong. The document holds a tracking, a publisher, a product tree
		// and a vulnerability at the least, twice over.
		if objects < 10 {
			t.Fatalf("only %d objects were reached, so this proves little", objects)
		}
	})
}

// sortedObjects fails every object in a JSON document whose keys are out of
// order, and answers how many objects it read.
func sortedObjects(t *testing.T, body []byte) int {
	t.Helper()
	reader := json.NewDecoder(strings.NewReader(string(body)))
	type frame struct {
		object bool
		last   string
		key    bool
	}
	var stack []frame
	objects := 0
	for {
		token, err := reader.Token()
		if err != nil {
			break
		}
		top := len(stack) - 1
		switch held := token.(type) {
		case json.Delim:
			switch held {
			case '{':
				objects++
				if top >= 0 && stack[top].object {
					stack[top].key = true
				}
				stack = append(stack, frame{object: true, key: true})
			case '[':
				if top >= 0 && stack[top].object {
					stack[top].key = true
				}
				stack = append(stack, frame{})
			default:
				stack = stack[:top]
			}
		case string:
			if top >= 0 && stack[top].object && stack[top].key {
				if held < stack[top].last {
					t.Errorf("%q comes after %q", held, stack[top].last)
				}
				stack[top].last, stack[top].key = held, false
				continue
			}
			if top >= 0 && stack[top].object {
				stack[top].key = true
			}
		default:
			if top >= 0 && stack[top].object {
				stack[top].key = true
			}
		}
	}
	return objects
}
