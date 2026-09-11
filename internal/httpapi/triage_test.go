package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// asPerson makes a request the way a signed-in person does.
func asPerson(t *testing.T, r *reach, who, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(testHeader, who)
	fromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return rec
}

func TestTheReviewQueueIsReadableAndNarrowed(t *testing.T) {
	// The queue is the screen somebody works down. It has to be reachable by
	// whoever reads the product, and empty for somebody who holds nothing.
	eachReach(t, func(t *testing.T, r *reach) {
		got := asPerson(t, r, "triager", http.MethodGet, "/v1/review-queue", "")
		if got.Code != http.StatusOK {
			t.Fatalf("a triager reading the queue answered %d: %s", got.Code, got.Body.String())
		}
		var out struct {
			Items []map[string]any `json:"items"`
			Total int              `json:"total"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, got.Body.String())
		}
		if out.Total != 0 || len(out.Items) != 0 {
			t.Errorf("a deployment that has decided nothing has %d waiting", out.Total)
		}
	})
}

func TestDecidingAboutSomethingNobodyScannedIsNotThere(t *testing.T) {
	// A decision is about a finding. Naming a place freely would be choosing
	// which decisions apply where, so the names are resolved against what was
	// actually scanned.
	twoReach(t, func(t *testing.T, r *reach) {
		const body = `{"outcome":"wont-fix","reasoning":"Not worth it."}`
		got := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom/findings/CVE-2026-1/places/nowhere/decision", body)
		if got.Code != http.StatusNotFound {
			t.Errorf("deciding about an unscanned build answered %d, want 404: %s", got.Code, got.Body.String())
		}
	})
}

func TestDecidingIsRefusedToSomebodyWhoOnlyReads(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		const body = `{"outcome":"wont-fix","reasoning":"Not worth it."}`
		got := asPerson(t, r, "reader", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom/findings/CVE-2026-1/places/somewhere/decision", body)
		// Not there rather than forbidden: a build nothing was scanned against
		// answers the same way whoever asks, and somebody who may not decide
		// learns nothing from the difference.
		if got.Code != http.StatusNotFound && got.Code != http.StatusForbidden {
			t.Errorf("a reader deciding answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestApprovingSomethingThatIsNotThereSaysSo(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		got := asPerson(t, r, "triager", http.MethodPost, "/v1/decisions/999999/approval", `{}`)
		if got.Code != http.StatusNotFound {
			t.Errorf("approving a decision that does not exist answered %d", got.Code)
		}
	})
}

func TestARefusalOfTypedTextSaysWhereToLook(t *testing.T) {
	// A justification runs to dozens of lines, and a refusal naming only a
	// category means somebody hunting for the offending line by eye. The
	// answer carries the position because an interface can only point at the
	// problem if it is told where the problem is.
	//
	// Against a decision that exists. The first version of this ran against an
	// identifier nothing had ever created, so it was asserting that a missing
	// decision is not found — which it would have done just as well with the
	// text check removed altogether.
	twoReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		id, claim := r.decidedAt(t, place)

		body := `{"reasoning":"This is fine.\n\nBut see ![proof](https://evil.example/x.png)"}`
		got := asPerson(t, r, "triager", http.MethodPut,
			fmt.Sprintf("/v1/claims/%d/reasoning", claim), body)
		if got.Code != http.StatusUnprocessableEntity {
			t.Fatalf("a remote image answered %d: %s", got.Code, got.Body.String())
		}

		var refusal struct {
			Detail string `json:"detail"`
			Errors []struct {
				Message  string `json:"message"`
				Location string `json:"location"`
				Value    any    `json:"value"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &refusal); err != nil {
			t.Fatalf("decode: %v (%s)", err, got.Body.String())
		}
		if len(refusal.Errors) == 0 {
			t.Fatalf("the refusal carries nothing to point at: %s", got.Body.String())
		}
		one := refusal.Errors[0]
		if one.Location != "line 3" {
			t.Errorf("the fault is reported at %q, want the line it is on", one.Location)
		}
		if fmt.Sprint(one.Value) != "https://evil.example/x.png" {
			t.Errorf("the refusal does not name what was wrong: %v", one.Value)
		}
		if !strings.Contains(one.Message, "image") {
			t.Errorf("the reason reads as %q", one.Message)
		}

		// And nothing was stored: the reasoning still says what it said.
		var detail struct {
			Reasoning string `json:"reasoning"`
		}
		read(t, r, "triager", fmt.Sprintf("/v1/decisions/%d", id), &detail)
		if strings.Contains(detail.Reasoning, "evil.example") {
			t.Error("refused text was stored anyway")
		}
	})
}

func TestAPipelineHasNoJudgment(t *testing.T) {
	// A build server has no business deciding anything about what it uploaded.
	twoReach(t, func(t *testing.T, r *reach) {
		if got := r.asKey(t, http.MethodGet, "/v1/review-queue"); got != http.StatusForbidden {
			t.Errorf("a pipeline read the review queue: %d", got)
		}
	})
}

func TestATokenDecidesOnlyWhatItsOwnerCould(t *testing.T) {
	// A personal token is a live reference to its owner, so it reaches the
	// queue exactly when they do.
	twoReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		person, err := r.rights.ByIdentity(ctx, "triager")
		if err != nil {
			t.Fatal(err)
		}
		_, secret, err := r.rights.NewToken(ctx, person.ID, "scripting", nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := r.withKey(t, secret, http.MethodGet, "/v1/review-queue").code; got != http.StatusOK {
			t.Errorf("a token could not read what its owner reads: %d", got)
		}

		reader, err := r.rights.ByIdentity(ctx, "assigner-only")
		if err != nil {
			t.Fatal(err)
		}
		_, weak, err := r.rights.NewToken(ctx, reader.ID, "dispatching", nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		// Holding a capability and no read role, this person sees no products
		// at all — so their token sees no queue.
		got := r.withKey(t, weak, http.MethodGet, "/v1/review-queue")
		if got.code != http.StatusOK {
			t.Fatalf("reading the queue answered %d", got.code)
		}
		if !strings.Contains(got.text, `"total":0`) {
			t.Errorf("somebody holding only a capability was shown work: %s", got.text)
		}
	})
}

var _ = access.PublicTriage

func TestABackportIsRecordableAndAnUpgradeIsNotRecordedFromOneFinding(t *testing.T) {
	// the outcomes that promise work at the issue grain. A backport is the
	// answer a version comparison cannot see: the fix is carried in and
	// the version stays where it was, so unless somebody can say so, the
	// row sits open with nothing true to say about it. It needs the date,
	// because "we will deal with this" is what leaving it alone already
	// says.
	//
	// And the other half: the same vocabulary at the wrong grain. An
	// upgrade answers a component and everything open on it, so recorded
	// from one finding it would be a promise covering one row of what it
	// is about.
	eachReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		at := fmt.Sprintf("/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/places/%s/decision", place)

		// No date: refused, because there is nothing to gate against and
		// nothing to lapse.
		if got := asPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"patch-needed",`+
				`"reasoning":"Taking the upstream commit as a distro patch."}`); got.Code < 400 {
			t.Errorf("a promise with no date answered %d", got.Code)
		}
		// A version: refused, because a backport moves none — that is the
		// whole difference between the two outcomes.
		if got := asPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"patch-needed","committed_to":"`+aheadOfUs+`","upgrade_to":"3.9.0",`+
				`"reasoning":"Taking the upstream commit as a distro patch."}`); got.Code < 400 {
			t.Errorf("a backport naming a version answered %d", got.Code)
		}
		// The grain, not the word: an upgrade is right, and this is the wrong
		// place for it.
		if got := asPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"upgrade-needed","committed_to":"`+aheadOfUs+`","upgrade_to":"3.9.0",`+
				`"reasoning":"Moving to 3.9.0."}`); got.Code < 400 {
			t.Errorf("an upgrade recorded from one finding answered %d", got.Code)
		}

		got := asPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"patch-needed","committed_to":"`+aheadOfUs+`",`+
				`"reasoning":"Taking the upstream commit as a distro patch in the next build."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording a backport answered %d: %s", got.Code, got.Body.String())
		}
		var wrote struct {
			Outcome     string `json:"outcome"`
			CommittedTo string `json:"committed_to"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &wrote); err != nil {
			t.Fatal(err)
		}
		if wrote.Outcome != "patch-needed" || wrote.CommittedTo != aheadOfUs {
			t.Errorf("the claim reads back as %+v", wrote)
		}

		// And it is findable as itself, which is what makes "what are we
		// backporting" a question with an answer.
		var page struct {
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/products/mine/findings?outcome=patch-needed", &page)
		if page.Total != 1 {
			t.Errorf("asking for what is being backported found %d rows", page.Total)
		}
	})
}
