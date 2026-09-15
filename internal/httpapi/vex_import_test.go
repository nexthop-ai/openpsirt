package httpapi_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/adapters/humachi"

	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// vexed uploads one OpenVEX document as a publisher's statements.
func (r *reach) vexed(t *testing.T, who, publisher, document string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("statements", publisher+".json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(document)); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost,
		"/v1/products/mine/vex-statements?publisher="+publisher, &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	req.Header.Set(testHeader, who)
	fromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return rec
}

// said is a conforming OpenVEX document making one statement.
func said(status, justification, statement string) string {
	return `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/1",
		"author":"Example Distribution","timestamp":"2026-09-01T00:00:00Z","version":1,
		"statements":[{"vulnerability":{"name":"CVE-2026-9999"},
		"products":[{"@id":"pkg:deb/debian/libnl-3-200@3.7.0"}],
		"status":"` + status + `"` +
		func() string {
			out := ""
			if justification != "" {
				out += `,"justification":"` + justification + `"`
			}
			if statement != "" {
				// The format's own field names: a reason under not_affected is
				// an impact statement, and one under affected is an action
				// statement. There is no bare "statement".
				if status == "affected" {
					out += `,"action_statement":"` + statement + `"`
				} else {
					out += `,"impact_statement":"` + statement + `"`
				}
			}
			return out
		}() + `}]}`
}

func TestAVexStatementIsEvidenceAndNeverADecision(t *testing.T) {
	// A third layer beside the build's own claims and our
	// decisions: shown, offered as a prefill, and never applied by itself.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		// Only an administrator uploads one: it is a statement about a
		// product, not a judgment somebody triages.
		refusedWith(t, r.vexed(t, "triager", "debian", said("not_affected",
			"vulnerable_code_not_present", "The affected routine is not built.")),
			http.StatusForbidden)

		got := r.vexed(t, "admin", "debian", said("not_affected",
			"vulnerable_code_not_present", "The affected routine is not built here."))
		if got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}
		var taken struct {
			Publisher  string `json:"publisher"`
			Recorded   int    `json:"recorded"`
			Superseded int    `json:"superseded"`
			Digest     string `json:"digest"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &taken); err != nil {
			t.Fatal(err)
		}
		if taken.Recorded != 1 || taken.Publisher != "debian" || taken.Digest == "" {
			t.Fatalf("the upload reports %+v", taken)
		}

		// It shows on the finding as its own layer, with the reasoning, which
		// is what it adds over what the scanner already reports.
		var detail struct {
			State string `json:"state"`
			Vex   []struct {
				Publisher string `json:"publisher"`
				Status    string `json:"status"`
				Statement string `json:"statement"`
				Offers    string `json:"offers"`
			} `json:"vex"`
			Standing []struct{} `json:"standing"`
		}
		read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/components/libnl-3-200", &detail)
		if len(detail.Vex) != 1 {
			t.Fatalf("the finding shows %d VEX statements", len(detail.Vex))
		}
		one := detail.Vex[0]
		if one.Publisher != "debian" || one.Statement == "" {
			t.Errorf("the statement reads %+v, and the reasoning is the point", one)
		}
		// **Never applied.** Nothing was decided by uploading it.
		if len(detail.Standing) != 0 {
			t.Errorf("a VEX statement became a decision: %d standing", len(detail.Standing))
		}
		var open struct {
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/products/mine/findings?state=undecided", &open)
		if open.Total != 1 {
			t.Errorf("uploading a statement changed what is open: %d undecided", open.Total)
		}
	})
}

func TestWillNotFixNeverOffersADismissal(t *testing.T) {
	// Debian's no-dsa, Ubuntu's ignored and Red Hat's will-not-fix all
	// mean *affected, and judged minor*. Prefilling a dismissal from one
	// would record a claim the publisher never made, with their name on
	// it.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		for _, each := range []struct {
			status string
			offers string
		}{
			{"affected", "wont-fix"},
			{"not_affected", "not-applicable"},
			{"fixed", "already-fixed"},
			{"under_investigation", ""},
		} {
			if got := r.vexed(t, "admin", "debian",
				said(each.status, "vulnerable_code_not_present", "Because.")); got.Code != http.StatusCreated {
				t.Fatalf("%s answered %d: %s", each.status, got.Code, got.Body.String())
			}
			var detail struct {
				Vex []struct {
					Status string `json:"status"`
					Offers string `json:"offers"`
				} `json:"vex"`
			}
			read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/components/libnl-3-200", &detail)
			if len(detail.Vex) != 1 {
				t.Fatalf("%s left %d standing statements", each.status, len(detail.Vex))
			}
			if detail.Vex[0].Offers != each.offers {
				t.Errorf("%q offers %q, want %q",
					each.status, detail.Vex[0].Offers, each.offers)
			}
		}
	})
}

func TestTheListFindsWhatAVexPublisherHasSpokenAbout(t *testing.T) {
	// Being able to find the population is the point of taking the
	// statements at all: on a real image 1,113 of 1,125 no-fix findings
	// are distribution packages, and a distribution publishes
	// machine-readable judgments about exactly those. Found they are an
	// afternoon.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		if got := r.vexed(t, "admin", "debian",
			said("affected", "", "Minor, and not worth a stable update.")); got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}

		count := func(t *testing.T, query string) int {
			t.Helper()
			var page struct {
				Total int `json:"total"`
			}
			read(t, r, "triager", "/v1/products/mine/findings?"+query, &page)
			return page.Total
		}
		if got := count(t, ""); got != 1 {
			t.Fatalf("the fixture lists %d rows", got)
		}
		if got := count(t, "vex_publisher=debian"); got != 1 {
			t.Errorf("what debian spoke about is %d rows", got)
		}
		if got := count(t, "vex_status=affected"); got != 1 {
			t.Errorf("what a publisher called affected is %d rows", got)
		}
		// Both have to hold, and a publisher nobody uploaded reaches nothing.
		if got := count(t, "vex_publisher=debian&vex_status=not_affected"); got != 0 {
			t.Errorf("debian saying not-affected reaches %d rows, and they said affected", got)
		}
		if got := count(t, "vex_publisher=ubuntu"); got != 0 {
			t.Errorf("a publisher nobody uploaded reaches %d rows", got)
		}

		// A statement set aside by a later document stops narrowing: what a
		// publisher says now is what the filter answers about.
		if got := r.vexed(t, "admin", "debian",
			said("fixed", "", "Backported in 3.7.0-1.")); got.Code != http.StatusCreated {
			t.Fatalf("the second document answered %d: %s", got.Code, got.Body.String())
		}
		if got := count(t, "vex_status=affected"); got != 0 {
			t.Errorf("a superseded statement still narrows: %d rows", got)
		}
		if got := count(t, "vex_status=fixed"); got != 1 {
			t.Errorf("what they say now reaches %d rows", got)
		}
	})
}

func TestARevisedStatementRaisesAnAlertAndLeavesTheDecisionStanding(t *testing.T) {
	// A publisher changing their mind does not withdraw somebody's
	// judgment — a third party's claim never becomes ours — but something
	// has to notice that the ground moved under a dismissal approved on
	// the strength of it.
	eachReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		if got := r.vexed(t, "admin", "debian", said("not_affected",
			"vulnerable_code_not_present", "Not built here.")); got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}

		// Which statement to cite, as the finding offers it.
		var detail struct {
			Vex []struct {
				ID int64 `json:"id"`
			} `json:"vex"`
		}
		read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/components/libnl-3-200", &detail)
		if len(detail.Vex) != 1 || detail.Vex[0].ID == 0 {
			t.Fatalf("the finding offers %+v to cite", detail.Vex)
		}

		// A dismissal started from it, agreed to by somebody else.
		made := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/places/"+place+"/decision",
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
				`"reasoning":"Debian says the affected routine is not built.",`+
				`"from_statement":`+itoa(detail.Vex[0].ID)+`}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("deciding answered %d: %s", made.Code, made.Body.String())
		}
		var recorded struct {
			ID      int64 `json:"id"`
			ClaimID int64 `json:"claim_id"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		if got := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/claims/"+itoa(recorded.ClaimID)+"/approval", `{}`); got.Code >= 300 {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}

		// Nothing is wrong yet.
		if told := r.alerts(t, "triager", "statement-revised"); len(told) != 0 {
			t.Fatalf("something was raised before the publisher changed anything: %v", told)
		}

		// And then they change their mind.
		if got := r.vexed(t, "admin", "debian",
			said("affected", "", "On reflection, it is built.")); got.Code != http.StatusCreated {
			t.Fatalf("the second document answered %d: %s", got.Code, got.Body.String())
		}
		told := r.alerts(t, "triager", "statement-revised")
		if len(told) != 1 {
			t.Fatalf("a revised statement raised %d alerts, want one: %v", len(told), told)
		}

		// The decision stands. A publisher changing their mind is not a
		// withdrawal of somebody's judgment.
		var still struct {
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/products/mine/findings?state=agreed", &still)
		if still.Total != 1 {
			t.Errorf("the decision stopped standing when the publisher changed their mind")
		}
	})
}

// alerts is what somebody has been told, of one kind.
func (r *reach) alerts(t *testing.T, who, kind string) []string {
	t.Helper()
	// Driven directly: the sweep is a background pass rather than a route, so
	// there is nothing to ask for it over HTTP.
	if _, _, err := notify.NewWatch(r.db.DB,
		slog.New(slog.NewTextHandler(io.Discard, nil))).Once(t.Context()); err != nil {
		t.Fatal(err)
	}
	var waiting struct {
		Items []struct {
			Kind string `json:"kind"`
			Body string `json:"body"`
		} `json:"items"`
	}
	read(t, r, who, "/v1/notifications", &waiting)
	var about []string
	for _, one := range waiting.Items {
		if one.Kind == kind {
			about = append(about, one.Body)
		}
	}
	return about
}

func TestAnUploadLeavesNothingBehindOnDisk(t *testing.T) {
	// The server removes spooled multipart parts from the request it was
	// handed, and what parses the form is the copy the middleware makes — so
	// nothing owned the copy's temporary files and they stayed for the life of
	// the container. A refused upload leaked them as readily as an accepted
	// one, which is a disk anybody with a credential fills by repeating a
	// request that fails.
	// dbtest.Alone rather than the usual fixture: TMPDIR is read by the whole
	// process, so a test that changes it cannot run beside another.
	reachOn(t, dbtest.Alone, func(t *testing.T, r *reach) {
		spool := t.TempDir()
		t.Setenv("TMPDIR", spool)

		before, err := os.ReadDir(spool)
		if err != nil {
			t.Fatal(err)
		}

		// Larger than the in-memory threshold, so the parts are spooled rather
		// than held; and sent by somebody this endpoint refuses, because a
		// refusal is the case that leaked.
		body := &bytes.Buffer{}
		form := multipart.NewWriter(body)
		part, err := form.CreateFormFile("statements", "statements.json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(bytes.Repeat([]byte("a"), int(2*humachi.MultipartMaxMemory))); err != nil {
			t.Fatal(err)
		}
		if err := form.Close(); err != nil {
			t.Fatal(err)
		}

		request := httptest.NewRequest(http.MethodPost,
			"/v1/products/mine/vex-statements?publisher=debian", body)
		request.Header.Set("Content-Type", form.FormDataContentType())
		request.Header.Set(testHeader, "triager")
		fromOurOwnPage(request)
		got := httptest.NewRecorder()
		r.handler.ServeHTTP(got, request)
		// Refused, because a triager may not upload these — and a refusal is
		// the case that leaked, since by the time this endpoint's own check
		// runs the parts are already on disk.
		if got.Code != http.StatusForbidden {
			t.Fatalf("a triager uploading VEX statements answered %d: %s",
				got.Code, got.Body.String())
		}

		after, err := os.ReadDir(spool)
		if err != nil {
			t.Fatal(err)
		}
		if len(after) != len(before) {
			names := make([]string, 0, len(after))
			for _, each := range after {
				names = append(names, each.Name())
			}
			t.Errorf("a refused upload left %d files behind: %v", len(after)-len(before), names)
		}
	})
}

// The document is read as a stream, and the digest still covers all of it.
//
// It used to be held whole and then copied to parse from — about two and a
// half times the byte limit, against a container that ships with less than
// that, so importing a large vendor document killed the process instead of
// answering. Streaming it puts the digest on the way past, and a digest over
// part of a document is worse than none: it is what says whether a publisher
// has revised what they said, so two different documents hashing alike would
// leave a decision citing evidence that has since changed.
func TestTheDigestCoversTheWholeDocumentItStreamed(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		// The padding sits **outside** the top-level object, so the parser
		// stops at the closing brace and the drain past it actually runs.
		// Inside the object it is a field the parser skips on its way to the
		// end, which leaves the drain reading nothing and the test passing
		// whatever the drain does.
		padding := strings.Repeat("\n", 64*1024)
		document := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/1",
			"author":"Example Distribution","timestamp":"2026-09-01T00:00:00Z","version":1,
			"statements":[{"vulnerability":{"name":"CVE-2026-9999"},"status":"not_affected",
			  "justification":"vulnerable_code_not_present",
			  "impact_statement":"The affected routine is not built here.",
			  "products":[{"@id":"pkg:deb/debian/libnl-3-200@3.7.0-0.2"}]}]}` + padding

		got := r.vexed(t, "admin", "debian", document)
		if got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}
		var taken struct {
			Digest string `json:"digest"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &taken); err != nil {
			t.Fatal(err)
		}
		whole := sha256.Sum256([]byte(document))
		if taken.Digest != hex.EncodeToString(whole[:]) {
			t.Errorf("the digest recorded is %q, want the hash of the whole document %q",
				taken.Digest, hex.EncodeToString(whole[:]))
		}
	})
}

func TestWhoPublishedItIsBoundedRatherThanShortened(t *testing.T) {
	// It is the key a later upload supersedes on and an indexed column of a
	// fixed width, so two publishers agreeing for that many characters would
	// collapse into one and the second upload would set aside statements it
	// has nothing to do with. And where the query parameter is absent the
	// value falls back to the name the client gave the file it uploaded,
	// which is the path with nothing else guarding it.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		document := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/1",
			"author":"Example","timestamp":"2026-09-01T00:00:00Z","version":1,
			"statements":[{"vulnerability":{"name":"CVE-2026-9998"},"status":"not_affected",
			  "justification":"vulnerable_code_not_present",
			  "products":[{"@id":"pkg:deb/debian/libnl-3-200@3.7.0-0.2"}]}]}`

		if got := r.vexed(t, "admin", strings.Repeat("d", 192), document); got.Code < 400 {
			t.Errorf("a publisher longer than the column answered %d", got.Code)
		}
		if got := r.vexed(t, "admin", strings.Repeat("d", 191), document); got.Code != http.StatusCreated {
			t.Errorf("a publisher exactly the width of the column answered %d: %s",
				got.Code, got.Body.String())
		}
	})
}
