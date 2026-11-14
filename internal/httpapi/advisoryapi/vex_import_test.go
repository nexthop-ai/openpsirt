// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/adapters/humachi"

	"github.com/nexthop-ai/openpsirt/internal/bound/boundtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/advisoryapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

func TestAVexStatementIsEvidenceAndNeverADecision(t *testing.T) {
	// A third layer beside the build's own claims and our decisions. A
	// statement naming no supplier's product is shown, offered as a prefill,
	// and never applied by itself.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)

		// Only an administrator uploads one: it is a statement about a
		// product, not a judgment somebody triages.
		httpapitest.RefusedWith(t, r.Vexed(t, "triager", "debian", httpapitest.Said("not_affected",
			"vulnerable_code_not_present", "The affected routine is not built.")),
			http.StatusForbidden)

		// Named with capitals, so the answer shows whether it names the
		// publisher as given or as folded for matching.
		got := r.Vexed(t, "admin", "Debian", httpapitest.Said("not_affected",
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
		if taken.Recorded != 1 || taken.Publisher != "Debian" || taken.Digest == "" {
			t.Fatalf("the upload reports %+v", taken)
		}

		// It shows on the finding as its own layer, with the reasoning, which
		// is what it adds over what the scanner already reports.
		var detail struct {
			State string `json:"state"`
			Said  []struct {
				Publisher string `json:"publisher"`
				Status    string `json:"status"`
				Statement string `json:"statement"`
				Offers    string `json:"offers"`
			} `json:"said"`
			Standing []struct{} `json:"standing"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/branches-and-tags/master/variants/broadcom"+
			"/findings/CVE-2026-9999/components/libnl-3-200", &detail)
		if len(detail.Said) != 1 {
			t.Fatalf("the finding shows %d VEX statements", len(detail.Said))
		}
		one := detail.Said[0]
		if one.Publisher != "debian" || one.Statement == "" {
			t.Errorf("the statement reads %+v, and the reasoning is the point", one)
		}
		// Never applied. Nothing was decided by uploading it.
		if len(detail.Standing) != 0 {
			t.Errorf("a VEX statement became a decision: %d standing", len(detail.Standing))
		}
		var open struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/findings?state=undecided", &open)
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
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		for _, each := range []struct {
			status string
			offers string
		}{
			{"affected", "wont-fix"},
			{"not_affected", "not-applicable"},
			{"fixed", "already-fixed"},
			{"under_investigation", ""},
		} {
			if got := r.Vexed(t, "admin", "debian",
				httpapitest.Said(each.status, "vulnerable_code_not_present", "Because.")); got.Code != http.StatusCreated {
				t.Fatalf("%s answered %d: %s", each.status, got.Code, got.Body.String())
			}
			var detail struct {
				Said []struct {
					Status string `json:"status"`
					Offers string `json:"offers"`
				} `json:"said"`
			}
			httpapitest.Read(t, r, "triager", "/v1/products/mine/branches-and-tags/master/variants/broadcom"+
				"/findings/CVE-2026-9999/components/libnl-3-200", &detail)
			if len(detail.Said) != 1 {
				t.Fatalf("%s left %d standing statements", each.status, len(detail.Said))
			}
			if detail.Said[0].Offers != each.offers {
				t.Errorf("%q offers %q, want %q",
					each.status, detail.Said[0].Offers, each.offers)
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
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		if got := r.Vexed(t, "admin", "debian",
			httpapitest.Said("affected", "", "Minor, and not worth a stable update.")); got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}

		count := func(t *testing.T, query string) int {
			t.Helper()
			var page struct {
				Total int `json:"total"`
			}
			httpapitest.Read(t, r, "triager", "/v1/products/mine/findings?"+query, &page)
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
		if got := r.Vexed(t, "admin", "debian",
			httpapitest.Said("fixed", "", "Backported in 3.7.0-1.")); got.Code != http.StatusCreated {
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
	// decision — a third party's claim never becomes ours — but something
	// has to notice that the ground moved under a dismissal approved on
	// the strength of it.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := r.Scanned(t)
		if got := r.Vexed(t, "admin", "debian", httpapitest.Said("not_affected",
			"vulnerable_code_not_present", "Not built here.")); got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}

		// detail is which statement to cite, as the finding offers it.
		var detail struct {
			Said []struct {
				ID int64 `json:"id"`
			} `json:"said"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/branches-and-tags/master/variants/broadcom"+
			"/findings/CVE-2026-9999/components/libnl-3-200", &detail)
		if len(detail.Said) != 1 || detail.Said[0].ID == 0 {
			t.Fatalf("the finding offers %+v to cite", detail.Said)
		}

		// A dismissal started from it, agreed to by somebody else.
		made := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom"+
				"/findings/CVE-2026-9999/occurrences/"+occurrence+"/decision",
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
				`"reasoning":"Debian says the affected routine is not built.",`+
				`"from_statement":`+httpapitest.Itoa(detail.Said[0].ID)+`}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("deciding answered %d: %s", made.Code, made.Body.String())
		}
		var recorded struct {
			ID         int64 `json:"id"`
			DecisionID int64 `json:"decision_id"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			"/v1/decisions/"+httpapitest.Itoa(recorded.DecisionID)+"/approval", `{}`); got.Code >= 300 {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}

		// Nothing is wrong yet.
		if told := r.Alerts(t, "triager", "statement-revised"); len(told) != 0 {
			t.Fatalf("something was raised before the publisher changed anything: %v", told)
		}

		// And then they change their mind.
		if got := r.Vexed(t, "admin", "debian",
			httpapitest.Said("affected", "", "On reflection, it is built.")); got.Code != http.StatusCreated {
			t.Fatalf("the second document answered %d: %s", got.Code, got.Body.String())
		}
		told := r.Alerts(t, "triager", "statement-revised")
		if len(told) != 1 {
			t.Fatalf("a revised statement raised %d alerts, want one: %v", len(told), told)
		}

		// The decision stands. A publisher changing their mind is not a
		// withdrawal of somebody's decision.
		var still struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/findings?state=agreed", &still)
		if still.Total != 1 {
			t.Errorf("the decision stopped standing when the publisher changed their mind")
		}
	})
}

func TestAnUploadLeavesNothingBehindOnDisk(t *testing.T) {
	// The server removes spooled multipart parts from the request it was
	// handed, and what parses the form is the copy the middleware makes — so
	// nothing owned the copy's temporary files and they stayed for the life of
	// the container. A refused upload leaked them as readily as an accepted
	// one, which is a disk anybody with a credential fills by repeating a
	// request that fails.
	// CastSeed.Alone rather than the usual fixture: TMPDIR is read by the whole
	// process, so a test that changes it cannot run beside another.
	httpapitest.ReachOn(t, httpapitest.CastSeed.Alone, func(t *testing.T, r *httpapitest.Reach) {
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
			"/v1/products/mine/vex-documents?publisher=debian", body)
		request.Header.Set("Content-Type", form.FormDataContentType())
		request.Header.Set(httpapitest.TestHeader, "triager")
		httpapitest.FromOurOwnPage(request)
		got := httptest.NewRecorder()
		r.Handler.ServeHTTP(got, request)
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
// Held whole and then copied to parse from, it costs about two and a half
// times the byte limit against a container that ships with less than that, so
// importing a large vendor document kills the process instead of answering.
// Streaming it puts the digest on the way past, and a digest over
// part of a document is worse than none: it is what says whether a publisher
// has revised what they said, so two different documents hashing alike would
// leave a decision citing evidence that has since changed.
func TestTheDigestCoversTheWholeDocumentItStreamed(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		// The padding sits outside the top-level object, which the parser
		// reads to the end of the file on its way to refusing anything but
		// whitespace there.
		padding := strings.Repeat("\n", 64*1024)
		document := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/1",
			"author":"Example Distribution","timestamp":"2026-09-01T00:00:00Z","version":1,
			"statements":[{"vulnerability":{"name":"CVE-2026-9999"},"status":"not_affected",
			  "justification":"vulnerable_code_not_present",
			  "impact_statement":"The affected routine is not built here.",
			  "products":[{"@id":"pkg:deb/debian/libnl-3-200@3.7.0-0.2"}]}]}` + padding

		got := r.Vexed(t, "admin", "debian", document)
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
	// value is the author the document names, which has nothing else
	// guarding its width.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		document := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/1",
			"author":"Example","timestamp":"2026-09-01T00:00:00Z","version":1,
			"statements":[{"vulnerability":{"name":"CVE-2026-9998"},"status":"not_affected",
			  "justification":"vulnerable_code_not_present",
			  "products":[{"@id":"pkg:deb/debian/libnl-3-200@3.7.0-0.2"}]}]}`

		httpapitest.RefusedWith(t, r.Vexed(t, "admin", strings.Repeat("d", 192), document),
			http.StatusUnprocessableEntity)
		// The document's author stands in for a publisher the query leaves
		// out, and is held to the same width by the handler. The handler's
		// refusal says how to name a publisher instead; the store's, reached
		// with the handler's check deleted, does not.
		named := r.VexedAs(t, "admin", "", "statements.json",
			strings.Replace(document, `"Example"`, `"`+strings.Repeat("d", 192)+`"`, 1))
		httpapitest.RefusedWith(t, named, http.StatusUnprocessableEntity)
		if !strings.Contains(named.Body.String(), "?publisher=") {
			t.Errorf("a file name too long to be the publisher is not told how to name one: %s",
				named.Body.String())
		}
		if got := r.Vexed(t, "admin", strings.Repeat("d", 191), document); got.Code != http.StatusCreated {
			t.Errorf("a publisher exactly the width of the column answered %d: %s",
				got.Code, got.Body.String())
		}
		// The width is in characters. A name of 191 that takes two bytes each
		// fits the column, and counted in bytes it was refused.
		if got := r.Vexed(t, "admin", strings.Repeat("é", 191), document); got.Code != http.StatusCreated {
			t.Errorf("a publisher of 191 characters outside ASCII answered %d: %s",
				got.Code, got.Body.String())
		}
	})
}

func TestWhoPublishedItIsHeldWithoutCharactersThatReorderText(t *testing.T) {
	// The publisher is shown wherever the evidence is, and a right-to-left
	// override in it reads reversed there. The author it falls back to is the
	// document's, and the query parameter is the client's.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		document := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/1",
			"author":"acme\u202enosj","timestamp":"2026-09-01T00:00:00Z","version":1,
			"statements":[{"vulnerability":{"name":"CVE-2026-9998"},"status":"not_affected",
			  "justification":"vulnerable_code_not_present",
			  "products":[{"@id":"pkg:deb/debian/libnl-3-200@3.7.0-0.2"}]}]}`
		for _, each := range []struct{ query, file, want string }{
			{"", "statements.json", "acmenosj"},
			{"acme%E2%80%AE%07", "statements.json", "acme"},
		} {
			got := r.VexedAs(t, "admin", each.query, each.file, document)
			if got.Code != http.StatusCreated {
				t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
			}
			var taken struct {
				Publisher string `json:"publisher"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &taken); err != nil {
				t.Fatal(err)
			}
			if taken.Publisher != each.want {
				t.Errorf("the publisher recorded is %q, want %q", taken.Publisher, each.want)
			}
		}
	})
}

func TestADocumentsIdentifierIsHeldWithoutCharactersThatReorderText(t *testing.T) {
	// The identifier is what a revision is matched by. One differing from
	// another only by a right-to-left override reads the same on every
	// screen, and is the same document.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		named := func(id, issue string) string {
			return `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"` + id + `",
				"author":"acme","timestamp":"2026-09-01T00:00:00Z","version":1,
				"statements":[{"vulnerability":{"name":"` + issue + `"},"status":"not_affected",
				  "justification":"vulnerable_code_not_present",
				  "products":[{"@id":"pkg:deb/debian/libnl-3-200@3.7.0-0.2"}]}]}`
		}
		if got := r.VexedAs(t, "admin", "", "vex.json",
			named("https://example.test/vex/1", "CVE-2026-9998")); got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}
		got := r.VexedAs(t, "admin", "", "vex.json",
			named("https://example.test/vex\u202e/1", "CVE-2026-9997"))
		if got.Code != http.StatusCreated {
			t.Fatalf("uploading the revision answered %d: %s", got.Code, got.Body.String())
		}
		var taken advisoryapi.StatementsTakenBody
		if err := json.Unmarshal(got.Body.Bytes(), &taken); err != nil {
			t.Fatal(err)
		}
		if taken.Superseded != 1 {
			t.Errorf("a revision whose identifier differs by an override set aside %d statements, want 1",
				taken.Superseded)
		}
	})
}

func TestADocumentWithALongIdentifierIsReplacedByItsRevision(t *testing.T) {
	// An OpenVEX identifier is an IRI of any length. One longer than is
	// recorded is held as its digest, which its revision states again.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		long := "https://example.test/vex/" + strings.Repeat("x", finding.MostDocumentName)
		named := func(id, issue string) string {
			return `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"` + id + `",
				"author":"acme","timestamp":"2026-09-01T00:00:00Z","version":1,
				"statements":[{"vulnerability":{"name":"` + issue + `"},"status":"not_affected",
				  "justification":"vulnerable_code_not_present",
				  "products":[{"@id":"pkg:deb/debian/libnl-3-200@3.7.0-0.2"}]}]}`
		}
		taken := func(id, issue string) advisoryapi.StatementsTakenBody {
			t.Helper()
			got := r.VexedAs(t, "admin", "", "vex.json", named(id, issue))
			if got.Code != http.StatusCreated {
				t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
			}
			var body advisoryapi.StatementsTakenBody
			if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			return body
		}
		taken(long, "CVE-2026-9998")
		if other := taken(long+"y", "CVE-2026-9996"); other.Superseded != 0 {
			t.Errorf("another long identifier set aside %d statements, want none", other.Superseded)
		}
		if revised := taken(long, "CVE-2026-9997"); revised.Superseded != 1 {
			t.Errorf("the revision set aside %d statements, want 1", revised.Superseded)
		}
	})
}

func TestADocumentCutOffPartwayIsRefusedAsMalformed(t *testing.T) {
	// A document ending inside a string is the sender's to fix, and the
	// parser's to report in words.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		whole := httpapitest.Said("not_affected", "vulnerable_code_not_present", "The routine is not built here.")
		cut := whole[:strings.Index(whole, "Example Distri")+len("Example Distri")]
		got := r.Vexed(t, "admin", "debian", cut)
		if got.Code != http.StatusUnprocessableEntity {
			t.Fatalf("a document cut off partway answered %d, want 422: %s", got.Code, got.Body.String())
		}
		if !strings.Contains(got.Body.String(), "partway through a value") {
			t.Errorf("the refusal does not say the document ends partway: %s", got.Body.String())
		}
	})
}

func TestADocumentPastTheByteLimitIsRefusedAsTooLarge(t *testing.T) {
	const most = 4096
	small := func(d *core.Deps) { d.Limits = sbom.Limits{MaxBytes: most} }
	httpapitest.ReachAdjusted(t, httpapitest.CastSeed.Two, small, func(t *testing.T, r *httpapitest.Reach) {
		document := httpapitest.Said("not_affected", "vulnerable_code_not_present", "Not built.")
		if len(document) >= most {
			t.Fatalf("the document is %d bytes, which leaves no room under the limit", len(document))
		}
		tooLarge := func(got *httptest.ResponseRecorder) bool {
			return got.Code == http.StatusRequestEntityTooLarge &&
				strings.Contains(got.Body.String(), "4096 bytes")
		}

		// Whitespace after the document is read, and counts.
		var last *httptest.ResponseRecorder
		boundtest.Edges(t, most, func(n int) error {
			last = r.Vexed(t, "admin", "debian", document+strings.Repeat("\n", n-len(document)))
			if last.Code != http.StatusCreated {
				return errors.New(last.Body.String())
			}
			return nil
		}, func(error) bool { return tooLarge(last) })

		// And a field inside the document running past the limit is refused
		// for its size rather than read as a document cut off partway.
		padded := strings.Replace(document, "Not built.", strings.Repeat("a", 6<<10), 1)
		if got := r.Vexed(t, "admin", "debian", padded); !tooLarge(got) {
			t.Errorf("a document with a 6 KiB field answered %d: %s", got.Code, got.Body.String())
		}
	})
}

// A VEX document is replaced by a later revision of itself, its publisher and
// its own identifier, and never by its file name or by another document from
// the same publisher. A document naming no publisher is refused.
func TestAVexDocumentIsSupersededByItsRevisionAndNeverByItsFileName(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		document := "https://example.test/vex/1"
		by := func(author, issue string) string {
			return `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"` + document + `",
				"author":` + author + `,"timestamp":"2026-09-01T00:00:00Z","version":1,
				"statements":[{"vulnerability":{"name":"` + issue + `"},"status":"not_affected",
				  "justification":"vulnerable_code_not_present",
				  "products":[{"@id":"pkg:deb/debian/libnl-3-200@3.7.0-0.2"}]}]}`
		}
		taken := func(got *httptest.ResponseRecorder) advisoryapi.StatementsTakenBody {
			t.Helper()
			if got.Code != http.StatusCreated {
				t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
			}
			var body advisoryapi.StatementsTakenBody
			if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			return body
		}

		first := taken(r.VexedAs(t, "admin", "", "debian-vex-1.json", by(`"Debian"`, "CVE-2026-9998")))
		if first.Publisher != "Debian" {
			t.Errorf("recorded under %q, want the author the document names", first.Publisher)
		}
		revised := taken(r.VexedAs(t, "admin", "", "debian-vex-2.json", by(`"Debian"`, "CVE-2026-9997")))
		if revised.Superseded != 1 {
			t.Errorf("a revision under a new file name set aside %d statements, want 1",
				revised.Superseded)
		}
		document = "https://example.test/vex/2"
		another := taken(r.VexedAs(t, "admin", "", "debian-vex-2.json", by(`"Debian"`, "CVE-2026-9996")))
		if another.Superseded != 0 {
			t.Errorf("another document from the same publisher set aside %d statements, want none",
				another.Superseded)
		}
		document = "https://example.test/vex/1"
		other := taken(r.VexedAs(t, "admin", "", "debian-vex-2.json", by(`"Ubuntu"`, "CVE-2026-9997")))
		if other.Publisher != "Ubuntu" || other.Superseded != 0 {
			t.Errorf("another publisher's file of the same name answered %+v, want nothing set aside",
				other)
		}

		nobody := r.VexedAs(t, "admin", "", "vex.json", by(`null`, "CVE-2026-9997"))
		httpapitest.RefusedWith(t, nobody, http.StatusUnprocessableEntity)
		if !strings.Contains(nobody.Body.String(), "?publisher=") {
			t.Errorf("a document naming no publisher is not told how to name one: %s",
				nobody.Body.String())
		}
		if named := r.VexedAs(t, "admin", "Debian", "vex.json", by(`null`, "CVE-2026-9997")); named.Code != http.StatusCreated {
			t.Errorf("a publisher the request names answered %d: %s", named.Code, named.Body.String())
		}

		// What an older release filed under a file name carries no
		// identifier, and a document stating none and saying nothing,
		// uploaded under that name, sets it aside.
		unnamed := func(issue string) string {
			statements := `[]`
			if issue != "" {
				statements = `[{"vulnerability":{"name":"` + issue + `"},"status":"not_affected",
				  "justification":"vulnerable_code_not_present",
				  "products":[{"@id":"pkg:deb/debian/libnl-3-200@3.7.0-0.2"}]}]`
			}
			return `{"@context":"https://openvex.dev/ns/v0.2.0","author":"Debian",
				"timestamp":"2026-09-01T00:00:00Z","version":1,"statements":` + statements + `}`
		}
		taken(r.VexedAs(t, "admin", "old-vex.json", "old-vex.json", unnamed("CVE-2026-9995")))
		if cleared := taken(r.VexedAs(t, "admin", "old-vex.json", "empty.json", unnamed(""))); cleared.Superseded != 1 {
			t.Errorf("an empty document stating no identifier set aside %d statements, want 1",
				cleared.Superseded)
		}
	})
}

// A publisher's newest statement about a product and an issue is the one in
// force, whichever of their documents carried it: a June "affected" in one
// document overtakes a March "not affected" in another. Newer is the
// statement's own time, else its document's, else the upload order, and a
// revision withdrawing the newest restores the one it overtook.
func TestThePublishersNewestStatementStandsAcrossDocuments(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		document := func(id, issued, status, statementAt string) string {
			statements := `[]`
			if status != "" {
				at := ""
				if statementAt != "" {
					at = `"timestamp":"` + statementAt + `",`
				}
				statements = `[{` + at + `"vulnerability":{"name":"CVE-2026-9999"},"status":"` + status + `",
				  "justification":"vulnerable_code_not_present",
				  "products":[{"@id":"pkg:deb/debian/libnl-3-200@3.7.0"}]}]`
			}
			return `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/` + id + `",
				"author":"Example Distribution","timestamp":"` + issued + `","version":1,
				"statements":` + statements + `}`
		}
		upload := func(name, body string) advisoryapi.StatementsTakenBody {
			t.Helper()
			got := r.VexedAs(t, "admin", "", name+".json", body)
			if got.Code != http.StatusCreated {
				t.Fatalf("uploading %s answered %d: %s", name, got.Code, got.Body.String())
			}
			var taken advisoryapi.StatementsTakenBody
			if err := json.Unmarshal(got.Body.Bytes(), &taken); err != nil {
				t.Fatal(err)
			}
			return taken
		}
		standing := func(after, want string) {
			t.Helper()
			said := r.WhatPublishersSay(t).Said
			if len(said) != 1 || said[0].Status != want {
				t.Errorf("after %s the publisher's statements in force are %+v, want %s alone", after, said, want)
			}
		}

		upload("march", document("march", "2026-03-01T00:00:00Z", "not_affected", ""))
		standing("the March document", "not_affected")
		if june := upload("june", document("june", "2026-06-01T00:00:00Z", "affected", "")); june.Superseded != 1 {
			t.Errorf("the June document set aside %d statements, want the March one", june.Superseded)
		}
		standing("the June document", "affected")

		upload("june", document("june", "2026-06-02T00:00:00Z", "", ""))
		standing("a revision of the June document withdrawing it", "not_affected")

		if january := upload("january", document("january", "2026-01-01T00:00:00Z", "affected", "")); january.Superseded != 0 {
			t.Errorf("an older document uploaded later set aside %d statements, want none: its own was never in force",
				january.Superseded)
		}
		standing("an older document uploaded later", "not_affected")

		upload("stamped", document("stamped", "2026-12-01T00:00:00Z", "affected", "2026-02-01T00:00:00Z"))
		standing("a later document whose statement is dated before March", "not_affected")

		// An overtaken statement its document repeats keeps its one row.
		upload("january", document("january", "2026-01-01T00:00:00Z", "affected", ""))
		var rows int
		if err := r.DB.DB.NewSelect().TableExpr(`"received_vex_statement"`).ColumnExpr(`COUNT(*)`).
			Where(`"document_id" = ?`, "https://example.test/vex/january").Scan(t.Context(), &rows); err != nil {
			t.Fatal(err)
		}
		if rows != 1 {
			t.Errorf("the January document uploaded again holds %d rows, want its one", rows)
		}
		standing("the January document uploaded again", "not_affected")
	})
}
