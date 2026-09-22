package httpapi_test

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// advised uploads one CSAF security advisory.
func (r *reach) advised(t *testing.T, who, filename, document string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("advisory", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(document)); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/products/mine/supplier-advisories", &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	req.Header.Set(testHeader, who)
	fromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return rec
}

// supplierAdvisory is a conforming CSAF security advisory about one package at
// one version, in the shape a distribution publishes: the package defined in a
// branch, the platform in another, and the claim pointing at the composite the
// relationship between them makes.
func supplierAdvisory(identifier, status, version string) string {
	return `{
	  "document": {
	    "category": "csaf_security_advisory", "csaf_version": "2.0",
	    "publisher": {"category": "vendor", "name": "Example Distribution",
	                  "namespace": "https://example.test"},
	    "title": "Example Security Advisory: libnl update",
	    "tracking": {"id": "` + identifier + `", "version": "1", "status": "final",
	                 "initial_release_date": "2026-09-01T00:00:00Z",
	                 "current_release_date": "2026-09-01T00:00:00Z",
	                 "revision_history": [{"number": "1", "date": "2026-09-01T00:00:00Z",
	                                       "summary": "First"}]}
	  },
	  "product_tree": {
	    "branches": [{"category": "vendor", "name": "Example", "branches": [
	      {"category": "product_name", "name": "Example Platform",
	       "product": {"name": "Example Platform", "product_id": "PLATFORM"}},
	      {"category": "architecture", "name": "x86_64", "branches": [
	        {"category": "product_version", "name": "libnl-3-200 ` + version + `",
	         "product": {"name": "libnl-3-200 ` + version + `", "product_id": "PKG",
	           "product_identification_helper": {
	             "purl": "pkg:deb/debian/libnl-3-200@` + version + `"}}}]}]}],
	    "relationships": [{"category": "default_component_of",
	      "full_product_name": {"name": "libnl-3-200 in Example Platform",
	                            "product_id": "PLATFORM:PKG"},
	      "product_reference": "PKG", "relates_to_product_reference": "PLATFORM"}]
	  },
	  "vulnerabilities": [{"cve": "CVE-2026-9999",
	    "product_status": {"` + status + `": ["PLATFORM:PKG"]},
	    "remediations": [{"category": "vendor_fix",
	      "details": "Upgrade to libnl-3-200 ` + version + `.",
	      "product_ids": ["PLATFORM:PKG"]}]}]
	}`
}

// saidOnTheFinding is what publishers have said, as the finding shows it.
type saidOnTheFinding struct {
	Said []struct {
		Publisher  string `json:"publisher"`
		Source     string `json:"source"`
		Identifier string `json:"identifier"`
		Status     string `json:"status"`
		About      string `json:"about"`
		Statement  string `json:"statement"`
		Offers     string `json:"offers"`
	} `json:"said"`
	Standing []struct{} `json:"standing"`
}

// whatPublishersSay reads the seeded finding's evidence.
func (r *reach) whatPublishersSay(t *testing.T) saidOnTheFinding {
	t.Helper()
	var detail saidOnTheFinding
	read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
		"/findings/CVE-2026-9999/components/libnl-3-200", &detail)
	return detail
}

func TestASupplierAdvisoryIsEvidenceAndNeverADecision(t *testing.T) {
	// REQ-31: a third party's judgment is shown as evidence and offered as a
	// prefill, and never decides anything by itself.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		// Only an administrator uploads one: it is a document about somebody
		// else's products, not a judgment anybody here triages.
		//
		// Two controls refuse, and either alone is enough: the scope the
		// operation declares, which the middleware enforces before any handler
		// runs, and the check inside the handler. Removing one leaves the test
		// green because the other covers it, which is what the declaration
		// exists for — a handler check somebody deletes does not quietly
		// widen an operation that still says it requires an administrator.
		refusedWith(t, r.advised(t, "triager", "exsa.json",
			supplierAdvisory("EXSA-2026:1001", "fixed", "3.7.0")),
			http.StatusForbidden)

		got := r.advised(t, "admin", "exsa.json",
			supplierAdvisory("EXSA-2026:1001", "fixed", "3.7.0"))
		if got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}
		var taken struct {
			Publisher  string `json:"publisher"`
			Identifier string `json:"identifier"`
			Title      string `json:"title"`
			Recorded   int    `json:"recorded"`
			Superseded int    `json:"superseded"`
			Digest     string `json:"digest"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &taken); err != nil {
			t.Fatal(err)
		}
		// Who published it and what they called it are read from the document
		// rather than from the request: an advisory names both, and it is not
		// a conforming advisory without them.
		// As the document names itself: the response says "the publisher the
		// document names", and the folding is how the record matches rather
		// than how the publisher spells their own name.
		if taken.Publisher != "Example Distribution" || taken.Identifier != "EXSA-2026:1001" {
			t.Fatalf("the upload reports %+v", taken)
		}
		if taken.Recorded != 1 || taken.Digest == "" || taken.Title == "" {
			t.Fatalf("the upload reports %+v", taken)
		}

		detail := r.whatPublishersSay(t)
		if len(detail.Said) != 1 {
			t.Fatalf("the finding shows %d claims", len(detail.Said))
		}
		one := detail.Said[0]
		if one.Source != "advisory" || one.Identifier != "EXSA-2026:1001" {
			t.Errorf("where it came from reads %+v, which is how a reader places it", one)
		}
		if one.Status != "fixed" || one.About != "3.7.0" {
			t.Errorf("what it says reads %+v", one)
		}
		if !strings.Contains(one.Statement, "Upgrade to libnl-3-200") {
			t.Errorf("the reasoning reads %q, and it is the part worth having", one.Statement)
		}
		// Offered, because the publisher spoke about the version shipped here.
		if one.Offers != "already-fixed" {
			t.Errorf("it offers %q", one.Offers)
		}
		// Never applied. Nothing was decided by uploading it.
		if len(detail.Standing) != 0 {
			t.Errorf("uploading an advisory decided %d things", len(detail.Standing))
		}
	})
}

func TestAnAdvisoryAboutAnotherVersionOffersNothing(t *testing.T) {
	// An advisory exists to name the version that carries the fix, which is
	// not the version shipped here. Offered anyway, the control comes
	// prefilled with a claim the publisher never made, with their name on it.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		got := r.advised(t, "admin", "exsa.json",
			supplierAdvisory("EXSA-2026:1002", "fixed", "3.9.0"))
		if got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}
		detail := r.whatPublishersSay(t)
		if len(detail.Said) != 1 {
			t.Fatalf("the finding shows %d claims", len(detail.Said))
		}
		// Shown, because which versions a publisher spoke about is what a
		// triager reading the evidence wants.
		if detail.Said[0].About != "3.9.0" {
			t.Errorf("the version it spoke about reads %q", detail.Said[0].About)
		}
		if detail.Said[0].Offers != "" {
			t.Errorf("a claim about 3.9.0 offered %q against 3.7.0", detail.Said[0].Offers)
		}
	})
}

func TestUploadingOneAdvisoryLeavesTheOthersStanding(t *testing.T) {
	// A publisher issues hundreds. Replaced on the publisher alone, the
	// deployment holds exactly the last document anybody uploaded.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		if got := r.advised(t, "admin", "one.json",
			supplierAdvisory("EXSA-2026:1001", "fixed", "3.7.0")); got.Code != http.StatusCreated {
			t.Fatalf("the first answered %d: %s", got.Code, got.Body.String())
		}
		second := r.advised(t, "admin", "two.json",
			supplierAdvisory("EXSA-2026:1002", "known_not_affected", "3.7.0"))
		if second.Code != http.StatusCreated {
			t.Fatalf("the second answered %d: %s", second.Code, second.Body.String())
		}
		var taken struct {
			Superseded int `json:"superseded"`
		}
		if err := json.Unmarshal(second.Body.Bytes(), &taken); err != nil {
			t.Fatal(err)
		}
		if taken.Superseded != 0 {
			t.Errorf("a second advisory set aside %d claims of the first", taken.Superseded)
		}
		if said := r.whatPublishersSay(t).Said; len(said) != 2 {
			t.Errorf("%d claims stand, want both advisories", len(said))
		}

		// A revision of the first replaces its own claims and no others.
		revised := r.advised(t, "admin", "one.json",
			supplierAdvisory("EXSA-2026:1001", "known_not_affected", "3.7.0"))
		if revised.Code != http.StatusCreated {
			t.Fatalf("the revision answered %d: %s", revised.Code, revised.Body.String())
		}
		if err := json.Unmarshal(revised.Body.Bytes(), &taken); err != nil {
			t.Fatal(err)
		}
		if taken.Superseded != 1 {
			t.Errorf("a revision set aside %d claims, want its own one", taken.Superseded)
		}
		if said := r.whatPublishersSay(t).Said; len(said) != 2 {
			t.Errorf("%d claims stand after a revision, want one per advisory", len(said))
		}
	})
}

func TestEachUploadRefusesTheOtherKindOfDocument(t *testing.T) {
	// The two are read into the same claims and mean different things around
	// them, so each refusal names the route that does take the document.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		asAdvisory := r.advised(t, "admin", "vex.json",
			said("not_affected", "vulnerable_code_not_present", ""))
		if asAdvisory.Code == http.StatusCreated {
			t.Error("a VEX document was taken as a security advisory")
		}
		asVex := r.vexed(t, "admin", "example",
			supplierAdvisory("EXSA-2026:1001", "fixed", "3.7.0"))
		if asVex.Code == http.StatusCreated {
			t.Error("a security advisory was taken as VEX statements")
		}
		if !strings.Contains(asVex.Body.String(), "supplier advisory") {
			t.Errorf("the refusal does not say where it goes: %s", asVex.Body.String())
		}
	})
}

func TestAnAdvisorysPrefillIsSomethingAPersonStillHasToRecord(t *testing.T) {
	// The half of "evidence, never a decision" that an empty list cannot
	// show: the field that stays empty when an advisory is uploaded is the
	// one that fills when a person acts on it, so the assertion above is a
	// check rather than a sentence that cannot be false.
	eachReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		if got := r.advised(t, "admin", "exsa.json",
			supplierAdvisory("EXSA-2026:1001", "known_not_affected",
				"3.7.0")); got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}
		before := r.whatPublishersSay(t)
		if len(before.Standing) != 0 {
			t.Fatalf("uploading decided %d things", len(before.Standing))
		}
		cited := before.Said
		if len(cited) != 1 {
			t.Fatalf("the finding offers %+v to cite", cited)
		}
		if cited[0].Offers != "not-applicable" {
			t.Fatalf("it offers %q", cited[0].Offers)
		}

		var said struct {
			Said []struct {
				ID int64 `json:"id"`
			} `json:"said"`
		}
		read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/components/libnl-3-200", &said)
		made := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/places/"+place+"/decision",
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
				`"reasoning":"The supplier says this build is not affected.",`+
				`"from_statement":`+itoa(said.Said[0].ID)+`}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("deciding answered %d: %s", made.Code, made.Body.String())
		}
		if after := r.whatPublishersSay(t); len(after.Standing) != 1 {
			t.Errorf("after a person decided, %d things stand", len(after.Standing))
		}
	})
}

func TestANameLongerThanTheRecordIsRefusedRatherThanShortened(t *testing.T) {
	// Both names are part of the key a later upload replaces on, and both are
	// stored in a column of a fixed width. Shortened, two advisories agreeing
	// for the width of the column collapse into one, and a revision of one
	// sets aside claims it has nothing to do with.
	//
	// Two layers refuse and either alone is enough, the way the scope and the
	// handler check are: the endpoint, and the store behind it, which is
	// reachable from any other caller. Both have to go before this fails.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		tooLong := strings.Repeat("x", 200)

		named := r.advised(t, "admin", "exsa.json",
			supplierAdvisory(tooLong, "fixed", "3.7.0"))
		refusedWith(t, named, http.StatusUnprocessableEntity)
		if !strings.Contains(named.Body.String(), "the name the publisher gave it") {
			t.Errorf("the refusal does not say which name is too long: %s", named.Body.String())
		}

		published := strings.Replace(supplierAdvisory("EXSA-2026:1001", "fixed", "3.7.0"),
			`"name": "Example Distribution"`, `"name": "`+tooLong+`"`, 1)
		who := r.advised(t, "admin", "exsa.json", published)
		refusedWith(t, who, http.StatusUnprocessableEntity)
		if !strings.Contains(who.Body.String(), "who published it") {
			t.Errorf("the refusal does not say which name is too long: %s", who.Body.String())
		}
	})
}
