package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// csaf is as much of a CSAF document as these tests make claims about.
type csaf struct {
	Document struct {
		Category    string `json:"category"`
		CSAFVersion string `json:"csaf_version"`
		Title       string `json:"title"`
		Publisher   struct {
			Category  string `json:"category"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"publisher"`
		Tracking struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"tracking"`
		Notes []struct {
			Category string `json:"category"`
			Text     string `json:"text"`
		} `json:"notes"`
	} `json:"document"`
	ProductTree struct {
		Branches []struct {
			Category string `json:"category"`
			Name     string `json:"name"`
			Branches []struct {
				Category string `json:"category"`
				Name     string `json:"name"`
				Branches []struct {
					Category string `json:"category"`
					Name     string `json:"name"`
					Product  struct {
						Name string `json:"name"`
						ID   string `json:"product_id"`
					} `json:"product"`
				} `json:"branches"`
			} `json:"branches"`
		} `json:"branches"`
	} `json:"product_tree"`
	Vulnerabilities []struct {
		CVE string `json:"cve"`
		IDs []struct {
			SystemName string `json:"system_name"`
			Text       string `json:"text"`
		} `json:"ids"`
		Status struct {
			KnownAffected []string `json:"known_affected"`
			Fixed         []string `json:"fixed"`
		} `json:"product_status"`
	} `json:"vulnerabilities"`
}

// advisoryOver mints an advisory, names one issue in one product on it, and
// answers the identifier it was minted under.
//
// Two requests where there used to be none: an advisory is a record of its own
// now, so what a document is about is stated rather than read off the path.
func advisoryOver(t *testing.T, r *reach, who, product, identifier string) string {
	t.Helper()
	made := asPerson(t, r, who, http.MethodPost, "/v1/advisories", `{}`)
	if made.Code != http.StatusCreated {
		t.Fatalf("starting an advisory answered %d: %s", made.Code, made.Body.String())
	}
	var started struct {
		Advisory string `json:"advisory"`
	}
	if err := json.Unmarshal(made.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	added := asPerson(t, r, who, http.MethodPost,
		"/v1/advisories/"+started.Advisory+"/issues",
		`{"product":"`+product+`","vulnerability":"`+identifier+`"}`)
	if added.Code != http.StatusCreated {
		t.Fatalf("adding %s answered %d: %s", identifier, added.Code, added.Body.String())
	}
	return started.Advisory
}

func TestAnAdvisoryIsGeneratedForAFlawWeRecordedAndRefusedForOneWeDidNot(t *testing.T) {
	// The two halves of publishing only our own flaws in one test, because the
	// boundary is the whole point: an advisory is about a vulnerability in our
	// own product, and a known CVE in a shipped third-party component is
	// dependency hygiene a consumer can already read out of the inventory. A
	// document that looked the same for both would mean something different in
	// each case.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const findings = "/v1/products/mine/findings"

		made := asPerson(t, r, "private-triage", http.MethodPost, findings,
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"The management socket answers before anyone authenticated.",`+
				`"severity":"critical"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", made.Code, made.Body.String())
		}
		var recorded struct {
			Identifier string `json:"identifier"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}

		named := advisoryOver(t, r, "private-triage", "mine", recorded.Identifier)
		at := "/v1/advisories/" + named
		got := asPerson(t, r, "private-triage", http.MethodGet, at+"/document", "")
		if got.Code != http.StatusOK {
			t.Fatalf("generating answered %d: %s", got.Code, got.Body.String())
		}
		var doc csaf
		if err := json.Unmarshal(got.Body.Bytes(), &doc); err != nil {
			t.Fatalf("decode: %v (%s)", err, got.Body.String())
		}

		if doc.Document.CSAFVersion != "2.0" {
			t.Errorf("the document claims CSAF %q", doc.Document.CSAFVersion)
		}
		// A flaw of our own, recorded a moment ago and written up nowhere.
		// That is the security-advisory profile's whole subject — CSAF § 4.4
		// asks for a product tree, the vulnerabilities and notes and a status
		// on each, and asks nothing of the document's own notes or
		// references. Declared the base profile, a customer's tooling
		// filtering for security advisories skips it.
		if doc.Document.Category != "csaf_security_advisory" {
			t.Errorf("the document is categorized %q", doc.Document.Category)
		}
		// The advisory's own name, not the issue's. A document naming an
		// issue's identifier as its own tracking identifier claims to be the
		// authority on that issue, which a coordinator is and this deployment
		// is not — and it breaks outright at two issues.
		if doc.Document.Tracking.ID != named {
			t.Errorf("tracked as %q, want the advisory's own identifier %q",
				doc.Document.Tracking.ID, named)
		}
		if doc.Document.Tracking.ID == recorded.Identifier {
			t.Error("the document is tracked under the issue's identifier")
		}
		// Undisclosed, so the document is prepared rather than issued — the
		// one field a reader checks before acting on it.
		if doc.Document.Tracking.Status != "draft" {
			t.Errorf("a document about an undisclosed flaw is %q, want draft",
				doc.Document.Tracking.Status)
		}
		if doc.Document.Publisher.Name == "" || doc.Document.Publisher.Namespace == "" {
			t.Errorf("the document names no publisher: %+v", doc.Document.Publisher)
		}

		// The identifier this deployment minted is not a CVE, and saying so in
		// that field would be a claim nobody assigned.
		if len(doc.Vulnerabilities) != 1 {
			t.Fatalf("the document carries %d vulnerabilities, want one",
				len(doc.Vulnerabilities))
		}
		if doc.Vulnerabilities[0].CVE != "" {
			t.Errorf("a minted identifier is reported as CVE %q", doc.Vulnerabilities[0].CVE)
		}
		if len(doc.Vulnerabilities[0].IDs) == 0 {
			t.Error("the document says nothing about what the issue is called")
		}

		// The release it is in is named, and named by its stream and variant
		// together: the same branch built two ways is two builds.
		if len(doc.Vulnerabilities[0].Status.KnownAffected) != 1 {
			t.Fatalf("affected releases: %v", doc.Vulnerabilities[0].Status.KnownAffected)
		}
		affected := doc.Vulnerabilities[0].Status.KnownAffected[0]
		if affected != "mine:master:broadcom" {
			t.Errorf("the affected release is %q, want it named by stream and variant", affected)
		}
		// Everything a status refers to has to be named in the tree, or the
		// document refers to something it never introduced.
		var introduced bool
		for _, vendor := range doc.ProductTree.Branches {
			for _, product := range vendor.Branches {
				for _, release := range product.Branches {
					if release.Product.ID == affected {
						introduced = true
					}
				}
			}
		}
		if !introduced {
			t.Errorf("the product tree does not name %q, which a status refers to", affected)
		}

		// gone is what has gone out, readable without generating a
		// document. Nothing yet, which is the honest answer rather
		// than an empty list meaning "cannot say".
		var gone struct {
			Items []struct {
				Version int    `json:"version"`
				Digest  string `json:"digest"`
				Summary string `json:"summary"`
			} `json:"items"`
		}
		read(t, r, "private-triage", at+"/issuance", &gone)
		if len(gone.Items) != 0 {
			t.Errorf("nothing has been published and %d issuances came back", len(gone.Items))
		}
		agreedTo(t, r, at)
		if issued := asPerson(t, r, "private-triage", http.MethodPost, at+"/issuance",
			`{"summary":"First advisory."}`); issued.Code != http.StatusCreated {
			t.Fatalf("recording an issuance answered %d: %s", issued.Code, issued.Body.String())
		}
		read(t, r, "private-triage", at+"/issuance", &gone)
		if len(gone.Items) != 1 {
			t.Fatalf("%d issuances after one went out", len(gone.Items))
		}
		if gone.Items[0].Version != 1 || gone.Items[0].Digest == "" ||
			gone.Items[0].Summary != "First advisory." {
			t.Errorf("the issuance reads as %+v", gone.Items[0])
		}

		// And the other half: an issue a scanner reported is refused, at the
		// point somebody names it rather than when the document is generated,
		// so the refusal names the issue they chose.
		scanned := asPerson(t, r, "private-triage", http.MethodPost, at+"/issues",
			`{"product":"mine","vulnerability":"CVE-2026-9999"}`)
		if scanned.Code != http.StatusUnprocessableEntity {
			t.Errorf("a scanner's finding was added to an advisory: %d %s",
				scanned.Code, scanned.Body.String())
		}
	})
}

func TestAnAdvisoryAboutAnUndisclosedFlawIsNotGeneratedForSomebodyWhoMayNotSeeIt(t *testing.T) {
	// The document is a disclosure in its own right: every fact in it is about
	// a flaw nobody has announced. Answering "no such issue" is the same
	// answer somebody gets for one that does not exist, because telling those
	// apart is how a lookup becomes a directory.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		made := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/findings",
			`{"builds":[{"stream":"master","variant":"broadcom"}],`+
				`"summary":"The recovery console does not clear the previous session.",`+
				`"severity":"high"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", made.Code, made.Body.String())
		}
		var recorded struct {
			Identifier string `json:"identifier"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}

		named := advisoryOver(t, r, "private-triage", "mine", recorded.Identifier)
		for _, who := range []string{"reader", "triager"} {
			got := asPerson(t, r, who, http.MethodGet,
				"/v1/advisories/"+named+"/document", "")
			if got.Code != http.StatusNotFound {
				t.Errorf("%s generated an advisory about an undisclosed flaw: %d %s",
					who, got.Code, got.Body.String())
			}
		}
	})
}

func TestAProductYouCannotSeeAnswersLikeOneNobodyDeclared(t *testing.T) {
	// Every refusal here is shaped so that "you may not see that" and "that
	// does not exist" cannot be told apart. Both of the reads had a refusal
	// for it and neither was ever executed — and one of them was broken: it
	// answered a denial the handler had no arm for, so a product the reader
	// could not see faulted with a 500 while an undeclared name answered 404.
	// The pair of answers is the directory.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		made := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/findings",
			`{"builds":[{"stream":"master","variant":"broadcom"}],`+
				`"summary":"The console does not clear the previous session.",`+
				`"severity":"high"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", made.Code, made.Body.String())
		}
		var recorded struct {
			Identifier string `json:"identifier"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}

		// "outsider" holds a role on theirs and nothing on mine, so "mine" is
		// a product they may not see. "nosuch" was never declared. The two
		// must be indistinguishable wherever a product is named.
		named := advisoryOver(t, r, "private-triage", "mine", recorded.Identifier)
		for _, route := range []struct {
			what   string
			method string
			path   func(product string) string
			body   func(product string) string
		}{
			{"adding an issue", http.MethodPost,
				func(string) string { return "/v1/advisories/" + named + "/issues" },
				func(p string) string {
					return `{"product":"` + p + `","vulnerability":"` + recorded.Identifier + `"}`
				}},
			{"taking one off", http.MethodDelete,
				func(p string) string {
					return "/v1/advisories/" + named + "/issues/" + p + "/" + recorded.Identifier
				},
				func(string) string { return "" }},
		} {
			invisible := asPerson(t, r, "outsider", route.method,
				route.path("mine"), route.body("mine"))
			undeclared := asPerson(t, r, "outsider", route.method,
				route.path("nosuch"), route.body("nosuch"))

			if invisible.Code != undeclared.Code {
				t.Errorf("%s: a product they may not see answers %d and one nobody "+
					"declared answers %d — the difference is a directory",
					route.what, invisible.Code, undeclared.Code)
			}
			if invisible.Code >= 500 {
				t.Errorf("%s: a product they may not see faulted: %d %s",
					route.what, invisible.Code, invisible.Body.String())
			}
			if invisible.Body.String() != undeclared.Body.String() {
				t.Errorf("%s: the two refusals read differently:\n  %s\n  %s",
					route.what, invisible.Body.String(), undeclared.Body.String())
			}
		}

		// And the same pair one level up: an advisory somebody may not see
		// and one nobody minted. The agreement is on this list because it is
		// a write against a name, which is the shape that turns a lookup
		// into a directory of what exists.
		for _, at := range []string{"", "/document", "/issuance", "/approval"} {
			method := http.MethodGet
			if at == "/approval" {
				method = http.MethodPost
			}
			unseeable := asPerson(t, r, "outsider", method,
				"/v1/advisories/"+named+at, "")
			nonexistent := asPerson(t, r, "outsider", method,
				"/v1/advisories/EXNET-1999-0001"+at, "")
			if unseeable.Code != nonexistent.Code ||
				unseeable.Body.String() != nonexistent.Body.String() {
				t.Errorf("GET %s: an advisory they may not see answers %d %s and one "+
					"nobody minted answers %d %s", at,
					unseeable.Code, unseeable.Body.String(),
					nonexistent.Code, nonexistent.Body.String())
			}
		}
	})
}
