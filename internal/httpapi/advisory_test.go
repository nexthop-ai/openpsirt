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

func TestAnAdvisoryIsGeneratedForAFlawWeRecordedAndRefusedForOneWeDidNot(t *testing.T) {
	// The two halves of publishing only our own flaws in one test, because the boundary is the whole
	// point: an advisory is about a vulnerability in our own product, and a
	// known CVE in a shipped third-party component is dependency hygiene a
	// consumer can already read out of the inventory. A document that looked
	// the same for both would mean something different in each case.
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

		at := "/v1/products/mine/issues/" + recorded.Identifier + "/advisory"
		got := asPerson(t, r, "private-triage", http.MethodGet, at, "")
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
		// The category follows what the document can support. The VEX profile
		// is the one carrying "not affected, and here is why", and claiming it
		// while carrying none of those would describe this as something it is
		// not.
		if doc.Document.Category != "csaf_security_advisory" {
			t.Errorf("the document is categorized %q", doc.Document.Category)
		}
		if doc.Document.Tracking.ID != recorded.Identifier {
			t.Errorf("tracked as %q, want the identifier it is filed under",
				doc.Document.Tracking.ID)
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
		var named bool
		for _, vendor := range doc.ProductTree.Branches {
			for _, product := range vendor.Branches {
				for _, release := range product.Branches {
					if release.Product.ID == affected {
						named = true
					}
				}
			}
		}
		if !named {
			t.Errorf("the product tree does not name %q, which a status refers to", affected)
		}

		// What has gone out, readable without generating a document. Nothing
		// yet, which is the honest answer rather than an empty list meaning
		// "cannot say".
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

		// And the other half: an issue a scanner reported is refused.
		scanned := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/products/mine/issues/CVE-2026-9999/advisory", "")
		if scanned.Code != http.StatusUnprocessableEntity {
			t.Errorf("an advisory for a scanner's finding answered %d: %s",
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

		at := "/v1/products/mine/issues/" + recorded.Identifier + "/advisory"
		for _, who := range []string{"reader", "triager"} {
			got := asPerson(t, r, who, http.MethodGet, at, "")
			if got.Code != http.StatusNotFound {
				t.Errorf("%s generated an advisory about an undisclosed flaw: %d %s",
					who, got.Code, got.Body.String())
			}
		}
	})
}
