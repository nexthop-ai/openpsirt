package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// vexDocument is the parts of a generated document a revision is read from.
type vexDocument struct {
	ID         string `json:"@id"`
	Version    int    `json:"version"`
	Statements []any  `json:"statements"`
}

const aBuild = "/v1/products/mine/streams/master/variants/broadcom/vex"

func TestASecondVEXDocumentIsARevisionOfTheFirst(t *testing.T) {
	// A document assembled from what stands now holds no history of its own,
	// so without a record of what went out every generation is the first
	// revision of something — and a reader keeping documents by the
	// identifier they carry cannot tell which supersedes which.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		var first vexDocument
		read(t, r, "triager", aBuild, &first)
		if first.Version != 1 {
			t.Fatalf("a document nobody has published is version %d", first.Version)
		}

		// The identifier names the build and nothing that moves, so the same
		// build asked for twice is the same document.
		var again vexDocument
		read(t, r, "triager", aBuild, &again)
		if again.ID != first.ID {
			t.Fatalf("two fetches of one build minted %q then %q", first.ID, again.ID)
		}
		// The publisher's namespace and the build, and nothing else. An
		// identifier carrying the moment made every fetch a document in its
		// own right, and minted one name for two documents inside a second.
		if first.ID != "https://example.test/vex/mine:master:broadcom" {
			t.Errorf("the document is called %q", first.ID)
		}

		// Somebody publishes it and says so.
		recorded := recordedIssuance(t, r, "triager")
		if recorded.Version != 1 || len(recorded.Digest) != 64 {
			t.Errorf("what was recorded reads as %+v", recorded)
		}

		// The next document is the second revision of the same document.
		var second vexDocument
		read(t, r, "triager", aBuild, &second)
		if second.Version != 2 {
			t.Errorf("after one issuance the next document is version %d", second.Version)
		}
		if second.ID != first.ID {
			t.Errorf("a revision renamed the document: %q then %q", first.ID, second.ID)
		}

		// The digest is over what the document says, so an unchanged document
		// hashed twice agrees. The moment, the version and the build of
		// OpenPSIRT that wrote it all move between these two and none of them
		// is what the document says.
		unchanged := recordedIssuance(t, r, "triager")
		if unchanged.Digest != recorded.Digest {
			t.Errorf("an unchanged document hashed differently: %q then %q",
				recorded.Digest, unchanged.Digest)
		}
		if unchanged.Version != 2 {
			t.Errorf("the second issuance is version %d", unchanged.Version)
		}

		// A document that says something different hashes differently, which
		// is the half that makes the comparison worth making.
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}
		moved := recordedIssuance(t, r, "triager")
		if moved.Digest == recorded.Digest {
			t.Errorf("a document carrying a statement it did not carry before hashed the same")
		}

		// What has gone out is readable without generating anything, oldest
		// first, which is what somebody deciding whether to publish a
		// revision is asking.
		var gone struct {
			Items []struct {
				Version  int    `json:"version"`
				Digest   string `json:"digest"`
				IssuedBy string `json:"issued_by"`
			} `json:"items"`
		}
		read(t, r, "triager", aBuild+"/issuance", &gone)
		if len(gone.Items) != 3 {
			t.Fatalf("what has gone out reads as %+v", gone.Items)
		}
		for i, one := range gone.Items {
			if one.Version != i+1 {
				t.Errorf("entry %d is version %d", i, one.Version)
			}
		}
		if gone.Items[2].Digest != moved.Digest {
			t.Errorf("the last entry is not what was last recorded")
		}
		// Who published it, by name. The act leaves this row and nothing
		// else — no trail entry sits beside it — so a row that named nobody
		// would leave "who published this" unanswerable.
		for _, one := range gone.Items {
			if one.IssuedBy != "triager" {
				t.Errorf("an entry says %q published it", one.IssuedBy)
			}
		}
	})
}

// TestAVEXDocumentIsNamedTheSameHoweverTheBuildIsSpelled pins the identifier
// against the names that were stored rather than the ones that were typed.
//
// A name people type is matched without regard to capitals, so the same build
// resolves from two spellings. An identifier built from the request spells the
// document two ways, and a reader holding both has two documents about one
// build rather than one document.
func TestAVEXDocumentIsNamedTheSameHoweverTheBuildIsSpelled(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		var typed, shouted vexDocument
		read(t, r, "triager", aBuild, &typed)
		read(t, r, "triager", "/v1/products/MINE/streams/Master/variants/BROADCOM/vex", &shouted)
		if typed.ID != shouted.ID {
			t.Errorf("one build is called %q and %q", typed.ID, shouted.ID)
		}
	})
}

// TestRecordingAVEXIssuanceNeedsTheTriageRoleOnTheProduct reaches the arm that
// answers that refusal.
//
// A reader may generate the document and may not say one went out: it is this
// deployment's word to a customer. Left to the arm below it, the refusal
// answers as a build nobody declared — which contradicts the document the same
// caller has just been handed.
func TestRecordingAVEXIssuanceNeedsTheTriageRoleOnTheProduct(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		// A reader reaches the document itself.
		var doc vexDocument
		read(t, r, "reader", aBuild, &doc)

		if got := asPerson(t, r, "reader", http.MethodPost,
			aBuild+"/issuance", ""); got.Code != http.StatusForbidden {
			t.Errorf("a reader recording an issuance answered %d: %s",
				got.Code, got.Body.String())
		}
		// Somebody who may not see the product at all is told the build is
		// not there, which is the answer a name nobody declared gets.
		if got := asPerson(t, r, "auditor", http.MethodPost,
			"/v1/products/theirs/streams/master/variants/broadcom/vex/issuance",
			""); got.Code != http.StatusNotFound {
			t.Errorf("a stranger recording an issuance answered %d: %s",
				got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "triager", http.MethodPost,
			aBuild+"/issuance", ""); got.Code != http.StatusCreated {
			t.Fatalf("a triager recording an issuance answered %d: %s",
				got.Code, got.Body.String())
		}

		// Reading what went out is narrowed the way the document is. A reader
		// may have it, and a row saying a document about a build they may not
		// see went out is as much a disclosure as the document.
		if got := asPerson(t, r, "reader", http.MethodGet,
			aBuild+"/issuance", ""); got.Code != http.StatusOK {
			t.Errorf("a reader listing what went out answered %d: %s",
				got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "auditor", http.MethodGet,
			"/v1/products/theirs/streams/master/variants/broadcom/vex/issuance",
			""); got.Code != http.StatusNotFound {
			t.Errorf("a stranger listing what went out answered %d: %s",
				got.Code, got.Body.String())
		}
	})
}

// recordedIssuance records that the document for the build went out and
// answers with what was recorded.
func recordedIssuance(t *testing.T, r *reach, who string) struct {
	Version int    `json:"version"`
	Digest  string `json:"digest"`
} {
	t.Helper()
	var recorded struct {
		Version int    `json:"version"`
		Digest  string `json:"digest"`
	}
	got := asPerson(t, r, who, http.MethodPost, aBuild+"/issuance", "")
	if got.Code != http.StatusCreated {
		t.Fatalf("recording that it went out answered %d: %s", got.Code, got.Body.String())
	}
	if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
		t.Fatal(err)
	}
	return recorded
}

// TestEveryDateTheDocumentStatesIsOneTheStandardParses walks a generated CSAF
// document and fails a date a validator would refuse.
//
// The standard defines every date it carries as a date and a time. A bare day
// passes a schema check run without format assertions and is refused by the
// validator a customer runs, which drops the document — the failure that looks
// like nothing happening.
//
// Over every field the standard names as a date rather than over the one that
// was wrong, because the next field added carries the same rule and nobody
// will remember it. The standard spells some of them plainly — a revision's
// and an involvement's — so the suffix alone reaches neither.
func TestEveryDateTheDocumentStatesIsOneTheStandardParses(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		flaw := r.embargoed(t)
		named := advisoryOver(t, r, "private-triage", "mine", flaw)

		var document map[string]any
		read(t, r, "private-triage", "/v1/advisories/"+named+"/document", &document)

		checked := 0
		var walk func(path string, node any)
		walk = func(path string, node any) {
			switch held := node.(type) {
			case map[string]any:
				for key, value := range held {
					if text, is := value.(string); is &&
						(key == "date" || strings.HasSuffix(key, "_date")) {
						checked++
						if _, err := time.Parse(time.RFC3339, text); err != nil {
							t.Errorf("%s/%s is %q, which the standard cannot parse as a "+
								"date and a time", path, key, text)
						}
						continue
					}
					walk(path+"/"+key, value)
				}
			case []any:
				for at, value := range held {
					walk(fmt.Sprintf("%s/%d", path, at), value)
				}
			}
		}
		walk("", document)
		// A sweep that reached nothing looks exactly like a sweep that found
		// nothing wrong. The document states when the flaw was recorded, when
		// it was released and when each revision happened.
		if checked < 4 {
			t.Fatalf("only %d dates were reached, so this proves little", checked)
		}
	})
}
