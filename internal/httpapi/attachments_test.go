package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAskingAboutAnIssueSomewhereElseSaysNothingAboutIt(t *testing.T) {
	// The resolver looked an identifier up across the whole deployment and
	// then asked how disclosed it is *here* — and "no undisclosed findings in
	// this product" and "not in this product at all" were the same answer, so
	// an issue filed against another product read as public here. Any reader
	// of any product could then confirm, one request at a time, whether a name
	// exists somewhere in the deployment: 200 for one that does and 404 for
	// one that does not.
	//
	// That is what makes a minted identifier guessable again. The random draw
	// stops the sequence being walked; a confirm-or-deny oracle turns it back
	// into a space somebody can check a guess against.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		hidden := r.embargoed(t)

		// An issue recorded in the deployment and not in this product, which
		// is what the resolver could not tell from an issue nobody has ever
		// filed. Written directly: what is being measured is the resolver's
		// answer, and the shortest way to a vulnerability row that this
		// product holds nothing against is to make one.
		if _, err := r.db.DB.NewInsert().Model(&finding.Vulnerability{
			Identity: "cve-2026-elsewhere", Identifier: "CVE-2026-ELSEWHERE",
			Severity: "high",
		}).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		at := func(product, issue string) int {
			return asPerson(t, r, "triager", http.MethodGet,
				"/v1/products/"+product+"/issues/"+issue+"/attachments", "").Code
		}

		// The product the issue is actually in refuses this reader, correctly:
		// it is undisclosed and they hold no private role.
		if got := at("mine", hidden); got != http.StatusNotFound {
			t.Errorf("an undisclosed issue answered %d in its own product", got)
		}
		// A name nobody has ever used answers the same.
		absent := at("mine", "OPENPSIRT-2026-000001")
		if absent != http.StatusNotFound {
			t.Errorf("a name nobody has used answered %d", absent)
		}
		// And so must a real name asked about somewhere it is not, or the two
		// answers tell a guesser which guesses were right.
		if got := at("mine", "CVE-2026-ELSEWHERE"); got != absent {
			t.Errorf("an issue that is not in this product answered %d where a name "+
				"nobody has used answered %d", got, absent)
		}
	})
}
