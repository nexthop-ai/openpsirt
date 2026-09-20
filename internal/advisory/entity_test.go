package advisory_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
)

func TestOneAdvisoryCoversSeveralFlawsAndTheDocumentStatesEachOfThem(t *testing.T) {
	// The whole of why an advisory is keyed on itself. Several embargoed
	// flaws released together is one document on one date, and a key made of
	// a product and an issue cannot express it: the standard carries
	// vulnerabilities as an array, and this held exactly one.
	each(t, func(t *testing.T, f *fixture) {
		first := f.recorded(t, f.master)
		second := f.recorded(t, f.tagged)
		named := f.covering(t,
			[2]string{"sonic", first}, [2]string{"sonic", second})

		doc, err := f.store.ForAdvisory(t.Context(), f.who, issuer, named)
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		if len(doc.Vulnerabilities) != 2 {
			t.Fatalf("the document carries %d vulnerabilities, want both",
				len(doc.Vulnerabilities))
		}
		// Each names the flaw it is about, in the order they were added.
		for at, want := range []string{first, second} {
			var said bool
			for _, id := range doc.Vulnerabilities[at].IDs {
				said = said || id.Text == want
			}
			if !said {
				t.Errorf("entry %d says nothing about %s: %+v", at, want, doc.Vulnerabilities[at].IDs)
			}
		}
		// And the document is tracked under its own name rather than under
		// either flaw's, which is the thing that cannot be true of two.
		if doc.Document.Tracking.ID != named {
			t.Errorf("tracked as %q, want the advisory's own name %q",
				doc.Document.Tracking.ID, named)
		}
	})
}

func TestTwoFlawsInOneProductNameItsReleasesOnce(t *testing.T) {
	// Every status refers to a release the tree introduced, and the tree
	// introduces each one once. Written per issue, a document covering two
	// flaws in one product would carry the product twice and every release
	// twice — which a reader's tooling reads as two products.
	each(t, func(t *testing.T, f *fixture) {
		first := f.recorded(t, f.master)
		second := f.recorded(t, f.master)
		named := f.covering(t, [2]string{"sonic", first}, [2]string{"sonic", second})

		doc, err := f.store.ForAdvisory(t.Context(), f.who, issuer, named)
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		if len(doc.ProductTree.Branches) != 1 {
			t.Fatalf("the tree carries %d vendors", len(doc.ProductTree.Branches))
		}
		products := doc.ProductTree.Branches[0].Branches
		if len(products) != 1 {
			t.Fatalf("one product is named %d times: %+v", len(products), products)
		}
		seen := map[string]int{}
		for _, release := range products[0].Branches {
			seen[release.Product.ID]++
		}
		for id, times := range seen {
			if times != 1 {
				t.Errorf("the tree names %q %d times", id, times)
			}
		}
		// And both entries still refer to what the tree introduced.
		for at, one := range doc.Vulnerabilities {
			for _, id := range one.Status.KnownAffected {
				if seen[id] == 0 {
					t.Errorf("entry %d refers to %q, which the tree never names", at, id)
				}
			}
		}
	})
}

func TestAnAdvisoryIsReadWholeOrNotAtAll(t *testing.T) {
	// A document with one of its products quietly left out reads as a
	// complete statement about a product it says nothing about. So somebody
	// who may not see everything it covers is told it does not exist, which
	// is the same answer they get for a name nobody minted.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		named := f.covering(t, [2]string{"sonic", identifier})

		// Somebody holding nothing on this product at all.
		stranger := access.NewPerson(f.who.ID+1, "stranger", false,
			map[int64][]access.Role{}, 0)
		if _, _, err := f.store.Covers(t.Context(), stranger, named); !errors.Is(
			err, advisory.ErrNoSuchAdvisory) {
			t.Errorf("somebody holding nothing read it: %v", err)
		}
		if _, err := f.store.ForAdvisory(t.Context(), stranger, issuer, named); !errors.Is(
			err, advisory.ErrNoSuchAdvisory) {
			t.Errorf("somebody holding nothing generated it: %v", err)
		}
		// The same answer a name nobody minted gets, so the pair says nothing
		// about what exists.
		if _, _, err := f.store.Covers(t.Context(), stranger, "EXNET-1999-0001"); !errors.Is(
			err, advisory.ErrNoSuchAdvisory) {
			t.Errorf("a name nobody minted answered differently: %v", err)
		}
		// And it is listed to neither, which is the count half of the same
		// rule: a row saying an advisory exists is as much a disclosure.
		rows, total, err := f.store.List(t.Context(), stranger, advisory.Covering{}, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 || total != 0 {
			t.Errorf("somebody holding nothing was shown %d of %d advisories", len(rows), total)
		}
	})
}

func TestAnIdentifierIsMintedInSequenceAndMatchedWithoutRegardToCapitals(t *testing.T) {
	// The name is minted rather than chosen: it is what a reader cites the
	// document by and what a revision of it keeps, so two under one name is a
	// state there is no way back from.
	each(t, func(t *testing.T, f *fixture) {
		first, err := f.store.Mint(t.Context(), f.who, issuer, "")
		if err != nil {
			t.Fatalf("starting one: %v", err)
		}
		second, err := f.store.Mint(t.Context(), f.who, issuer, "")
		if err != nil {
			t.Fatalf("starting a second: %v", err)
		}
		if first.Identifier == second.Identifier {
			t.Fatalf("two advisories were minted as %q", first.Identifier)
		}
		// The prefix the deployment configures, the year, and a number within
		// it — which is what makes it citable as this publisher's.
		want := fmt.Sprintf("%s-%d-", issuer.Prefix, first.MintedAt.Year())
		if !strings.HasPrefix(first.Identifier, want) {
			t.Errorf("minted as %q, want it opening with %q", first.Identifier, want)
		}
		if second.Number != first.Number+1 {
			t.Errorf("the numbers ran %d then %d", first.Number, second.Number)
		}
		// Matched however it is typed, which is the rule every identifier
		// here is matched under.
		if _, _, err := f.store.Covers(t.Context(), f.who,
			strings.ToLower(first.Identifier)); err != nil {
			t.Errorf("the name did not resolve in lower case: %v", err)
		}
	})
}

func TestAnAdvisoryCannotBeStartedWhereNothingSaysWhatToMintUnder(t *testing.T) {
	// An identifier traceable to no publisher is in every document that went
	// out, where a refusal is fixed once by an operator.
	each(t, func(t *testing.T, f *fixture) {
		_, err := f.store.Mint(t.Context(), f.who,
			publisher.Named{Name: "Example Networks", Namespace: "https://example.test"}, "")
		if !errors.Is(err, advisory.ErrNoPrefix) {
			t.Errorf("an unconfigured deployment minted a name: %v", err)
		}
	})
}

func TestAnIssueIsNamedOncePerProductAndRefusedWhereAScannerReportedIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		made, err := f.store.Mint(t.Context(), f.who, issuer, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Add(t.Context(), f.who, made.Identifier,
			"sonic", identifier); err != nil {
			t.Fatalf("adding it: %v", err)
		}
		// Twice is refused: the pair is what a status is stated about, and
		// named twice a reader gets two answers about one release.
		if _, err := f.store.Add(t.Context(), f.who, made.Identifier,
			"sonic", identifier); !errors.Is(err, advisory.ErrAlreadyCovered) {
			t.Errorf("the same issue was named twice: %v", err)
		}
	})
}

func TestAnAdvisoryCoveringNothingGeneratesNothing(t *testing.T) {
	// The standard requires at least one vulnerability, and a document about
	// nothing is not a draft of anything.
	each(t, func(t *testing.T, f *fixture) {
		made, err := f.store.Mint(t.Context(), f.who, issuer, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.ForAdvisory(t.Context(), f.who, issuer,
			made.Identifier); !errors.Is(err, advisory.ErrNothingToSay) {
			t.Errorf("an empty advisory generated a document: %v", err)
		}
	})
}

func TestTakingAnIssueOffRecordsWhoDidAndPuttingItBackRevivesTheRow(t *testing.T) {
	// Who removed an issue from an advisory is a question a deleted row does
	// not answer, so the row stays. Adding it again revives that row rather
	// than writing a second, which is what keeps the pair unique.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		named := f.covering(t, [2]string{"sonic", identifier})

		if err := f.store.Drop(t.Context(), f.who, named, "sonic", identifier); err != nil {
			t.Fatalf("taking it off: %v", err)
		}
		_, held, err := f.store.Covers(t.Context(), f.who, named)
		if err != nil {
			t.Fatal(err)
		}
		if len(held) != 0 {
			t.Errorf("it still covers %d issues", len(held))
		}
		// The row it left behind carries who took it off.
		var off struct {
			By int64 `bun:"removed_by"`
		}
		if err := f.db.DB.NewSelect().TableExpr(`"advisory_issue" AS "ac"`).
			ColumnExpr("ac.removed_by").
			Where("ac.removed_at IS NOT NULL").
			Limit(1).Scan(t.Context(), &off); err != nil {
			t.Fatalf("reading what it left behind: %v", err)
		}
		if off.By != f.who.ID {
			t.Errorf("the removal records %d as having done it, want %d", off.By, f.who.ID)
		}
		// Taking off something already off is the caller's to fix rather than
		// a quiet success.
		if err := f.store.Drop(t.Context(), f.who, named, "sonic", identifier); err == nil {
			t.Error("taking it off twice answered as though it had been there")
		}
		// And putting it back is one row, not two.
		if _, err := f.store.Add(t.Context(), f.who, named, "sonic", identifier); err != nil {
			t.Fatalf("putting it back: %v", err)
		}
		_, held, err = f.store.Covers(t.Context(), f.who, named)
		if err != nil {
			t.Fatal(err)
		}
		if len(held) != 1 {
			t.Errorf("after putting it back it covers %d issues", len(held))
		}
	})
}

func TestTwoAdvisoriesMayCoverOneFlaw(t *testing.T) {
	// Keyed on the pair, a second document about one flaw was unrepresentable
	// — which is wrong in both directions: a flaw written up once for
	// customers and again for a coordinator is two documents about one flaw.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		first := f.covering(t, [2]string{"sonic", identifier})
		second := f.covering(t, [2]string{"sonic", identifier})
		if first == second {
			t.Fatal("the two advisories were minted under one name")
		}
		for _, named := range []string{first, second} {
			doc, err := f.store.ForAdvisory(t.Context(), f.who, issuer, named)
			if err != nil {
				t.Fatalf("%s: %v", named, err)
			}
			if doc.Document.Tracking.ID != named {
				t.Errorf("%s is tracked as %q", named, doc.Document.Tracking.ID)
			}
		}
		// And a list narrowed to that flaw shows both.
		rows, total, err := f.store.List(t.Context(), f.who,
			advisory.Covering{Vulnerability: identifier}, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 2 || len(rows) != 2 {
			t.Errorf("%d of %d advisories cover it, want both", len(rows), total)
		}
	})
}

func TestAnIssuanceIsOneRecordForADocumentCoveringTwoFlaws(t *testing.T) {
	// Keyed on the pair, publishing a document about two flaws wrote two
	// issuances and each carried its own version — so the next document's
	// revision history depended on which flaw was asked about.
	each(t, func(t *testing.T, f *fixture) {
		first := f.recorded(t, f.master)
		second := f.recorded(t, f.tagged)
		named := f.covering(t, [2]string{"sonic", first}, [2]string{"sonic", second})

		if _, err := f.store.Issued(t.Context(), f.who, issuer, named, "Both"); err != nil {
			t.Fatalf("recording that it went out: %v", err)
		}
		gone, err := f.store.Issuances(t.Context(), f.who, named)
		if err != nil {
			t.Fatal(err)
		}
		if len(gone) != 1 {
			t.Fatalf("a document about two flaws went out %d times", len(gone))
		}
		if gone[0].Ordinal != 1 {
			t.Errorf("the first issuance is numbered %d", gone[0].Ordinal)
		}
		// And the next document is a revision of the one document.
		doc, err := f.store.ForAdvisory(t.Context(), f.who, issuer, named)
		if err != nil {
			t.Fatal(err)
		}
		history := doc.Document.Tracking.RevisionHistory
		if len(history) != 3 {
			t.Fatalf("its history reads as %+v", history)
		}
		if doc.Document.Tracking.Version != history[len(history)-1].Number {
			t.Errorf("the document is version %q and its history ends at %q",
				doc.Document.Tracking.Version, history[len(history)-1].Number)
		}
	})
}

func TestOneAdvisoryCoversFlawsInTwoProductsAndNamesEachProductsReleases(t *testing.T) {
	// The half of the decision that reversed it. Keyed on a product and an
	// issue, an advisory about two products could not exist — and a vendor
	// releasing one fix across two products writes one document about it.
	each(t, func(t *testing.T, f *fixture) {
		here := f.recorded(t, f.master)
		there := f.recorded(t, f.other)
		named := f.covering(t,
			[2]string{"sonic", here}, [2]string{"switchd", there})

		doc, err := f.store.ForAdvisory(t.Context(), f.who, issuer, named)
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		if len(doc.Vulnerabilities) != 2 {
			t.Fatalf("the document carries %d vulnerabilities", len(doc.Vulnerabilities))
		}
		// One vendor, two products under it. The vendor is the publisher and
		// does not repeat; the products do.
		if len(doc.ProductTree.Branches) != 1 {
			t.Fatalf("the tree carries %d vendors", len(doc.ProductTree.Branches))
		}
		products := doc.ProductTree.Branches[0].Branches
		if len(products) != 2 {
			t.Fatalf("the tree names %d products, want both: %+v", len(products), products)
		}
		// Each status names releases of the product its issue was covered in
		// and of no other, which is what the pair is for: a status about a
		// release of the wrong product is a claim about a build nobody made.
		under := map[string]string{}
		for _, product := range products {
			for _, release := range product.Branches {
				under[release.Product.ID] = product.Name
			}
		}
		for at, want := range []string{"Hardware Platform Images", "Switch Daemon"} {
			named := doc.Vulnerabilities[at].Status.KnownAffected
			if len(named) == 0 {
				t.Fatalf("entry %d names no affected release", at)
			}
			for _, id := range named {
				if under[id] != want {
					t.Errorf("entry %d names %q, which the tree puts under %q, want %q",
						at, id, under[id], want)
				}
			}
		}
	})
}

func TestAnAdvisorySpanningTwoProductsIsHiddenFromSomebodyHoldingOne(t *testing.T) {
	// Whole or not at all, in the case that makes it matter: a reader
	// holding one of the two products would otherwise be handed a document
	// that reads as a complete statement about a product it never mentions.
	each(t, func(t *testing.T, f *fixture) {
		here := f.recorded(t, f.master)
		there := f.recorded(t, f.other)
		both := f.covering(t, [2]string{"sonic", here}, [2]string{"switchd", there})
		one := f.covering(t, [2]string{"sonic", here})

		// Somebody holding the first product and nothing on the second.
		partly := access.NewPerson(f.who.ID+2, "partly", false, map[int64][]access.Role{
			f.product: {access.PublicRead, access.PrivateRead, access.PrivateTriage},
		}, 0)
		if _, err := f.store.ForAdvisory(t.Context(), partly, issuer, both); !errors.Is(
			err, advisory.ErrNoSuchAdvisory) {
			t.Errorf("a document about a product they hold nothing on was generated: %v", err)
		}
		// And the one they can see the whole of still answers, so the rule is
		// a narrowing rather than a wall.
		if _, err := f.store.ForAdvisory(t.Context(), partly, issuer, one); err != nil {
			t.Errorf("an advisory wholly within what they hold was refused: %v", err)
		}
		rows, total, err := f.store.List(t.Context(), partly, advisory.Covering{}, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(rows) != 1 || rows[0].Identifier != one {
			t.Errorf("%d of %d advisories were listed, want only %s", len(rows), total, one)
		}
	})
}

func TestNamingAFlawOnAnAdvisoryAsksForTheRoleOnThatProduct(t *testing.T) {
	// Naming a flaw on an advisory is what puts it into a document published
	// about that product. Asked for the role anywhere, somebody who triages
	// one product and only reads another publishes about the second.
	each(t, func(t *testing.T, f *fixture) {
		here := f.recorded(t, f.master)
		there := f.recorded(t, f.other)
		named := f.covering(t, [2]string{"sonic", here})

		// Triage on the first product, reading on the second — and somebody
		// the database knows, because a subject invented here fails the
		// foreign key on whoever did it and passes a refusal test for the
		// wrong reason.
		reader := access.NewPerson(f.second.ID, f.second.Identity, false,
			map[int64][]access.Role{
				f.product:      {access.PublicRead, access.PrivateRead, access.PrivateTriage},
				f.otherProduct: {access.PublicRead, access.PrivateRead},
			}, 0)
		if _, err := f.store.Add(t.Context(), reader, named, "switchd", there); err == nil {
			t.Error("somebody who only reads a product named its flaw on an advisory")
		}
		// And taking one off asks the same, because it is as much a statement
		// about that product as putting it on was.
		both := f.covering(t, [2]string{"switchd", there})
		if err := f.store.Drop(t.Context(), reader, both, "switchd", there); err == nil {
			t.Error("somebody who only reads a product took its flaw off an advisory")
		}
		// The product they do triage still answers, so this is a rule rather
		// than a wall.
		if _, err := f.store.Add(t.Context(), reader, named, "sonic", here); !errors.Is(
			err, advisory.ErrAlreadyCovered) {
			t.Errorf("the product they triage refused them: %v", err)
		}
	})
}

func TestWhatWentOutAboutAnotherProductIsNotReported(t *testing.T) {
	// The flaw's visibility is the wrong question to ask on its own. Asked
	// alone it says whether this reader reads undisclosed work anywhere, so
	// somebody holding private reading on one product passes it for a
	// disclosed flaw in a product they hold nothing on — and the row carries
	// the identifier, the title, the summary and the digest.
	each(t, func(t *testing.T, f *fixture) {
		// Disclosed, and in the second product, so nothing but the product
		// rules it out.
		there := f.disclosed(t, f.other)
		named := f.covering(t, [2]string{"switchd", there})
		if _, err := f.store.Issued(t.Context(), f.who, issuer, named, "Went out"); err != nil {
			t.Fatalf("recording that it went out: %v", err)
		}

		// Somebody holding both sees it, which is what says the row is there.
		rows, err := f.store.Published(t.Context(), f.who, nil, time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("the row it went out as is not there: %+v", rows)
		}

		// And somebody who reads undisclosed work on the first product and
		// holds nothing on the second does not.
		elsewhere := access.NewPerson(f.second.ID, f.second.Identity, false,
			map[int64][]access.Role{
				f.product: {access.PublicRead, access.PrivateRead, access.PrivateTriage},
			}, 0)
		rows, err = f.store.Published(t.Context(), elsewhere, nil, time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Errorf("an advisory about another product was reported here: %+v", rows)
		}
	})
}
