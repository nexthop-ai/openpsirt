// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestTheDocumentsUploadedToAProductAreReadOnlyByAPersonWhoSeesIt(t *testing.T) {
	// Decided in the store, so a second route over it cannot forget it.
	catalogSeed.Two(t, func(t *testing.T, db *database.DB, c seededCatalog) {
		ctx := t.Context()
		store := finding.NewStore(db.DB)
		person, err := access.NewStore(db.DB).Ensure(ctx, "somebody@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		reader := access.NewPerson(person.ID, "somebody@example.com", false,
			map[int64][]access.Role{c.product: {access.PublicRead}}, 0)
		if _, _, err := store.RecordStatements(ctx, reader, c.product, finding.Supplied{
			Source: finding.FromVex, Publisher: "Debian", Document: "debian.json", Digest: "sha256:one",
			Arrived: &finding.Arrival{},
		}, []finding.Statement{{Vulnerability: "CVE-2026-1", Component: "libnl", Status: "fixed"}}); err != nil {
			t.Fatal(err)
		}

		held, total, err := store.Uploads(ctx, reader, c.product, finding.FromVex, 50, 0)
		if err != nil || total != 1 || len(held) != 1 {
			t.Fatalf("a reader of the product is answered %d of %d: %v", len(held), total, err)
		}
		for name, who := range map[string]access.Subject{
			"somebody granted another product": access.NewPerson(person.ID, "somebody@example.com",
				false, map[int64][]access.Role{c.product + 1: {access.PublicRead}}, 0),
			"a pipeline key for the product": access.NewPipeline(1, "ci",
				access.Scope{ProductID: c.product}),
			"anybody, where the product publishes": access.Published([]int64{c.product}),
		} {
			if _, _, err := store.Uploads(ctx, who, c.product, finding.FromVex, 50, 0); !errors.Is(err, access.ErrDenied) {
				t.Errorf("%s is answered %v, want a refusal", name, err)
			}
		}
	})
}

func TestEveryUploadOfADocumentIsListedAndTheNewestTakenStands(t *testing.T) {
	catalogSeed.Each(t, func(t *testing.T, db *database.DB, c seededCatalog) {
		ctx := t.Context()
		store := finding.NewStore(db.DB)
		person, err := access.NewStore(db.DB).Ensure(ctx, "admin@example.com", "Admin", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		by := access.NewPerson(person.ID, "admin@example.com", true, nil, 0)
		uploaded := &finding.Arrival{}
		send := func(publisher, digest, status string) {
			t.Helper()
			if _, _, err := store.RecordStatements(ctx, by, c.product, finding.Supplied{
				Source: finding.FromVex, Publisher: publisher, Document: publisher + ".json",
				Digest: digest, Arrived: uploaded,
			}, []finding.Statement{{Vulnerability: "CVE-2026-1", Component: "libnl", Status: status}}); err != nil {
				t.Fatal(err)
			}
		}
		send("Debian", "sha256:one", "affected")
		send("Debian", "sha256:two", "fixed")
		send("Ubuntu", "sha256:three", "fixed")
		if err := store.TurnedAway(ctx, by, c.product, finding.Supplied{
			Source: finding.FromVex, Document: "broken.json", Arrived: uploaded,
		}, "that is not a VEX document"); err != nil {
			t.Fatal(err)
		}
		// Recorded by an upstream this product trusts, which arrives no way
		// this records.
		if _, _, err := store.RecordStatements(ctx, by, c.product, finding.Supplied{
			Source: finding.FromVex, Publisher: "Fedora", Document: "fedora.json", Digest: "sha256:four",
		}, []finding.Statement{{Vulnerability: "CVE-2026-1", Component: "libnl", Status: "fixed"}}); err != nil {
			t.Fatal(err)
		}

		held, total, err := store.Uploads(ctx, by, c.product, finding.FromVex, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 4 || len(held) != 4 {
			t.Fatalf("the list holds %d of %d: %+v", len(held), total, held)
		}
		// Newest first.
		refused, ubuntu, debian, first := held[0], held[1], held[2], held[3]
		if refused.Status != finding.UploadTurnedAway || refused.Reason == nil ||
			*refused.Reason != "that is not a VEX document" || refused.Current() || refused.Digest != nil {
			t.Errorf("the refusal reads %+v", refused)
		}
		if ubuntu.Publisher != "ubuntu" || !ubuntu.Current() {
			t.Errorf("ubuntu's reads %+v; want it standing", ubuntu)
		}
		if debian.Publisher != "debian" || !debian.Current() || debian.Recorded != 1 || debian.Superseded != 1 {
			t.Errorf("debian's second reads %+v; want it standing, having set the first aside", debian)
		}
		if first.Publisher != "debian" || first.Current() || first.Superseded != 0 {
			t.Errorf("debian's first reads %+v; want it replaced", first)
		}
		for _, u := range held {
			if u.Credential == nil || *u.Credential != access.Sender(by) || u.FeedID != nil {
				t.Errorf("%q arrived by %v and %v; want the uploader alone", u.Document, u.Credential, u.FeedID)
			}
		}

		// A page is a page of uploads, and the total is of all of them.
		page, total, err := store.Uploads(ctx, by, c.product, finding.FromVex, 1, 2)
		if err != nil || total != 4 || len(page) != 1 || page[0].ID != debian.ID {
			t.Errorf("the third page of one reads %+v of %d: %v", page, total, err)
		}
		// Two advisories from one publisher are two documents, and a refusal
		// under one's key replaces nothing.
		for _, name := range []string{"DSA-1", "DSA-2"} {
			if _, _, err := store.RecordStatements(ctx, by, c.product, finding.Supplied{
				Source: finding.FromAdvisory, Publisher: "Debian", Identifier: name,
				Document: name + ".json", Digest: "sha256:" + name, Arrived: uploaded,
			}, []finding.Statement{{Vulnerability: "CVE-2026-1", Component: "libnl", Status: "fixed"}}); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.TurnedAway(ctx, by, c.product, finding.Supplied{
			Source: finding.FromAdvisory, Publisher: "Debian", Identifier: "DSA-1",
			Document: "dsa-1-again.json", Arrived: uploaded,
		}, "it does not match its digest"); err != nil {
			t.Fatal(err)
		}
		advisories, total, err := store.Uploads(ctx, by, c.product, finding.FromAdvisory, 50, 0)
		if err != nil || total != 3 {
			t.Fatalf("the advisories hold %+v of %d: %v", advisories, total, err)
		}
		if again := advisories[0]; again.Status != finding.UploadTurnedAway || again.Identifier != "DSA-1" ||
			again.Current() {
			t.Errorf("the refusal reads %+v", again)
		}
		for _, u := range advisories[1:] {
			if !u.Current() {
				t.Errorf("%s reads as replaced; want it standing beside the other and the refusal", u.Identifier)
			}
		}
	})
}
