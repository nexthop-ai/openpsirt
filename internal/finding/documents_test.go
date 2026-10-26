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

func TestTheDocumentsAProductHoldsAreReadOnlyByAPersonWhoSeesIt(t *testing.T) {
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
		}, []finding.Statement{{Vulnerability: "CVE-2026-1", Component: "libnl", Status: "fixed"}}); err != nil {
			t.Fatal(err)
		}

		held, total, err := store.Documents(ctx, reader, c.product, finding.FromVex, 50, 0)
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
			if _, _, err := store.Documents(ctx, who, c.product, finding.FromVex, 50, 0); !errors.Is(err, access.ErrDenied) {
				t.Errorf("%s is answered %v, want a refusal", name, err)
			}
		}
	})
}

func TestADocumentAFeedFetchedIsToldFromAnUploadByItsAddress(t *testing.T) {
	t.Parallel()
	for name, fetched := range map[string]bool{
		"https://example.test/csaf/2026/dsa-1.json": true,
		"dsa-1.json": false,
	} {
		if got := (finding.Document{Name: name}).Fetched(); got != fetched {
			t.Errorf("%q reads as fetched %v, want %v", name, got, fetched)
		}
	}
}
