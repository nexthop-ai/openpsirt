//go:build measure

// What one real supplier advisory costs to record.
//
// A VEX document is a publisher's whole statement set and a real one about a
// single issue lists a few thousand products. A security advisory about a
// kernel lists every package of every architecture on every platform it
// shipped to, and one real one names 95,933 product identifiers — so an
// administrator uploading it writes on that order of rows, in one
// transaction, in batches.
//
// Behind a build tag because it is a measurement and not a gate: it asserts
// almost nothing and its output is a number to write down. `make measure`
// runs it.
package finding_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// claimed is how many product identifiers one advisory lists. Taken from a
// real distribution advisory about a kernel: 341 vulnerabilities over 279
// composed products, 95,139 of them listed under a status.
const claimed = 95_139

func TestMeasureRecordingOneRealAdvisory(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		// A real row, because the statement records who uploaded it and the
		// schema says that has to be a person.
		person, err := access.NewStore(db.DB).Ensure(ctx, "them@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		who := access.NewPerson(person.ID, "them@example.com", true,
			map[int64][]access.Role{product.ID: {access.PrivateTriage}}, 0)

		statements := make([]finding.Statement, 0, claimed)
		for i := range claimed {
			statements = append(statements, finding.Statement{
				Vulnerability: fmt.Sprintf("CVE-2026-%d", i%341),
				Component:     fmt.Sprintf("package-%d", i),
				Purl: fmt.Sprintf(
					"pkg:rpm/example/package-%d@5.14.0-427.13.1?arch=x86_64", i),
				Status:    "fixed",
				Statement: "For details on how to apply this update, refer to the errata.",
			})
		}
		from := finding.Supplied{
			Source: finding.FromAdvisory, Identifier: "EXSA-2026:2394",
			Publisher: "Example Platform Security", Document: "exsa.json",
			Digest: "sha256:measured",
		}

		store := finding.NewStore(db.DB)
		began := time.Now()
		recorded, superseded, err := store.RecordStatements(ctx, who, product.ID,
			from, statements)
		took := time.Since(began)
		if err != nil {
			t.Fatal(err)
		}
		if recorded != claimed || superseded != 0 {
			t.Fatalf("recorded %d and set aside %d", recorded, superseded)
		}
		t.Logf("recording %d claims from one advisory: %s", claimed, took.Round(time.Millisecond))

		// A revision of the same advisory: every claim set aside and written
		// again, which is what an upload of a document already held costs.
		began = time.Now()
		_, replaced, err := store.RecordStatements(ctx, who, product.ID, from, statements)
		again := time.Since(began)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("revising it, setting aside %d and writing %d again: %s",
			replaced, claimed, again.Round(time.Millisecond))
	})
}
