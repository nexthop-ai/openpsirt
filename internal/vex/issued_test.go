package vex_test

import (
	"encoding/json"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

func TestADocumentRecordedAfterSomebodyElsesStatesTheLaterVersion(t *testing.T) {
	// A second issuance committing between the document being generated and
	// the write recording it moves the count. The document handed back has to
	// carry the number it is recorded under.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)
		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true); err != nil {
			t.Fatal(err)
		}
		if _, err := cat.Resolve(ctx, "sonic", "master", "broadcom"); err != nil {
			t.Fatal(err)
		}
		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana",
			access.Stated(false), nil)
		if err != nil {
			t.Fatal(err)
		}
		subject := access.NewPerson(who.ID, who.Email, false,
			map[int64][]access.Role{product.ID: {access.PublicTriage}}, 0)
		named := publisher.Named{Name: "Example Networks", Namespace: "https://example.test"}

		racing := vex.NewStore(db.DB)
		vex.Between(racing, func() {
			if _, err := vex.NewStore(db.DB).Issued(ctx, subject, named,
				"sonic", "master", "broadcom"); err != nil {
				t.Fatal(err)
			}
		})
		recorded, err := racing.Issued(ctx, subject, named, "sonic", "master", "broadcom")
		if err != nil {
			t.Fatal(err)
		}
		var doc vex.Statements
		if err := json.Unmarshal([]byte(recorded.Document), &doc); err != nil {
			t.Fatal(err)
		}
		if recorded.Ordinal != 2 || doc.Version != 2 {
			t.Errorf("recorded as revision %d, the document handed back says %d",
				recorded.Ordinal, doc.Version)
		}
		if !doc.Timestamp.Equal(recorded.IssuedAt) {
			t.Errorf("the document is dated %v and was recorded at %v",
				doc.Timestamp, recorded.IssuedAt)
		}
	})
}
