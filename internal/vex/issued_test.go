// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vex_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

func TestADocumentRecordedAfterSomebodyElsesStatesTheLaterVersion(t *testing.T) {
	// A second issuance committing between the document being generated and
	// the write recording it moves the count. The document handed back has to
	// carry the number it is recorded under.
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		product := w.Product
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
				"sonic", "master", "broadcom", vex.Ours); err != nil {
				t.Fatal(err)
			}
		})
		recorded, err := racing.Issued(ctx, subject, named, "sonic", "master", "broadcom", vex.Ours)
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

// insertsIssuance runs rival before the first statement writing an issuance,
// on another connection, and counts the writes it sees.
type insertsIssuance struct {
	once   sync.Once
	rival  func()
	writes int
}

func (h *insertsIssuance) BeforeQuery(ctx context.Context, e *bun.QueryEvent) context.Context {
	if strings.HasPrefix(e.Query, "INSERT ") && strings.Contains(e.Query, "vex_issuance") {
		h.writes++
		h.once.Do(h.rival)
	}
	return ctx
}

func (h *insertsIssuance) AfterQuery(context.Context, *bun.QueryEvent) {}

func TestTwoIssuancesAtOnceTakeTheNextNumberRatherThanFail(t *testing.T) {
	// Both read the same highest number inside their transactions, and the
	// unique constraint refuses the second write. That refusal is a lost race:
	// the whole attempt is taken again, reads the number the first wrote, and
	// records the next one. The harness holds SQLite to one connection, so
	// nothing lands between the read and the write there.
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		if db.Stats().MaxOpenConnections == 1 {
			t.Skip("one connection: nothing lands between a read and a write")
		}
		ctx := t.Context()
		product := w.Product
		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana",
			access.Stated(false), nil)
		if err != nil {
			t.Fatal(err)
		}
		subject := access.NewPerson(who.ID, who.Email, false,
			map[int64][]access.Role{product.ID: {access.PublicTriage}}, 0)
		named := publisher.Named{Name: "Example Networks", Namespace: "https://example.test"}

		hook := &insertsIssuance{rival: func() {
			if _, err := vex.NewStore(db.DB).Issued(context.Background(), subject, named,
				"sonic", "master", "broadcom", vex.Ours); err != nil {
				t.Errorf("the rival issuance: %v", err)
			}
		}}
		hooked := bun.NewDB(db.DB.DB, db.Dialect())
		hooked.AddQueryHook(hook)

		recorded, err := vex.NewStore(hooked).Issued(ctx, subject, named, "sonic", "master", "broadcom", vex.Ours)
		if err != nil {
			t.Fatalf("an issuance that lost the race for its number answered %v", err)
		}
		if hook.writes != 2 {
			t.Errorf("the issuance was written %d times, want a refused write and its retry", hook.writes)
		}
		var doc vex.Statements
		if err := json.Unmarshal([]byte(recorded.Document), &doc); err != nil {
			t.Fatal(err)
		}
		if recorded.Ordinal != 2 || doc.Version != 2 {
			t.Errorf("recorded as revision %d, the document handed back says %d, want 2",
				recorded.Ordinal, doc.Version)
		}
	})
}

// A document is not recorded under a name the build lost while it was being
// written. The document is generated before the write that records it, and a
// rename committing in between would record one naming what the build had
// been called.
func TestADocumentIsNotRecordedUnderANameTheBuildLost(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		product := w.Product
		variant := w.Customer
		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana",
			access.Stated(false), nil)
		if err != nil {
			t.Fatal(err)
		}
		subject := access.NewPerson(who.ID, who.Email, false,
			map[int64][]access.Role{product.ID: {access.PublicTriage}}, 0)
		named := publisher.Named{Name: "Example Networks", Namespace: "https://example.test"}

		store := vex.NewStore(db.DB)
		vex.Between(store, func() {
			if _, err := db.DB.NewUpdate().Model((*catalog.Variant)(nil)).
				Set("name = ?", "bcm").Where("id = ?", variant.ID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		})
		if _, err := store.Issued(ctx, subject, named, "sonic", "master", "broadcom", vex.Ours); !errors.Is(err, vex.ErrRenamed) {
			t.Errorf("recording a document for a build renamed meanwhile answered %v", err)
		}
		went, err := db.DB.NewSelect().Table("vex_issuance").Count(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if went != 0 {
			t.Errorf("%d documents were recorded under a name the build no longer has", went)
		}
	})
}
