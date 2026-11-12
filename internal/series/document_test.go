// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package series_test

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/chunked"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

// A run's document let go while it is read runs out of parts before its size,
// and ends in an error rather than cleanly, so a reader does not take the
// bytes it got for the whole document.
func TestARunDocumentLetGoWhileItIsReadEndsShortWithAnError(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		f := fixture.New(t, db)
		store := series.NewStore(db.DB)
		run, _, err := store.Receive(ctx, series.Arriving{
			ProductID: f.Product.ID, BuildID: f.Build.ID, Kind: kind.Analysis, Series: "nightly",
			ContentHash: "hash-1", BuiltAt: time.Now().UTC().Add(-time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		body := bytes.Repeat([]byte("x"), 3<<20)
		doc, err := store.Write(ctx, run.ID, 0, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		parts, err := db.DB.NewSelect().Table(string(chunked.SeriesParts)).
			Where(`"document_id" = ?`, doc.ID).Count(ctx)
		if err != nil || parts < 2 {
			t.Fatalf("the document is held in %d parts (%v), so this checked nothing", parts, err)
		}
		whole, err := io.ReadAll(store.Open(ctx, doc))
		if err != nil || !bytes.Equal(whole, body) {
			t.Fatalf("the document read back as %d bytes (%v), want %d", len(whole), err, len(body))
		}
		reading := store.Open(ctx, doc)
		if _, err := io.ReadFull(reading, make([]byte, 1024)); err != nil {
			t.Fatal(err)
		}
		if err := store.Discard(ctx, run.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(reading); !errors.Is(err, chunked.ErrReleased) {
			t.Errorf("reading on past a discard ended with %v, want the document released", err)
		}
	})
}
