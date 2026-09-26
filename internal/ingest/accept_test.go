// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// each gives every engine a migrated database, an empty catalog, and one
// declared variant to file scans against.
func each(t *testing.T, fn func(t *testing.T, s *ingest.Store, targetID int64)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		cat := catalog.NewStore(db.DB)
		p, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		br, err := cat.DeclareStream(ctx, p.ID, "release-2.4", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		v, err := cat.DeclareVariant(ctx, p.ID, "broadcom", true)
		if err != nil {
			t.Fatal(err)
		}
		target, err := cat.TargetFor(ctx, br.ID, v.ID)
		if err != nil {
			t.Fatal(err)
		}
		fn(t, ingest.NewStore(db.DB), target.ID)
	})
}

func arriving(targetID int64, hash string, builtAt time.Time) ingest.Arriving {
	return ingest.Arriving{
		TargetID: targetID, ContentHash: hash, BuiltAt: builtAt,
		ParserVersion: "test", Credential: "key-1",
	}
}

func TestFirstScanIsTaken(t *testing.T) {
	each(t, func(t *testing.T, s *ingest.Store, v int64) {
		got, outcome, err := s.Record(t.Context(), arriving(v, "aaa", time.Now().UTC().Add(-time.Hour)))
		if err != nil || outcome != ingest.Accept {
			t.Fatalf("outcome %v, err %v", outcome, err)
		}
		if got.ID == 0 || got.Status != ingest.Accepted {
			t.Errorf("recorded oddly: %+v", got)
		}
	})
}

func TestAnIdenticalFileIsNotTakenTwice(t *testing.T) {
	// The ordinary case is a retry after a timeout that actually succeeded.
	// Failing it would turn a landed scan into a red build, and the usual
	// response is retry logic that swallows errors — which hides real ones.
	each(t, func(t *testing.T, s *ingest.Store, v int64) {
		built := time.Now().UTC().Add(-time.Hour)
		first, _, err := s.Record(t.Context(), arriving(v, "same", built))
		if err != nil {
			t.Fatal(err)
		}
		again, outcome, err := s.Record(t.Context(), arriving(v, "same", built))
		if err != nil {
			t.Fatalf("a re-upload failed: %v", err)
		}
		if outcome != ingest.AlreadyHave {
			t.Errorf("outcome %v, want AlreadyHave", outcome)
		}
		if again == nil || again.ID != first.ID {
			t.Error("the re-upload did not resolve to the scan already held")
		}
	})
}

func TestAnOlderScanIsRefused(t *testing.T) {
	// Uploads do not arrive in the order they were made. Taking an older one
	// would replace today's picture with yesterday's, reopening findings that
	// were closed, with no symptom anyone would notice.
	each(t, func(t *testing.T, s *ingest.Store, v int64) {
		now := time.Now().UTC()
		if _, _, err := s.Record(t.Context(), arriving(v, "new", now.Add(-time.Hour))); err != nil {
			t.Fatal(err)
		}
		_, outcome, err := s.Record(t.Context(), arriving(v, "old", now.Add(-24*time.Hour)))
		if outcome != ingest.NotNewer {
			t.Errorf("outcome %v, want NotNewer", outcome)
		}
		if !errors.Is(err, ingest.ErrRejected) {
			t.Errorf("error is not ErrRejected: %v", err)
		}
	})
}

func TestAScanBuiltAtTheSameMomentIsRefused(t *testing.T) {
	// Different content, same build time. Neither is newer, so taking it would
	// be a coin toss over which picture is current.
	each(t, func(t *testing.T, s *ingest.Store, v int64) {
		built := time.Now().UTC().Add(-time.Hour)
		if _, _, err := s.Record(t.Context(), arriving(v, "first", built)); err != nil {
			t.Fatal(err)
		}
		if _, outcome, _ := s.Record(t.Context(), arriving(v, "second", built)); outcome != ingest.NotNewer {
			t.Errorf("outcome %v, want NotNewer", outcome)
		}
	})
}

func TestAFutureBuildTimeIsRefused(t *testing.T) {
	// Worse than a stray bad value: once the current scan is dated years
	// ahead, nothing legitimate is ever newer and the variant takes no further
	// scans at all.
	each(t, func(t *testing.T, s *ingest.Store, v int64) {
		_, outcome, err := s.Record(t.Context(), arriving(v, "future", time.Now().UTC().Add(48*time.Hour)))
		if outcome != ingest.BuiltInFuture {
			t.Fatalf("outcome %v, want BuiltInFuture", outcome)
		}
		if !errors.Is(err, ingest.ErrRejected) {
			t.Errorf("error is not ErrRejected: %v", err)
		}
		// And the refusal must leave the variant able to take a real scan.
		if _, outcome, err := s.Record(t.Context(), arriving(v, "real", time.Now().UTC().Add(-time.Hour))); err != nil || outcome != ingest.Accept {
			t.Errorf("a normal scan was refused after a future one: %v %v", outcome, err)
		}
	})
}

func TestASmallClockDifferenceIsTolerated(t *testing.T) {
	// Build machines are seconds out, not hours. Refusing them would fail
	// legitimate scans for no benefit.
	each(t, func(t *testing.T, s *ingest.Store, v int64) {
		if _, outcome, err := s.Record(t.Context(), arriving(v, "skew", time.Now().UTC().Add(30*time.Second))); err != nil || outcome != ingest.Accept {
			t.Errorf("a slightly fast clock was refused: %v %v", outcome, err)
		}
	})
}

func TestNewestIsTheMostRecentlyBuilt(t *testing.T) {
	// Not the most recently received: that is the whole point.
	each(t, func(t *testing.T, s *ingest.Store, v int64) {
		ctx := t.Context()
		now := time.Now().UTC()
		if _, _, err := s.Record(ctx, arriving(v, "older", now.Add(-3*time.Hour))); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Record(ctx, arriving(v, "newer", now.Add(-1*time.Hour))); err != nil {
			t.Fatal(err)
		}
		newest, err := s.Newest(ctx, v)
		if err != nil {
			t.Fatal(err)
		}
		if newest.ContentHash != "newer" {
			t.Errorf("newest is %q", newest.ContentHash)
		}
	})
}

func TestTheBuildInForceIsTheJudgmentsThatArrivedLast(t *testing.T) {
	// One build re-sent with different judgments beside it is two
	// submissions at one build time, so which one the picture stands on
	// cannot be left to whichever row the engine hands back first.
	each(t, func(t *testing.T, s *ingest.Store, v int64) {
		ctx := t.Context()
		built := time.Now().UTC().Add(-time.Hour)
		inventory := []byte(`{"bomFormat":"CycloneDX"}`)
		digest := sha256.Sum256(inventory)
		hash := hex.EncodeToString(digest[:])

		first := arriving(v, "first-submission", built)
		first.InventoryHash = hash
		taken, _, err := s.Record(ctx, first)
		if err != nil {
			t.Fatal(err)
		}
		// The fields the arrival decision reads to tell a build re-argued from
		// a second document claiming the same build time.
		if _, err := ingest.NewDocuments(s.DB()).Write(ctx, taken.ID,
			ingest.InventoryKind, 0, bytes.NewReader(inventory)); err != nil {
			t.Fatal(err)
		}

		second := arriving(v, "second-submission", built)
		second.InventoryHash = hash
		again, outcome, err := s.Record(ctx, second)
		if err != nil || outcome != ingest.Accept {
			t.Fatalf("outcome %v, err %v: the same inventory re-argued is a new submission", outcome, err)
		}
		newest, err := s.Newest(ctx, v)
		if err != nil {
			t.Fatal(err)
		}
		if newest.ID != again.ID {
			t.Errorf("the build stands on scan %d, want the judgments that arrived last (%d)", newest.ID, again.ID)
		}
	})
}

func TestASecondDocumentClaimingTheSameBuildTimeIsStillRefused(t *testing.T) {
	// The exception is narrow: the same inventory with new judgments. Two
	// different inventories at one build time is a coin toss over which
	// picture is current, and stays refused.
	each(t, func(t *testing.T, s *ingest.Store, v int64) {
		ctx := t.Context()
		built := time.Now().UTC().Add(-time.Hour)
		first := arriving(v, "one", built)
		first.InventoryHash = "aaaa"
		taken, _, err := s.Record(ctx, first)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ingest.NewDocuments(s.DB()).Write(ctx, taken.ID,
			ingest.InventoryKind, 0, bytes.NewReader([]byte("one"))); err != nil {
			t.Fatal(err)
		}
		second := arriving(v, "two", built)
		second.InventoryHash = "bbbb"
		if _, outcome, _ := s.Record(ctx, second); outcome != ingest.NotNewer {
			t.Errorf("outcome %v, want NotNewer", outcome)
		}
	})
}

func TestNewestIsNilBeforeAnythingArrives(t *testing.T) {
	each(t, func(t *testing.T, s *ingest.Store, v int64) {
		got, err := s.Newest(t.Context(), v)
		if err != nil {
			t.Fatalf("err %v", err)
		}
		if got != nil {
			t.Errorf("got %+v for a variant with no scans", got)
		}
	})
}

func TestBuildTimeSurvivesTheRoundTrip(t *testing.T) {
	// The ordering rule compares stored times against arriving ones, so a
	// timestamp that loses precision or a timezone on the way through the
	// database would make the comparison wrong rather than merely untidy.
	each(t, func(t *testing.T, s *ingest.Store, v int64) {
		built := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		if _, _, err := s.Record(t.Context(), arriving(v, "rt", built)); err != nil {
			t.Fatal(err)
		}
		got, err := s.Newest(t.Context(), v)
		if err != nil {
			t.Fatal(err)
		}
		if !got.BuiltAt.UTC().Equal(built) {
			t.Errorf("built_at came back as %v, stored %v", got.BuiltAt.UTC(), built)
		}
	})
}

func TestAFailureQuotingAProducersOwnTextIsStoredAsText(t *testing.T) {
	// A message saying why a scan could not be read quotes the producer's own
	// text, which carries multi-byte characters. Cutting the message at a
	// byte boundary can land inside one of them, and the invalid UTF-8 that
	// leaves is refused outright by PostgreSQL and in strict mode by MySQL
	// and MariaDB — so recording why a scan failed failed, leaving the scan
	// accepted with nothing saying why nothing happened.
	//
	// SQLite stores it happily, which is why the quick loop never saw this
	// and why only the early return had ever executed: no test had ever
	// passed MarkFailed a message long enough to cut.
	each(t, func(t *testing.T, s *ingest.Store, targetID int64) {
		ctx := t.Context()
		scan, _, err := s.Record(ctx, arriving(targetID, "cut-inside-a-rune", time.Now().UTC()))
		if err != nil {
			t.Fatal(err)
		}

		// One ASCII character and then 3,000 bytes of two-byte ones, so the
		// cut at 2,000 lands between the two halves of a character rather
		// than between two characters. An even offset is the case that
		// happens to be safe, which is why the input matters as much as the
		// length.
		cause := errors.New("x" + strings.Repeat("é", 1500))
		if err := s.MarkFailed(ctx, scan.ID, cause); err != nil {
			t.Fatalf("record that the scan failed: %v", err)
		}

		stored, err := s.ByID(ctx, scan.ID)
		if err != nil {
			t.Fatalf("read the scan back: %v", err)
		}
		if stored.Failure == "" {
			t.Fatal("the scan is failed and says nothing about why")
		}
		if !utf8.ValidString(stored.Failure) {
			t.Error("what is stored is not text, so a strict engine would have refused it")
		}
		if len(stored.Failure) > 2000 {
			t.Errorf("stored %d bytes, over the 2000 the column takes", len(stored.Failure))
		}
	})
}

func TestAnUndatedDocumentSentAgainKeepsTheTimeItFirstArrivedWith(t *testing.T) {
	// Undated A arrives and fails to read; B arrives after it; A is sent
	// again. A is the upload already held, dated when it first arrived, so it
	// is older than B and refused as not newer. Dated by the retry instead, it
	// was taken as newer while its row kept the first time, and the reader
	// then set it aside as superseded after the producer had been told 202.
	each(t, func(t *testing.T, s *ingest.Store, v int64) {
		ctx := t.Context()
		first, outcome, err := s.Record(ctx, arriving(v, "undated-a", time.Time{}))
		if err != nil || outcome != ingest.Accept {
			t.Fatalf("the first arrival: %v %v", outcome, err)
		}
		if err := s.MarkFailed(ctx, first.ID, errors.New("could not be read")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
		if _, outcome, err := s.Record(ctx, arriving(v, "dated-b", time.Now().UTC())); err != nil ||
			outcome != ingest.Accept {
			t.Fatalf("the newer build: %v %v", outcome, err)
		}
		time.Sleep(10 * time.Millisecond)
		if _, outcome, _ := s.Record(ctx, arriving(v, "undated-a", time.Time{})); outcome != ingest.NotNewer {
			t.Errorf("the undated document sent again was %v, want not newer than the build after it", outcome)
		}
	})
}
