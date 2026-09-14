package ingest_test

import (
	"errors"
	"testing"
	"time"

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
