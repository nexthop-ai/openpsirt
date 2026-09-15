package ingest_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// What became of an upload, and which run's numbers belong to it.
//
// None of this had a test. The runs query went from "the newest finished one"
// to every finished one, a receipt gained the run that answered it, and both
// design documents assert behavior that would regress with nothing saying so.
func TestAFailedRunDoesNotPoisonTheUploadsBeforeIt(t *testing.T) {
	// One bad night used to be permanent. The earliest run to finish after an
	// upload was taken as the one that answered it whatever became of that
	// run, so a scanner that fell over once made every receipt already waiting
	// on it report that failure for ever — and the screen got steadily more
	// wrong the longer a deployment ran.
	scanned(t, func(t *testing.T, _ *database.DB, s *ingest.Store, reader access.Subject, ours, _ int64) {
		ctx := t.Context()
		target := quietTarget(t, s, ours)
		now := time.Now().UTC()

		// An upload, then a run that fails, then a run that succeeds.
		file(t, s, target, "first", now.Add(-3*time.Hour))
		finishRun(t, s, target, now.Add(-2*time.Hour), "the scanner fell over")
		finishRun(t, s, target, now.Add(-time.Hour), "")

		receipts, _, err := s.Receipts(ctx, reader, target, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(receipts) == 0 {
			t.Fatal("wanted the upload back")
		}
		if receipts[0].Scan.ContentHash != "first" {
			t.Fatalf("newest receipt is %q, want the upload just filed",
				receipts[0].Scan.ContentHash)
		}
		if receipts[0].State != ingest.Scanned {
			t.Errorf("after a later run succeeded the upload reads %q (%q), want scanned",
				receipts[0].State, receipts[0].Failure)
		}
	})
}

func TestAnUploadReadsAsFailedWhileEveryRunSinceHasFailed(t *testing.T) {
	// The other half of the rule above: tolerating a failure that a later run
	// made irrelevant must not turn into never reporting one at all.
	scanned(t, func(t *testing.T, _ *database.DB, s *ingest.Store, reader access.Subject, ours, _ int64) {
		ctx := t.Context()
		target := quietTarget(t, s, ours)
		now := time.Now().UTC()

		file(t, s, target, "only", now.Add(-3*time.Hour))
		finishRun(t, s, target, now.Add(-2*time.Hour), "the scanner fell over")

		receipts, _, err := s.Receipts(ctx, reader, target, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if receipts[0].State != ingest.Refused {
			t.Errorf("the upload reads %q, want the failure reported", receipts[0].State)
		}
		if receipts[0].Failure != "the scanner fell over" {
			t.Errorf("the failure reads %q, want the scanner's own words", receipts[0].Failure)
		}
	})
}

func TestARunIsAttributedToOneUploadHoweverThePageFalls(t *testing.T) {
	// A page is a window on one history, so which upload a run belongs to
	// cannot be decided from the rows in front of us: page two would claim it
	// again, and the same opened-and-closed numbers would render twice.
	scanned(t, func(t *testing.T, _ *database.DB, s *ingest.Store, reader access.Subject, ours, _ int64) {
		ctx := t.Context()
		target := quietTarget(t, s, ours)
		now := time.Now().UTC()

		// Three uploads, then one run covering all of them.
		for i, hash := range []string{"one", "two", "three"} {
			file(t, s, target, hash, now.Add(-time.Duration(9-i)*time.Hour))
		}
		finishRun(t, s, target, now.Add(-time.Hour), "")

		claimed := 0
		for offset := range 3 {
			page, _, err := s.Receipts(ctx, reader, target, "", 1, offset)
			if err != nil {
				t.Fatal(err)
			}
			if len(page) != 1 {
				t.Fatalf("page at %d returned %d rows", offset, len(page))
			}
			if page[0].RunID != nil {
				claimed++
			}
		}
		if claimed != 1 {
			t.Errorf("one run was attributed to %d uploads across three pages of one, want 1",
				claimed)
		}
	})
}

// quietTarget is the fixture's build whose only scan is a month old, so an
// upload filed now is newer than what it holds.
//
// The build the fixture scanned an hour ago cannot be used: a scan older than
// the one a variant already holds is refused, which is the monotonicity rule
// doing its job rather than something to work around.
func quietTarget(t *testing.T, s *ingest.Store, productID int64) int64 {
	t.Helper()
	var id int64
	if err := s.DB().NewSelect().TableExpr("\"target\" AS \"tg\"").
		Join("JOIN \"stream\" AS \"st\" ON st.id = tg.stream_id").
		Join("JOIN \"variant\" AS \"v\" ON v.id = tg.variant_id").
		Column("tg.id").
		Where("st.product_id = ?", productID).
		Where("v.name = ?", "mellanox").
		Scan(t.Context(), &id); err != nil {
		t.Fatal(err)
	}
	return id
}

// file records an upload that has been read, arriving and parsed at the given
// moment.
//
// The read job is marked done because that is what says an upload was parsed:
// an upload still sitting in the queue reads as "reading" whatever the runs
// around it did, so leaving it pending would make every assertion below pass
// for the wrong reason.
func file(t *testing.T, s *ingest.Store, target int64, hash string, at time.Time) {
	t.Helper()
	ctx := t.Context()
	scan, _, err := s.Record(ctx, ingest.Arriving{
		TargetID: target, ContentHash: hash, BuiltAt: at, ParserVersion: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().NewUpdate().Model((*ingest.Scan)(nil)).
		Set("received_at = ?", at).Where("id = ?", scan.ID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	// The upload endpoint enqueues the read in the same transaction as the
	// scan; recording one directly does not, so the job is written here.
	job := map[string]any{
		"kind": queue.Parse, "reference": strconv.FormatInt(scan.ID, 10),
		"state": queue.Done, "attempts": 1, "max_attempts": 5,
		"run_after": at, "created_at": at, "updated_at": at,
	}
	if _, err := s.DB().NewInsert().Model(&job).TableExpr("\"job\"").
		Exec(ctx); err != nil {
		t.Fatal(err)
	}
}

// finishRun records a scan run that has already ended, failing where a cause
// is given.
func finishRun(t *testing.T, s *ingest.Store, target int64, at time.Time, failure string) {
	t.Helper()
	finishRunWith(t, s, target, at, failure, "", "")
}

// finishRunWith is the same, saying what the run was measured with.
func finishRunWith(t *testing.T, s *ingest.Store, target int64, at time.Time,
	failure, scannerVersion, databaseVersion string) {
	t.Helper()
	row := map[string]any{
		"target_id": target, "scanner": "test", "ran_here": true,
		"scanner_version": scannerVersion, "database_version": databaseVersion,
		"started_at": at.Add(-time.Minute), "finished_at": at, "failure": failure,
	}
	if _, err := s.DB().NewInsert().Model(&row).TableExpr("\"scan_run\"").
		Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// Every receipt carries what the run answering it was measured with.
//
// Only the newest finished run's versions were reported, beside the page — so
// a page spanning a scanner upgrade or a vulnerability database that stopped
// moving said one thing about all of it, and "which database produced the
// finding you dismissed on 3 March" had no answer.
func TestEachReceiptSaysWhatItsOwnRunWasMeasuredWith(t *testing.T) {
	scanned(t, func(t *testing.T, _ *database.DB, s *ingest.Store, reader access.Subject, ours, _ int64) {
		ctx := t.Context()
		target := quietTarget(t, s, ours)
		now := time.Now().UTC()

		// Two uploads, each answered by its own run, against databases four
		// months apart.
		file(t, s, target, "march", now.Add(-6*time.Hour))
		finishRunWith(t, s, target, now.Add(-5*time.Hour), "", "0.100.0", "2026-03-01")
		file(t, s, target, "september", now.Add(-4*time.Hour))
		finishRunWith(t, s, target, now.Add(-3*time.Hour), "", "0.101.0", "2026-09-01")

		receipts, _, err := s.Receipts(ctx, reader, target, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		measured := map[string]string{}
		for _, r := range receipts {
			if r.Scan.ContentHash != "march" && r.Scan.ContentHash != "september" {
				continue
			}
			if r.Measured == nil {
				t.Fatalf("the receipt for %q says nothing about what measured it",
					r.Scan.ContentHash)
			}
			measured[r.Scan.ContentHash] = r.Measured.DatabaseVersion
		}
		if len(measured) != 2 {
			t.Fatalf("wanted both uploads back, got %v of %d receipts", measured, len(receipts))
		}
		// Two uploads answered by one run. The counts go only to the newest of
		// them — repeating what a run opened down three rows reads as three
		// separate changes — but what it was measured with belongs to both,
		// because that is a property of the run rather than a change it made.
		file(t, s, target, "one", now.Add(-2*time.Hour))
		file(t, s, target, "two", now.Add(-90*time.Minute))
		finishRunWith(t, s, target, now.Add(-time.Hour), "", "0.102.0", "2026-09-06")
		receipts, _, err = s.Receipts(ctx, reader, target, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		shared := 0
		attributed := 0
		for _, r := range receipts {
			if r.Scan.ContentHash != "one" && r.Scan.ContentHash != "two" {
				continue
			}
			if r.Measured == nil || r.Measured.DatabaseVersion != "2026-09-06" {
				t.Errorf("%q was measured as %+v, wanted the one run that answered both",
					r.Scan.ContentHash, r.Measured)
				continue
			}
			shared++
			if r.RunID != nil {
				attributed++
			}
		}
		if shared != 2 {
			t.Errorf("%d of the two uploads one run answered say what measured them", shared)
		}
		if attributed != 1 {
			t.Errorf("the run's counts landed on %d uploads, wanted the newest one only",
				attributed)
		}
		// Each upload's own run, not the newest: the older one is answered by
		// the database that was current when it was read.
		if measured["march"] != "2026-03-01" || measured["september"] != "2026-09-01" {
			t.Errorf("measured as %v, wanted each upload's own run", measured)
		}
	})
}

func TestARunIsAttributedToTheUploadThatArrivedLastBeforeIt(t *testing.T) {
	// Which upload a run answers is decided by when the uploads arrived, and
	// identifiers are not arrival order: two uploads recorded at the same
	// moment take their identifiers in whichever order they reach the table.
	// Deciding it by identifier attributed a run's numbers to the older of the
	// two, and the receipt for the upload the run actually read said nothing.
	scanned(t, func(t *testing.T, _ *database.DB, s *ingest.Store, reader access.Subject, ours, _ int64) {
		ctx := t.Context()
		target := quietTarget(t, s, ours)
		now := time.Now().UTC()

		// Filed in the order a build produces them, then set to have arrived
		// the other way round: the lower identifier arrived second. A scan
		// built before one already held is refused, so the two are recorded in
		// order and their arrival is written afterwards.
		file(t, s, target, "arrived-second", now.Add(-3*time.Hour))
		file(t, s, target, "arrived-first", now.Add(-2*time.Hour))
		for hash, at := range map[string]time.Time{
			"arrived-second": now.Add(-2 * time.Hour),
			"arrived-first":  now.Add(-3 * time.Hour),
		} {
			if _, err := s.DB().NewUpdate().Model((*ingest.Scan)(nil)).
				Set("received_at = ?", at).Where("content_hash = ?", hash).
				Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		finishRun(t, s, target, now.Add(-time.Hour), "")

		receipts, _, err := s.Receipts(ctx, reader, target, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		answered := ""
		for _, r := range receipts {
			if r.RunID != nil {
				if answered != "" {
					t.Fatalf("one run was attributed to %q and %q both",
						answered, r.Scan.ContentHash)
				}
				answered = r.Scan.ContentHash
			}
		}
		if answered != "arrived-second" {
			t.Errorf("the run's numbers landed on %q, want the upload that arrived last "+
				"before it finished", answered)
		}
	})
}

func TestEveryRunKeepsItsOwnUploadAcrossALongHistory(t *testing.T) {
	// The uploads and the runs are each read once and walked together, so a
	// walk that ran ahead of itself would attribute a run to an upload older
	// than the one it read, and every run after it would be wrong the same
	// way. A night at a time, over enough nights for that to show.
	scanned(t, func(t *testing.T, _ *database.DB, s *ingest.Store, reader access.Subject, ours, _ int64) {
		ctx := t.Context()
		target := quietTarget(t, s, ours)
		now := time.Now().UTC()

		const nights = 12
		for i := range nights {
			at := now.Add(-time.Duration(nights-i) * 2 * time.Hour)
			file(t, s, target, "night-"+strconv.Itoa(i), at)
			finishRun(t, s, target, at.Add(time.Hour), "")
		}

		receipts, _, err := s.Receipts(ctx, reader, target, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		answered := 0
		for _, r := range receipts {
			if !strings.HasPrefix(r.Scan.ContentHash, "night-") {
				continue
			}
			if r.RunID == nil {
				t.Errorf("%q was read by a run of its own and reports no numbers",
					r.Scan.ContentHash)
				continue
			}
			answered++
		}
		if answered != nights {
			t.Errorf("%d of %d nights carry their own run", answered, nights)
		}
	})
}
