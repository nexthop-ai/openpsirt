package ingest_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// scanned gives every engine a database holding two builds of one product: one
// filed against recently, one that has gone silent. A third build belongs to a
// product the reader cannot see.
func scanned(t *testing.T, fn func(t *testing.T, db *database.DB, s *ingest.Store, reader access.Subject, ours, theirs int64)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		cat := catalog.NewStore(db.DB)
		store := ingest.NewStore(db.DB)

		// Declaring is refused where the name is taken, and two builds of one
		// product share a product and a branch by construction — so each level
		// falls back to the one that exists.
		build := func(product, stream, variant string) (int64, int64) {
			p, err := cat.DeclareProduct(ctx, product, product)
			if err != nil {
				if p, err = cat.ProductByName(ctx, product); err != nil {
					t.Fatal(err)
				}
			}
			br, err := cat.DeclareStream(ctx, p.ID, stream, catalog.Branch, nil)
			if err != nil {
				if br, err = cat.StreamByName(ctx, p.ID, stream); err != nil {
					t.Fatal(err)
				}
			}
			v, err := cat.DeclareVariant(ctx, p.ID, variant, true)
			if err != nil {
				if v, err = cat.VariantByName(ctx, p.ID, variant); err != nil {
					t.Fatal(err)
				}
			}
			target, err := cat.TargetFor(ctx, br.ID, v.ID)
			if err != nil {
				t.Fatal(err)
			}
			return p.ID, target.ID
		}

		ours, current := build("sonic", "master", "broadcom")
		_, silent := build("sonic", "master", "mellanox")
		theirs, hidden := build("edge-router", "main", "generic")

		file := func(target int64, hash string, ago time.Duration) {
			at := time.Now().UTC().Add(-ago)
			if _, _, err := store.Record(ctx, ingest.Arriving{
				TargetID: target, ContentHash: hash, BuiltAt: at,
				ParserVersion: "test", Credential: "key-1",
			}); err != nil {
				t.Fatal(err)
			}
		}
		file(current, "recent", time.Hour)
		file(hidden, "elsewhere", time.Hour)
		// The silent build has one scan, long enough ago to have gone quiet.
		// A build with a scan and a build with none are different situations,
		// and both have to be reported.
		file(silent, "stale", 30*24*time.Hour)
		if _, err := db.DB.NewUpdate().Table("scan").
			Set("received_at = ?", time.Now().UTC().Add(-30*24*time.Hour)).
			Where("content_hash = ?", "stale").Exec(ctx); err != nil {
			t.Fatal(err)
		}

		reader := access.NewPerson(1, "reader", false, map[int64][]access.Role{
			ours: {access.PublicRead},
		}, 0)
		fn(t, db, store, reader, ours, theirs)
	})
}

func TestScanningNamesTheBuildThatWentQuiet(t *testing.T) {
	scanned(t, func(t *testing.T, _ *database.DB, s *ingest.Store, reader access.Subject, _, _ int64) {
		rows, err := s.Scanning(t.Context(), reader, finding.Scope{}, 7*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatalf("wanted the reader's two builds, got %d: %+v", len(rows), rows)
		}
		// Quietest first, because the answer somebody needs is which one
		// stopped rather than which one is alphabetically first.
		if rows[0].Variant != "mellanox" || !rows[0].Quiet {
			t.Errorf("the silent build should lead and be quiet, got %+v", rows[0])
		}
		if rows[1].Variant != "broadcom" || rows[1].Quiet {
			t.Errorf("the scanned build should follow and be quiet=false, got %+v", rows[1])
		}
		if rows[0].LastReceivedAt == nil {
			t.Error("a build that was scanned once should still say when")
		}
		if rows[0].Since < 20*24*time.Hour {
			t.Errorf("silence measured as %v, wanted about thirty days", rows[0].Since)
		}
	})
}

func TestScanningCountsFromDeclarationWhereNothingEverArrived(t *testing.T) {
	// The same failure caught earlier: a build declared and never filed
	// against. An inner join to the scan table cannot see it at all, which is
	// the mistake this asserts against.
	scanned(t, func(t *testing.T, _ *database.DB, s *ingest.Store, reader access.Subject, ours, _ int64) {
		cat := catalog.NewStore(s.DB())
		br, err := cat.DeclareStream(t.Context(), ours, "never-built", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		v, err := cat.VariantByName(t.Context(), ours, "broadcom")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cat.TargetFor(t.Context(), br.ID, v.ID); err != nil {
			t.Fatal(err)
		}

		rows, err := s.Scanning(t.Context(), reader, finding.Scope{}, 7*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, row := range rows {
			if row.Stream == "never-built" {
				found = true
				if row.LastReceivedAt != nil {
					t.Error("nothing was ever filed against it, so it has no last arrival")
				}
			}
		}
		if !found {
			t.Error("a build nothing has ever been filed against was left out entirely")
		}
	})
}

func TestScanningShowsOnlyWhatTheReaderMaySee(t *testing.T) {
	scanned(t, func(t *testing.T, _ *database.DB, s *ingest.Store, reader access.Subject, _, theirs int64) {
		rows, err := s.Scanning(t.Context(), reader, finding.Scope{}, 7*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.ProductID == theirs {
				t.Errorf("a product the reader holds nothing on was listed: %+v", row)
			}
		}
	})
}

func TestScanningTellsAPipelineKeyNothing(t *testing.T) {
	// A key sees the receipts for what it sent and nothing more. When a build
	// was last scanned by anybody is a fact about the deployment, and a key
	// that could read it would learn about uploads it did not make.
	//
	// **Refused rather than answered empty.** "Here is nothing" and "you
	// cannot ask" are different statements, and this is the second: a key
	// holds no products, so an empty answer is what a person who holds nothing
	// gets and says the wrong thing about a credential that may never ask.
	//
	// This asserted the empty answer, with a comment saying it pinned the
	// outcome rather than one guard — and the outcome it pinned was the one
	// the data layer was supposed to stop giving.
	scanned(t, func(t *testing.T, _ *database.DB, s *ingest.Store, _ access.Subject, ours, _ int64) {
		pipeline := access.NewPipeline(1, "nightly", access.Scope{ProductID: ours})
		rows, err := s.Scanning(t.Context(), pipeline, finding.Scope{}, 7*24*time.Hour)
		if !errors.Is(err, access.ErrDenied) {
			t.Errorf("a pipeline key asking when builds were last scanned got %v", err)
		}
		if len(rows) != 0 {
			t.Errorf("a pipeline key was told about %d builds", len(rows))
		}
	})
}

func TestScanningJudgesNothingWithoutAThreshold(t *testing.T) {
	// Zero is how a caller asks "when was each of these last seen" without
	// also asking for a judgment, and a threshold of zero must not make
	// everything quiet.
	scanned(t, func(t *testing.T, _ *database.DB, s *ingest.Store, reader access.Subject, _, _ int64) {
		rows, err := s.Scanning(t.Context(), reader, finding.Scope{}, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			t.Fatal("wanted the builds back")
		}
		for _, row := range rows {
			if row.Quiet {
				t.Errorf("nothing should be quiet with no threshold: %+v", row)
			}
		}
	})
}

func TestAnUploadThatCouldNotBeReadIsNotBeingHeardFrom(t *testing.T) {
	// A build whose upload arrives nightly and fails to parse nightly read as
	// perfectly quiet=false — on the one report whose subject is that silence
	// must not look like health.
	scanned(t, func(t *testing.T, db *database.DB, s *ingest.Store, reader access.Subject, _, _ int64) {
		ctx := t.Context()
		before, err := s.Scanning(ctx, reader, finding.Scope{}, 7*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if len(before) != 2 || before[1].Variant != "broadcom" || before[1].Quiet {
			t.Fatalf("the scanned build is not the quiet=false one to begin with: %+v", before)
		}

		// The one scan it has could not be read.
		var id int64
		if err := db.DB.NewSelect().Table("scan").Column("id").
			Where("content_hash = ?", "recent").Scan(ctx, &id); err != nil {
			t.Fatal(err)
		}
		if err := s.MarkFailed(ctx, id, errors.New("the inventory could not be read")); err != nil {
			t.Fatal(err)
		}

		after, err := s.Scanning(ctx, reader, finding.Scope{}, 7*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		var build *ingest.Coverage
		for i := range after {
			if after[i].Variant == "broadcom" {
				build = &after[i]
			}
		}
		if build == nil {
			t.Fatalf("the build went missing: %+v", after)
		}
		// Measured from declaration, like a build nothing was ever filed
		// against, because nothing readable ever was.
		if build.LastReceivedAt != nil {
			t.Errorf("an upload nothing could read counts as having been heard from: %+v", build)
		}
	})
}

func TestAReleaseOutOfSupportIsNotReportedAsHavingGoneQuiet(t *testing.T) {
	// A dead release not being scanned is expected rather than a fault,
	// and without this the coverage view — the thing that catches a
	// product silently dropping out — fills with releases that stopped on
	// purpose and nobody reads it.
	//
	// **Reported rather than left out**: "not scanned, and that is
	// fine" and "not listed" are different answers, and only one is true.
	scanned(t, func(t *testing.T, db *database.DB, s *ingest.Store, reader access.Subject, ours, _ int64) {
		ctx := t.Context()
		before, err := s.Scanning(ctx, reader, finding.Scope{}, 7*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if len(before) != 2 || !before[0].Quiet {
			t.Fatalf("the silent build is not quiet to begin with: %+v", before)
		}
		if before[0].Retired {
			t.Fatal("a build nobody has dated reads as out of support")
		}

		// Support for the whole product ended yesterday.
		yesterday := time.Now().UTC().Add(-24 * time.Hour)
		if err := catalog.NewStore(db.DB).SetProductEndOfLife(ctx, ours, &yesterday); err != nil {
			t.Fatal(err)
		}

		after, err := s.Scanning(ctx, reader, finding.Scope{}, 7*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if len(after) != len(before) {
			t.Fatalf("a release out of support left the list: %d rows, was %d", len(after), len(before))
		}
		for _, row := range after {
			if !row.Retired {
				t.Errorf("%s %s does not read as out of support", row.Stream, row.Variant)
			}
			if row.Quiet {
				t.Errorf("%s %s is reported as having gone quiet while out of support",
					row.Stream, row.Variant)
			}
			// And the silence is still measured and still shown, so a reader
			// can see it stopped rather than being told nothing.
			if row.Since == 0 {
				t.Errorf("%s %s reports no silence at all", row.Stream, row.Variant)
			}
		}
	})
}

// TestCoverageSaysWhetherAnybodyIsTrying holds the line that a build nobody
// uploads to and a build whose uploads are turned away are distinguishable.
//
// Both are quiet. They are different faults with different people to tell: one
// is a pipeline nobody wired up, the other is a pipeline failing nightly and
// reporting success to its own log. Counting only the scans that could be read
// answers the first half of "silence looks exactly like health"; this is the
// other half, which is whether anybody is trying.
func TestCoverageSaysWhetherAnybodyIsTrying(t *testing.T) {
	scanned(t, func(t *testing.T, db *database.DB, s *ingest.Store, reader access.Subject, _, _ int64) {
		ctx := t.Context()
		// The build rather than the product it is under. A refusal is recorded
		// against the thing an upload was addressed to, and the fixture hands
		// back product identifiers.
		ours := targetOf(t, db, "master", "broadcom")

		rows, err := s.Scanning(ctx, reader, finding.Scope{}, 7*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.LastRefusedAt != nil || row.RefusedBecause != nil {
				t.Errorf("a build nothing was refused against reports one: %+v", row)
			}
		}

		why := "the inventory does not say when it was built"
		if err := s.Refused(ctx, reader, ingest.Refusal{TargetID: ours, Reason: why}); err != nil {
			t.Fatal(err)
		}
		told := refusalsIn(t, s, reader)
		if len(told) != 1 {
			t.Fatalf("%d builds report a refusal, want the one it was recorded against", len(told))
		}
		if told[0] != why {
			t.Errorf("the report does not repeat what the producer was told: %q", told[0])
		}

		// A producer retrying a document nothing can read writes one of these
		// a minute. The row is replaced rather than added to, so what a report
		// holds is the last refusal and not a history of one build.
		later := "the inventory could not be read"
		if err := s.Refused(ctx, reader, ingest.Refusal{TargetID: ours, Reason: later}); err != nil {
			t.Fatal(err)
		}
		told = refusalsIn(t, s, reader)
		if len(told) != 1 {
			t.Fatalf("%d builds report a refusal after a second one, want one", len(told))
		}
		if told[0] != later {
			t.Errorf("the report holds an older refusal than the last: %q", told[0])
		}
	})
}

// refusalsIn is what each build in the report says it was last refused for.
func refusalsIn(t *testing.T, s *ingest.Store, reader access.Subject) []string {
	t.Helper()
	rows, err := s.Scanning(t.Context(), reader, finding.Scope{}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var told []string
	for _, row := range rows {
		if row.LastRefusedAt == nil {
			continue
		}
		if row.RefusedBecause == nil {
			t.Errorf("a refusal was recorded with no reason: %+v", row)
			continue
		}
		told = append(told, *row.RefusedBecause)
	}
	return told
}

// targetOf is the build a release and a variant name, by their names.
//
// The coverage fixture hands back products, and a refusal is recorded against
// the build an upload was addressed to. Looked up rather than threaded through
// the fixture, so the tests that do not need it keep the signature they have.
func targetOf(t *testing.T, db *database.DB, stream, variant string) int64 {
	t.Helper()
	var id int64
	if err := db.DB.NewSelect().
		TableExpr(`"target" AS "tg"`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "variant" AS "va" ON va.id = tg.variant_id`).
		ColumnExpr(`tg.id`).
		Where("st.name = ?", stream).Where("va.name = ?", variant).
		Scan(t.Context(), &id); err != nil {
		t.Fatal(err)
	}
	return id
}
