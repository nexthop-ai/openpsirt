package supplier_test

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/supplier"
)

// quiet is a logger a test does not have to read.
func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestADeploymentThatNamesNoSupplierReachesNothing(t *testing.T) {
	// Naming a supplier is the switch. A deployment that has named none makes
	// no request, and one that cannot reach out loses this evidence and
	// nothing else.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)

		pass := supplier.NewPass(f.db.DB, quiet(), "test", sbom.Limits{})
		supplier.FetchForTest(pass, fetching(t, f, p))
		took, err := pass.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 0 || took.Recorded != 0 {
			t.Errorf("a deployment with no supplier read %+v", took)
		}
		if len(p.asked) != 0 {
			t.Errorf("a publisher was reached at %v", p.asked)
		}
	})
}

func TestThePassRecordsHowFarThroughAPublisherItHasRead(t *testing.T) {
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-7.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0007", "libnl-3-200", "3.7.1", "CVE-2026-9111"))

		store := supplier.NewStore(f.db.DB)
		if _, err := store.Add(ctx, f.by, f.product, "Example Linux", p.described()); err != nil {
			t.Fatal(err)
		}
		pass := supplier.NewPass(f.db.DB, quiet(), "test", sbom.Limits{})
		supplier.FetchForTest(pass, fetching(t, f, p))
		if _, err := pass.Once(ctx); err != nil {
			t.Fatal(err)
		}

		rows, err := store.For(ctx, f.by, f.product)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].FetchedAt == nil {
			t.Fatalf("the supplier reads as %+v", rows)
		}
		if rows[0].Failed != "" {
			t.Errorf("a pass that worked recorded %q", rows[0].Failed)
		}
		// A supplier configured now starts reading now, so a document dated
		// before it was configured is not taken — and the mark stays where it
		// was rather than jumping to the document's date.
		if rows[0].CaughtUpTo != nil {
			t.Errorf("a document published before the supplier was named was taken: %v",
				rows[0].CaughtUpTo)
		}
		// And it is no longer due, so the next cycle a minute later reaches
		// nobody.
		due, err := store.Due(ctx, access.Everything("the pass"),
			time.Now().UTC().Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if len(due) != 0 {
			t.Errorf("the supplier is due again a moment after being read: %+v", due)
		}
	})
}

func TestASupplierThatCannotBeReachedDoesNotStopTheNext(t *testing.T) {
	// One publisher unreachable says nothing about another, and a pass that
	// stopped at the first would leave every supplier after it unread for as
	// long as that one stayed down.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-8.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0008", "libnl-3-200", "3.7.1", "CVE-2026-9222"))

		store := supplier.NewStore(f.db.DB)
		// Named first, so it is read first: the list is oldest read first and
		// neither has been read.
		down, err := store.Add(ctx, f.by, f.product, "Gone",
			"https://nothing.invalid/.well-known/csaf/provider-metadata.json")
		if err != nil {
			t.Fatal(err)
		}
		up, err := store.Add(ctx, f.by, f.product, "Example Linux", p.described())
		if err != nil {
			t.Fatal(err)
		}
		// Wound back so the publisher's document is ahead of the mark.
		if _, err := f.db.DB.NewUpdate().Model((*supplier.Source)(nil)).
			Set("caught_up_to = ?", long).
			Where("id IN (?, ?)", down.ID, up.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		pass := supplier.NewPass(f.db.DB, quiet(), "test", sbom.Limits{})
		supplier.FetchForTest(pass, fetching(t, f, p))
		took, err := pass.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 1 || took.Recorded != 1 {
			t.Fatalf("the pass read %+v, want the one publisher that answered", took)
		}

		rows, err := store.For(ctx, f.by, f.product)
		if err != nil {
			t.Fatal(err)
		}
		byName := map[string]supplier.Source{}
		for _, row := range rows {
			if row.FetchedAt == nil {
				t.Errorf("%q was never tried", row.Display)
			}
			byName[row.Display] = row
		}
		if byName["Gone"].Failed == "" {
			t.Error("a publisher that could not be reached recorded no reason")
		}
		// The attempt is recorded and the success is not, which is what makes
		// "unreachable for a week" visible: one moment moving on every attempt
		// reads as a supplier answering fine right up to the failure.
		if byName["Gone"].ReachedAt != nil {
			t.Errorf("a publisher that could not be reached reads as reached at %v",
				byName["Gone"].ReachedAt)
		}
		if byName["Example Linux"].Failed != "" {
			t.Errorf("the publisher that answered recorded %q",
				byName["Example Linux"].Failed)
		}
		if byName["Example Linux"].ReachedAt == nil {
			t.Error("the publisher that answered does not read as reached")
		}
	})
}

func TestOneReplicaReachesOutAndTheOtherDoesNothing(t *testing.T) {
	// The politeness this pass keeps to is a rate per deployment rather than
	// per replica, and three replicas each keeping to it would be three times
	// the traffic at a publisher's expense.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-9.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0009", "libnl-3-200", "3.7.1", "CVE-2026-9333"))

		store := supplier.NewStore(f.db.DB)
		row, err := store.Add(ctx, f.by, f.product, "Example Linux", p.described())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewUpdate().Model((*supplier.Source)(nil)).
			Set("caught_up_to = ?", long).Where("id = ?", row.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		// The lease is taken by one replica while the supplier is still due, so
		// what stops the second is the lease and nothing else. Run the other
		// way round the first pass marks the supplier read, and the second
		// finds nothing due whatever the lease says — which is a test that
		// passes with the lease removed.
		if mine, err := queue.NewLeases(f.db.DB).Take(ctx, supplier.FetchLease,
			"one", time.Hour); err != nil || !mine {
			t.Fatalf("taking the lease as the first replica: %v (%v)", mine, err)
		}
		due, err := store.Due(ctx, access.Everything("the test"), time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if len(due) != 1 {
			t.Fatalf("the supplier is not due, so the lease is not what is being tested")
		}

		second := supplier.NewPass(f.db.DB, quiet(), "two", sbom.Limits{})
		supplier.FetchForTest(second, fetching(t, f, p))
		took, err := second.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 0 {
			t.Errorf("the replica without the lease read %+v", took)
		}
		if len(p.asked) != 0 {
			t.Errorf("the publisher was reached at %v by a replica without the lease",
				p.asked)
		}

		// And the replica holding it does the work, so the refusal above is
		// the lease rather than something that stops both.
		first := supplier.NewPass(f.db.DB, quiet(), "one", sbom.Limits{})
		supplier.FetchForTest(first, fetching(t, f, p))
		if took, err := first.Once(ctx); err != nil || took.Documents != 1 {
			t.Fatalf("the replica holding the lease read %+v (%v)", took, err)
		}
	})
}

func TestAnAdvisoryIsRecordedAsTheAdministratorWhoNamedTheSupplier(t *testing.T) {
	// Configuring a supplier is the act that admitted this publisher's
	// judgment, and it is the only decision anybody made — nothing chose the
	// individual document.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-10.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0010", "libnl-3-200", "3.7.1", "CVE-2026-9444"))

		store := supplier.NewStore(f.db.DB)
		row, err := store.Add(ctx, f.by, f.product, "Example Linux", p.described())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewUpdate().Model((*supplier.Source)(nil)).
			Set("caught_up_to = ?", long).Where("id = ?", row.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		pass := supplier.NewPass(f.db.DB, quiet(), "test", sbom.Limits{})
		supplier.FetchForTest(pass, fetching(t, f, p))
		if _, err := pass.Once(ctx); err != nil {
			t.Fatal(err)
		}

		var by []int64
		if err := f.db.DB.NewSelect().TableExpr(`"vex_statement" AS "ss"`).
			ColumnExpr(`"ss"."uploaded_by"`).Scan(ctx, &by); err != nil {
			t.Fatal(err)
		}
		if len(by) != 1 || by[0] != f.by.ID {
			t.Errorf("the claim is recorded as having been brought in by %v, want %d",
				by, f.by.ID)
		}
	})
}

func TestTheBoundOnOneCycleIsTheSameWhicheverWayTheFeedIsOrdered(t *testing.T) {
	// A pass that stopped at its bound having taken the newest first would
	// leave the mark past everything it had not read, and those documents
	// would never be taken.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		day := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
		for i := range supplier.MostPerPass * 2 {
			p.publishes(byteName(i), day.AddDate(0, 0, i).Format(time.RFC3339),
				advisory("EL-2026-1"+byteName(i), "libnl-3-200", "3.7.1",
					"CVE-2026-95"+byteName(i)))
		}

		store := supplier.NewStore(f.db.DB)
		row, err := store.Add(ctx, f.by, f.product, "Example Linux", p.described())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewUpdate().Model((*supplier.Source)(nil)).
			Set("caught_up_to = ?", long).Where("id = ?", row.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		pass := supplier.NewPass(f.db.DB, quiet(), "test", sbom.Limits{})
		supplier.FetchForTest(pass, fetching(t, f, p))
		if _, err := pass.Once(ctx); err != nil {
			t.Fatal(err)
		}
		rows, err := store.For(ctx, f.by, f.product)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].CaughtUpTo == nil {
			t.Fatalf("the supplier reads as %+v", rows)
		}
		// The backlog drains rather than being skipped: the mark stands at the
		// last one read, so the next cycle starts at the one after it.
		want := day.AddDate(0, 0, supplier.MostPerPass-1)
		if got := rows[0].CaughtUpTo.UTC(); !got.Equal(want) {
			t.Errorf("the mark stands at %v, want %v", got, want)
		}
	})
}

// byteName is a short distinct path per document.
func byteName(i int) string {
	return "/" + strings.Repeat("a", 1+i/26) + string(rune('a'+i%26)) + ".json"
}
