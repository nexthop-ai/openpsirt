package supplier_test

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
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
		reasons := map[string]string{}
		for _, row := range rows {
			if row.FetchedAt == nil {
				t.Errorf("%q was never reached", row.Name)
			}
			reasons[row.Name] = row.Failed
		}
		if reasons["Gone"] == "" {
			t.Error("a publisher that could not be reached recorded no reason")
		}
		if reasons["Example Linux"] != "" {
			t.Errorf("the publisher that answered recorded %q", reasons["Example Linux"])
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

		first := supplier.NewPass(f.db.DB, quiet(), "one", sbom.Limits{})
		supplier.FetchForTest(first, fetching(t, f, p))
		second := supplier.NewPass(f.db.DB, quiet(), "two", sbom.Limits{})
		supplier.FetchForTest(second, fetching(t, f, p))

		took, err := first.Once(ctx)
		if err != nil || took.Documents != 1 {
			t.Fatalf("the replica holding the lease read %+v (%v)", took, err)
		}
		asked := len(p.asked)
		took, err = second.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 0 {
			t.Errorf("the replica without the lease read %+v", took)
		}
		if len(p.asked) != asked {
			t.Errorf("the publisher was reached %d more times", len(p.asked)-asked)
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
