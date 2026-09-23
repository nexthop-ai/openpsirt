// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/supplier"
)

func TestASupplierThatStoppedAnsweringIsRaised(t *testing.T) {
	// A supplier that stopped answering looks exactly like one that has
	// published nothing, so the silence is looked for. Each supplier here
	// reaches one arm: read a week and more ago, read recently, never read
	// and configured long ago, never read and configured today, and one
	// withdrawn. Then the product is retired.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)
		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "admin@example.com", "Admin", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := rights.Ensure(ctx, "reader@example.com", "Reader", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		aScannedTarget(t, db)
		product, err := catalog.NewStore(db.DB).ProductByName(ctx, "sonic")
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, reader.ID, product.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		ago := func(days int) *time.Time {
			at := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour).Truncate(time.Microsecond)
			return &at
		}
		configured := func(name string, created, reached *time.Time, failed string, retired bool) {
			t.Helper()
			source := &supplier.Source{
				ProductID: product.ID, Name: name, Display: name,
				URL:       "https://" + name + ".example.test/.well-known/csaf/provider-metadata.json",
				CreatedBy: admin.ID, CreatedAt: *created, ReachedAt: reached, Failed: failed,
			}
			if retired {
				source.RetiredAt = ago(1)
			}
			if _, err := db.DB.NewInsert().Model(source).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		configured("gone-quiet", ago(60), ago(10), "https://gone-quiet.example.test: 503 Service Unavailable", false)
		configured("answering", ago(60), ago(2), "", false)
		configured("never-answered", ago(10), nil, "", false)
		configured("just-added", ago(1), nil, "", false)
		configured("withdrawn", ago(60), ago(30), "", true)

		heard := func(who *access.Account) []string {
			t.Helper()
			quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
			if _, _, err := notify.NewWatch(db.DB, quiet).Once(ctx); err != nil {
				t.Fatal(err)
			}
			rows, _, err := notify.NewStore(db.DB).Waiting(ctx, asks(t, db, who), 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			var bodies []string
			for _, row := range rows {
				if row.Kind == notify.SupplierSilent {
					bodies = append(bodies, row.Body)
				}
			}
			return bodies
		}

		said := strings.Join(heard(admin), "\n")
		for _, want := range []string{"gone-quiet", "503 Service Unavailable", "never-answered"} {
			if !strings.Contains(said, want) {
				t.Errorf("administrators were told %q, want it to say %q", said, want)
			}
		}
		for _, not := range []string{"answering for", "just-added", "withdrawn"} {
			if strings.Contains(said, not) {
				t.Errorf("administrators were told %q, which names %q", said, not)
			}
		}
		if told := heard(reader); len(told) != 0 {
			t.Errorf("somebody who administers nothing was told %v", told)
		}

		// Read once each scan interval, so a fortnightly schedule is not a
		// supplier going quiet after a week.
		if err := setting.NewStore(db.DB).Set(ctx, setting.ScanEvery, "336h"); err != nil {
			t.Fatal(err)
		}
		if told := heard(admin); len(told) != 0 {
			t.Errorf("under a fortnightly schedule, ten days unread raised %v", told)
		}

		// A retired product's suppliers are never read again, so their
		// silence is not raised.
		if err := setting.NewStore(db.DB).Set(ctx, setting.ScanEvery, "24h"); err != nil {
			t.Fatal(err)
		}
		if told := heard(admin); len(told) == 0 {
			t.Fatal("a daily schedule raised nothing, so the retired product checks nothing")
		}
		if err := catalog.NewStore(db.DB).RetireProduct(ctx, product.ID); err != nil {
			t.Fatal(err)
		}
		if told := heard(admin); len(told) != 0 {
			t.Errorf("the suppliers of a retired product were raised: %v", told)
		}
	})
}
