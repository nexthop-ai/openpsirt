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
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/upstream"
)

// An upstream that cannot be read is said once in an administrator's own
// area, however many sweeps find it still failing, and said once more when it
// is read again. A failed read the next one answers says nothing.
func TestAnUpstreamThatCannotBeReadIsSaidOnceAndItsRecoveryOnce(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		admin, err := access.NewStore(db.DB).Ensure(ctx, "admin@example.com", "Admin", new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		at := func(ago time.Duration) *time.Time {
			when := time.Now().UTC().Add(-ago).Truncate(time.Microsecond)
			return &when
		}
		up := &upstream.Upstream{
			ProductID: w.Product.ID, URL: "https://psirt.example.test/.well-known/csaf/provider-metadata.json",
			Publisher: "SONiC Project", TrustedBy: admin.ID, TrustedAt: *at(72 * time.Hour),
			ReachedAt: at(10 * time.Minute), FetchedAt: at(time.Minute),
			Failed: "https://psirt.example.test/.well-known/csaf/provider-metadata.json answered 503",
		}
		if _, err := db.DB.NewInsert().Model(up).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		set := func(columns map[string]any) {
			t.Helper()
			q := db.DB.NewUpdate().Model((*upstream.Upstream)(nil)).Where(`"id" = ?`, up.ID)
			for column, value := range columns {
				q = q.Set(`"`+column+`" = ?`, value)
			}
			if _, err := q.Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		// What the administrator's own area holds of each kind, after a sweep.
		swept := func() map[notify.Kind][]string {
			t.Helper()
			if _, _, err := notify.NewWatch(db.DB, slog.New(slog.NewTextHandler(io.Discard, nil))).
				Once(ctx); err != nil {
				t.Fatal(err)
			}
			rows, _, err := notify.NewStore(db.DB).Waiting(ctx, asks(t, db, admin), 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			out := map[notify.Kind][]string{}
			for _, row := range rows {
				out[row.Kind] = append(out[row.Kind], row.Body)
			}
			return out
		}

		if got := swept(); len(got[notify.UpstreamFailing]) != 0 {
			t.Errorf("one failed read the next could answer was said: %v", got[notify.UpstreamFailing])
		}
		set(map[string]any{"reached_at": at(7 * time.Hour)})
		for range 2 {
			got := swept()
			if len(got[notify.UpstreamFailing]) != 1 {
				t.Fatalf("an upstream failing for hours is said %d times, want once", len(got[notify.UpstreamFailing]))
			}
			said := got[notify.UpstreamFailing][0]
			for _, want := range []string{"psirt.example.test", "503", "last read"} {
				if !strings.Contains(said, want) {
					t.Errorf("the notice %q does not say %q", said, want)
				}
			}
		}

		set(map[string]any{"failed": nil, "reached_at": at(0)})
		for range 2 {
			got := swept()
			if len(got[notify.UpstreamFailing]) != 0 {
				t.Errorf("an upstream read again is still said to be failing")
			}
			if len(got[notify.UpstreamRecovered]) != 1 ||
				!strings.Contains(got[notify.UpstreamRecovered][0], "read again") {
				t.Fatalf("the recovery is said %v, want once", got[notify.UpstreamRecovered])
			}
		}
	})
}
