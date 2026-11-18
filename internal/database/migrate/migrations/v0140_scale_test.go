// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

package migrations_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// componentsV0140 is how many components the measured v0.13.0 database holds.
const componentsV0140 = 100_000

// The v0.14.0 upgrade on a v0.13.0 database holding a hundred thousand Debian
// packages, one in ten named apart from its package identifier, logged for the
// upgrade note: the names step reads every component and writes a name for
// each, and two for the ones named apart.
//
// Timed alone with OPENPSIRT_TEST_ENGINES naming one engine.
func TestMeasureTheV0140UpgradeAgainstTheComponentsItHolds(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0130)
		at := time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC)
		const batch = 1_000
		start := time.Now()
		for first := 0; first < componentsV0140; first += batch {
			var values []string
			var args []any
			for i := first; i < first+batch; i++ {
				name := fmt.Sprintf("package-%d", i)
				called := name
				if i%10 == 0 {
					called = fmt.Sprintf("Package %d library", i)
				}
				values = append(values, "(?, ?, ?, ?, ?, ?, ?)")
				args = append(args, name+"@1.0-1", fmt.Sprintf("pkg:deb/debian/%s@1.0-1?arch=amd64&distro=debian-12", name),
					called, "1.0-1", strings.ToLower(called), name+"@1.0-1", at)
			}
			if _, err := db.ExecContext(ctx, `INSERT INTO "component" ("identity", "purl", "name", "version",
				"name_folded", "fold_key", "first_seen_at") VALUES `+strings.Join(values, ", "), args...); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("seeded %d components in %s", componentsV0140, time.Since(start))
		start = time.Now()
		dbtest.MigrateTo(t, db, v0140)
		t.Logf("upgraded %d components in %s", componentsV0140, time.Since(start))
		var names int
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "component_name"`).Scan(ctx, &names); err != nil {
			t.Fatal(err)
		}
		if want := componentsV0140 + componentsV0140/10; names != want {
			t.Errorf("the upgrade kept %d names, want %d", names, want)
		}
		leaveAtLatest(t, ctx, db)
	})
}
