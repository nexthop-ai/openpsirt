// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Upgraded, a claim v0.4.0 holds records no build it was made on: v0.4.0 kept
// none, and the record is never guessed.
func claimsRecordNoBuildTheyWereMadeOn() upgradeCheck {
	var claim int64
	recordsNone := func(t *testing.T, ctx context.Context, db *database.DB) {
		t.Helper()
		var held, recorded int
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "claim" WHERE "id" = ?`, claim).
			Scan(ctx, &held); err != nil {
			t.Fatal(err)
		}
		if held != 1 {
			t.Fatalf("the seeded claim is not there, so this checked nothing")
		}
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "claim_build" WHERE "claim_id" = ?`, claim).
			Scan(ctx, &recorded); err != nil {
			t.Fatal(err)
		}
		if recorded != 0 {
			t.Errorf("a claim v0.4.0 held records %d builds it was made on, want none", recorded)
		}
	}
	return upgradeCheck{
		name: "AnUpgradedClaimRecordsNoBuildItWasMadeOn",
		seed: func(t *testing.T, ctx context.Context, db *database.DB) {
			person, err := access.NewStore(db.DB).Ensure(ctx, "claimant", "", access.Stated(false), nil)
			if err != nil {
				t.Fatal(err)
			}
			// Found again by who made it, which is one statement on every
			// engine where returning the key is not.
			if _, err := db.DB.NewRaw(`INSERT INTO "claim"
				("kind", "proposed_by", "proposed_at", "outcome") VALUES (?, ?, ?, ?)`,
				"finding", person.ID, time.Now().UTC().Truncate(time.Microsecond),
				"not-applicable").Exec(ctx); err != nil {
				t.Fatal(err)
			}
			if err := db.DB.NewRaw(`SELECT MAX("id") FROM "claim" WHERE "proposed_by" = ?`,
				person.ID).Scan(ctx, &claim); err != nil {
				t.Fatal(err)
			}
		},
		upgraded: recordsNone,
	}
}
