// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// credentialWithdrawnAt is when the credentials a folding check makes as
// withdrawn were withdrawn, before the upgrade.
var credentialWithdrawnAt = time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)

// Upgraded, every key's name is stored folded. Among keys whose names fold to
// one, the key in force, or the oldest where both are alike, keeps the name
// and goes on authenticating. Every other is withdrawn if it was in force,
// with a trail row saying the upgrade did it, and left as it was if it was
// withdrawn already; each is named by its number, since a name is unique
// across withdrawn keys too.
func keyNamesAreFoldedAndClashesWithdrawn() upgradeCheck {
	ids := map[string]int64{}
	var numbered string
	var sent int64
	want := func() map[string]string {
		number := func(typed string) string { return strconv.FormatInt(ids[typed], 10) }
		return map[string]string{
			"CI":             numbered + ".2",
			"ci":             "ci",
			" Nightly ":      "nightly",
			"Release":        "release",
			"RELEASE":        "release #" + number("RELEASE"),
			"already-folded": "already-folded",
			"deploy":         "deploy #" + number("deploy"),
			"DEPLOY":         "deploy",
			"   ":            "key #" + number("   "),
			numbered:         numbered,
		}
	}
	check := func(when string, t *testing.T, ctx context.Context, db *database.DB) {
		t.Helper()
		for typed, name := range want() {
			if got := credentialName(t, ctx, db, "api_key", ids[typed]); got != name {
				t.Errorf("%s, the key made as %q is named %q, want %q", when, typed, got, name)
			}
		}
		keys := access.NewStore(db.DB)
		for _, kept := range []string{"ci", " Nightly ", "Release", "already-folded", "DEPLOY", "   ", numbered} {
			if _, err := keys.ResolveKey(ctx, keySecret(kept)); err != nil {
				t.Errorf("%s, the key made as %q no longer authenticates: %v", when, kept, err)
			}
		}
		for _, clashed := range []string{"CI", "RELEASE", "deploy"} {
			if _, err := keys.ResolveKey(ctx, keySecret(clashed)); !errors.Is(err, access.ErrDenied) {
				t.Errorf("%s, the key made as %q answered %v, want it refused", when, clashed, err)
			}
		}
		// Withdrawn before the upgrade, and left as it was.
		for _, before := range []string{"CI", "deploy"} {
			if got := withdrawnAt(t, ctx, db, "api_key", ids[before]); !got.Equal(credentialWithdrawnAt) {
				t.Errorf("%s, the key made as %q reads withdrawn at %v, want %v",
					when, before, got, credentialWithdrawnAt)
			}
		}
	}
	return upgradeCheck{
		name: "AnUpgradeFoldsKeyNamesAndWithdrawsTheOnesThatClash",
		seed: func(t *testing.T, ctx context.Context, db *database.DB) {
			cat := catalog.NewStore(db.DB)
			product, err := cat.DeclareProduct(ctx, "keyring", "Keyring")
			if err != nil {
				t.Fatal(err)
			}
			made := func(name string, withdrawn bool) {
				t.Helper()
				var revoked *time.Time
				if withdrawn {
					revoked = &credentialWithdrawnAt
				}
				if _, err := db.DB.NewRaw(`INSERT INTO "api_key"
					("name", "secret_hash", "product_id", "created_at", "revoked_at")
					VALUES (?, ?, ?, ?, ?)`, name, digest(keySecret(name)), product.ID,
					credentialWithdrawnAt, revoked).Exec(ctx); err != nil {
					t.Fatal(err)
				}
				var id int64
				if err := db.DB.NewRaw(`SELECT "id" FROM "api_key" WHERE "name" = ?`, name).
					Scan(ctx, &id); err != nil {
					t.Fatal(err)
				}
				ids[name] = id
			}
			// Withdrawn and older, so the key in force keeps the name.
			made("CI", true)
			made("ci", false)
			made(" Nightly ", false)
			// Both in force, so the older keeps it.
			made("Release", false)
			made("RELEASE", false)
			made("already-folded", false)
			// The keeper moves onto the name the withdrawn key still holds,
			// which only the placeholders make possible.
			made("deploy", true)
			made("DEPLOY", false)
			// Names nothing and clashes with nothing.
			made("   ", false)
			// Already named like the number CI would take, which keeps its
			// name and pushes CI's number past it.
			numbered = "ci #" + strconv.FormatInt(ids["CI"], 10)
			made(numbered, false)

			// v0.4.0 recorded a scan's sender by the name it sent as.
			stream, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
			if err != nil {
				t.Fatal(err)
			}
			variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
			if err != nil {
				t.Fatal(err)
			}
			target, err := cat.TargetFor(ctx, stream.ID, variant.ID)
			if err != nil {
				t.Fatal(err)
			}
			scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
				TargetID: target.ID, ContentHash: "sent-as-DEPLOY", ParserVersion: "test",
				BuiltAt: credentialWithdrawnAt, Credential: "DEPLOY",
			})
			if err != nil {
				t.Fatal(err)
			}
			sent = scan.ID
		},
		upgraded: func(t *testing.T, ctx context.Context, db *database.DB) {
			check("upgraded", t, ctx, db)
			names := want()
			if got := upgradeWithdrawals(t, ctx, db, names["RELEASE"]); got != 1 {
				t.Errorf("upgraded, the trail records the upgrade withdrawing %s %d times, want once",
					names["RELEASE"], got)
			}
			for _, before := range []string{"CI", "deploy"} {
				if got := upgradeWithdrawals(t, ctx, db, names[before]); got != 0 {
					t.Errorf("upgraded, the trail records withdrawing %s, which was withdrawn already",
						names[before])
				}
			}
			// The sender was read by the name v0.4.0 recorded, before it folded.
			var credential string
			if err := db.DB.NewRaw(`SELECT "credential" FROM "scan" WHERE "id" = ?`, sent).
				Scan(ctx, &credential); err != nil {
				t.Fatal(err)
			}
			if want := "key:" + strconv.FormatInt(ids["DEPLOY"], 10); credential != want {
				t.Errorf("upgraded, the scan sent as DEPLOY reads as sent by %q, want %s", credential, want)
			}
		},
	}
}

// Upgraded, every personal token's name is stored folded, and a name is unique
// to the person holding it. Among one person's tokens whose names fold to one,
// the token in force, or the oldest where both are alike, keeps the name and
// goes on authenticating. Every other is withdrawn if it was in force, with a
// trail row by the upgrade naming its owner, and left as it was if it was
// withdrawn already; each is named by its number. Another person's token of
// the same name is theirs and untouched.
func tokenNamesAreFoldedAndClashesWithdrawn() upgradeCheck {
	type made struct {
		owner int64
		name  string
	}
	ids := map[made]int64{}
	var owner, other int64
	var numbered string
	want := func() map[made]string {
		number := func(typed string) string { return strconv.FormatInt(ids[made{owner, typed}], 10) }
		return map[made]string{
			{owner, "CI"}:      numbered + ".2",
			{owner, "ci"}:      "ci",
			{owner, "Release"}: "release",
			{owner, "RELEASE"}: "release #" + number("RELEASE"),
			{owner, "deploy"}:  "deploy #" + number("deploy"),
			{owner, "DEPLOY"}:  "deploy",
			{owner, "   "}:     "token #" + number("   "),
			{owner, numbered}:  numbered,
			{other, "RELEASE"}: "release",
		}
	}
	inForce := func() map[made]bool {
		return map[made]bool{
			{owner, "ci"}: true, {owner, "Release"}: true, {owner, "DEPLOY"}: true,
			{owner, "   "}: true, {owner, numbered}: true, {other, "RELEASE"}: true,
		}
	}
	withdrawal := func() string { return "token-owner · " + want()[made{owner, "RELEASE"}] }
	check := func(when string, t *testing.T, ctx context.Context, db *database.DB) {
		t.Helper()
		live := inForce()
		for typed, name := range want() {
			if got := credentialName(t, ctx, db, "personal_token", ids[typed]); got != name {
				t.Errorf("%s, the token made as %q is named %q, want %q", when, typed.name, got, name)
			}
			if got := withdrawnAt(t, ctx, db, "personal_token", ids[typed]); got.IsZero() != live[typed] {
				t.Errorf("%s, the token made as %q reads withdrawn at %v", when, typed.name, got)
			}
		}
		// Withdrawn before the upgrade, and left as it was.
		for _, before := range []made{{owner, "CI"}, {owner, "deploy"}} {
			if got := withdrawnAt(t, ctx, db, "personal_token", ids[before]); !got.Equal(credentialWithdrawnAt) {
				t.Errorf("%s, the token made as %q reads withdrawn at %v, want %v",
					when, before.name, got, credentialWithdrawnAt)
			}
		}
	}
	return upgradeCheck{
		name: "AnUpgradeFoldsTokenNamesAndWithdrawsTheOnesThatClash",
		seed: func(t *testing.T, ctx context.Context, db *database.DB) {
			people := access.NewStore(db.DB)
			holder, err := people.Ensure(ctx, "token-owner", "", access.Stated(true), nil)
			if err != nil {
				t.Fatal(err)
			}
			somebody, err := people.Ensure(ctx, "token-other", "", access.Stated(true), nil)
			if err != nil {
				t.Fatal(err)
			}
			owner, other = holder.ID, somebody.ID
			expires := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
			mint := func(who int64, name string, withdrawn bool) {
				t.Helper()
				var revoked *time.Time
				if withdrawn {
					revoked = &credentialWithdrawnAt
				}
				if _, err := db.DB.NewRaw(`INSERT INTO "personal_token"
					("name", "secret_hash", "person_id", "created_at", "expires_at", "revoked_at")
					VALUES (?, ?, ?, ?, ?, ?)`, name, digest(tokenSecret(who, name)), who,
					credentialWithdrawnAt, expires, revoked).Exec(ctx); err != nil {
					t.Fatal(err)
				}
				var id int64
				if err := db.DB.NewRaw(`SELECT "id" FROM "personal_token" WHERE "person_id" = ? AND "name" = ?`,
					who, name).Scan(ctx, &id); err != nil {
					t.Fatal(err)
				}
				ids[made{who, name}] = id
			}
			// Withdrawn and older, so the token in force keeps the name.
			mint(owner, "CI", true)
			mint(owner, "ci", false)
			// Both in force, so the older keeps it.
			mint(owner, "Release", false)
			mint(owner, "RELEASE", false)
			// The keeper moves onto the name the withdrawn token still holds.
			mint(owner, "deploy", true)
			mint(owner, "DEPLOY", false)
			// Names nothing and clashes with nothing.
			mint(owner, "   ", false)
			// Already named like the number CI would take.
			numbered = "ci #" + strconv.FormatInt(ids[made{owner, "CI"}], 10)
			mint(owner, numbered, false)
			// Another person's, which clashes with none of the owner's.
			mint(other, "RELEASE", false)
		},
		upgraded: func(t *testing.T, ctx context.Context, db *database.DB) {
			check("upgraded", t, ctx, db)
			// Presented after the upgrade: the kept tokens authenticate and the
			// withdrawn duplicate is refused.
			people := access.NewStore(db.DB)
			for typed := range inForce() {
				if _, err := people.ResolveToken(ctx, tokenSecret(typed.owner, typed.name)); err != nil {
					t.Errorf("upgraded, the token made as %q no longer authenticates: %v", typed.name, err)
				}
			}
			if _, err := people.ResolveToken(ctx, tokenSecret(owner, "RELEASE")); !errors.Is(err, access.ErrDenied) {
				t.Errorf("upgraded, the withdrawn duplicate answered %v, want it refused", err)
			}
			if got := upgradeWithdrawals(t, ctx, db, withdrawal()); got != 1 {
				t.Errorf("upgraded, the trail records the upgrade withdrawing %s %d times, want once",
					withdrawal(), got)
			}
		},
	}
}

// Upgraded, each claim a build made records the name it is about folded,
// beside the name as the producer spelled it, and no version.
func claimSubjectsAreFolded() upgradeCheck {
	var target int64
	// A capital outside ASCII, which the engines' own LOWER folds on three
	// engines and not on SQLite.
	subjects := map[string]string{"ÉCLAIR-Lib": "éclair-lib", "openssl": "openssl"}
	return upgradeCheck{
		name: "AnUpgradeFoldsTheNameEachClaimIsAbout",
		seed: func(t *testing.T, ctx context.Context, db *database.DB) {
			cat := catalog.NewStore(db.DB)
			product, err := cat.DeclareProduct(ctx, "claimant", "Claimant")
			if err != nil {
				t.Fatal(err)
			}
			stream, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
			if err != nil {
				t.Fatal(err)
			}
			variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
			if err != nil {
				t.Fatal(err)
			}
			made, err := cat.TargetFor(ctx, stream.ID, variant.ID)
			if err != nil {
				t.Fatal(err)
			}
			target = made.ID
			scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
				TargetID: target, ContentHash: "claims", ParserVersion: "test",
				BuiltAt: time.Now().UTC().Add(-time.Hour),
			})
			if err != nil {
				t.Fatal(err)
			}
			for name := range subjects {
				if _, err := db.DB.NewRaw(`INSERT INTO "suppression"
					("target_id", "identity", "vulnerability", "status", "origin",
					 "subject_name", "opened_scan_id") VALUES (?, ?, ?, ?, ?, ?, ?)`,
					target, "claim about "+name, "CVE-2026-0001", "not_affected", "component",
					name, scan.ID).Exec(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.DB.NewRaw(`INSERT INTO "suppression"
				("target_id", "identity", "vulnerability", "status", "origin",
				 "subject_purl", "opened_scan_id") VALUES (?, ?, ?, ?, ?, ?, ?)`,
				target, "claim about a package", "CVE-2026-0001", "not_affected", "document",
				"pkg:deb/debian/zlib", scan.ID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		},
		upgraded: func(t *testing.T, ctx context.Context, db *database.DB) {
			var rows []struct {
				Name    *string `bun:"subject_name"`
				Folded  *string `bun:"subject_folded"`
				Version *string `bun:"subject_version"`
			}
			if err := db.DB.NewRaw(`SELECT "subject_name", "subject_folded", "subject_version"
				FROM "suppression" WHERE "target_id" = ?`,
				target).Scan(ctx, &rows); err != nil {
				t.Fatal(err)
			}
			if len(rows) != 3 {
				t.Fatalf("upgraded, %d claims remain, want 3", len(rows))
			}
			for _, row := range rows {
				// v0.4.0 kept no version beside a claim, so each covers what it
				// covered before.
				if row.Version != nil {
					t.Errorf("upgraded, a claim states the version %q, which v0.4.0 never kept", *row.Version)
				}
				switch {
				case row.Name == nil:
					if row.Folded != nil {
						t.Errorf("upgraded, a claim naming no subject folds to %q", *row.Folded)
					}
				case row.Folded == nil || *row.Folded != subjects[*row.Name]:
					t.Errorf("upgraded, the claim about %q folds to %v, want %q",
						*row.Name, row.Folded, subjects[*row.Name])
				}
			}
		},
	}
}

// keySecret is the secret the key made under name was issued with.
func keySecret(name string) string { return "opk_" + name + "_secret" }

// tokenSecret is the secret the token its owner made under name was minted
// with.
func tokenSecret(owner int64, name string) string {
	return "opt_" + strconv.FormatInt(owner, 10) + "_" + name + "_secret"
}

// digest is how a key's or token's secret is stored.
func digest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// upgradeWithdrawals is how many trail rows say the upgrade withdrew the
// credential the trail calls about.
func upgradeWithdrawals(t *testing.T, ctx context.Context, db *database.DB, about string) int {
	t.Helper()
	var rows int
	if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "admin_change" WHERE "kind" = ? AND "about" = ?`+
		` AND "was" = ?`, "credential", about, "in force").Scan(ctx, &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

// credentialName is what a key or a token is called now.
func credentialName(t *testing.T, ctx context.Context, db *database.DB, table string, id int64) string {
	t.Helper()
	var name string
	if err := db.DB.NewRaw(`SELECT "name" FROM "`+table+`" WHERE "id" = ?`, id).
		Scan(ctx, &name); err != nil {
		t.Fatalf("read %s %d: %v", table, id, err)
	}
	return name
}

// withdrawnAt is when a key or a token was withdrawn, and zero where it is in
// force.
func withdrawnAt(t *testing.T, ctx context.Context, db *database.DB, table string, id int64) time.Time {
	t.Helper()
	var at *time.Time
	if err := db.DB.NewRaw(`SELECT "revoked_at" FROM "`+table+`" WHERE "id" = ?`, id).
		Scan(ctx, &at); err != nil {
		t.Fatalf("read %s %d: %v", table, id, err)
	}
	if at == nil {
		return time.Time{}
	}
	return *at
}
