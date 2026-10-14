// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// A v0.8.0 database holding a build's claims, a supplier's statements and an
// issue's references is upgraded: each piece of reasoning is stored once and
// every row giving it points at that copy, every build claim is keyed on its
// reasoning so the next scan restating it writes nothing, and every reference
// is keyed on its address as given, so two addresses v0.8.0 took for one stay
// two from the next report on.
func TestAV080DatabaseStoresEachClaimsReasoningOnce(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v080)

		declared, err := world.Declare(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		who, err := access.NewStore(db.DB).Ensure(ctx, "claims-uploader", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		at := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
		rec, outcome, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
			TargetID: declared.Target.ID, ContentHash: "claims-night", BuiltAt: at, ParserVersion: "test",
		})
		if err != nil || outcome != ingest.Accept {
			t.Fatalf("record a scan: %v %v", outcome, err)
		}
		exec := func(query string, args ...any) {
			t.Helper()
			if _, err := db.DB.NewRaw(query, args...).Exec(ctx); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
		}

		const reasoning = "the vulnerable code is not compiled in"
		long := "CVE-2026-1" + strings.Repeat("9", 300)
		claims := []sbom.Suppression{{
			Vulnerability: "CVE-2026-1", Status: sbom.NotAffected,
			Justification: "vulnerable_code_not_present", Statement: reasoning,
			Targets: []sbom.Target{{Name: "libnl"}, {Name: "libnl-route"}},
			Origin:  sbom.FromStatement,
		}, {
			Vulnerability: "CVE-2026-2", Status: sbom.Affected,
			Targets: []sbom.Target{{Name: "libnl"}}, Origin: sbom.FromStatement,
		}, {
			Vulnerability: long, Status: sbom.NotAffected, Statement: "another explanation",
			Targets: []sbom.Target{{Name: "libnl"}}, Origin: sbom.FromStatement,
		}}
		// As v0.8.0 wrote them: a copy of the reasoning on every row, and a
		// key worked out without it.
		for i, claim := range claims {
			for _, subject := range claim.Targets {
				var justification, statement any
				if claim.Justification != "" {
					justification = claim.Justification
				}
				if claim.Statement != "" {
					statement = claim.Statement
				}
				exec(`INSERT INTO "suppression" ("target_id", "identity", "vulnerability", "status",
					"justification", "statement", "origin", "subject_purl", "subject_name", "subject_folded",
					"opened_scan_id") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					declared.Target.ID, "v080-key-"+string(rune('a'+i))+subject.Name, claim.Vulnerability,
					string(claim.Status), justification, statement, string(claim.Origin), "", subject.Name,
					graph.Folded(subject.Name), rec.ID)
			}
		}
		for _, component := range []string{"zlib", "openssl"} {
			exec(`INSERT INTO "vex_statement" ("product_id", "publisher", "source", "document_id",
				"vulnerability", "component", "about", "status", "statement", "document", "digest",
				"uploaded_by", "uploaded_at") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				declared.Product.ID, "acme", "vex", "", "cve-2026-1", component, "", "not_affected",
				reasoning, "acme.json", "digest", who.ID, at)
		}
		exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "exploited", "first_seen_at", "issue_id")
			VALUES (?, ?, ?, ?, ?)`, "CVE-2026-1", "cve-2026-1", false, at, 0)
		var issue int64
		if err := db.DB.NewRaw(`SELECT "id" FROM "vulnerability" WHERE "identifier" = ?`, "CVE-2026-1").
			Scan(ctx, &issue); err != nil {
			t.Fatal(err)
		}
		exec(`UPDATE "vulnerability" SET "issue_id" = "id"`)
		addresses := []string{"https://lore.kernel.org/r/AbCd@example", "https://example.org/fix"}
		for i, address := range addresses {
			exec(`INSERT INTO "vulnerability_reference" ("vulnerability_id", "url", "kind", "url_identity")
				VALUES (?, ?, ?, ?)`, issue, address, "report", "v080-reference-"+string(rune('a'+i)))
		}

		dbtest.MigrateTo(t, db, v090)

		var held []struct {
			ID    int64  `bun:"id"`
			Words string `bun:"words"`
		}
		if err := db.DB.NewRaw(`SELECT "id", "words" FROM "statement_text" ORDER BY "id"`).Scan(ctx, &held); err != nil {
			t.Fatal(err)
		}
		copies := map[string]int64{}
		for _, row := range held {
			copies[row.Words] = row.ID
		}
		if len(held) != 2 || copies[reasoning] == 0 || copies["another explanation"] == 0 {
			t.Fatalf("the reasoning is stored as %+v, want each explanation once", held)
		}
		var pointing []struct {
			Table string `bun:"tbl"`
			Words *int64 `bun:"statement_id"`
		}
		if err := db.DB.NewRaw(`SELECT 'suppression' AS "tbl", "statement_id" FROM "suppression"
			WHERE "vulnerability" = 'CVE-2026-1'
			UNION ALL SELECT 'vex_statement', "statement_id" FROM "vex_statement"`).Scan(ctx, &pointing); err != nil {
			t.Fatal(err)
		}
		if len(pointing) != 4 {
			t.Fatalf("%d rows giving the shared reasoning were read, want 4", len(pointing))
		}
		for _, row := range pointing {
			if row.Words == nil || *row.Words != copies[reasoning] {
				t.Errorf("a %s row does not point at the stored reasoning", row.Table)
			}
		}

		// The next scan restating every claim finds each one held.
		applied, err := finding.NewStore(db.DB).RecordClaims(ctx, declared.Target.ID, rec.ID, claims,
			map[sbom.Origin]bool{sbom.FromStatement: true, sbom.FromPedigree: true})
		if err != nil {
			t.Fatal(err)
		}
		if !applied.Unchanged() {
			t.Errorf("the first scan after the upgrade wrote %+v, want every claim held", applied)
		}

		var keys []struct {
			URL      string `bun:"url"`
			Identity string `bun:"url_identity"`
		}
		if err := db.DB.NewRaw(`SELECT "url", "url_identity" FROM "vulnerability_reference"`).Scan(ctx, &keys); err != nil {
			t.Fatal(err)
		}
		for _, key := range keys {
			sum := sha256.Sum256([]byte(key.URL))
			if key.Identity != hex.EncodeToString(sum[:]) {
				t.Errorf("%s is keyed %s, want its address as given", key.URL, key.Identity)
			}
		}
		if len(keys) != len(addresses) {
			t.Errorf("%d references remain, want %d", len(keys), len(addresses))
		}

		t.Run("TheDeclarationsAreTheTablesTheMigrationsBuild", func(t *testing.T) {
			declarationsAreBuilt(t, ctx, db, migrations.StatementsV090(db.Server.Engine))
		})
		leaveAtLatest(t, ctx, db)
	})
}
