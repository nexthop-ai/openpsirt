// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// v0130 is the migration v0.13.0 carries v0.12.0's schema across with.
const v0130 = 47

// coversV0120 is a v0.12.0 advisory covering one issue still, and one it was
// taken off.
type coversV0120 struct {
	advisory, product, person, kept, dropped int64
}

// seedCoversV0120 seeds a v0.12.0 advisory with an issue on it and one taken
// off it.
func seedCoversV0120(t *testing.T, db *database.DB) coversV0120 {
	t.Helper()
	ctx := t.Context()
	at := time.Date(2026, 11, 12, 2, 0, 0, 0, time.UTC)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.DB.NewRaw(query, args...).Exec(ctx); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
	}
	id := func(query string) int64 {
		t.Helper()
		var out int64
		if err := db.DB.NewRaw(query).Scan(ctx, &out); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
		return out
	}
	var out coversV0120
	exec(`INSERT INTO "party" ("kind") VALUES (?)`, "person")
	party := id(`SELECT MAX("id") FROM "party"`)
	exec(`INSERT INTO "person" ("party_id", "identity", "is_admin", "is_bootstrap", "admin_derived", "audits",
		"audits_derived", "email_source", "digest", "digest_unassigned", "created_at")
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		party, "writer", false, false, false, false, false, "", false, false, at)
	out.person = id(`SELECT MAX("id") FROM "person"`)
	exec(`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`, "p", "P", at)
	out.product = id(`SELECT MAX("id") FROM "product"`)
	issue := func(name string) int64 {
		exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "kind", "exploited",
			"first_seen_at", "issue_id") VALUES (?, ?, ?, ?, ?, ?)`, name, name, "vulnerability", false, at, 0)
		made := id(`SELECT MAX("id") FROM "vulnerability"`)
		exec(`UPDATE "vulnerability" SET "issue_id" = "id" WHERE "id" = ?`, made)
		return made
	}
	out.kept, out.dropped = issue("cve-2026-1"), issue("cve-2026-2")
	exec(`INSERT INTO "advisory" ("identifier", "identifier_folded", "minted_year", "mint_number",
		"minted_at", "minted_by") VALUES (?, ?, ?, ?, ?, ?)`, "EX-2026-0001", "ex-2026-0001", 2026, 1, at,
		out.person)
	out.advisory = id(`SELECT MAX("id") FROM "advisory"`)
	exec(`INSERT INTO "advisory_issue" ("advisory_id", "product_id", "vulnerability_id", "added_at", "added_by")
		VALUES (?, ?, ?, ?, ?)`, out.advisory, out.product, out.kept, at, out.person)
	exec(`INSERT INTO "advisory_issue" ("advisory_id", "product_id", "vulnerability_id", "added_at", "added_by",
		"removed_at", "removed_by") VALUES (?, ?, ?, ?, ?, ?, ?)`,
		out.advisory, out.product, out.dropped, at, out.person, at.Add(time.Hour), out.person)
	return out
}

// checkLive checks each cover's mark after the upgrade, and that an issue is
// unique among the rows on the advisory alone.
func (c coversV0120) checkLive(t *testing.T, db *database.DB) {
	t.Helper()
	ctx := t.Context()
	live := func(issue int64) *bool {
		t.Helper()
		var out *bool
		if err := db.DB.NewRaw(`SELECT "live" FROM "advisory_issue" WHERE "vulnerability_id" = ?`, issue).
			Scan(ctx, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := live(c.kept); got == nil || !*got {
		t.Errorf("an issue on the advisory is marked %v, want true", got)
	}
	if got := live(c.dropped); got != nil {
		t.Errorf("an issue taken off the advisory is marked %v, want null", *got)
	}
	at := time.Date(2026, 11, 13, 2, 0, 0, 0, time.UTC)
	if _, err := db.DB.NewRaw(`INSERT INTO "advisory_issue" ("advisory_id", "product_id", "vulnerability_id",
		"added_at", "added_by", "live") VALUES (?, ?, ?, ?, ?, ?)`,
		c.advisory, c.product, c.dropped, at, c.person, true).Exec(ctx); err != nil {
		t.Errorf("an issue taken off could not be put back on: %v", err)
	}
	if _, err := db.DB.NewRaw(`INSERT INTO "advisory_issue" ("advisory_id", "product_id", "vulnerability_id",
		"added_at", "added_by", "live") VALUES (?, ?, ?, ?, ?, ?)`,
		c.advisory, c.product, c.kept, at, c.person, true).Exec(ctx); err == nil {
		t.Error("an issue on the advisory was put on it a second time")
	}
}

// A v0.12.0 database's advisory covers are marked by whether each is still on
// the advisory, whether the upgrade ran whole or a start of it stopped after
// the column or after the rule holding it; the second and third are stops
// SQLite never makes, since it changes a table in one transaction.
func TestAV0120DatabaseResumesTheV0130UpgradeFromEveryStop(t *testing.T) {
	for _, stop := range []struct {
		name string
		make func(t *testing.T, db *database.DB) error
	}{
		{"whole", nil},
		{"after the column", func(t *testing.T, db *database.DB) error {
			return migrations.StopV0130AfterLiveColumn(t.Context(), db)
		}},
		{"after the rule", func(t *testing.T, db *database.DB) error {
			return migrations.StopV0130AfterLiveRule(t.Context(), db)
		}},
	} {
		t.Run(stop.name, func(t *testing.T) {
			dbtest.Each(t, func(t *testing.T, db *database.DB) {
				ctx := t.Context()
				if stop.make != nil && db.Server.Engine == database.SQLite {
					t.Skip("SQLite changes a table in one transaction, so it never stops there")
				}
				dbtest.Empty(t, db)
				dbtest.MigrateTo(t, db, v0120)
				covers := seedCoversV0120(t, db)
				if stop.make != nil {
					if err := stop.make(t, db); err != nil {
						t.Fatalf("make what a stopped upgrade left: %v", err)
					}
				}
				dbtest.MigrateTo(t, db, v0130)
				declarationsAreBuilt(t, ctx, db, migrations.StatementsV0130(db.Server.Engine))
				covers.checkLive(t, db)
				leaveAtLatest(t, ctx, db)
			})
		})
	}
}

// A v0.12.0 database's package identifiers lose the credential a qualifier's
// address held, on the component, the node and the image version, and keep
// every qualifier holding none.
func TestTheV0130UpgradeTakesCredentialsOutOfPackageIdentifiers(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0120)
		at := time.Date(2026, 11, 12, 2, 0, 0, 0, time.UTC)
		exec := func(query string, args ...any) {
			t.Helper()
			if _, err := db.DB.NewRaw(query, args...).Exec(ctx); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
		}
		id := func(query string) int64 {
			t.Helper()
			var out int64
			if err := db.DB.NewRaw(query).Scan(ctx, &out); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
			return out
		}
		//nolint:gosec // G101: the credentials this upgrade takes out
		cases := []struct{ stored, want string }{
			{"pkg:golang/example.com/x@v1?vcs_url=git%2Bhttps://oauth2:glpat-SECRET@gitlab.example.com/x.git&arch=amd64",
				"pkg:golang/example.com/x@v1?vcs_url=git%2Bhttps://gitlab.example.com/x.git&arch=amd64"},
			{"pkg:golang/example.com/e@v1?vcs_url=git%2Bhttps%3A%2F%2Foauth2%3Aglpat-SECRET%40gitlab.example.com%2Fe.git",
				"pkg:golang/example.com/e@v1?vcs_url=git%2Bhttps://gitlab.example.com/e.git"},
			{"pkg:generic/fw@1?download_url=https%3A%2F%2Fexample.com%2Ffw.bin%3Fprivate_token%3DSECRET&arch=arm64",
				"pkg:generic/fw@1?download_url=https://example.com/fw.bin&arch=arm64"},
			{"pkg:generic/s3@1?download_url=https://bucket.example.com/s3.bin?X-Amz-Credential=A&X-Amz-Signature=SECRET",
				"pkg:generic/s3@1?download_url=https://bucket.example.com/s3.bin"},
			{"pkg:golang/example.com/p@v1?vcs_url=git%2Bhttps%3A//oauth2:glpat-SECRET@gitlab.example.com/p.git",
				"pkg:golang/example.com/p@v1?vcs_url=git%2Bhttps://gitlab.example.com/p.git"},
			{"pkg:generic/frag@1?download_url=https%3A%2F%2Fexample.com%2Ff.bin%23access_token%3DSECRET",
				"pkg:generic/frag@1?download_url=https://example.com/f.bin"},
			{"pkg:generic/f@1?download_url=https://example.com/f.bin#access_token=SECRET",
				"pkg:generic/f@1?download_url=https://example.com/f.bin"},
			{"pkg:golang/example.com/b@v1?vcs_url=git%2Bhttps%3A%2F%2Foauth2%3Aglpat-SECRET%40gitlab.example.com%2Fx%ZZ&arch=amd64",
				"pkg:golang/example.com/b@v1?arch=amd64"},
			{"pkg:golang/example.com/s@v1?vcs_url=git%2Bhttps://github.com/s.git#sub/dir",
				"pkg:golang/example.com/s@v1?vcs_url=git%2Bhttps://github.com/s.git#sub/dir"},
			{"pkg:generic/q@1?download_url=https://b.example.com/q.bin%3FX-Amz-Credential=A&X-Amz-Signature=SECRET",
				"pkg:generic/q@1?download_url=https://b.example.com/q.bin"},
			{"pkg:golang/example.com/g@v1?vcs_url=git%2Bssh://git@github.com/org/g.git",
				"pkg:golang/example.com/g@v1?vcs_url=git%2Bssh://git@github.com/org/g.git"},
			{"pkg:golang/example.com/t@v1?vcs_url=git%2Bhttps://glpat-SECRET@gitlab.example.com/t.git",
				"pkg:golang/example.com/t@v1?vcs_url=git%2Bhttps://gitlab.example.com/t.git"},
			{"pkg:maven/org/x@1?repository_url=deploy:SECRET@repo.example.com/maven&type=jar",
				"pkg:maven/org/x@1?repository_url=repo.example.com/maven&type=jar"},
			{"pkg:maven/org/z@1?repository_url=deploy%3ASECRET%40repo.example.com%2Fmaven",
				"pkg:maven/org/z@1?repository_url=repo.example.com/maven"},
			{"pkg:golang/example.com/p@v1?vcs_url=git@github.com:org/p.git",
				"pkg:golang/example.com/p@v1?vcs_url=git@github.com:org/p.git"},
			{"pkg:generic/c@1?checksum=sha256:abc123", "pkg:generic/c@1?checksum=sha256:abc123"},
			{"pkg:maven/org/hp@1?repository_url=deploy:pa%23SECRET@repo.example.com/maven&type=jar",
				"pkg:maven/org/hp@1?repository_url=repo.example.com/maven&type=jar"},
			{"pkg:maven/org/qp@1?repository_url=deploy:pa%3FSECRET@repo.example.com/maven&type=jar",
				"pkg:maven/org/qp@1?repository_url=repo.example.com/maven&type=jar"},
			{"pkg:golang/example.com/ls@v1?repository_url=user:SECRET@github.com/o/https://r",
				"pkg:golang/example.com/ls@v1?repository_url=github.com/o/https://r"},
			{"pkg:golang/example.com/pr@v1?vcs_url=//user:SECRET@host.example.com/x",
				"pkg:golang/example.com/pr@v1?vcs_url=//host.example.com/x"},
			{"pkg:generic/ux@1?download_url=https://h.example.com/a%zz?x=1&token=SECRET&arch=amd64",
				"pkg:generic/ux@1"},
			{"pkg:golang/example.com/sl@v1?repository_url=deploy:ab%2FSECRET@gitlab.example.com:grp/x.git&arch=amd64",
				"pkg:golang/example.com/sl@v1?arch=amd64"},
			{"pkg:golang/example.com/fr@v1?repository_url=gitlab.example.com/x.git#private_token=SECRET",
				"pkg:golang/example.com/fr@v1?repository_url=gitlab.example.com/x.git"},
			{"pkg:generic/bp@1?download_url=https://b.example.com:abc/s3.bin?X-Amz-Credential=A&X-Amz-Signature=SECRET",
				"pkg:generic/bp@1"},
			{"pkg:maven/org/rq@1?repository_url=repo.example.com/maven?private_token=SECRET&type=jar",
				"pkg:maven/org/rq@1?repository_url=repo.example.com/maven"},
			{"pkg:maven/org/re@1?repository_url=repo.example.com/maven%3Fprivate_token%3DSECRET&type=jar",
				"pkg:maven/org/re@1?repository_url=repo.example.com/maven&type=jar"},
			{"pkg:generic/h@1?download_url=https://h.example.com/a=b/f.tgz%3Ftoken%3Dx&upstream=openssl%403.0",
				"pkg:generic/h@1?download_url=https://h.example.com/a%3Db/f.tgz&upstream=openssl%403.0"},
			{"pkg://deb/debian/curl@8.5.0", "pkg:deb/debian/curl@8.5.0"},
			{"PKG://deb/debian/wget@1.21", "PKG:deb/debian/wget@1.21"},
			{"pkg:npm/%40scope/y@2?vcs_url=git%2Bhttps://github.com/scope/y.git",
				"pkg:npm/%40scope/y@2?vcs_url=git%2Bhttps://github.com/scope/y.git"},
		}
		exec(`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`, "p", "P", at)
		product := id(`SELECT MAX("id") FROM "product"`)
		exec(`INSERT INTO "branch_or_tag" ("product_id", "name", "display_name", "kind", "created_at")
			VALUES (?, ?, ?, ?, ?)`, product, "main", "main", "branch", at)
		line := id(`SELECT MAX("id") FROM "branch_or_tag"`)
		exec(`INSERT INTO "variant" ("product_id", "name", "display_name", "customer_facing", "created_at")
			VALUES (?, ?, ?, ?, ?)`, product, "image", "Image", true, at)
		variant := id(`SELECT MAX("id") FROM "variant"`)
		exec(`INSERT INTO "build" ("branch_or_tag_id", "variant_id", "created_at") VALUES (?, ?, ?)`,
			line, variant, at)
		build := id(`SELECT MAX("id") FROM "build"`)
		exec(`INSERT INTO "scan" ("build_id", "content_hash", "built_at", "received_at", "parser_version",
			"status", "components") VALUES (?, ?, ?, ?, ?, ?, ?)`, build, "hash", at, at, "test", "accepted", 2)
		scan := id(`SELECT MAX("id") FROM "scan"`)
		for i, c := range cases {
			purl, key := c.stored, fmt.Sprintf("identity-%d", i)
			exec(`INSERT INTO "component" ("identity", "purl", "name", "version", "name_folded", "fold_key",
				"first_seen_at") VALUES (?, ?, ?, ?, ?, ?, ?)`, key, purl, "x", "1", "x", key, at)
			component := id(`SELECT MAX("id") FROM "component"`)
			exec(`INSERT INTO "graph_node" ("build_id", "component_id", "is_root", "opened_scan_id", "purl")
				VALUES (?, ?, ?, ?, ?)`, build, component, false, scan, purl)
			node := id(`SELECT MAX("id") FROM "graph_node"`)
			exec(`INSERT INTO "image_version" ("node_id", "version", "purl", "opened_scan_id")
				VALUES (?, ?, ?, ?)`, node, "1", purl, scan)
			exec(`INSERT INTO "scan" ("build_id", "content_hash", "built_at", "received_at", "parser_version",
				"status", "components", "root_identifier") VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				build, key, at, at, "test", "accepted", 1, purl)
		}

		dbtest.MigrateTo(t, db, v0130)

		for _, at := range [][2]string{
			{"component", "purl"}, {"graph_node", "purl"}, {"image_version", "purl"}, {"scan", "root_identifier"},
		} {
			table := at[0]
			var got []string
			if err := db.DB.NewRaw(`SELECT "`+at[1]+`" FROM "`+table+`" WHERE "`+at[1]+
				`" IS NOT NULL ORDER BY "id"`).Scan(ctx, &got); err != nil {
				t.Fatal(err)
			}
			if len(got) != len(cases) {
				t.Fatalf("%s holds %d identifiers after the upgrade, want %d", table, len(got), len(cases))
			}
			for i, c := range cases {
				if got[i] != c.want {
					t.Errorf("%s holds %q after the upgrade for %q, want %q", table, got[i], c.stored, c.want)
				}
			}
		}
		leaveAtLatest(t, ctx, db)
	})
}

// A document served to anybody states each identifier as the upgrade leaves
// it, and an identifier a cleaned one begins is left as it was.
func TestTheV0130UpgradeTakesCredentialsOutOfPublishedDocuments(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0120)
		at := time.Date(2026, 11, 12, 2, 0, 0, 0, time.UTC)
		exec := func(query string, args ...any) {
			t.Helper()
			if _, err := db.DB.NewRaw(query, args...).Exec(ctx); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
		}
		//nolint:gosec // G101: the credential this upgrade takes out
		const (
			raw     = "pkg:golang/example.com/x@v1?vcs_url=git%2Bhttps://oauth2:glpat-SECRET@gitlab.example.com/x.git&arch=amd64"
			clean   = "pkg:golang/example.com/x@v1?vcs_url=git%2Bhttps://gitlab.example.com/x.git&arch=amd64"
			slashed = "pkg://deb/debian/curl@8.5.0"
			longer  = "pkg://deb/debian/curl@8.5.0-1"
		)
		exec(`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`, "p", "P", at)
		var product int64
		if err := db.DB.NewRaw(`SELECT MAX("id") FROM "product"`).Scan(ctx, &product); err != nil {
			t.Fatal(err)
		}
		for i, purl := range []string{raw, slashed} {
			exec(`INSERT INTO "component" ("identity", "purl", "name", "version", "name_folded", "fold_key",
				"first_seen_at") VALUES (?, ?, ?, ?, ?, ?, ?)`,
				fmt.Sprintf("identity-%d", i), purl, "x", "1", "x", fmt.Sprintf("fold-%d", i), at)
		}
		body := func(root, other string) string {
			encoded, err := json.Marshal(map[string]any{
				"product": map[string]string{"@id": root},
				"helpers": []string{other, longer},
			})
			if err != nil {
				t.Fatal(err)
			}
			return string(encoded)
		}
		// More than one read's worth, so a document past the first is reached.
		documents := migrations.PublishedBatchV0130 + 1
		for i := range documents {
			subject := fmt.Sprintf("CVE-2026-%d", i)
			exec(`INSERT INTO "published_document" ("product_id", "kind", "subject", "path", "path_digest",
				"tracking_id", "title", "version", "first_at", "current_at", "statuses", "settled", "document")
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				product, "csaf-vex", subject, "p/"+subject+".json", "digest-"+subject, "tracking", "title", 1,
				at, at, "affected", "settled", body(raw, slashed))
		}

		dbtest.MigrateTo(t, db, v0130)

		var got []string
		if err := db.DB.NewRaw(`SELECT "document" FROM "published_document" ORDER BY "id"`).
			Scan(ctx, &got); err != nil {
			t.Fatal(err)
		}
		if len(got) != documents {
			t.Fatalf("%d documents are published after the upgrade, want %d", len(got), documents)
		}
		want := body(clean, "pkg:deb/debian/curl@8.5.0")
		for i, document := range got {
			if document != want {
				t.Errorf("published document %d holds\n%s\nafter the upgrade, want\n%s", i, document, want)
			}
		}
		leaveAtLatest(t, ctx, db)
	})
}

// A remote a node holds, written without a scheme, loses a password before its
// host and its query, and one whose credential cannot be told apart is no
// remote.
func TestTheV0130UpgradeTakesCredentialsOutOfRemotes(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0120)
		at := time.Date(2026, 11, 12, 2, 0, 0, 0, time.UTC)
		exec := func(query string, args ...any) {
			t.Helper()
			if _, err := db.DB.NewRaw(query, args...).Exec(ctx); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
		}
		id := func(query string) int64 {
			t.Helper()
			var out int64
			if err := db.DB.NewRaw(query).Scan(ctx, &out); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
			return out
		}
		//nolint:gosec // G101: the credentials this upgrade takes out
		cases := []struct {
			stored string
			want   *string
		}{
			{"oauth2:SECRET@gitlab.example.com:g/p.git", ptr("gitlab.example.com:g/p.git")},
			{"gitlab.example.com/g/p.git?private_token=SECRET", ptr("gitlab.example.com/g/p.git")},
			{"deploy:ab/SECRET@gitlab.example.com:g/p.git", nil},
			{"git@github.com:a/b.git", ptr("git@github.com:a/b.git")},
			{"deploy:pa#SECRET@git.example.com:org/x.git", ptr("git.example.com:org/x.git")},
			{"user:SECRET@gitlab.example.com/o/https://r", ptr("gitlab.example.com/o/https://r")},
			{"//user:SECRET@gitlab.example.com/g/p.git", ptr("//gitlab.example.com/g/p.git")},
			{"https://github.com/a/b.git", ptr("https://github.com/a/b.git")},
		}
		exec(`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`, "p", "P", at)
		product := id(`SELECT MAX("id") FROM "product"`)
		exec(`INSERT INTO "branch_or_tag" ("product_id", "name", "display_name", "kind", "created_at")
			VALUES (?, ?, ?, ?, ?)`, product, "main", "main", "branch", at)
		line := id(`SELECT MAX("id") FROM "branch_or_tag"`)
		exec(`INSERT INTO "variant" ("product_id", "name", "display_name", "customer_facing", "created_at")
			VALUES (?, ?, ?, ?, ?)`, product, "image", "Image", true, at)
		variant := id(`SELECT MAX("id") FROM "variant"`)
		exec(`INSERT INTO "build" ("branch_or_tag_id", "variant_id", "created_at") VALUES (?, ?, ?)`,
			line, variant, at)
		build := id(`SELECT MAX("id") FROM "build"`)
		exec(`INSERT INTO "scan" ("build_id", "content_hash", "built_at", "received_at", "parser_version",
			"status", "components") VALUES (?, ?, ?, ?, ?, ?, ?)`, build, "hash", at, at, "test", "accepted", 1)
		scan := id(`SELECT MAX("id") FROM "scan"`)
		for i, c := range cases {
			key := fmt.Sprintf("identity-%d", i)
			exec(`INSERT INTO "component" ("identity", "name", "version", "name_folded", "fold_key",
				"first_seen_at") VALUES (?, ?, ?, ?, ?, ?)`, key, "x", "1", "x", key, at)
			component := id(`SELECT MAX("id") FROM "component"`)
			exec(`INSERT INTO "graph_node" ("build_id", "component_id", "is_root", "opened_scan_id", "repository")
				VALUES (?, ?, ?, ?, ?)`, build, component, false, scan, c.stored)
		}

		dbtest.MigrateTo(t, db, v0130)

		// No remote reads as a word no remote is, since a scan of a null into
		// a string reads as empty.
		var got []string
		if err := db.DB.NewRaw(`SELECT COALESCE("repository", '(none)') FROM "graph_node" ORDER BY "id"`).
			Scan(ctx, &got); err != nil {
			t.Fatal(err)
		}
		if len(got) != len(cases) {
			t.Fatalf("the build holds %d nodes after the upgrade, want %d", len(got), len(cases))
		}
		for i, c := range cases {
			want := "(none)"
			if c.want != nil {
				want = *c.want
			}
			if got[i] != want {
				t.Errorf("%q is held as %q after the upgrade, want %q", c.stored, got[i], want)
			}
		}
		leaveAtLatest(t, ctx, db)
	})
}

func ptr(s string) *string { return &s }
