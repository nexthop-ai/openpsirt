// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/csaf"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
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
// the column or after the rule holding it.
func coversPartV0130() partV0130 {
	return partV0130{
		name: "AnAdvisoryCoverIsMarkedByWhetherItIsStillOn",
		seed: func(t *testing.T, db *database.DB) func(t *testing.T) {
			covers := seedCoversV0120(t, db)
			return func(t *testing.T) { covers.checkLive(t, db) }
		},
		stops: []stopV0130{
			{"after the column", func(t *testing.T, db *database.DB) error {
				return migrations.StopV0130AfterLiveColumn(t.Context(), db)
			}},
			{"after the rule", func(t *testing.T, db *database.DB) error {
				return migrations.StopV0130AfterLiveRule(t.Context(), db)
			}},
		},
	}
}

// A v0.12.0 database's package identifiers lose the credential a qualifier's
// address held, on the component, the node and the image version, and keep
// every qualifier holding none.
func packageIdentifiersPartV0130() partV0130 {
	return partV0130{name: "TheV0130UpgradeTakesCredentialsOutOfPackageIdentifiers", seed: func(t *testing.T, db *database.DB) func(t *testing.T) {
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
				"pkg:golang/example.com/b@v1"},
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
			{"pkg:generic/bu@1?arch=amd64&vcs_url=https://to&SECRET@host.example.com/x", "pkg:generic/bu@1?arch=amd64"},
			{"pkg:generic/am@1?vcs_url=https://u:SEC&RET@host.example.com/x", "pkg:generic/am@1"},
			{"pkg:generic/ae@1?vcs_url=https://u:SEC&x=RET@host.example.com/x", "pkg:generic/ae@1"},
			{"pkg:generic/ah@1?vcs_url=https://u:SEC#a&RET@host.example.com/x", "pkg:generic/ah@1"},
			{"pkg:maven/org/rh@1?repository_url=user:pa#SECRET@repo.example.com/maven",
				"pkg:maven/org/rh@1?repository_url=repo.example.com/maven"},
			{"pkg:golang/example.com/vh@v1?vcs_url=git%2Bhttps://user:pa#SECRET@github.com/x",
				"pkg:golang/example.com/vh@v1"},
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
				"pkg:golang/example.com/sl@v1"},
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
			{"pkg:generic/pk@1?download_url=https://h.example.com/a&b/c%3Ftoken=SECRET",
				"pkg:generic/pk@1"},
			{"pkg:generic/de@1?download_url=https%253A%252F%252Fuser%253ASECRET%2540h.example.com%252Ff.bin",
				"pkg:generic/de@1?download_url=https://h.example.com/f.bin"},
			{"pkg:generic/sx@1?download_url=https://h.example.com/a%zz#SECRETTOKEN", "pkg:generic/sx@1"},
			{"pkg:generic/sf@1?download_url=https://h.example.com/f.bin#access_token%3DSECRET",
				"pkg:generic/sf@1?download_url=https://h.example.com/f.bin"},
			{"pkg:maven/org/nc@1?repository_url=repo.example.com/maven%23SECRET&type=jar",
				"pkg:maven/org/nc@1?repository_url=repo.example.com/maven&type=jar"},
			{"pkg:golang/example.com/tu@v1?vcs_url=//glpat-SECRET@host.example.com/x",
				"pkg:golang/example.com/tu@v1?vcs_url=//host.example.com/x"},
			{"pkg:maven/org/ru@1?repository_url=to&ken@repo.example.com/maven", "pkg:maven/org/ru@1"},
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
		return func(t *testing.T) {
			ctx := t.Context()
			// The rows of this part's build, each found through the build.
			for _, at := range [][3]string{
				{"component", "purl", `"id" IN (SELECT "component_id" FROM "graph_node" WHERE "build_id" = ?)`},
				{"graph_node", "purl", `"build_id" = ?`},
				{"image_version", "purl", `"node_id" IN (SELECT "id" FROM "graph_node" WHERE "build_id" = ?)`},
				{"scan", "root_identifier", `"build_id" = ?`},
			} {
				table := at[0]
				var got []string
				if err := db.DB.NewRaw(`SELECT "`+at[1]+`" FROM "`+table+`" WHERE "`+at[1]+
					`" IS NOT NULL AND `+at[2]+` ORDER BY "id"`, build).Scan(ctx, &got); err != nil {
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
		}
	}}
}

// A document served to anybody states each identifier as the upgrade leaves
// it, and an identifier a cleaned one begins is left as it was.
func publishedDocumentsPartV0130() partV0130 {
	return partV0130{name: "TheV0130UpgradeTakesCredentialsOutOfPublishedDocuments", seed: func(t *testing.T, db *database.DB) func(t *testing.T) {
		ctx := t.Context()
		at := time.Date(2026, 11, 12, 2, 0, 0, 0, time.UTC)
		exec := func(query string, args ...any) {
			t.Helper()
			if _, err := db.DB.NewRaw(query, args...).Exec(ctx); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
		}
		//nolint:gosec // G101: the credential this upgrade takes out
		const (
			raw     = "pkg:golang/example.com/served@v1?vcs_url=git%2Bhttps://oauth2:glpat-SECRET@gitlab.example.com/served.git&arch=amd64"
			clean   = "pkg:golang/example.com/served@v1?vcs_url=git%2Bhttps://gitlab.example.com/served.git&arch=amd64"
			slashed = "pkg://deb/debian/served@8.5.0"
			longer  = "pkg://deb/debian/served@8.5.0-1"
		)
		// Identifiers no other part seeds: the credential step cleans every
		// document from one set built from every table's identifiers, so a
		// shared one is cleaned through another part's rows.
		seeded := seedCoversV0120(t, db)
		product := seeded.product
		for i, purl := range []string{raw, slashed} {
			exec(`INSERT INTO "component" ("identity", "purl", "name", "version", "name_folded", "fold_key",
				"first_seen_at") VALUES (?, ?, ?, ?, ?, ?, ?)`,
				fmt.Sprintf("identity-%d", i), purl, "x", "1", "x", fmt.Sprintf("fold-%d", i), at)
		}
		// A CSAF product tree names a component by its identifier, and a
		// relationship by the component's identifier joined to what holds it,
		// both as an identifier and as a name.
		body := func(root, other string) string {
			encoded, err := json.Marshal(map[string]any{
				"product": map[string]string{"@id": root},
				"helpers": []string{other, longer},
				"relationship": map[string]string{
					"product_id": root + "|" + other,
					"name":       root + " as part of " + other,
				},
				"known_affected": []string{root + "|build-1", longer + "|" + other},
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
		// An advisory that went out names a build by its root as the
		// product's identification helper, and is served to anybody too.
		exec(`INSERT INTO "advisory_edition" ("advisory_id", "ordinal", "written_by", "written_at")
			VALUES (?, ?, ?, ?)`, seeded.advisory, 1, seeded.person, at)
		var edition int64
		if err := db.DB.NewRaw(`SELECT MAX("id") FROM "advisory_edition"`).Scan(ctx, &edition); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO "advisory_issuance" ("advisory_id", "ordinal", "edition_id", "document", "digest",
			"issued_by", "issued_at") VALUES (?, ?, ?, ?, ?, ?, ?)`,
			seeded.advisory, 1, edition, body(raw, slashed), "digest", seeded.person, at)
		return func(t *testing.T) {
			ctx := t.Context()

			want := body(clean, "pkg:deb/debian/served@8.5.0")
			for _, table := range []string{"published_document", "advisory_issuance"} {
				var got []string
				owner := map[string]string{"published_document": `"product_id"`, "advisory_issuance": `"advisory_id"`}[table]
				of := map[string]int64{"published_document": product, "advisory_issuance": seeded.advisory}[table]
				if err := db.DB.NewRaw(`SELECT "document" FROM "`+table+`" WHERE `+owner+` = ? ORDER BY "id"`, of).
					Scan(ctx, &got); err != nil {
					t.Fatal(err)
				}
				if want := map[string]int{"published_document": documents, "advisory_issuance": 1}[table]; len(got) != want {
					t.Fatalf("%s holds %d documents after the upgrade, want %d", table, len(got), want)
				}
				for i, document := range got {
					if document != want {
						t.Errorf("%s %d holds\n%s\nafter the upgrade, want\n%s", table, i, document, want)
					}
				}
			}
		}
	}}
}

// An issued advisory the upgrade rewrites takes its settled digest from what
// it says now, so it reads as unchanged since it went out.
func TestAnAdvisoryTheV0130UpgradeRewritesReadsAsUnchanged(t *testing.T) {
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
			raw   = "pkg:golang/example.com/x@v1?vcs_url=git%2Bhttps://oauth2:glpat-SECRET@gitlab.example.com/x.git"
			clean = "pkg:golang/example.com/x@v1?vcs_url=git%2Bhttps://gitlab.example.com/x.git"
		)
		seeded := seedCoversV0120(t, db)
		exec(`INSERT INTO "component" ("identity", "purl", "name", "version", "name_folded", "fold_key",
			"first_seen_at") VALUES (?, ?, ?, ?, ?, ?, ?)`, "identity", raw, "x", "1", "x", "fold", at)
		// An advisory as it went out: its tracking dated and versioned, and
		// its product tree naming the build by its root.
		body := func(purl string) string {
			encoded, err := json.Marshal(map[string]any{
				"document": map[string]any{
					"title": "A flaw",
					"tracking": map[string]any{
						"id": "OPSIRT-1", "status": "final", "version": "2",
						"current_release_date": "2026-11-12T02:00:00Z",
						"revision_history":     []any{map[string]any{"number": "2"}},
					},
					"references": []any{map[string]any{"category": "self", "url": "https://x/1.json"}},
				},
				"product_tree": map[string]any{"full_product_names": []any{
					map[string]any{"product_identification_helper": map[string]any{"purl": purl}}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			return string(encoded)
		}
		issued, err := csaf.SettledDigest([]byte(body(raw)))
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO "advisory_edition" ("advisory_id", "ordinal", "written_by", "written_at")
			VALUES (?, ?, ?, ?)`, seeded.advisory, 1, seeded.person, at)
		var edition int64
		if err := db.DB.NewRaw(`SELECT MAX("id") FROM "advisory_edition"`).Scan(ctx, &edition); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO "advisory_issuance" ("advisory_id", "ordinal", "edition_id", "document", "digest",
			"issued_by", "issued_at") VALUES (?, ?, ?, ?, ?, ?, ?)`,
			seeded.advisory, 1, edition, body(raw), issued, seeded.person, at)

		dbtest.MigrateTo(t, db, v0130)

		var got struct {
			Document string `bun:"document"`
			Digest   string `bun:"digest"`
		}
		if err := db.DB.NewRaw(`SELECT "document", "digest" FROM "advisory_issuance"`).Scan(ctx, &got); err != nil {
			t.Fatal(err)
		}
		now, err := csaf.SettledDigest([]byte(body(clean)))
		if err != nil {
			t.Fatal(err)
		}
		if got.Document != body(clean) || got.Digest != now {
			t.Errorf("the advisory holds %s with the digest %s after the upgrade, want %s with %s",
				got.Document, got.Digest, body(clean), now)
		}
		leaveAtLatest(t, ctx, db)
	})
}

// A start of the credential step that stopped after any of its phases leaves
// the next start nothing served still holding the credential: the documents
// are rewritten before the identifiers they are matched against are.
func stoppedCredentialPartV0130() partV0130 {
	part := partV0130{
		name: "AStoppedCredentialStepLeavesNoDocumentHoldingACredential",
		seed: func(t *testing.T, db *database.DB) func(t *testing.T) {
			ctx := t.Context()
			at := time.Date(2026, 11, 12, 2, 0, 0, 0, time.UTC)
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := db.DB.NewRaw(query, args...).Exec(ctx); err != nil {
					t.Fatalf("%v\n%s", err, query)
				}
			}
			//nolint:gosec // G101: the credential this upgrade takes out
			const (
				raw   = "pkg:generic/x@1?download_url=https://user:SECRET@example.com/x.bin"
				clean = "pkg:generic/x@1?download_url=https://example.com/x.bin"
			)
			product := seedCoversV0120(t, db).product
			exec(`INSERT INTO "component" ("identity", "purl", "name", "version", "name_folded", "fold_key",
				"first_seen_at") VALUES (?, ?, ?, ?, ?, ?, ?)`, "identity", raw, "x", "1", "x", "fold", at)
			var component int64
			if err := db.DB.NewRaw(`SELECT MAX("id") FROM "component"`).Scan(ctx, &component); err != nil {
				t.Fatal(err)
			}
			body := func(purl string) string {
				encoded, err := json.Marshal(map[string]string{"@id": purl})
				if err != nil {
					t.Fatal(err)
				}
				return string(encoded)
			}
			exec(`INSERT INTO "published_document" ("product_id", "kind", "subject", "path", "path_digest",
				"tracking_id", "title", "version", "first_at", "current_at", "statuses", "settled", "document")
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				product, "csaf-vex", "CVE-2026-1", "p/CVE-2026-1.json", "digest", "tracking", "title", 1,
				at, at, "affected", "settled", body(raw))
			return func(t *testing.T) {
				ctx := t.Context()
				var document, purl string
				if err := db.DB.NewRaw(`SELECT "document" FROM "published_document" WHERE "product_id" = ?`, product).
					Scan(ctx, &document); err != nil {
					t.Fatal(err)
				}
				if document != body(clean) {
					t.Errorf("the published document holds %s after the upgrade, want %s", document, body(clean))
				}
				if err := db.DB.NewRaw(`SELECT "purl" FROM "component" WHERE "id" = ?`, component).
					Scan(ctx, &purl); err != nil {
					t.Fatal(err)
				}
				if purl != clean {
					t.Errorf("the component holds %s after the upgrade, want %s", purl, clean)
				}
			}
		},
	}
	for phases := 1; phases < migrations.PurlPhasesV0130; phases++ {
		part.stops = append(part.stops, stopV0130{fmt.Sprintf("after credential phase %d", phases),
			func(t *testing.T, db *database.DB) error {
				return migrations.StopV0130AfterPurlPhase(t.Context(), db, phases)
			}})
	}
	return part
}

// A remote a node holds, written without a scheme, loses a password before its
// host and its query, and one whose credential cannot be told apart is no
// remote.
func remotesPartV0130() partV0130 {
	return partV0130{name: "TheV0130UpgradeTakesCredentialsOutOfRemotes", seed: func(t *testing.T, db *database.DB) func(t *testing.T) {
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
			{"https://github.com/a/b.git#access_token=SECRET", ptr("https://github.com/a/b.git")},
			{"gitlab.example.com/g/p.git#private_token=SECRET", ptr("gitlab.example.com/g/p.git")},
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
		return func(t *testing.T) {
			ctx := t.Context()

			// No remote reads as a word no remote is, since a scan of a null into
			// a string reads as empty.
			var got []string
			if err := db.DB.NewRaw(`SELECT COALESCE("repository", '(none)') FROM "graph_node" WHERE "build_id" = ?
				ORDER BY "id"`, build).
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
		}
	}}
}

func ptr(s string) *string { return &s }
