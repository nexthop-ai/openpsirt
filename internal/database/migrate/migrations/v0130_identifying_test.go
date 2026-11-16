// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// kernelV0120 is a Debian kernel image named after its version, as SONiC's
// inventory describes it.
func kernelV0120(version string) (name, at, purl string) {
	name = "linux-image-" + version + "+deb13-sonic-amd64-unsigned"
	return name, version + "-1",
		"pkg:deb/debian/" + strings.ReplaceAll(name, "+", "%2B") + "@" + version + "-1?arch=amd64&distro=debian-13"
}

func TestTheV0130UpgradeIdentifiesANameByItsReleaseAsTheApplicationDoes(t *testing.T) {
	// The upgrade carries its own copy of the rule, so a later change to the
	// application's leaves what the upgrade wrote as it was. Held to the
	// application's here, over every shape the rule reads.
	names := []string{"linux-image-6.12.41+deb13-amd64", "libssl3", "python3.11", "openjdk-17-jre",
		"foo-1.0-bar-1.0", "x1.0-1.0", "6.12.41", "6.12.41-kbuild", "torch-2.1.0", "py3-foo-1.2",
		"kernel-5.14.0", "foo-UNKNOWN", "2.0", "lib-1.2rc", " padded-1.0 ", "ünï-1.0-ç", "lib_15.2.0.0.0.0.16.2.deb", "openssl-1.1.1", "a.1.0", "1.0.b", "a1.1.0"}
	versions := []string{"6.12.41-1", "3.5.1-1", "3.11.2-6+deb12u6", "17.0.12+7-2~deb12u1", "1.0-1", "1.0",
		"2.1.0+cu121", "1.2-r3", "2:5.14.0-427.el9", "UNKNOWN", "2.0", "1.2-1", "x:1.0-1", "", "1:1.0", "0.0.0", "1.1"}
	purls := []string{"", "pkg:deb/debian/x@1", "pkg:rpm/redhat/x@1", "pkg:apk/alpine/x@1", "pkg:pypi/x@1",
		"pkg:npm/x@1", "pkg:golang/x/y@1", "pkg:maven/x/y@1", "pkg:nuget/x@1", "pkg:cargo/x@1",
		"pkg:github/x/y@1", "pkg:generic/x@1", "PKG://DEB/debian/x@1?arch=amd64", "not a purl"}
	compared := 0
	for _, name := range names {
		for _, version := range versions {
			for _, purl := range purls {
				compared++
				want := graph.IdentifyingName(name, version, purl)
				if got := migrations.IdentifyingNameV0130(name, version, purl); got != want {
					t.Errorf("%q at %q (%q): the upgrade reads %q, the application %q", name, version, purl, got, want)
				}
			}
		}
	}
	if compared == 0 {
		t.Fatal("no name was compared, so this checked nothing")
	}
}

// identifyingSeedV0120 is what a v0.12.0 database holds about one kernel
// before and after an upgrade renamed it.
type identifyingSeedV0120 struct {
	product, issue                                  int64
	nested, atRootBefore, atRootAfter, libssl, code int64
	anyBefore, anyAfter, risk, unrelated            int64
	before, after, headers                          [3]string
}

func TestTheV0130UpgradeKeysAnOccurrenceByTheNameWithoutItsVersion(t *testing.T) {
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
		var s identifyingSeedV0120
		exec(`INSERT INTO "party" ("kind") VALUES (?)`, "person")
		party := id(`SELECT MAX("id") FROM "party"`)
		exec(`INSERT INTO "person" ("party_id", "identity", "is_admin", "is_bootstrap", "admin_derived", "audits",
			"audits_derived", "email_source", "digest", "digest_unassigned", "created_at")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			party, "triager", false, false, false, false, false, "", false, false, at)
		person := id(`SELECT MAX("id") FROM "person"`)
		exec(`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`, "p", "P", at)
		s.product = id(`SELECT MAX("id") FROM "product"`)
		exec(`INSERT INTO "branch_or_tag" ("product_id", "name", "display_name", "kind", "created_at")
			VALUES (?, ?, ?, ?, ?)`, s.product, "main", "main", "branch", at)
		line := id(`SELECT MAX("id") FROM "branch_or_tag"`)
		exec(`INSERT INTO "variant" ("product_id", "name", "display_name", "customer_facing", "created_at")
			VALUES (?, ?, ?, ?, ?)`, s.product, "image", "Image", true, at)
		variant := id(`SELECT MAX("id") FROM "variant"`)
		exec(`INSERT INTO "build" ("branch_or_tag_id", "variant_id", "created_at") VALUES (?, ?, ?)`,
			line, variant, at)
		build := id(`SELECT MAX("id") FROM "build"`)
		exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "kind", "exploited",
			"first_seen_at", "issue_id") VALUES (?, ?, ?, ?, ?, ?)`, "CVE-2026-1", "cve-2026-1", "vulnerability",
			false, at, 0)
		s.issue = id(`SELECT MAX("id") FROM "vulnerability"`)
		exec(`UPDATE "vulnerability" SET "issue_id" = "id" WHERE "id" = ?`, s.issue)

		component := func(name, version, purl string) int64 {
			t.Helper()
			exec(`INSERT INTO "component" ("identity", "purl", "name", "version", "name_folded", "fold_key",
				"first_seen_at") VALUES (?, ?, ?, ?, ?, ?, ?)`, name+"@"+version, purl, name, version,
				strings.ToLower(name), name+"@"+version, at)
			return id(`SELECT MAX("id") FROM "component"`)
		}
		var ids [3]int64
		s.before[0], s.before[1], s.before[2] = kernelV0120("6.12.41")
		s.after[0], s.after[1], s.after[2] = kernelV0120("6.12.94")
		s.headers = [3]string{"linux-headers-6.12.41+deb13-sonic-amd64", "6.12.41-1",
			"pkg:deb/debian/linux-headers-6.12.41%2Bdeb13-sonic-amd64@6.12.41-1"}
		ids[0] = component(s.before[0], s.before[1], s.before[2])
		ids[1] = component(s.after[0], s.after[1], s.after[2])
		ids[2] = component(s.headers[0], s.headers[1], s.headers[2])
		libssl := component("libssl3", "3.5.1-1", "pkg:deb/debian/libssl3@3.5.1-1")

		findingAt := func(componentID int64, consumerID *int64, occurrence, kind string, closed bool) int64 {
			t.Helper()
			var closedAt *time.Time
			if closed {
				closedAt = &at
			}
			exec(`INSERT INTO "finding" ("build_id", "kind", "visibility", "vulnerability_id", "component_id",
				"consumer_id", "occurrence_identity", "urgency", "urgency_exploited", "urgency_incident",
				"urgency_shipped", "opened_at", "closed_at") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				build, kind, "public", s.issue, componentID, consumerID, occurrence, 0, false, false, false, at, closedAt)
			return id(`SELECT MAX("id") FROM "finding"`)
		}
		s.nested = findingAt(ids[0], &ids[2], finding.OccurrenceIdentity(s.before[0], s.headers[0]), "vulnerable", true)
		s.atRootBefore = findingAt(ids[0], nil, finding.OccurrenceIdentity(s.before[0], ""), "vulnerable", true)
		s.atRootAfter = findingAt(ids[1], nil, finding.OccurrenceIdentity(s.after[0], ""), "vulnerable", false)
		s.libssl = findingAt(libssl, nil, finding.OccurrenceIdentity("libssl3", ""), "vulnerable", false)
		s.code = findingAt(ids[0], nil, strings.Repeat("c", 64), "code", false)

		decided := func(outcome, occurrence, state string, component *string, proposed time.Time) int64 {
			t.Helper()
			exec(`INSERT INTO "decision" ("kind", "proposed_by", "proposed_at", "outcome") VALUES (?, ?, ?, ?)`,
				"finding", person, proposed, outcome)
			decision := id(`SELECT MAX("id") FROM "decision"`)
			exec(`INSERT INTO "decision_occurrence" ("decision_id", "product_id", "vulnerability_id",
				"occurrence_identity", "visibility", "component_upstream_version", "needs_approval", "state",
				"proposed_by", "proposed_at", "live_key") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				decision, s.product, s.issue, occurrence, "public", component, true, state, person, proposed,
				finding.LiveKey(s.product, s.issue, occurrence, deref(component), "", component == nil))
			return id(`SELECT MAX("id") FROM "decision_occurrence"`)
		}
		version := s.before[1]
		s.anyBefore = decided(finding.OutcomeDismissed, finding.OccurrenceIdentity(s.before[0], ""), "approved", nil, at)
		s.anyAfter = decided(finding.OutcomeDismissed, finding.OccurrenceIdentity(s.after[0], ""), "proposed", nil,
			at.Add(time.Hour))
		s.risk = decided(finding.OutcomeNotApplicable, finding.OccurrenceIdentity(s.before[0], s.headers[0]), "approved",
			&version, at)
		s.unrelated = decided(finding.OutcomeDismissed, finding.OccurrenceIdentity("libssl3", ""), "approved", nil, at)

		dbtest.MigrateTo(t, db, v0130)

		occurrenceOf := func(table string, row int64) string {
			t.Helper()
			var out string
			if err := db.DB.NewRaw(`SELECT "occurrence_identity" FROM "`+table+`" WHERE "id" = ?`, row).
				Scan(ctx, &out); err != nil {
				t.Fatal(err)
			}
			return out
		}
		image := graph.IdentifyingName(s.before[0], s.before[1], s.before[2])
		if image != graph.IdentifyingName(s.after[0], s.after[1], s.after[2]) {
			t.Fatal("the two kernels are identified apart, so the upgrade has nothing to join")
		}
		headers := graph.IdentifyingName(s.headers[0], s.headers[1], s.headers[2])
		atRoot, nested := finding.OccurrenceIdentity(image, ""), finding.OccurrenceIdentity(image, headers)
		for _, c := range []struct {
			what, table string
			row         int64
			want        string
		}{
			{"the kernel under its headers", "finding", s.nested, nested},
			{"the kernel before the upgrade", "finding", s.atRootBefore, atRoot},
			{"the kernel after the upgrade", "finding", s.atRootAfter, atRoot},
			{"a library carrying no version in its name", "finding", s.libssl, finding.OccurrenceIdentity("libssl3", "")},
			{"a code finding", "finding", s.code, strings.Repeat("c", 64)},
			{"a dismissal before the upgrade", "decision_occurrence", s.anyBefore, atRoot},
			{"a dismissal after the upgrade", "decision_occurrence", s.anyAfter, atRoot},
			{"a decision keyed on the kernel's version", "decision_occurrence", s.risk, nested},
			{"a decision about the library", "decision_occurrence", s.unrelated, finding.OccurrenceIdentity("libssl3", "")},
		} {
			if got := occurrenceOf(c.table, c.row); got != c.want {
				t.Errorf("%s is keyed %s after the upgrade, want %s", c.what, got, c.want)
			}
		}

		type standing struct {
			State string  `bun:"state"`
			Key   *string `bun:"live_key"`
			Ended *time.Time
		}
		read := func(row int64) standing {
			t.Helper()
			var out standing
			if err := db.DB.NewRaw(`SELECT "state", "live_key", "ended_at" AS "ended" FROM "decision_occurrence"
				WHERE "id" = ?`, row).Scan(ctx, &out.State, &out.Key, &out.Ended); err != nil {
				t.Fatal(err)
			}
			return out
		}
		if got := read(s.anyBefore); got.State != "approved" || got.Key == nil ||
			*got.Key != finding.LiveKey(s.product, s.issue, atRoot, "", "", true) {
			t.Errorf("the approved dismissal reads %+v, want it standing under the identifying name", got)
		}
		if got := read(s.anyAfter); got.State != "lapsed" || got.Key != nil || got.Ended == nil {
			t.Errorf("the proposed dismissal at the same occurrence reads %+v, want it lapsed", got)
		}
		if got := read(s.risk); got.State != "approved" || got.Key == nil ||
			*got.Key != finding.LiveKey(s.product, s.issue, nested, version, "", false) {
			t.Errorf("the decision keyed on the kernel's version reads %+v, want it standing under the identifying name", got)
		}
		if got := read(s.unrelated); got.Key == nil ||
			*got.Key != finding.LiveKey(s.product, s.issue, finding.OccurrenceIdentity("libssl3", ""), "", "", true) {
			t.Errorf("the decision about the library reads %+v, want its key untouched", got)
		}
		leaveAtLatest(t, ctx, db)
	})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
