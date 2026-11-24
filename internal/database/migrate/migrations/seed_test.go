// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// seederV0130 writes rows as a v0.13.0 database holds them, for one product,
// build and issue.
type seederV0130 struct {
	t                      *testing.T
	db                     *database.DB
	at                     time.Time
	person, product, build int64
	issue                  int64
}

func (s *seederV0130) exec(query string, args ...any) {
	s.t.Helper()
	if _, err := s.db.DB.NewRaw(query, args...).Exec(s.t.Context()); err != nil {
		s.t.Fatalf("%v\n%s", err, query)
	}
}

func (s *seederV0130) id(query string) int64 {
	s.t.Helper()
	var out int64
	if err := s.db.DB.NewRaw(query).Scan(s.t.Context(), &out); err != nil {
		s.t.Fatalf("%v\n%s", err, query)
	}
	return out
}

// seedRowsV0130 writes a person, a product with one build, and one issue into
// a v0.13.0 database.
func seedRowsV0130(t *testing.T, db *database.DB) *seederV0130 {
	t.Helper()
	s := &seederV0130{t: t, db: db, at: time.Date(2026, 11, 12, 2, 0, 0, 0, time.UTC)}
	s.exec(`INSERT INTO "party" ("kind") VALUES (?)`, "person")
	party := s.id(`SELECT MAX("id") FROM "party"`)
	s.exec(`INSERT INTO "person" ("party_id", "identity", "is_admin", "is_bootstrap", "admin_derived", "audits",
		"audits_derived", "email_source", "digest", "digest_unassigned", "created_at")
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		party, "triager", false, false, false, false, false, "", false, false, s.at)
	s.person = s.id(`SELECT MAX("id") FROM "person"`)
	s.exec(`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`, "p", "P", s.at)
	s.product = s.id(`SELECT MAX("id") FROM "product"`)
	s.exec(`INSERT INTO "branch_or_tag" ("product_id", "name", "display_name", "kind", "created_at")
		VALUES (?, ?, ?, ?, ?)`, s.product, "main", "main", "branch", s.at)
	line := s.id(`SELECT MAX("id") FROM "branch_or_tag"`)
	s.exec(`INSERT INTO "variant" ("product_id", "name", "display_name", "customer_facing", "created_at")
		VALUES (?, ?, ?, ?, ?)`, s.product, "image", "Image", true, s.at)
	variant := s.id(`SELECT MAX("id") FROM "variant"`)
	s.exec(`INSERT INTO "build" ("branch_or_tag_id", "variant_id", "created_at") VALUES (?, ?, ?)`,
		line, variant, s.at)
	s.build = s.id(`SELECT MAX("id") FROM "build"`)
	s.exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "kind", "exploited",
		"first_seen_at", "issue_id") VALUES (?, ?, ?, ?, ?, ?)`, "CVE-2026-1", "cve-2026-1", "vulnerability",
		false, s.at, 0)
	s.issue = s.id(`SELECT MAX("id") FROM "vulnerability"`)
	s.exec(`UPDATE "vulnerability" SET "issue_id" = "id" WHERE "id" = ?`, s.issue)
	return s
}

func (s *seederV0130) component(name, version, purl string) int64 {
	s.t.Helper()
	s.exec(`INSERT INTO "component" ("identity", "purl", "name", "version", "name_folded", "fold_key",
		"first_seen_at") VALUES (?, ?, ?, ?, ?, ?, ?)`, name+"@"+version, purl, name, version,
		strings.ToLower(name), name+"@"+version, s.at)
	return s.id(`SELECT MAX("id") FROM "component"`)
}

func (s *seederV0130) finding(componentID int64, occurrence string) int64 {
	s.t.Helper()
	s.exec(`INSERT INTO "finding" ("build_id", "kind", "visibility", "vulnerability_id", "component_id",
		"occurrence_identity", "urgency", "urgency_exploited", "urgency_incident", "urgency_shipped",
		"opened_at") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.build, "vulnerable", "public", s.issue, componentID, occurrence, 0, false, false, false, s.at)
	return s.id(`SELECT MAX("id") FROM "finding"`)
}
