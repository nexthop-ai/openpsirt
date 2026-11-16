// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
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
		"kernel-5.14.0", "foo-UNKNOWN", "2.0", "lib-1.2rc", " padded-1.0 ", "ünï-1.0-ç", "lib_15.2.0.0.0.0.16.2.deb", "openssl-1.1.1", "a.1.0", "1.0.b", "a1.1.0",
		"torch-2.1.0+cu121"}
	versions := []string{"6.12.41-1", "3.5.1-1", "3.11.2-6+deb12u6", "17.0.12+7-2~deb12u1", "1.0-1", "1.0",
		"2.1.0+cu121", "1.2-r3", "2:5.14.0-427.el9", "UNKNOWN", "2.0", "1.2-1", "x:1.0-1", "", "1:1.0", "0.0.0", "1.1"}
	purls := []string{"", "pkg:deb/debian/x@1", "pkg:rpm/redhat/x@1", "pkg:apk/alpine/x@1", "pkg:pypi/x@1",
		"pkg:npm/x@1", "pkg:golang/x/y@1", "pkg:maven/x/y@1", "pkg:nuget/x@1", "pkg:cargo/x@1",
		"pkg:github/x/y@1", "pkg:generic/x@1", "PKG://DEB/debian/x@1?arch=amd64", "not a purl",
		"pkg:%20pypi/x@1", "pkg: npm/x@1", "pkg:py%00pi/x@1", "pkg:\x01apk/x@1", "pkg:%zzdeb/x@1", "pkg:apk%FF/x@1"}
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
	nested, atRootBefore, atRootAfter, libssl, code int64
	beneathBefore, beneathAfter                     int64
	anyBefore, anyAfter, risk, unrelated            int64
	olderBeneath, newerBeneath                      int64
	before, after, headers                          [3]string
}

// seederV0120 writes rows as a v0.12.0 database holds them, for one product,
// build and issue.
type seederV0120 struct {
	t                      *testing.T
	db                     *database.DB
	at                     time.Time
	person, product, build int64
	issue                  int64
}

func (s *seederV0120) exec(query string, args ...any) {
	s.t.Helper()
	if _, err := s.db.DB.NewRaw(query, args...).Exec(s.t.Context()); err != nil {
		s.t.Fatalf("%v\n%s", err, query)
	}
}

func (s *seederV0120) id(query string) int64 {
	s.t.Helper()
	var out int64
	if err := s.db.DB.NewRaw(query).Scan(s.t.Context(), &out); err != nil {
		s.t.Fatalf("%v\n%s", err, query)
	}
	return out
}

// seedRowsV0120 writes a person, a product with one build, and one issue into
// a v0.12.0 database.
func seedRowsV0120(t *testing.T, db *database.DB) *seederV0120 {
	t.Helper()
	s := &seederV0120{t: t, db: db, at: time.Date(2026, 11, 12, 2, 0, 0, 0, time.UTC)}
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

// another is a second product with one build, holding the same person and
// issue.
func (s *seederV0120) another(name string) *seederV0120 {
	s.t.Helper()
	out := *s
	out.exec(`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`, name, name, s.at)
	out.product = out.id(`SELECT MAX("id") FROM "product"`)
	out.exec(`INSERT INTO "branch_or_tag" ("product_id", "name", "display_name", "kind", "created_at")
		VALUES (?, ?, ?, ?, ?)`, out.product, "main", "main", "branch", s.at)
	line := out.id(`SELECT MAX("id") FROM "branch_or_tag"`)
	out.exec(`INSERT INTO "variant" ("product_id", "name", "display_name", "customer_facing", "created_at")
		VALUES (?, ?, ?, ?, ?)`, out.product, "image", "Image", true, s.at)
	variant := out.id(`SELECT MAX("id") FROM "variant"`)
	out.exec(`INSERT INTO "build" ("branch_or_tag_id", "variant_id", "created_at") VALUES (?, ?, ?)`,
		line, variant, s.at)
	out.build = out.id(`SELECT MAX("id") FROM "build"`)
	return &out
}

func (s *seederV0120) component(name, version, purl string) int64 {
	s.t.Helper()
	s.exec(`INSERT INTO "component" ("identity", "purl", "name", "version", "name_folded", "fold_key",
		"first_seen_at") VALUES (?, ?, ?, ?, ?, ?, ?)`, name+"@"+version, purl, name, version,
		strings.ToLower(name), name+"@"+version, s.at)
	return s.id(`SELECT MAX("id") FROM "component"`)
}

func (s *seederV0120) finding(componentID int64, consumerID *int64, occurrence, kind string, closed bool) int64 {
	s.t.Helper()
	var closedAt *time.Time
	if closed {
		closedAt = &s.at
	}
	s.exec(`INSERT INTO "finding" ("build_id", "kind", "visibility", "vulnerability_id", "component_id",
		"consumer_id", "occurrence_identity", "urgency", "urgency_exploited", "urgency_incident",
		"urgency_shipped", "opened_at", "closed_at") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.build, kind, "public", s.issue, componentID, consumerID, occurrence, 0, false, false, false, s.at, closedAt)
	return s.id(`SELECT MAX("id") FROM "finding"`)
}

func (s *seederV0120) decided(outcome, occurrence, state string, component *string, proposed time.Time) int64 {
	s.t.Helper()
	s.exec(`INSERT INTO "decision" ("kind", "proposed_by", "proposed_at", "outcome") VALUES (?, ?, ?, ?)`,
		"finding", s.person, proposed, outcome)
	decision := s.id(`SELECT MAX("id") FROM "decision"`)
	s.exec(`INSERT INTO "decision_occurrence" ("decision_id", "product_id", "vulnerability_id",
		"occurrence_identity", "visibility", "component_upstream_version", "needs_approval", "state",
		"proposed_by", "proposed_at", "live_key") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		decision, s.product, s.issue, occurrence, "public", component, true, state, s.person, proposed,
		finding.LiveKey(s.product, s.issue, occurrence, deref(component), "", component == nil))
	return s.id(`SELECT MAX("id") FROM "decision_occurrence"`)
}

func (s *seederV0120) occurrenceOf(table string, row int64) string {
	s.t.Helper()
	var out string
	if err := s.db.DB.NewRaw(`SELECT "occurrence_identity" FROM "`+table+`" WHERE "id" = ?`, row).
		Scan(s.t.Context(), &out); err != nil {
		s.t.Fatal(err)
	}
	return out
}

// standingV0130 is where a decision occurrence stands after the upgrade.
type standingV0130 struct {
	State string
	Key   *string
	Ended *time.Time
}

func (s *seederV0120) standing(row int64) standingV0130 {
	s.t.Helper()
	var out standingV0130
	if err := s.db.DB.NewRaw(`SELECT "state", "live_key", "ended_at" FROM "decision_occurrence"
		WHERE "id" = ?`, row).Scan(s.t.Context(), &out.State, &out.Key, &out.Ended); err != nil {
		s.t.Fatal(err)
	}
	return out
}

func keysPartV0130() partV0130 {
	return partV0130{
		name: "TheV0130UpgradeKeysAnOccurrenceByTheNameWithoutItsVersion",
		seed: func(t *testing.T, db *database.DB) func(t *testing.T) {
			seed := seedRowsV0120(t, db)
			at := seed.at
			var s identifyingSeedV0120
			var ids [3]int64
			s.before[0], s.before[1], s.before[2] = kernelV0120("6.12.41")
			s.after[0], s.after[1], s.after[2] = kernelV0120("6.12.94")
			s.headers = [3]string{"linux-headers-6.12.41+deb13-sonic-amd64", "6.12.41-1",
				"pkg:deb/debian/linux-headers-6.12.41%2Bdeb13-sonic-amd64@6.12.41-1"}
			ids[0] = seed.component(s.before[0], s.before[1], s.before[2])
			ids[1] = seed.component(s.after[0], s.after[1], s.after[2])
			ids[2] = seed.component(s.headers[0], s.headers[1], s.headers[2])
			libssl := seed.component("libssl3", "3.5.1-1", "pkg:deb/debian/libssl3@3.5.1-1")
			// Beneath the kernel and holding no version in its name, so only the
			// consumer's side of its key moves.
			initramfs := seed.component("initramfs-tools", "0.148.3", "pkg:deb/debian/initramfs-tools@0.148.3")

			s.nested = seed.finding(ids[0], &ids[2], finding.OccurrenceIdentity(s.before[0], s.headers[0]), "vulnerable", true)
			s.atRootBefore = seed.finding(ids[0], nil, finding.OccurrenceIdentity(s.before[0], ""), "vulnerable", true)
			s.atRootAfter = seed.finding(ids[1], nil, finding.OccurrenceIdentity(s.after[0], ""), "vulnerable", false)
			s.libssl = seed.finding(libssl, nil, finding.OccurrenceIdentity("libssl3", ""), "vulnerable", false)
			s.code = seed.finding(ids[0], nil, strings.Repeat("c", 64), "code", false)
			s.beneathBefore = seed.finding(initramfs, &ids[0], finding.OccurrenceIdentity("initramfs-tools", s.before[0]),
				"vulnerable", true)
			s.beneathAfter = seed.finding(initramfs, &ids[1], finding.OccurrenceIdentity("initramfs-tools", s.after[0]),
				"vulnerable", false)

			version := s.before[1]
			s.anyBefore = seed.decided(finding.OutcomeDismissed, finding.OccurrenceIdentity(s.before[0], ""), "approved", nil, at)
			s.anyAfter = seed.decided(finding.OutcomeDismissed, finding.OccurrenceIdentity(s.after[0], ""), "proposed", nil,
				at.Add(time.Hour))
			s.risk = seed.decided(finding.OutcomeNotApplicable, finding.OccurrenceIdentity(s.before[0], s.headers[0]), "approved",
				&version, at)
			s.unrelated = seed.decided(finding.OutcomeDismissed, finding.OccurrenceIdentity("libssl3", ""), "approved", nil, at)
			// Two proposals, the newer written first, so neither the order written
			// nor approval tells them apart.
			s.newerBeneath = seed.decided(finding.OutcomeDismissed, finding.OccurrenceIdentity("initramfs-tools", s.after[0]),
				"proposed", nil, at.Add(time.Hour))
			s.olderBeneath = seed.decided(finding.OutcomeDismissed, finding.OccurrenceIdentity("initramfs-tools", s.before[0]),
				"proposed", nil, at)

			return func(t *testing.T) {
				seed.t = t

				image := graph.IdentifyingName(s.before[0], s.before[1], s.before[2])
				if image != graph.IdentifyingName(s.after[0], s.after[1], s.after[2]) {
					t.Fatal("the two kernels are identified apart, so the upgrade has nothing to join")
				}
				headers := graph.IdentifyingName(s.headers[0], s.headers[1], s.headers[2])
				atRoot, nested := finding.OccurrenceIdentity(image, ""), finding.OccurrenceIdentity(image, headers)
				beneath := finding.OccurrenceIdentity("initramfs-tools", image)
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
					{"a package beneath the kernel before the upgrade", "finding", s.beneathBefore, beneath},
					{"a package beneath the kernel after the upgrade", "finding", s.beneathAfter, beneath},
					{"a dismissal before the upgrade", "decision_occurrence", s.anyBefore, atRoot},
					{"a dismissal after the upgrade", "decision_occurrence", s.anyAfter, atRoot},
					{"a decision keyed on the kernel's version", "decision_occurrence", s.risk, nested},
					{"a decision about the library", "decision_occurrence", s.unrelated, finding.OccurrenceIdentity("libssl3", "")},
					{"the older proposal beneath the kernel", "decision_occurrence", s.olderBeneath, beneath},
					{"the newer proposal beneath the kernel", "decision_occurrence", s.newerBeneath, beneath},
				} {
					if got := seed.occurrenceOf(c.table, c.row); got != c.want {
						t.Errorf("%s is keyed %s after the upgrade, want %s", c.what, got, c.want)
					}
				}

				if got := seed.standing(s.anyBefore); got.State != "approved" || got.Key == nil ||
					*got.Key != finding.LiveKey(seed.product, seed.issue, atRoot, "", "", true) {
					t.Errorf("the approved dismissal reads %+v, want it standing under the identifying name", got)
				}
				if got := seed.standing(s.anyAfter); got.State != "lapsed" || got.Key != nil || got.Ended == nil {
					t.Errorf("the proposed dismissal at the same occurrence reads %+v, want it lapsed", got)
				}
				if got := seed.standing(s.risk); got.State != "approved" || got.Key == nil ||
					*got.Key != finding.LiveKey(seed.product, seed.issue, nested, version, "", false) {
					t.Errorf("the decision keyed on the kernel's version reads %+v, want it standing under the identifying name", got)
				}
				if got := seed.standing(s.unrelated); got.Key == nil ||
					*got.Key != finding.LiveKey(seed.product, seed.issue, finding.OccurrenceIdentity("libssl3", ""), "", "", true) {
					t.Errorf("the decision about the library reads %+v, want its key untouched", got)
				}
				if got := seed.standing(s.newerBeneath); got.State != "proposed" || got.Key == nil ||
					*got.Key != finding.LiveKey(seed.product, seed.issue, beneath, "", "", true) {
					t.Errorf("the newer of two proposals brought together reads %+v, want it standing", got)
				}
				if got := seed.standing(s.olderBeneath); got.State != "lapsed" || got.Key != nil || got.Ended == nil {
					t.Errorf("the older of two proposals brought together reads %+v, want it lapsed", got)
				}
			}
		},
	}
}

func storedIdentifyingPartV0130() partV0130 {
	// A count across versions groups on the stored name, so a component
	// written before the upgrade has to hold what one written after does.
	return partV0130{
		name: "TheV0130UpgradeStoresTheIdentifyingNameAsTheApplicationDoes",
		seed: func(t *testing.T, db *database.DB) func(t *testing.T) {
			seed := seedRowsV0120(t, db)
			name, version, purl := kernelV0120("6.12.41")
			kernel := seed.component(name, version, purl)
			libssl := seed.component("libssl3", "3.5.1-1", "pkg:deb/debian/libssl3@3.5.1-1")
			return func(t *testing.T) {
				seed.t = t
				stored := func(id int64) *string {
					var got *string
					if err := db.DB.NewSelect().TableExpr(`"component"`).ColumnExpr(`"identifying_folded"`).
						Where(`"id" = ?`, id).Scan(t.Context(), &got); err != nil {
						t.Fatal(err)
					}
					return got
				}
				if got, want := stored(kernel), graph.StoredIdentifying(name, version, purl); got == nil || *got != want {
					t.Errorf("the kernel stores %v as its identifying name, want %q", got, want)
				}
				if got := stored(libssl); got != nil {
					t.Errorf("a library holding no version in its name stores %q, want nothing", *got)
				}
			}
		},
	}
}

// splitPartsV0130 holds a decision at a key the upgrade splits. One name, one
// consumer, so v0.12.0 made one key. The upgrade reads the name as carrying its
// version at one version and not at the other, so the key splits in two and
// nothing says which the decision was about.
func splitPartsV0130() []partV0130 {
	var parts []partV0130
	for _, c := range []struct {
		what, name string
		versions   [2]string
	}{
		// Named after its release at the first version only: the side
		// not carrying it keeps the key.
		{"a name holding its release at one version", "golang-1.20-go", [2]string{"1.20-1", "1.20.1-1"}},
		// Carrying each version in a different place: both sides move,
		// to different keys.
		{"a name holding each of two releases", "lib-1.0-2.0", [2]string{"1.0-1", "2.0-1"}},
	} {
		parts = append(parts, partV0130{
			name: "TheV0130UpgradeLeavesADecisionAtAKeyItSplits/" + c.what,
			seed: func(t *testing.T, db *database.DB) func(t *testing.T) {
				seed := seedRowsV0120(t, db)
				key := finding.OccurrenceIdentity(c.name, "")
				for i, version := range c.versions {
					id := seed.component(c.name, version, "pkg:deb/debian/"+c.name+"@"+version)
					seed.finding(id, nil, key, "vulnerable", i == 0)
				}
				decided := seed.decided(finding.OutcomeDismissed, key, "approved", nil, seed.at)
				return func(t *testing.T) {
					seed.t = t
					if got := seed.occurrenceOf("decision_occurrence", decided); got != key {
						t.Errorf("%s: the dismissal is keyed %s after the upgrade, want it left at %s", c.what, got, key)
					}
					if got := seed.standing(decided); got.State != "approved" || got.Key == nil ||
						*got.Key != finding.LiveKey(seed.product, seed.issue, key, "", "", true) {
						t.Errorf("%s: the dismissal reads %+v, want it standing at its key", c.what, got)
					}
				}
			},
		})
	}
	return parts
}

// ownProductPartsV0130 holds a decision to its own product's findings. One
// component name sits in two products: the split product's findings at the key
// v0.12.0 made go two ways, or one of them stays, while the other product's
// all go one way and its decision goes with them. A product holding no finding
// at a key follows what the other products' findings did there.
//
// The names are this part's alone, so another part's findings at the same key
// cannot stand in for these.
func ownProductPartsV0130() []partV0130 {
	const name = "TheV0130UpgradeMovesADecisionWithItsOwnProductsFindings/"
	var parts []partV0130
	for _, c := range []struct {
		what, name string
		versions   [2]string
	}{
		{"a name the split product keeps at its key", "golang-1.21-go", [2]string{"1.21-1", "1.21.1-1"}},
		{"a name the split product moves to two keys", "lib-3.0-4.0", [2]string{"3.0-1", "4.0-1"}},
	} {
		parts = append(parts, partV0130{
			name: name + c.what,
			seed: func(t *testing.T, db *database.DB) func(t *testing.T) {
				split := seedRowsV0120(t, db)
				clean := split.another("clean")
				key := finding.OccurrenceIdentity(c.name, "")
				var ids [2]int64
				for i, version := range c.versions {
					ids[i] = split.component(c.name, version, "pkg:deb/debian/"+c.name+"@"+version)
					split.finding(ids[i], nil, key, "vulnerable", i == 0)
				}
				cleanFinding := clean.finding(ids[0], nil, key, "vulnerable", false)
				splitDecided := split.decided(finding.OutcomeDismissed, key, "approved", nil, split.at)
				cleanDecided := clean.decided(finding.OutcomeDismissed, key, "approved", nil, clean.at)
				return func(t *testing.T) {
					split.t, clean.t = t, t
					moved := clean.occurrenceOf("finding", cleanFinding)
					if moved == key {
						t.Fatal("the clean product's finding stayed at its key, so nothing moved")
					}
					if got := clean.occurrenceOf("decision_occurrence", cleanDecided); got != moved {
						t.Errorf("the clean product's dismissal is keyed %s, want %s, where its finding moved", got, moved)
					}
					if got := clean.standing(cleanDecided); got.State != "approved" || got.Key == nil ||
						*got.Key != finding.LiveKey(clean.product, clean.issue, moved, "", "", true) {
						t.Errorf("the clean product's dismissal reads %+v, want it standing where its finding moved", got)
					}
					if got := split.occurrenceOf("decision_occurrence", splitDecided); got != key {
						t.Errorf("the split product's dismissal is keyed %s, want it left at %s", got, key)
					}
				}
			},
		})
	}
	return append(parts, partV0130{
		name: name + "a product holding no finding at the key",
		seed: func(t *testing.T, db *database.DB) func(t *testing.T) {
			held := seedRowsV0120(t, db)
			bare := held.another("bare")
			name, version := "tool-5.2", "5.2-1"
			key := finding.OccurrenceIdentity(name, "")
			heldFinding := held.finding(held.component(name, version, "pkg:deb/debian/"+name+"@"+version), nil, key,
				"vulnerable", false)
			bareDecided := bare.decided(finding.OutcomeDismissed, key, "approved", nil, bare.at)
			return func(t *testing.T) {
				held.t, bare.t = t, t
				moved := held.occurrenceOf("finding", heldFinding)
				if moved == key {
					t.Fatal("the finding stayed at its key, so nothing moved")
				}
				if got := bare.occurrenceOf("decision_occurrence", bareDecided); got != moved {
					t.Errorf("a dismissal in a product holding no finding is keyed %s, want %s, where the other's moved",
						got, moved)
				}
			}
		},
	})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
