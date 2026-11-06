// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/issuedate"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/scanner"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

// osvSays answers one date for every name, or none.
type osvSays struct{ published time.Time }

func (o osvSays) Dates(context.Context, string) (issuedate.Dates, error) {
	if o.published.IsZero() {
		return issuedate.Dates{}, issuedate.ErrUnknown
	}
	return issuedate.Dates{Published: o.published}, nil
}

// undatedMatch records a check's match on an issue OSV was asked about and
// gave no date, first seen here after the replacement, with the last scan's
// data dated twelve hours after the inventory arrived.
func undatedMatch(t *testing.T, w *fixture.World) (*checkFixture, *scanner.Checking) {
	t.Helper()
	return undatedMatchOn(t, w, "CVE-2026-0011")
}

// undatedMatchOn is undatedMatch on an issue of this name.
func undatedMatchOn(t *testing.T, w *fixture.World, name string) (*checkFixture, *scanner.Checking) {
	t.Helper()
	ctx := t.Context()
	f := replacedInventory(t, w)
	f.since = f.arrived.Add(12 * time.Hour)
	if _, err := f.db.NewUpdate().Table("scan_run").
		Set(`"database_version" = ?`, f.since.Format(time.RFC3339)).
		Where(`"build_id" = ?`, f.build).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
		[]finding.Named{{Identifier: name, Severity: "high"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.NewUpdate().Table("vulnerability").
		Set(`"dates_asked_at" = ?`, time.Now().UTC().Add(-60*24*time.Hour)).
		Set(`"first_seen_at" = ?`, f.replaced.Add(5*24*time.Hour)).
		Where(`"identifier" = ?`, name).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt(name, libnl)}}
	checking := f.check(t, s)
	if checking == nil {
		t.Fatal("the check waited on an issue OSV was already asked about")
	}
	return f, checking
}

// matchOf reads the one finding the check recorded and whether it is marked.
func matchOf(t *testing.T, f *checkFixture) (finding.Finding, bool) {
	t.Helper()
	var rows []finding.Finding
	if err := f.db.NewSelect().Model(&rows).Where(`"build_id" = ?`, f.build).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d findings, want the check's one", len(rows))
	}
	marked, err := f.db.NewSelect().TableExpr(`"finding" AS "f"`).
		Where(`"f"."id" = ?`, rows[0].ID).Where(finding.PublicationUnknown("f")).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return rows[0], marked == 1
}

// redate runs the date pass once with OSV giving this date.
func redate(t *testing.T, f *checkFixture, published time.Time) {
	t.Helper()
	p := issuedate.NewPass(f.db.DB, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	p.Asker, p.Pause = osvSays{published}, 0
	if _, err := p.Once(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// foundAfter is what the replaced upload's receipt counts as found after fixed.
func foundAfter(t *testing.T, f *checkFixture, runID int64) int {
	t.Helper()
	changed, err := finding.NewStore(f.db.DB).Changes(t.Context(),
		access.Everything("a test counting a check"), f.build, []int64{runID})
	if err != nil {
		t.Fatal(err)
	}
	return changed[runID].Opened
}

func TestAMatchOnAnIssueOSVNeverDatesIsRecordedMarked(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f, checking := undatedMatch(t, w)
		if checking.Checked.Recorded != 1 {
			t.Fatalf("recorded %d, want the match on the undated issue", checking.Checked.Recorded)
		}
		got, marked := matchOf(t, f)
		switch {
		case !marked:
			t.Error("the match is not marked publication date unknown")
		case !got.OpenedAt.Equal(f.since):
			t.Errorf("opened at %s, want the last scan's data date %s", got.OpenedAt, f.since)
		case got.ClosedAt == nil || !got.ClosedAt.Equal(f.replaced):
			t.Errorf("closed at %v, want the replacement at %s", got.ClosedAt, f.replaced)
		}
		// The list read on a day inside the stretch carries the marker.
		var productID int64
		if err := f.db.NewSelect().TableExpr(`"build" AS "b"`).
			Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "b"."branch_or_tag_id"`).
			ColumnExpr(`"st"."product_id"`).Where(`"b"."id" = ?`, f.build).Scan(t.Context(), &productID); err != nil {
			t.Fatal(err)
		}
		who := access.NewPerson(1, "someone", false, map[int64][]access.Role{productID: {access.PublicTriage}}, 101)
		day := f.since.Truncate(24 * time.Hour).Add(24 * time.Hour)
		groups, _, err := finding.NewStore(f.db.DB).Groups(t.Context(), who,
			finding.Scope{ProductID: &productID}, 50, 0, finding.Filter{OpenOn: &day})
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 1 || !groups[0].PublicationUnknown {
			t.Errorf("the list on %s holds %+v, want the one match marked", day, groups)
		}
		if n := foundAfter(t, f, checking.RunID); n != 1 {
			t.Errorf("found after fixed counts %d, want 1", n)
		}
	})
}

func TestAMatchDatedBeforeTheReplacementOpensAtItsDate(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f, _ := undatedMatch(t, w)
		when := f.arrived.Add(36 * time.Hour)
		redate(t, f, when)
		got, marked := matchOf(t, f)
		switch {
		case marked:
			t.Error("the match is still marked publication date unknown")
		case !got.OpenedAt.Equal(when):
			t.Errorf("opened at %s, want the publication at %s", got.OpenedAt, when)
		case got.ClosedBecause != finding.Upgraded:
			t.Errorf("closed because %q, want the replacement's upgraded kept", got.ClosedBecause)
		}
	})
}

func TestAMatchDatedAfterTheReplacementIsWithdrawn(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f, checking := undatedMatch(t, w)
		redate(t, f, f.replaced)
		got, _ := matchOf(t, f)
		if got.ClosedBecause != finding.Invalid {
			t.Errorf("closed because %q, want invalid: it was never exposed", got.ClosedBecause)
		}
		if !got.OpenedAt.Equal(f.since) {
			t.Errorf("opened at %s, want the stretch left as recorded", got.OpenedAt)
		}
		if n := foundAfter(t, f, checking.RunID); n != 0 {
			t.Errorf("found after fixed counts %d, want none once it is withdrawn", n)
		}
	})
}

func TestAMatchDatedBeforeTheChecksWindowIsWithdrawn(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f, _ := undatedMatch(t, w)
		// The check would have left it out: the last scan's data carried an
		// issue published a settle delay before it.
		redate(t, f, f.since.Add(-setting.DefaultCheckSettle-time.Microsecond))
		if got, _ := matchOf(t, f); got.ClosedBecause != finding.Invalid {
			t.Errorf("closed because %q, want invalid: the last scan saw it", got.ClosedBecause)
		}
	})
}

func TestAMatchDatedAtTheChecksWindowOpensAtTheArrival(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f, _ := undatedMatch(t, w)
		redate(t, f, f.since.Add(-setting.DefaultCheckSettle))
		got, _ := matchOf(t, f)
		switch {
		case got.ClosedBecause != finding.Upgraded:
			t.Errorf("closed because %q, want the replacement's upgraded kept", got.ClosedBecause)
		case !got.OpenedAt.Equal(f.arrived):
			t.Errorf("opened at %s, want the inventory's arrival %s", got.OpenedAt, f.arrived)
		}
	})
}

// merge interns one report naming both issues, which merges them.
func merge(t *testing.T, f *checkFixture, name string, alias string) {
	t.Helper()
	if _, err := finding.NewVulnerabilities(f.db.DB).Intern(t.Context(),
		[]finding.Named{{Identifier: name, Aliases: []string{alias}, Severity: "high"}}); err != nil {
		t.Fatal(err)
	}
}

// issueOfMatch is the identifier of the issue the check's match is read as.
func issueOfMatch(t *testing.T, f *checkFixture) string {
	t.Helper()
	got, _ := matchOf(t, f)
	var name string
	if err := f.db.NewSelect().TableExpr(`"vulnerability" AS "v"`).
		Join(`JOIN "vulnerability" AS "s" ON "s"."id" = "v"."issue_id"`).
		ColumnExpr(`"s"."identifier"`).Where(`"v"."id" = ?`, got.VulnerabilityID).
		Scan(t.Context(), &name); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestAMarkedMatchAbsorbedIntoADatedIssueIsDatedByIt(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f, _ := undatedMatchOn(t, w, "GHSA-AAAA-BBBB-CCCC")
		when := f.arrived.Add(36 * time.Hour)
		f.published(t, "CVE-2026-0031", when)
		merge(t, f, "CVE-2026-0031", "GHSA-AAAA-BBBB-CCCC")
		if name := issueOfMatch(t, f); name != "CVE-2026-0031" {
			t.Fatalf("the match is read as %s, want the issue kept", name)
		}
		got, marked := matchOf(t, f)
		switch {
		case marked:
			t.Error("the match is still marked publication date unknown")
		case !got.OpenedAt.Equal(when):
			t.Errorf("opened at %s, want the kept issue's publication at %s", got.OpenedAt, when)
		}
	})
}

func TestAMarkedMatchKeptTakesTheDateOfTheIssueItAbsorbs(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f, _ := undatedMatch(t, w)
		when := f.arrived.Add(36 * time.Hour)
		f.published(t, "GHSA-DDDD-EEEE-FFFF", when)
		merge(t, f, "CVE-2026-0011", "GHSA-DDDD-EEEE-FFFF")
		if name := issueOfMatch(t, f); name != "CVE-2026-0011" {
			t.Fatalf("the match is read as %s, want the issue kept", name)
		}
		got, marked := matchOf(t, f)
		switch {
		case marked:
			t.Error("the match is still marked publication date unknown")
		case !got.OpenedAt.Equal(when):
			t.Errorf("opened at %s, want the absorbed issue's publication at %s", got.OpenedAt, when)
		}
		var published *time.Time
		if err := f.db.NewSelect().Table("vulnerability").Column("published_at").
			Where(`"identifier" = ?`, "CVE-2026-0011").Scan(t.Context(), &published); err != nil {
			t.Fatal(err)
		}
		if published == nil || !published.Equal(when) {
			t.Errorf("the issue kept is published %v, want the absorbed issue's %s", published, when)
		}
	})
}

func TestAMarkedMatchMergedWithAnEarlierSightingIsDatedByIt(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f, _ := undatedMatch(t, w)
		seen := f.arrived.Add(36 * time.Hour)
		if _, err := finding.NewVulnerabilities(f.db.DB).Intern(t.Context(),
			[]finding.Named{{Identifier: "GHSA-GGGG-HHHH-IIII", Severity: "high"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.NewUpdate().Table("vulnerability").Set(`"first_seen_at" = ?`, seen).
			Where(`"identifier" = ?`, "GHSA-GGGG-HHHH-IIII").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		merge(t, f, "CVE-2026-0011", "GHSA-GGGG-HHHH-IIII")
		got, marked := matchOf(t, f)
		switch {
		case marked:
			t.Error("the match is still marked: the merged issue was carried here before the replacement")
		case !got.OpenedAt.Equal(seen):
			t.Errorf("opened at %s, want the earlier sighting at %s", got.OpenedAt, seen)
		}
	})
}

func TestALongKnownIssueNobodyAskedAboutWaitsForTheDatePass(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		// The check fell due an hour ago.
		f.replaced = time.Now().UTC().Add(-49 * time.Hour).Truncate(time.Second)
		if _, err := f.db.NewUpdate().Table("scan").Set(`"received_at" = ?`, f.replaced).
			Where(`"id" = ?`, f.replacement).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		// Carried here long before, and never asked about.
		if _, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
			[]finding.Named{{Identifier: "CVE-2026-0012", Severity: "high"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.NewUpdate().Table("vulnerability").
			Set(`"first_seen_at" = ?`, f.arrived.Add(-30*24*time.Hour)).
			Where(`"identifier" = ?`, "CVE-2026-0012").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0012", libnl)}}
		if checking := f.check(t, s); checking != nil {
			t.Fatalf("checked before OSV was asked about the issue: %+v", checking)
		}
	})
}

func TestAnIssuePublishedJustBeforeTheLastScansDataIsChecked(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f := replacedInventory(t, w)
		// Twelve hours before the data the last scan read, which need not yet
		// have carried it.
		f.published(t, "CVE-2026-0013", f.since.Add(-12*time.Hour))
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0013", libnl)}}
		checking := f.check(t, s)
		if checking == nil || checking.Checked.Recorded != 1 {
			t.Fatalf("checked %+v, want the issue recorded", checking)
		}
	})
}

func TestACheckClosedAsPatchedNamesTheClaimItStandsOn(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		f.published(t, "CVE-2026-0014", f.arrived.Add(24*time.Hour))
		// The replacement still holds the issue at the library, and says it is
		// fixed there.
		if _, err := fixture.RecordClaims(ctx, f.db.DB, f.build, f.replacement, []sbom.Suppression{{
			Vulnerability: "CVE-2026-0014", Status: sbom.AlreadyFixed,
			Targets: []sbom.Target{{Name: libnlFixed.Name, Version: libnlFixed.Version}},
			Origin:  sbom.FromStatement,
		}}, map[sbom.Origin]bool{sbom.FromStatement: true, sbom.FromPedigree: true}); err != nil {
			t.Fatal(err)
		}
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{
			reportAt("CVE-2026-0014", libnl), reportAt("CVE-2026-0014", libnlFixed),
		}}
		if checking := f.check(t, s); checking == nil || checking.Checked.Recorded != 1 {
			t.Fatalf("checked %+v, want one recorded", checking)
		}
		got, _ := matchOf(t, f)
		if got.ClosedBecause != finding.Patched || got.SuppressedBy == nil || got.ClaimedBy == nil {
			t.Errorf("closed because %q by claim %v claimed by %v, want patched naming the replacement's claim",
				got.ClosedBecause, got.SuppressedBy, got.ClaimedBy)
		}
	})
}

func TestAPatchDroppedAfterACheckArrivesFromTheReplacementsVersion(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		f.published(t, "CVE-2026-0032", f.arrived.Add(24*time.Hour))
		if _, err := fixture.RecordClaims(ctx, f.db.DB, f.build, f.replacement, []sbom.Suppression{{
			Vulnerability: "CVE-2026-0032", Status: sbom.AlreadyFixed,
			Targets: []sbom.Target{{Name: libnlFixed.Name, Version: libnlFixed.Version}},
			Origin:  sbom.FromStatement,
		}}, map[sbom.Origin]bool{sbom.FromStatement: true, sbom.FromPedigree: true}); err != nil {
			t.Fatal(err)
		}
		report := func(c graph.Described) *dated {
			return &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0032", c)}}
		}
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		scan := func(c graph.Described) {
			t.Helper()
			f.waiting(t)
			if _, err := scanner.NewRunner(f.db, f.queue, report(c), quiet, "test").Once(ctx); err != nil {
				t.Fatal(err)
			}
		}
		// The replacement's scan records the occurrence patched at its version,
		// then the check records the match at the old one.
		scan(libnlFixed)
		if checking := f.check(t, &dated{at: time.Now().UTC(), reported: []finding.Reported{
			reportAt("CVE-2026-0032", libnl), reportAt("CVE-2026-0032", libnlFixed),
		}}); checking == nil || checking.Checked.Recorded != 1 {
			t.Fatalf("checked %+v, want one recorded", checking)
		}
		// A third inventory moves the library on with no claim.
		moved := at("libnl-3-200", "3.10.0")
		third, _, err := ingest.NewStore(f.db.DB).Record(ctx, ingest.Arriving{
			BuildID: f.build, ContentHash: "hash-3", BuiltAt: time.Now().UTC(), ParserVersion: "test",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.ApplyGraph(ctx, f.db.DB, f.build, third.ID, graph.Snapshot{
			Root: root, Components: []graph.Described{swss, moved},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: swss, Child: moved}},
		}); err != nil {
			t.Fatal(err)
		}
		scan(moved)
		var arrived string
		if err := f.db.NewSelect().TableExpr(`"finding"`).ColumnExpr(`COALESCE("arrived_from", '')`).
			Where(`"build_id" = ?`, f.build).Where(`"closed_at" IS NULL`).Scan(ctx, &arrived); err != nil {
			t.Fatal(err)
		}
		if arrived != libnlFixed.Version {
			t.Errorf("arrived from %q, want the replacement's patched %s", arrived, libnlFixed.Version)
		}
	})
}

// disclaimedReplacement has a supplier say the library the replacement ships
// at the new version is not affected by CVE-2026-0015, on every route to it,
// and answers the product and the person reading it.
func disclaimedReplacement(t *testing.T, w *fixture.World, f *checkFixture) (int64, access.Subject) {
	t.Helper()
	ctx := t.Context()
	f.published(t, "CVE-2026-0015", f.arrived.Add(24*time.Hour))
	var productID int64
	if err := f.db.NewSelect().TableExpr(`"build" AS "b"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "b"."branch_or_tag_id"`).
		ColumnExpr(`"st"."product_id"`).Where(`"b"."id" = ?`, f.build).Scan(ctx, &productID); err != nil {
		t.Fatal(err)
	}
	person := w.DeclarePerson("supplier-reader@example.com", "Supplier reader", false)
	who := access.NewPerson(person.ID, "supplier-reader@example.com", false,
		map[int64][]access.Role{productID: {access.PublicTriage}}, person.PartyID)
	claim := sbom.Suppression{Vulnerability: "CVE-2026-0015", Status: sbom.NotAffected,
		Justification: "vulnerable_code_not_present"}
	target := sbom.Target{Purl: libnlFixed.Purl, Name: libnlFixed.Name, Version: libnlFixed.Version,
		Within: &sbom.Target{Purl: swss.Purl, Name: swss.Name}}
	if _, _, err := finding.NewStore(f.db.DB).RecordStatements(ctx, who, productID, finding.Supplied{
		Source: finding.FromVex, Publisher: "Acme Security", Document: "swss.openvex.json", Digest: "sha256:1",
	}, []finding.Statement{finding.StatementOf(claim, target)}); err != nil {
		t.Fatal(err)
	}
	return productID, who
}

// disclaimedReport is the scanner reporting CVE-2026-0015 at both versions.
func disclaimedReport() *dated {
	return &dated{at: time.Now().UTC(), reported: []finding.Reported{
		reportAt("CVE-2026-0015", libnl), reportAt("CVE-2026-0015", libnlFixed),
	}}
}

func TestACheckClosedAsDisclaimedNamesTheStatementItStandsOn(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f := replacedInventory(t, w)
		disclaimedReplacement(t, w, f)
		if checking := f.check(t, disclaimedReport()); checking == nil || checking.Checked.Recorded != 1 {
			t.Fatalf("checked %+v, want one recorded", checking)
		}
		got, _ := matchOf(t, f)
		if got.ClosedBecause != finding.Disclaimed || got.StatedBy == nil {
			t.Errorf("closed because %q by statement %v, want disclaimed naming the statement",
				got.ClosedBecause, got.StatedBy)
		}
	})
}

func TestACheckLeavesTheReplacementsStatementTheLatest(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		_, who := disclaimedReplacement(t, w, f)
		// The replacement's own scan records its occurrence closed by the
		// statement, before the check writes the match.
		f.waiting(t)
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if _, err := scanner.NewRunner(f.db, f.queue, disclaimedReport(), quiet, "test").Once(ctx); err != nil {
			t.Fatal(err)
		}
		statements := func() []vex.Statement {
			t.Helper()
			doc, err := vex.NewStore(f.db.DB).For(ctx, who,
				publisher.Named{Name: "Example Networks", Namespace: "https://example.test"},
				fixture.ProductName, fixture.BranchName, fixture.CustomerVariant, false, vex.WithSuppliers)
			if err != nil {
				t.Fatal(err)
			}
			return doc.Statements
		}
		if n := len(statements()); n != 1 {
			t.Fatalf("%d statements before the check, want the supplier's not_affected", n)
		}
		checking := f.check(t, disclaimedReport())
		if checking == nil || checking.Checked.Recorded != 1 {
			t.Fatalf("checked %+v, want one recorded", checking)
		}
		if got := statements(); len(got) != 1 || got[0].Status != "not_affected" {
			t.Errorf("the document states %+v after the check, want the supplier's not_affected kept", got)
		}
		// The replacement's row is the one somebody may decide about.
		var decidable []int64
		if err := f.db.NewSelect().TableExpr(`"finding" AS "f"`).ColumnExpr(`"f"."id"`).
			Where(`"f"."build_id" = ?`, f.build).Where(`"f"."closed_at" IS NOT NULL`).
			Where(finding.Decidable).Scan(ctx, &decidable); err != nil {
			t.Fatal(err)
		}
		var match int64
		if err := f.db.NewSelect().TableExpr(`"finding"`).ColumnExpr(`"id"`).
			Where(`"closed_run_id" = ?`, checking.RunID).Scan(ctx, &match); err != nil {
			t.Fatal(err)
		}
		if len(decidable) != 1 || decidable[0] == match {
			t.Errorf("decidable rows %v, want the replacement's alone, not the check's %d", decidable, match)
		}
		// A release comparison from a build that held the issue at the old
		// version says it went by the replacement's run.
		tagged := w.BuildFor(w.Tag, w.Customer)
		var oldVersion int64
		if err := f.db.NewSelect().TableExpr(`"component"`).ColumnExpr(`"id"`).
			Where(`"purl" = ?`, libnl.Purl).Scan(ctx, &oldVersion); err != nil {
			t.Fatal(err)
		}
		var issue int64
		if err := f.db.NewSelect().TableExpr(`"vulnerability"`).ColumnExpr(`"id"`).
			Where(`"identifier" = ?`, "CVE-2026-0015").Scan(ctx, &issue); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.NewInsert().Model(&finding.Finding{
			BuildID: tagged.ID, Kind: finding.Vulnerable, Visibility: access.Public,
			VulnerabilityID: issue, ComponentID: oldVersion, OccurrenceIdentity: "tagged libnl",
			OpenedAt: f.arrived,
		}).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		compared, err := finding.NewStore(f.db.DB).Compare(ctx, who, tagged.ID, f.build, false)
		if err != nil {
			t.Fatal(err)
		}
		var replacementRun int64
		if err := f.db.NewSelect().TableExpr(`"finding"`).ColumnExpr(`"closed_run_id"`).
			Where(`"build_id" = ?`, f.build).Where(`"id" <> ?`, match).Scan(ctx, &replacementRun); err != nil {
			t.Fatal(err)
		}
		went := append(compared.Fixed, compared.Closed...)
		if len(went) != 1 || went[0].ClosedRun != replacementRun {
			t.Errorf("the comparison says %+v went, want it gone by the replacement's run %d", went, replacementRun)
		}
	})
}

func TestACheckWritesNothingTheReplacedInventoryHadPatched(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		f.published(t, "CVE-2026-0016", f.arrived.Add(24*time.Hour))
		if _, err := fixture.RecordClaims(ctx, f.db.DB, f.build, f.old, []sbom.Suppression{{
			Vulnerability: "CVE-2026-0016", Status: sbom.AlreadyFixed,
			Targets: []sbom.Target{{Name: libnl.Name, Version: libnl.Version}},
			Origin:  sbom.FromStatement,
		}}, map[sbom.Origin]bool{sbom.FromStatement: true, sbom.FromPedigree: true}); err != nil {
			t.Fatal(err)
		}
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0016", libnl)}}
		if checking := f.check(t, s); checking == nil || checking.Checked.Recorded != 0 {
			t.Fatalf("checked %+v, want nothing recorded: it was never exposed", checking)
		}
	})
}

func TestACheckLeavesOutWhatWasPublishedAfterTheReplacement(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f := replacedInventory(t, w)
		f.published(t, "CVE-2026-0017", f.replaced.Add(time.Hour))
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0017", libnl)}}
		if checking := f.check(t, s); checking == nil || checking.Checked.Recorded != 0 {
			t.Fatalf("checked %+v, want nothing recorded", checking)
		}
	})
}

func TestACheckOpensNoEarlierThanTheInventoryArrived(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		// Data a day older than the inventory, and an issue published between.
		if _, err := f.db.NewUpdate().Table("scan_run").
			Set(`"database_version" = ?`, f.arrived.Add(-24*time.Hour).Format(time.RFC3339)).
			Where(`"build_id" = ?`, f.build).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		f.published(t, "CVE-2026-0018", f.arrived.Add(-12*time.Hour))
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0018", libnl)}}
		if checking := f.check(t, s); checking == nil || checking.Checked.Recorded != 1 {
			t.Fatalf("checked %+v, want one recorded", checking)
		}
		if got, _ := matchOf(t, f); !got.OpenedAt.Equal(f.arrived) {
			t.Errorf("opened at %s, want the inventory's arrival %s", got.OpenedAt, f.arrived)
		}
	})
}

func TestACheckWritesNothingARowCoversOverPartOfTheStretch(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		f.published(t, "CVE-2026-0019", f.arrived.Add(24*time.Hour))
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0019", libnl)}}
		if checking := f.check(t, s); checking == nil || checking.Checked.Recorded != 1 {
			t.Fatalf("the first check recorded %+v, want 1", checking)
		}
		// The row now covers only the second half of the stretch.
		if _, err := f.db.NewUpdate().Table("finding").Set(`"opened_at" = ?`, f.arrived.Add(48*time.Hour)).
			Where(`"build_id" = ?`, f.build).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if checking := f.check(t, s); checking == nil || checking.Checked.Recorded != 0 {
			t.Fatalf("the second check recorded %+v, want nothing", checking)
		}
	})
}

func TestACheckWhoseJobFailedIsNotAskedForAgain(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		schedule := scanner.NewSchedule(f.db, f.queue, quiet, "test")
		cycle := func() {
			t.Helper()
			if err := queue.NewLeases(f.db.DB).Release(ctx, scanner.ScheduleLease, "test"); err != nil {
				t.Fatal(err)
			}
			if _, err := schedule.Once(ctx); err != nil {
				t.Fatal(err)
			}
		}
		// A scan with data new enough makes the check owed.
		s := &dated{at: time.Now().UTC()}
		f.waiting(t)
		if _, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").Once(ctx); err != nil {
			t.Fatal(err)
		}
		cycle()
		checks := func(state queue.State) int {
			t.Helper()
			n, err := f.db.NewSelect().Table("job").Where(`"kind" = ?`, queue.Check).
				Where(`"state" = ?`, state).Count(ctx)
			if err != nil {
				t.Fatal(err)
			}
			return int(n)
		}
		if checks(queue.Pending) != 1 {
			t.Fatalf("%d checks asked for, want the one owed", checks(queue.Pending))
		}
		if _, err := f.db.NewUpdate().Table("job").Set(`"state" = ?`, queue.Failed).
			Where(`"kind" = ?`, queue.Check).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		cycle()
		if n := checks(queue.Pending); n != 0 {
			t.Errorf("%d checks asked for again after the job failed, want none until it is put back", n)
		}
	})
}

func TestACheckRunIsNeverABuildsLastScan(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		f.published(t, "CVE-2026-0020", f.arrived.Add(24*time.Hour))
		// Both uploads read when they arrived, so a run finishing after the
		// replacement's would answer it.
		for scan, at := range map[int64]time.Time{f.old: f.arrived, f.replacement: f.replaced} {
			job, err := f.queue.Add(ctx, queue.Parse, strconv.FormatInt(scan, 10))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.NewUpdate().Table("job").Set(`"state" = ?`, queue.Done).
				Set(`"updated_at" = ?`, at).Where(`"id" = ?`, job.ID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0020", libnl)}}
		checking := f.check(t, s)
		if checking == nil {
			t.Fatal("nothing was checked")
		}
		// The build's own scan was ten days ago; the check just now is not one.
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if _, err := scanner.NewSchedule(f.db, f.queue, quiet, "test").Once(ctx); err != nil {
			t.Fatal(err)
		}
		if f.queued(t) != 1 {
			t.Error("the build is not asked to be scanned again: the check read as its last scan")
		}
		receipts, _, err := ingest.NewStore(f.db.DB).Receipts(ctx, access.Everything("a test reading receipts"), f.build, 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range receipts {
			if (r.RunID != nil && *r.RunID == checking.RunID) || (r.Measured != nil && r.Measured.ID == checking.RunID) {
				t.Errorf("upload %d answers from the check run as its scan", r.Scan.ID)
			}
		}
	})
}

// remediationOf is the build's product's remediation figures over all time.
func remediationOf(t *testing.T, w *fixture.World, f *checkFixture) *finding.Remediation {
	t.Helper()
	ctx := t.Context()
	var productID int64
	if err := f.db.NewSelect().TableExpr(`"build" AS "b"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "b"."branch_or_tag_id"`).
		ColumnExpr(`"st"."product_id"`).Where(`"b"."id" = ?`, f.build).Scan(ctx, &productID); err != nil {
		t.Fatal(err)
	}
	person := w.DeclarePerson("remediation-reader@example.com", "Remediation reader", false)
	who := access.NewPerson(person.ID, "remediation-reader@example.com", false,
		map[int64][]access.Role{productID: {access.PublicRead}}, person.PartyID)
	got, err := finding.NewStore(f.db.DB).Remediation(ctx, who, finding.Scope{ProductID: &productID},
		time.Time{}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestADatedCheckMatchCountsAsAFixTimedFromItsOpening(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f := replacedInventory(t, w)
		f.published(t, "CVE-2026-0021", f.arrived.Add(24*time.Hour))
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0021", libnl)}}
		if checking := f.check(t, s); checking == nil || checking.Checked.Recorded != 1 {
			t.Fatalf("checked %+v, want one recorded", checking)
		}
		got := remediationOf(t, w, f)
		if got.Fixed != 1 {
			t.Errorf("%d fixed, want the check's match", got.Fixed)
		}
		if took := got.TimeToFix["high"]; took != 48*time.Hour {
			t.Errorf("took %s to fix, want the two days from publication to the replacement", took)
		}
		if got.Opened != 1 {
			t.Errorf("%d opened, want the check's match: a counted fix was also opened", got.Opened)
		}
	})
}

func TestAnUndatedCheckMatchIsInNoRemediationFigure(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f, _ := undatedMatch(t, w)
		if got := remediationOf(t, w, f); got.Fixed != 0 || len(got.TimeToFix) != 0 || got.Opened != 0 {
			t.Errorf("fixed %d taking %v, opened %d, want nothing: its opening is a guess",
				got.Fixed, got.TimeToFix, got.Opened)
		}
	})
}

func TestAWithdrawnCheckMatchIsInNoRemediationFigure(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f, _ := undatedMatch(t, w)
		redate(t, f, f.replaced)
		if got := remediationOf(t, w, f); got.Fixed != 0 || len(got.TimeToFix) != 0 || got.Opened != 0 {
			t.Errorf("fixed %d taking %v, opened %d, want nothing: it was never exposed",
				got.Fixed, got.TimeToFix, got.Opened)
		}
	})
}

func TestARowRecordedClosedByOneScanIsStillNoFix(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		f.published(t, "CVE-2026-0022", f.arrived.Add(24*time.Hour))
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0022", libnl)}}
		checking := f.check(t, s)
		if checking == nil || checking.Checked.Recorded != 1 {
			t.Fatalf("checked %+v, want one recorded", checking)
		}
		// The same row, as an ordinary scan records one closed on arrival.
		if _, err := f.db.NewUpdate().Table("scan_run").Set(`"checked_scan_id" = NULL`).
			Where(`"id" = ?`, checking.RunID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if got := remediationOf(t, w, f); got.Fixed != 0 || len(got.TimeToFix) != 0 {
			t.Errorf("fixed %d taking %v, want nothing: it was never open", got.Fixed, got.TimeToFix)
		}
	})
}
