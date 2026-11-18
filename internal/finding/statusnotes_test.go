// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// A claim's status notes are kept beside it whatever its status, and travel
// with it: on the build's own claim, on a received statement, and on the
// claim a statement about the build's root becomes.

// noted is a claim about zlib inside Y at the status given, with status notes
// and no other words.
func noted(status sbom.Status, notes string) sbom.Suppression {
	claim := insideOf(status, acmeY, "")
	claim.Justification = ""
	claim.Notes = notes
	return claim
}

func TestAFindingShowsTheBuildsStatusNotesBesideItsClaim(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.argues(t, noted(sbom.UnderInvestigation, "Reproducing against the 4.2 image"))
		f.reported(t, found(inside, zlib))
		who := f.holding(t, access.PublicTriage)
		for _, row := range f.open(t) {
			if row.ClaimedBy == nil {
				continue
			}
			evidence, err := f.store.Detail(t.Context(), who, f.build, row.VulnerabilityID, row.ComponentID)
			if err != nil {
				t.Fatal(err)
			}
			if len(evidence.Claimed) != 1 || evidence.Claimed[0].Notes != "Reproducing against the 4.2 image" ||
				evidence.Claimed[0].Statement != "" {
				t.Errorf("shown %+v, want the build's status notes and no other words", evidence.Claimed)
			}
			return
		}
		t.Fatal("no finding names the build's claim")
	})
}

func TestAStatementAboutTheBuildsRootKeepsItsStatusNotesAsTheBuildsClaim(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.rooted(t, rootPurl)
		claim := noted(sbom.NotAffected, "Checked against the shipped configuration")
		target := claim.Targets[0]
		target.Within = &sbom.Target{Purl: rootPurl, Name: "sonic"}
		f.publishes(t, []finding.Statement{finding.StatementOf(claim, target)}, "sha256:vendor-1")
		f.reported(t, found(inside, zlib))
		who := f.holding(t, access.PublicTriage)
		open := f.open(t)
		evidence, err := f.store.Detail(t.Context(), who, f.build, open[0].VulnerabilityID, open[0].ComponentID)
		if err != nil {
			t.Fatal(err)
		}
		if len(evidence.Claimed) != 1 || evidence.Claimed[0].Notes != "Checked against the shipped configuration" {
			t.Errorf("shown %+v, want the vendor's status notes on the build's claim", evidence.Claimed)
		}
	})
}

// Notes are part of what a claim says: a build changing only its notes
// withdraws the claim and makes the new one, and saying the same again writes
// nothing.
func TestABuildChangingOnlyItsStatusNotesMakesAnotherClaim(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.argues(t, noted(sbom.AlreadyFixed, "Backported in 4.2-3"))
		claims := f.openClaims(t)
		if len(claims) != 1 || claims[0].NotesID == nil {
			t.Fatalf("%+v open, want one claim pointing at its notes", claims)
		}
		applied, err := world.RecordClaims(t.Context(), f.db, f.build, f.lastScan,
			[]sbom.Suppression{noted(sbom.AlreadyFixed, "Backported in 4.2-3")}, everyOrigin)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Opened != 0 || applied.Closed != 0 {
			t.Errorf("saying the same notes again opened %d and closed %d", applied.Opened, applied.Closed)
		}
		applied, err = world.RecordClaims(t.Context(), f.db, f.build, f.lastScan,
			[]sbom.Suppression{noted(sbom.AlreadyFixed, "Backported in 4.2-4")}, everyOrigin)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Opened != 1 || applied.Closed != 1 {
			t.Errorf("changing only the notes opened %d and closed %d, want one of each",
				applied.Opened, applied.Closed)
		}
	})
}

// A publisher's status notes are kept with the statement and read back with
// it, bounded as its reasoning is, and a revision changing only the notes sets
// the earlier statement aside.
func TestAReceivedStatementKeepsItsStatusNotes(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		long := strings.Repeat("n", finding.MostWords+100)
		claim := noted(sbom.AlreadyFixed, long)
		f.publishes(t, []finding.Statement{finding.StatementOf(claim, claim.Targets[0])}, "sha256:vendor-1")
		said := f.standingStatements(t)
		if len(said) != 1 || said[0].Notes != finding.WordsOf(long) || len(said[0].Notes) != finding.MostWords {
			t.Fatalf("%d statements stand, the first with %d bytes of notes, want one cut to %d",
				len(said), len(said[0].Notes), finding.MostWords)
		}

		claim.Notes = "Fixed in 4.2-3"
		f.publishes(t, []finding.Statement{finding.StatementOf(claim, claim.Targets[0])}, "sha256:vendor-2")
		said = f.standingStatements(t)
		if len(said) != 1 || said[0].Notes != "Fixed in 4.2-3" {
			t.Errorf("%d statements stand after the revision, the first with %d bytes of notes, "+
				"want the revised notes alone", len(said), len(said[0].Notes))
		}
	})
}

// standingStatements is every received statement in force in the product,
// with its words.
func (f *fixture) standingStatements(t *testing.T) []finding.Statement {
	t.Helper()
	var rows []finding.Statement
	if err := f.db.DB.NewSelect().Model(&rows).
		Column("id", "status").
		Join(finding.NotesJoin("ss")).ColumnExpr(finding.NotesColumn+` AS "notes"`).
		Where(`"ss"."product_id" = ?`, f.productID).Where(`"ss"."superseded_at" IS NULL`).
		Order("ss.id").Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return rows
}

// upstreamSays records an upstream's document about zlib in the product, its
// one statement giving the notes given, under the digest given.
func (f *fixture) upstreamSays(t *testing.T, notes, digest string) {
	t.Helper()
	claim := noted(sbom.NotAffected, notes)
	who := f.planner(t, access.PublicTriage)
	if _, _, err := f.store.RecordStatements(t.Context(), who, f.productID, finding.Supplied{
		Source: finding.FromUpstream, Publisher: "Example Upstream", Identifier: "VEX-upstream-zlib",
		Document: "https://upstream.example.test/zlib.json", Digest: digest,
	}, []finding.Statement{finding.StatementOf(claim, claim.Targets[0])}); err != nil {
		t.Fatal(err)
	}
}

// standingRow is the one statement in force in the product, with when it was
// declined.
func (f *fixture) standingRow(t *testing.T) finding.Statement {
	t.Helper()
	var rows []finding.Statement
	if err := f.db.DB.NewSelect().Model(&rows).
		Column("id", "declined_at").
		Join(finding.NotesJoin("ss")).ColumnExpr(finding.NotesColumn+` AS "notes"`).
		Where(`"ss"."product_id" = ?`, f.productID).Where(`"ss"."superseded_at" IS NULL`).
		Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d statements stand, want one", len(rows))
	}
	return rows[0]
}

// A statement stored holding no notes, read again from a document now giving
// them, keeps its row and its decline and takes the notes.
func TestAStatementGainingStatusNotesKeepsItsRowAndItsDecline(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.upstreamSays(t, "", "sha256:upstream-1")
		before := f.standingRow(t)
		if _, err := f.store.Decline(t.Context(), f.planner(t, access.PublicTriage), before.ID); err != nil {
			t.Fatal(err)
		}
		f.upstreamSays(t, "Built without the gzip reader", "sha256:upstream-2")
		after := f.standingRow(t)
		if after.ID != before.ID || after.DeclinedAt == nil || after.Notes != "Built without the gzip reader" {
			t.Errorf("row %d declined at %v with notes %q stands, want row %d still declined with the notes",
				after.ID, after.DeclinedAt, after.Notes, before.ID)
		}
	})
}

// A revision repeating a statement's notes keeps its row, the same bytes read
// again over a row whose notes went missing write them back, and a revision
// giving other notes sets the row aside.
func TestARevisionRepeatingAStatementsNotesKeepsItsRow(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.upstreamSays(t, "Built without the gzip reader", "sha256:upstream-1")
		before := f.standingRow(t)
		f.upstreamSays(t, "Built without the gzip reader", "sha256:upstream-2")
		if after := f.standingRow(t); after.ID != before.ID {
			t.Errorf("repeating the notes set row %d aside for row %d", before.ID, after.ID)
		}

		if _, err := f.db.DB.NewUpdate().Table("received_vex_statement").
			Set(`"notes_id" = NULL`).Where(`"id" = ?`, before.ID).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.upstreamSays(t, "Built without the gzip reader", "sha256:upstream-2")
		if after := f.standingRow(t); after.ID != before.ID || after.Notes != "Built without the gzip reader" {
			t.Errorf("the same bytes again left row %d with notes %q, want row %d with them back",
				after.ID, after.Notes, before.ID)
		}

		// Other notes are another statement: the row is set aside, so what
		// cites it is told.
		f.upstreamSays(t, "Built with the gzip reader turned off", "sha256:upstream-3")
		if after := f.standingRow(t); after.ID == before.ID || after.Notes != "Built with the gzip reader turned off" {
			t.Errorf("other notes left row %d standing with notes %q, want a new row with them",
				after.ID, after.Notes)
		}
	})
}

// A build's notes are text cut to the bound, whatever the producer wrote.
func TestABuildsStatusNotesAreCutToTheBound(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.argues(t, noted(sbom.AlreadyFixed, strings.Repeat("n", finding.MostWords+100)+"\xff"))
		var notes string
		if err := f.db.DB.NewSelect().TableExpr(`"suppression" AS "sup"`).
			Join(finding.NotesJoin("sup")).ColumnExpr(finding.NotesColumn).
			Where(`"sup"."build_id" = ?`, f.build).Scan(t.Context(), &notes); err != nil {
			t.Fatal(err)
		}
		if len(notes) != finding.MostWords || !utf8.ValidString(notes) {
			t.Errorf("stored %d bytes of notes, valid text %v, want %d of valid text",
				len(notes), utf8.ValidString(notes), finding.MostWords)
		}
	})
}

// A claim stored holding no notes, said again with notes, stays open and takes
// them: closed and opened again, its patches would drop out of the published
// documents until the next scan is applied.
func TestABuildsClaimGainingStatusNotesStaysOpen(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.argues(t, noted(sbom.AlreadyFixed, ""))
		before := f.openClaims(t)
		applied, err := world.RecordClaims(t.Context(), f.db, f.build, f.lastScan,
			[]sbom.Suppression{noted(sbom.AlreadyFixed, "Backported in 4.2-3")}, everyOrigin)
		if err != nil {
			t.Fatal(err)
		}
		after := f.openClaims(t)
		if applied.Opened != 0 || applied.Closed != 0 || len(after) != 1 || after[0].ID != before[0].ID ||
			after[0].NotesID == nil {
			t.Errorf("opened %d and closed %d, leaving %+v open, want claim %d open with its notes",
				applied.Opened, applied.Closed, after, before[0].ID)
		}
		// Said again with the same notes, nothing moves.
		applied, err = world.RecordClaims(t.Context(), f.db, f.build, f.lastScan,
			[]sbom.Suppression{noted(sbom.AlreadyFixed, "Backported in 4.2-3")}, everyOrigin)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Opened != 0 || applied.Closed != 0 {
			t.Errorf("saying the notes again opened %d and closed %d", applied.Opened, applied.Closed)
		}
	})
}
