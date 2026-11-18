// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"strings"
	"testing"

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
