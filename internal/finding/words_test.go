// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// heldWords is every copy of reasoning the deployment stores.
func (f *fixture) heldWords(t *testing.T) []finding.Words {
	t.Helper()
	var rows []finding.Words
	if err := f.db.DB.NewSelect().Model(&rows).Order("id").Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestAStatementNamingManyComponentsStoresItsReasoningOnce(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		const named = 300
		reasoning := strings.Repeat("the vulnerable function is never compiled in. ", 200)
		claim := aClaim("CVE-2026-1", sbom.NotAffected, libnl, sbom.FromStatement)
		claim.Statement = reasoning
		claim.Targets = nil
		for i := range named {
			claim.Targets = append(claim.Targets, sbom.Target{Name: fmt.Sprintf("component-%d", i)})
		}
		applied, err := world.RecordClaims(t.Context(), f.db, f.target, f.lastScan,
			[]sbom.Suppression{claim}, everyOrigin)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Opened != named {
			t.Fatalf("opened %d claims, want one per component named", applied.Opened)
		}
		held := f.heldWords(t)
		if len(held) != 1 || held[0].Words != reasoning {
			t.Fatalf("the reasoning is stored as %d copies, want one", len(held))
		}
		for _, row := range f.openClaims(t) {
			if row.StatementID == nil || *row.StatementID != held[0].ID {
				t.Fatalf("a claim does not point at the stored reasoning: %+v", row)
			}
		}

		// And every reader joins it back.
		who := f.holding(t, access.PublicRead)
		rows, _, err := f.store.CarriedPatches(t.Context(), who, f.target, "component-7", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Statement != reasoning {
			t.Errorf("the carried claim reads back as %+v, want its reasoning", rows)
		}
	})
}

func TestReasoningLongerThanTheBoundIsCutAndStored(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		// A three-byte character straddles the bound, so the cut has to
		// land on a character rather than inside one.
		said := strings.Repeat("a", finding.MostWords-1) + "€" + strings.Repeat("b", 1000)
		claim := aClaim("CVE-2026-1", sbom.NotAffected, libnl, sbom.FromStatement)
		claim.Statement = said
		claim.Justification = strings.Repeat("j", 500)
		claim.Vulnerability = "CVE-2026-1" + strings.Repeat("9", 500)
		if _, err := world.RecordClaims(t.Context(), f.db, f.target, f.lastScan,
			[]sbom.Suppression{claim}, everyOrigin); err != nil {
			t.Fatalf("an over-long statement refused the scan: %v", err)
		}
		held := f.heldWords(t)
		if len(held) != 1 {
			t.Fatalf("%d copies of the reasoning, want one", len(held))
		}
		if got := held[0].Words; len(got) > finding.MostWords || !utf8.ValidString(got) ||
			!strings.HasPrefix(said, got) || len(got) < finding.MostWords-3 {
			t.Errorf("the reasoning was kept as %d bytes, want the first %d cut on a character",
				len(got), finding.MostWords)
		}
		open := f.openClaims(t)
		if len(open) != 1 || utf8.RuneCountInString(open[0].Justification) != 191 ||
			utf8.RuneCountInString(open[0].Vulnerability) != 191 {
			t.Errorf("the identifier and the term were not cut to their columns: %+v", open)
		}

		// The same over-long document read again is the same claim.
		f.shipped(t, twoConsumers())
		applied, err := world.RecordClaims(t.Context(), f.db, f.target, f.lastScan,
			[]sbom.Suppression{claim}, everyOrigin)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Opened != 0 || applied.Closed != 0 {
			t.Errorf("re-sending an over-long statement wrote %+v", applied)
		}
	})
}

func TestReasoningCarryingANulIsStoredWithoutIt(t *testing.T) {
	// PostgreSQL refuses the character in text, so a statement carrying one
	// would fail the scan there and nowhere else.
	if got := finding.WordsOf("patched\x00 upstream\xff"); got != "patched upstream�" {
		t.Errorf("WordsOf = %q", got)
	}
}

func TestAChangedExplanationIsANewClaim(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		claim := aClaim("CVE-2026-1", sbom.AlreadyFixed, libnl, sbom.FromPedigree)
		claim.Statement = "fixed by patch 0007"
		if _, err := world.RecordClaims(t.Context(), f.db, f.target, f.lastScan,
			[]sbom.Suppression{claim}, everyOrigin); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, twoConsumers())
		claim.Statement = "fixed by patch 0008"
		applied, err := world.RecordClaims(t.Context(), f.db, f.target, f.lastScan,
			[]sbom.Suppression{claim}, everyOrigin)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Opened != 1 || applied.Closed != 1 {
			t.Fatalf("changing only the explanation wrote %+v, want the old claim closed and the new opened",
				applied)
		}
		who := f.holding(t, access.PublicRead)
		rows, _, err := f.store.CarriedPatches(t.Context(), who, f.target, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 || rows[0].Statement != "fixed by patch 0008" || rows[0].Until != nil ||
			rows[1].Statement != "fixed by patch 0007" || rows[1].Until == nil {
			t.Errorf("the history reads %+v, want the new explanation standing and the old one ended", rows)
		}
	})
}

func TestTwoAddressesDifferingOnlyPastTheIndexWidthOrInCaseAreBothKept(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		long := "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/" +
			strings.Repeat("x", 200) + "?id="
		references := []finding.Reference{
			{URL: long + "aaaa", Kind: finding.Patch},
			{URL: long + "bbbb", Kind: finding.Patch},
			{URL: "https://lore.kernel.org/r/AbCd@example", Kind: finding.Report},
			{URL: "https://lore.kernel.org/r/abcd@example", Kind: finding.Report},
		}
		vulnerabilities := finding.NewVulnerabilities(f.db.DB)
		everyone := access.Everything("reading back every address held")
		interned, err := vulnerabilities.Intern(ctx, []finding.Named{
			{Identifier: "CVE-2026-1", References: references},
		})
		if err != nil {
			t.Fatal(err)
		}
		held, err := vulnerabilities.PointsAtFor(ctx, everyone, interned["CVE-2026-1"])
		if err != nil {
			t.Fatal(err)
		}
		if len(held) != len(references) {
			t.Fatalf("%d addresses are held, want all %d", len(held), len(references))
		}

		// And reporting them again writes nothing more.
		if _, err := vulnerabilities.Intern(ctx, []finding.Named{
			{Identifier: "CVE-2026-1", References: references},
		}); err != nil {
			t.Fatal(err)
		}
		again, err := vulnerabilities.PointsAtFor(ctx, everyone, interned["CVE-2026-1"])
		if err != nil {
			t.Fatal(err)
		}
		if len(again) != len(references) {
			t.Errorf("reporting the same addresses again holds %d", len(again))
		}
	})
}
