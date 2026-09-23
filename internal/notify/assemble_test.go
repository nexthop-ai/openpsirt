// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// A digest built from what somebody actually holds, rather than from a literal.
//
// The message half is tested against a Digest written out by hand, which says
// what the text does with a withheld count and nothing about how a row becomes
// one. Nothing else reaches the half that decides — the branch reading a row
// as undisclosed, the counter behind it, and the item built otherwise — so
// without this, deleting that branch would put the identifier and component of
// an embargoed finding into outbound mail and nothing would fail.
func TestADigestNamesWhatIsDisclosedAndOnlyCountsWhatIsNot(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		holder, err := rights.Ensure(ctx, "holder@example.com", "Hana Holder", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "Hardware Platform Images")
		if err != nil {
			t.Fatal(err)
		}
		// Undisclosed work is what a private role reaches, and reaching it is
		// what makes withholding it a decision rather than an accident of
		// visibility.
		if err := rights.GrantRole(ctx, holder.ID, product.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		branch, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
		if err != nil {
			t.Fatal(err)
		}
		target, err := cat.TargetFor(ctx, branch.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}
		named, err := finding.NewVulnerabilities(db.DB).Intern(ctx, []finding.Named{
			{Identifier: "CVE-2026-8001", Severity: "medium"},
			{Identifier: "SONIC-2026-8002", Severity: "critical"},
		})
		if err != nil {
			t.Fatal(err)
		}

		for i, each := range []struct {
			identifier string
			component  string
			visibility access.Visibility
		}{
			{"CVE-2026-8001", "libnl-3-200", access.Public},
			// The one nobody has announced. Its identifier and the component
			// it is in are what must not leave the building in a message.
			{"SONIC-2026-8002", "sonic-embargoed-driver", access.Private},
		} {
			component := &graph.Component{
				Identity: each.component, Name: each.component, Version: "1.0",
				Purl: "pkg:deb/debian/" + each.component + "@1.0",
			}
			if _, err := db.DB.NewInsert().Model(component).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			row := &finding.Finding{
				TargetID: target.ID, Kind: "dependency",
				VulnerabilityID: named[each.identifier],
				Visibility:      each.visibility, ComponentID: component.ID,
				PlaceIdentity: "place-" + each.component, Urgency: int64(i + 1),
				OpenedAt: time.Now().UTC(), AssignedTo: &holder.PartyID,
			}
			if _, err := db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}

		digest, err := notify.Assemble(ctx, db.DB, holder, 50)
		if err != nil {
			t.Fatalf("assemble: %v", err)
		}

		// The disclosed one is named, because naming it is what makes the
		// message worth opening.
		if len(digest.Mine) != 1 {
			t.Fatalf("the digest names %d of their findings, want the one that is disclosed: %+v",
				len(digest.Mine), digest.Mine)
		}
		if digest.Mine[0].Issue != "CVE-2026-8001" {
			t.Errorf("the digest names %q", digest.Mine[0].Issue)
		}

		// The undisclosed one is a number, and the number says how urgent —
		// "three undisclosed" does not tell somebody whether to open the tool
		// now or after coffee.
		if digest.Withheld.Count != 1 {
			t.Errorf("withheld %d, want the one nobody has announced", digest.Withheld.Count)
		}
		if digest.Withheld.BySeverity["critical"] != 1 {
			t.Errorf("the withheld count says nothing about severity: %v",
				digest.Withheld.BySeverity)
		}

		// And what actually goes out. This is the assertion the whole test is
		// for: neither the identifier nobody has announced nor the component
		// it names may appear in the text of a message.
		text := digest.Message("https://psirt.example").Text
		for _, secret := range []string{"SONIC-2026-8002", "sonic-embargoed-driver"} {
			if strings.Contains(text, secret) {
				t.Errorf("the message carries %q, which nobody has announced:\n%s", secret, text)
			}
		}
		if !strings.Contains(text, "CVE-2026-8001") {
			t.Errorf("the message does not name the finding that is disclosed:\n%s", text)
		}
	})
}
