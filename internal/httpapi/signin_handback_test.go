// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/signin"
)

// A group-bound sign-in whose groups no longer grant undisclosed reading hands
// back the reports the person held, inside the sign-in's own write.
func TestASignInThatTakesUndisclosedReadingAwayHandsBackTheReportsHeld(t *testing.T) {
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		ctx := t.Context()
		var product string
		if err := r.db.DB.NewSelect().Table("product").Column("name").
			Where(`"id" = ?`, r.product).Scan(ctx, &product); err != nil {
			t.Fatal(err)
		}
		if _, err := r.rights.ApplyMappings(ctx, []access.Mapping{
			{Group: "platform", Grants: string(access.PublicRead), Product: product},
			{Group: "security", Grants: string(access.PrivateTriage), Product: product},
		}); err != nil {
			t.Fatal(err)
		}
		if err := r.rights.SwitchTo(ctx, access.GroupBound); err != nil {
			t.Fatal(err)
		}
		r.mode = access.GroupBound
		signIn := func(groups ...string) {
			t.Helper()
			r.provider.Says = &signin.Identity{Subject: "1", Username: "granted", Groups: groups}
			if rec := callback(t, r, "the-state", "a-code", true); rec.Code != http.StatusFound {
				t.Fatalf("signing in through %v answered %d: %s", groups, rec.Code, rec.Body.String())
			}
		}
		signIn("platform", "security")

		person, err := r.rights.ByIdentity(ctx, "granted")
		if err != nil {
			t.Fatal(err)
		}
		recorder := access.NewPerson(person.ID, "granted", false,
			map[int64][]access.Role{r.product: {access.PrivateTriage}}, person.PartyID)
		row, err := finding.NewStore(r.db.DB).Record(ctx, recorder, r.product, finding.Claimed{
			Title: "A title", Summary: "Something.",
			Told: finding.Told{ReportedBy: "A. Researcher", Contact: "a@example.org", Received: "2026-09-01"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.db.DB.NewUpdate().Table("flaw_report").
			Set(`"assigned_to" = ?`, person.PartyID).Where(`"id" = ?`, row.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		held := func() int {
			t.Helper()
			n, err := r.db.DB.NewSelect().Table("flaw_report").
				Where(`"assigned_to" = ?`, person.PartyID).Count(ctx)
			if err != nil {
				t.Fatal(err)
			}
			return int(n)
		}

		signIn("platform", "security")
		if held() != 1 {
			t.Fatal("a sign-in that took nothing away handed back a report")
		}
		signIn("platform")
		if held() != 0 {
			t.Error("somebody whose groups no longer grant undisclosed reading still holds a report")
		}
	})
}
