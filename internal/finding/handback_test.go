// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// heldEverywhere puts one of each kind of work in one party's hands: an
// undisclosed vulnerability, a security testing code finding, a disclosed vulnerability, and
// a vulnerability report.
func (f *fixture) heldEverywhere(t *testing.T, party int64) {
	t.Helper()
	ctx := t.Context()
	f.shipped(t, twoConsumers())
	if _, err := f.store.Apply(ctx, f.build, f.run(t), []finding.Reported{
		found("CVE-2026-1", libnl), found("CVE-2026-2", libnl), found("CVE-2026-3", libnl),
	}); err != nil {
		t.Fatal(err)
	}
	for identifier, set := range map[string][2]string{
		"CVE-2026-1": {"vulnerability", string(access.Private)},
		"CVE-2026-2": {"analysis", string(access.SecurityTesting)},
	} {
		if _, err := f.db.DB.NewUpdate().Table("finding").
			Set(`"kind" = ?`, set[0]).Set(`"visibility" = ?`, set[1]).
			Where(`"vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "identifier" = ?)`, identifier).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := f.db.DB.NewUpdate().Table("finding").
		Set(`"assigned_to" = ?`, party).Set(`"assigned_at" = ?`, now).
		Where(`"closed_at" IS NULL`).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	recorder := f.holder(t, "recorder@example.com", access.PrivateTriage)
	row := f.aReport(t, recorder, "Something.")
	if _, err := f.db.DB.NewUpdate().Table("flaw_report").
		Set(`"assigned_to" = ?`, party).Set(`"assigned_at" = ?`, now).
		Where(`"id" = ?`, row.ID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
}

// stillHeld names what one party still holds: a visibility for each finding
// or code finding held at it, and "report" for a report.
func (f *fixture) stillHeld(t *testing.T, party int64) []string {
	t.Helper()
	ctx := t.Context()
	var visibilities []string
	if err := f.db.DB.NewSelect().Table("finding").ColumnExpr(`DISTINCT "visibility"`).
		Where(`"assigned_to" = ?`, party).Where(`"closed_at" IS NULL`).
		Scan(ctx, &visibilities); err != nil {
		t.Fatal(err)
	}
	reports, err := f.db.DB.NewSelect().Table("flaw_report").
		Where(`"assigned_to" = ?`, party).Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if reports > 0 {
		visibilities = append(visibilities, "report")
	}
	slices.Sort(visibilities)
	return visibilities
}

func held(names ...string) []string {
	slices.Sort(names)
	return names
}

// A person gives up what each withdrawn role let them read, and everything
// once nothing is left: undisclosed work and reports with the undisclosed
// role, security testing code findings with the security testing one, and disclosed work with the
// last role of all.
func TestAPersonHandsBackWhatTheyMayNoLongerRead(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.holder(t, "holder@example.com",
			access.PublicTriage, access.PrivateTriage, access.SecurityTestingRead)
		party := who.Party()
		f.heldEverywhere(t, party)
		rights := access.NewStore(f.db.DB)
		for _, step := range []struct {
			withdrawn access.Role
			want      []string
		}{
			{"", held("security-testing", "private", "public", "report")},
			{access.PrivateTriage, held("security-testing", "public")},
			{access.SecurityTestingRead, held("public")},
			{access.PublicTriage, nil},
		} {
			if step.withdrawn != "" {
				if err := rights.Withdraw(ctx, who.ID, f.productID, step.withdrawn); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.store.HandBackUnread(ctx, access.Narrowed{People: []int64{who.ID}}); err != nil {
				t.Fatal(err)
			}
			if got := f.stillHeld(t, party); !slices.Equal(got, step.want) {
				t.Errorf("after withdrawing %q they hold %v, want %v", step.withdrawn, got, step.want)
			}
		}
	})
}

// A team gives up what no member still reads, whichever way the reading
// went: a member taken off, a member's role withdrawn, a member deactivated,
// or the team retired.
func TestATeamHandsBackWhatNoMemberStillReads(t *testing.T) {
	type members struct{ product, team, private, securityTesting int64 }
	for name, c := range map[string]struct {
		act  func(t *testing.T, rights *access.Store, m members) access.Narrowed
		want []string
	}{
		"nothing changed": {
			func(*testing.T, *access.Store, members) access.Narrowed { return access.Narrowed{} },
			held("security-testing", "private", "public", "report"),
		},
		"a member taken off": {
			func(t *testing.T, rights *access.Store, m members) access.Narrowed {
				if err := rights.RemoveFromTeam(t.Context(), m.team, m.private); err != nil {
					t.Fatal(err)
				}
				return access.Narrowed{Teams: []int64{m.team}}
			},
			held("security-testing", "public"),
		},
		"a member's role withdrawn": {
			func(t *testing.T, rights *access.Store, m members) access.Narrowed {
				if err := rights.Withdraw(t.Context(), m.securityTesting, m.product, access.SecurityTestingRead); err != nil {
					t.Fatal(err)
				}
				return access.Narrowed{People: []int64{m.securityTesting}}
			},
			held("private", "public", "report"),
		},
		"a member deactivated": {
			func(t *testing.T, rights *access.Store, m members) access.Narrowed {
				if _, err := rights.Deactivate(t.Context(), m.private); err != nil {
					t.Fatal(err)
				}
				return access.Narrowed{People: []int64{m.private}}
			},
			held("security-testing", "public"),
		},
		"the team retired": {
			func(t *testing.T, rights *access.Store, m members) access.Narrowed {
				if err := rights.RetireTeam(t.Context(), m.team); err != nil {
					t.Fatal(err)
				}
				return access.Narrowed{Teams: []int64{m.team}}
			},
			nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				ctx := t.Context()
				rights := access.NewStore(f.db.DB)
				team, err := rights.DeclareTeam(ctx, "desk", "Desk")
				if err != nil {
					t.Fatal(err)
				}
				m := members{product: f.productID, team: team.ID}
				for _, one := range []struct {
					at    *int64
					name  string
					roles []access.Role
				}{
					{&m.private, "private@example.com", []access.Role{access.PublicRead, access.PrivateRead}},
					{&m.securityTesting, "security-testing@example.com", []access.Role{access.PublicRead, access.SecurityTestingRead}},
				} {
					*one.at = f.holder(t, one.name, one.roles...).ID
					if _, err := rights.AddToTeam(ctx, team.ID, *one.at, *one.at); err != nil {
						t.Fatal(err)
					}
				}
				f.heldEverywhere(t, team.PartyID)
				narrowed := c.act(t, rights, m)
				if _, err := f.store.HandBackUnread(ctx, narrowed); err != nil {
					t.Fatal(err)
				}
				if got := f.stillHeld(t, team.PartyID); !slices.Equal(got, c.want) {
					t.Errorf("the team holds %v, want %v", got, c.want)
				}
			})
		})
	}
}

// A sign-in whose groups no longer grant a role hands back what that role let
// them read, inside the sign-in's own write.
func TestASignInThatTakesARoleAwayHandsBackWhatItCovered(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		var product string
		if err := f.db.DB.NewSelect().Table("product").Column("name").
			Where(`"id" = ?`, f.productID).Scan(ctx, &product); err != nil {
			t.Fatal(err)
		}
		rights := access.NewStore(f.db.DB).HandingBack(finding.HandBack)
		if _, err := rights.ApplyMappings(ctx, []access.Mapping{
			{Group: "platform", Grants: string(access.PublicTriage), Product: product},
			{Group: "security", Grants: string(access.PrivateTriage), Product: product},
			{Group: "analysts", Grants: string(access.SecurityTestingRead), Product: product},
		}); err != nil {
			t.Fatal(err)
		}
		who := access.Arrival{ViaProxy: true, Username: "someone"}
		subject, err := rights.AdmitByGroups(ctx, who, []string{"platform", "security", "analysts"})
		if err != nil {
			t.Fatal(err)
		}
		party := subject.Party()
		f.heldEverywhere(t, party)
		for _, step := range []struct {
			groups []string
			want   []string
		}{
			{[]string{"platform", "security", "analysts"}, held("security-testing", "private", "public", "report")},
			{[]string{"platform", "analysts"}, held("security-testing", "public")},
			{[]string{"platform"}, held("public")},
		} {
			if _, err := rights.AdmitByGroups(ctx, who, step.groups); err != nil {
				t.Fatal(err)
			}
			if got := f.stillHeld(t, party); !slices.Equal(got, step.want) {
				t.Errorf("signed in through %v they hold %v, want %v", step.groups, got, step.want)
			}
		}
	})
}

// modeWorld gives two people accounts a sign-in recognizes and roles an
// administrator assigned, with the work of heldEverywhere split between them:
// the public finding and the security testing code finding with the first, the undisclosed
// finding and the report with the second. Both start in direct mode.
func (f *fixture) modeWorld(t *testing.T, rights *access.Store, groups []access.Mapping,
	first, second []access.Role) (access.Subject, access.Subject) {
	t.Helper()
	ctx := t.Context()
	if _, err := rights.ApplyMappings(ctx, groups); err != nil {
		t.Fatal(err)
	}
	var people [2]access.Subject
	for i, name := range []string{"first", "second"} {
		subject, err := rights.AdmitByGroups(ctx, access.Arrival{ViaProxy: true, Username: name},
			[]string{groups[0].Group})
		if err != nil {
			t.Fatal(err)
		}
		people[i] = subject
	}
	if err := rights.SwitchTo(ctx, access.Direct); err != nil {
		t.Fatal(err)
	}
	for i, roles := range [][]access.Role{first, second} {
		for _, role := range roles {
			if err := rights.GrantRole(ctx, people[i].ID, f.productID, role); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.heldEverywhere(t, people[0].Party())
	if _, err := f.db.DB.NewUpdate().Table("finding").
		Set(`"assigned_to" = ?`, people[1].Party()).
		Where(`"closed_at" IS NULL`).Where(`"visibility" = ?`, access.Private).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DB.NewUpdate().Table("flaw_report").
		Set(`"assigned_to" = ?`, people[1].Party()).
		Where(`"assigned_to" = ?`, people[0].Party()).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return people[0], people[1]
}

func (f *fixture) productName(t *testing.T) string {
	t.Helper()
	var product string
	if err := f.db.DB.NewSelect().Table("product").Column("name").
		Where(`"id" = ?`, f.productID).Scan(t.Context(), &product); err != nil {
		t.Fatal(err)
	}
	return product
}

// The way into group-bound mode hands nothing back, and each person's first
// sign-in after it hands back what their groups do not let them read.
// Somebody whose groups cover their work keeps it.
func TestSwitchingIntoGroupBoundModeHandsBackAtEachFirstSignIn(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		rights := access.NewStore(f.db.DB).HandingBack(finding.HandBack)
		product := f.productName(t)
		first, second := f.modeWorld(t, rights, []access.Mapping{
			{Group: "platform", Grants: string(access.PublicTriage), Product: product},
			{Group: "security", Grants: string(access.PrivateTriage), Product: product},
			{Group: "analysts", Grants: string(access.SecurityTestingRead), Product: product},
		},
			[]access.Role{access.PublicTriage, access.SecurityTestingRead},
			[]access.Role{access.PublicTriage, access.PrivateTriage})

		if err := rights.SwitchTo(ctx, access.GroupBound); err != nil {
			t.Fatal(err)
		}
		for _, one := range []struct {
			who  access.Subject
			want []string
		}{
			{first, held("security-testing", "public")},
			{second, held("private", "report")},
		} {
			if got := f.stillHeld(t, one.who.Party()); !slices.Equal(got, one.want) {
				t.Errorf("into group-bound mode, before signing in, %s holds %v, want %v",
					one.who.Identity, got, one.want)
			}
		}

		for _, one := range []struct {
			who    access.Subject
			groups []string
			want   []string
		}{
			{first, []string{"platform"}, held("public")},
			{second, []string{"platform", "security"}, held("private", "report")},
		} {
			if _, err := rights.AdmitByGroups(ctx,
				access.Arrival{ViaProxy: true, Username: one.who.Identity}, one.groups); err != nil {
				t.Fatal(err)
			}
			if got := f.stillHeld(t, one.who.Party()); !slices.Equal(got, one.want) {
				t.Errorf("first signed in through %v, %s holds %v, want %v",
					one.groups, one.who.Identity, got, one.want)
			}
		}
	})
}

// The way out of group-bound mode hands back at once what each person's
// restored assignments do not let them read. Somebody whose assignments cover
// their work keeps it.
func TestSwitchingOutOfGroupBoundModeHandsBackWhatTheAssignedRolesDoNotCover(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		rights := access.NewStore(f.db.DB).HandingBack(finding.HandBack)
		product := f.productName(t)
		groups := []string{"platform", "security", "analysts"}
		first, second := f.modeWorld(t, rights, []access.Mapping{
			{Group: "platform", Grants: string(access.PublicTriage), Product: product},
			{Group: "security", Grants: string(access.PrivateTriage), Product: product},
			{Group: "analysts", Grants: string(access.SecurityTestingRead), Product: product},
		}, nil, []access.Role{access.PublicTriage, access.PrivateTriage})

		if err := rights.SwitchTo(ctx, access.GroupBound); err != nil {
			t.Fatal(err)
		}
		for _, who := range []access.Subject{first, second} {
			if _, err := rights.AdmitByGroups(ctx,
				access.Arrival{ViaProxy: true, Username: who.Identity}, groups); err != nil {
				t.Fatal(err)
			}
		}
		if got := f.stillHeld(t, first.Party()); !slices.Equal(got, held("security-testing", "public")) {
			t.Fatalf("signed in through every group, the first holds %v", got)
		}

		if err := rights.SwitchTo(ctx, access.Direct); err != nil {
			t.Fatal(err)
		}
		if got := f.stillHeld(t, first.Party()); len(got) != 0 {
			t.Errorf("out of group-bound mode, somebody with no assigned role holds %v", got)
		}
		if got := f.stillHeld(t, second.Party()); !slices.Equal(got, held("private", "report")) {
			t.Errorf("out of group-bound mode, somebody whose assigned roles cover their work holds %v", got)
		}
	})
}

// Work a holder still reads stays with them, so asking about somebody whose
// reading did not change moves nothing.
func TestAHandBackMovesNothingStillRead(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.holder(t, "holder@example.com",
			access.PublicTriage, access.PrivateTriage, access.SecurityTestingRead)
		f.heldEverywhere(t, who.Party())
		before := f.stillHeld(t, who.Party())
		for _, narrowed := range []access.Narrowed{
			{People: []int64{who.ID}}, {Everybody: true},
		} {
			moved, err := f.store.HandBackUnread(ctx, narrowed)
			if err != nil || moved != 0 {
				t.Errorf("asking about %+v moved %d (%v)", narrowed, moved, err)
			}
		}
		if got := f.stillHeld(t, who.Party()); !slices.Equal(got, before) {
			t.Errorf("they hold %v, want %v", got, before)
		}
	})
}
