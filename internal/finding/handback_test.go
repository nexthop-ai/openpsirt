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
// undisclosed vulnerability, an internal lead, a disclosed vulnerability, and
// a vulnerability report.
func (f *fixture) heldEverywhere(t *testing.T, party int64) {
	t.Helper()
	ctx := t.Context()
	f.shipped(t, twoConsumers())
	if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
		found("CVE-2026-1", libnl), found("CVE-2026-2", libnl), found("CVE-2026-3", libnl),
	}); err != nil {
		t.Fatal(err)
	}
	for identifier, set := range map[string][2]string{
		"CVE-2026-1": {"vulnerability", string(access.Private)},
		"CVE-2026-2": {"analysis", string(access.Internal)},
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
// or lead held at it, and "report" for a report.
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
// role, internal leads with the internal one, and disclosed work with the
// last role of all.
func TestAPersonHandsBackWhatTheyMayNoLongerRead(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.holder(t, "holder@example.com",
			access.PublicTriage, access.PrivateTriage, access.InternalRead)
		party := who.Party()
		f.heldEverywhere(t, party)
		rights := access.NewStore(f.db.DB)
		for _, step := range []struct {
			withdrawn access.Role
			want      []string
		}{
			{"", held("internal", "private", "public", "report")},
			{access.PrivateTriage, held("internal", "public")},
			{access.InternalRead, held("public")},
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
	type members struct{ product, team, private, internal int64 }
	for name, c := range map[string]struct {
		act  func(t *testing.T, rights *access.Store, m members) access.Narrowed
		want []string
	}{
		"nothing changed": {
			func(*testing.T, *access.Store, members) access.Narrowed { return access.Narrowed{} },
			held("internal", "private", "public", "report"),
		},
		"a member taken off": {
			func(t *testing.T, rights *access.Store, m members) access.Narrowed {
				if err := rights.RemoveFromTeam(t.Context(), m.team, m.private); err != nil {
					t.Fatal(err)
				}
				return access.Narrowed{Teams: []int64{m.team}}
			},
			held("internal", "public"),
		},
		"a member's role withdrawn": {
			func(t *testing.T, rights *access.Store, m members) access.Narrowed {
				if err := rights.Withdraw(t.Context(), m.internal, m.product, access.InternalRead); err != nil {
					t.Fatal(err)
				}
				return access.Narrowed{People: []int64{m.internal}}
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
			held("internal", "public"),
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
					{&m.internal, "internal@example.com", []access.Role{access.PublicRead, access.InternalRead}},
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
			{Group: "analysts", Grants: string(access.InternalRead), Product: product},
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
			{[]string{"platform", "security", "analysts"}, held("internal", "private", "public", "report")},
			{[]string{"platform", "analysts"}, held("internal", "public")},
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

// A change of role mode hands back what it leaves people unable to read:
// assigned roles set aside on the way into group-bound mode, and derived
// roles cleared on the way out.
func TestAChangeOfRoleModeHandsBackWhatItSetAside(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		rights := access.NewStore(f.db.DB).HandingBack(finding.HandBack)
		assigned := f.holder(t, "assigned@example.com", access.PublicTriage, access.PrivateTriage)
		f.heldEverywhere(t, assigned.Party())
		if err := rights.SwitchTo(ctx, access.GroupBound); err != nil {
			t.Fatal(err)
		}
		if got := f.stillHeld(t, assigned.Party()); len(got) != 0 {
			t.Errorf("into group-bound mode, somebody whose roles were set aside holds %v", got)
		}

		var product string
		if err := f.db.DB.NewSelect().Table("product").Column("name").
			Where(`"id" = ?`, f.productID).Scan(ctx, &product); err != nil {
			t.Fatal(err)
		}
		if _, err := rights.ApplyMappings(ctx, []access.Mapping{
			{Group: "security", Grants: string(access.PrivateTriage), Product: product},
		}); err != nil {
			t.Fatal(err)
		}
		derived, err := rights.AdmitByGroups(ctx, access.Arrival{ViaProxy: true, Username: "derived"},
			[]string{"security"})
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		if _, err := f.db.DB.NewUpdate().Table("finding").
			Set(`"assigned_to" = ?`, derived.Party()).Set(`"assigned_at" = ?`, now).
			Where(`"closed_at" IS NULL`).Where(`"visibility" = ?`, access.Private).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if err := rights.SwitchTo(ctx, access.Direct); err != nil {
			t.Fatal(err)
		}
		if got := f.stillHeld(t, derived.Party()); len(got) != 0 {
			t.Errorf("out of group-bound mode, somebody whose roles a group derived holds %v", got)
		}
	})
}

// Work a holder still reads stays with them, so asking about somebody whose
// reading did not change moves nothing.
func TestAHandBackMovesNothingStillRead(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.holder(t, "holder@example.com",
			access.PublicTriage, access.PrivateTriage, access.InternalRead)
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
