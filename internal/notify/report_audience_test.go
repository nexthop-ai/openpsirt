// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// audienceWorld is the people a report's notices choose between: a person
// who reads reports and may hold one, two members of a team, one of whom
// reads reports, and somebody who works reports and holds nothing. A second
// team holds only the member who reads no reports, and a person who read
// reports has left.
type audienceWorld struct {
	w                       *fixture.World
	holder, member, outside *access.Account
	worker, departed        *access.Account
	team, unread            *access.Team
}

func newAudienceWorld(t *testing.T, w *fixture.World) audienceWorld {
	t.Helper()
	ctx := t.Context()
	rights := access.NewStore(w.DB.DB)
	person := func(identity string, role access.Role) *access.Account {
		t.Helper()
		them, err := rights.Ensure(ctx, identity, identity, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, them.ID, w.Product.ID, role); err != nil {
			t.Fatal(err)
		}
		return them
	}
	out := audienceWorld{
		w:        w,
		holder:   person("holder@example.com", access.PrivateRead),
		member:   person("member@example.com", access.PrivateRead),
		outside:  person("outside@example.com", access.PublicTriage),
		worker:   person("worker@example.com", access.PrivateTriage),
		departed: person("departed@example.com", access.PrivateRead),
	}
	if _, err := rights.Deactivate(ctx, out.departed.ID); err != nil {
		t.Fatal(err)
	}
	team, err := rights.DeclareTeam(ctx, "intake", "Intake")
	if err != nil {
		t.Fatal(err)
	}
	for _, each := range []*access.Account{out.member, out.outside} {
		if _, err := rights.AddToTeam(ctx, team.ID, each.ID, out.worker.ID); err != nil {
			t.Fatal(err)
		}
	}
	out.team = team
	unread, err := rights.DeclareTeam(ctx, "bystanders", "Bystanders")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rights.AddToTeam(ctx, unread.ID, out.outside.ID, out.worker.ID); err != nil {
		t.Fatal(err)
	}
	out.unread = unread
	return out
}

// report records an unanswered report held by a party, or by nobody.
func (a audienceWorld) report(t *testing.T, held *int64) *finding.FlawReport {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	report := &finding.FlawReport{
		Reference: "SONIC-R-2026-515151", ProductID: a.w.Product.ID,
		Summary:    "The management socket accepts a request nobody authenticated.",
		ReportedBy: "A Researcher", RecordedBy: a.worker.ID, RecordedAt: now,
		AssignedTo: held,
	}
	if held != nil {
		report.AssignedAt = &now
	}
	if _, err := a.w.DB.DB.NewInsert().Model(report).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	return report
}

// told counts the lines of one kind written for one person.
func (a audienceWorld) told(t *testing.T, who *access.Account, kind notify.Kind) int {
	t.Helper()
	n, err := a.w.DB.DB.NewSelect().TableExpr(`"notification" AS "n"`).
		Where(`"n"."person_id" = ?`, who.ID).
		Where(`"n"."kind" = ?`, kind).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return int(n)
}

// tiers is who a report's notices reach, by who holds it.
var tiers = []struct {
	name string
	held func(a audienceWorld) *int64
	// want is whether each of holder, member, outside and worker is told.
	want [4]bool
}{
	{"a person holding it tells them alone", func(a audienceWorld) *int64 {
		party := a.holder.PartyID
		return &party
	}, [4]bool{true, false, false, false}},
	{"a team's queue tells its members who read reports", func(a audienceWorld) *int64 {
		party := a.team.PartyID
		return &party
	}, [4]bool{false, true, false, false}},
	{"nobody holding it tells everybody who works reports", func(audienceWorld) *int64 {
		return nil
	}, [4]bool{false, false, false, true}},
	{"a holder who reads no reports tells everybody who works reports", func(a audienceWorld) *int64 {
		party := a.outside.PartyID
		return &party
	}, [4]bool{false, false, false, true}},
	{"a holder who has left tells everybody who works reports", func(a audienceWorld) *int64 {
		party := a.departed.PartyID
		return &party
	}, [4]bool{false, false, false, true}},
	{"a queue with no member reading reports tells everybody who works reports", func(a audienceWorld) *int64 {
		party := a.unread.PartyID
		return &party
	}, [4]bool{false, false, false, true}},
}

func (a audienceWorld) check(t *testing.T, kind notify.Kind, want [4]bool) {
	t.Helper()
	for i, who := range []*access.Account{a.holder, a.member, a.outside, a.worker} {
		got := a.told(t, who, kind) > 0
		if got != want[i] {
			t.Errorf("%s told %v, want %v", who.Identity, got, want[i])
		}
	}
}

func TestAnUnansweredReportIsRaisedToItsHolderItsTeamOrEverybodyWhoWorksReports(t *testing.T) {
	for _, tier := range tiers {
		t.Run(tier.name, func(t *testing.T) {
			fixture.Each(t, func(t *testing.T, w *fixture.World) {
				a := newAudienceWorld(t, w)
				a.report(t, tier.held(a))
				watch := notify.NewWatch(w.DB.DB, slog.New(slog.NewTextHandler(io.Discard, nil)))
				if _, _, err := watch.Once(t.Context()); err != nil {
					t.Fatal(err)
				}
				a.check(t, notify.Unanswered, tier.want)
			})
		})
	}
}

func TestAReporterWritingBackIsToldToTheHolderTheTeamOrEverybodyWhoWorksReports(t *testing.T) {
	for _, tier := range tiers {
		t.Run(tier.name, func(t *testing.T) {
			fixture.Each(t, func(t *testing.T, w *fixture.World) {
				a := newAudienceWorld(t, w)
				held := tier.held(a)
				report := a.report(t, held)
				// Recorded by somebody outside every tier, so nobody is
				// left out for being the one who recorded it.
				if err := notify.TellReportWritten(t.Context(), w.DB.DB, notify.ReportWritten{
					ProductID: w.Product.ID, Product: w.Product.Name,
					Reference: report.Reference, AssignedTo: held, By: 0,
				}); err != nil {
					t.Fatal(err)
				}
				a.check(t, notify.ReportMessage, tier.want)
			})
		})
	}
}

func TestWhoeverRecordsAReportersMessageIsNotToldOfIt(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		a := newAudienceWorld(t, w)
		report := a.report(t, nil)
		if err := notify.TellReportWritten(t.Context(), w.DB.DB, notify.ReportWritten{
			ProductID: w.Product.ID, Product: w.Product.Name,
			Reference: report.Reference, By: a.worker.ID,
		}); err != nil {
			t.Fatal(err)
		}
		if n := a.told(t, a.worker, notify.ReportMessage); n != 0 {
			t.Errorf("whoever recorded the message was told of it %d times", n)
		}
	})
}
