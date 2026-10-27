// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Each visibility is its own grant, so a condition about disclosed work does
// not reach somebody who holds only the undisclosed roles on a product, and
// the reverse.

// split is one scanned product, with the issue and the component every row
// written here names.
type split struct {
	db          *database.DB
	rights      *access.Store
	product     int64
	target      int64
	issue       int64
	component   int64
	occurrences int
}

func aSplit(t *testing.T, w *fixture.World) *split {
	t.Helper()
	db := w.DB
	ctx := t.Context()
	target := aScannedTarget(t, w)
	product := w.Product
	named, err := finding.NewVulnerabilities(db.DB).Intern(ctx, []finding.Named{
		{Identifier: "CVE-2026-4242", Severity: "high"},
	})
	if err != nil {
		t.Fatal(err)
	}
	component := &graph.Component{
		Identity: "libnl", Name: "libnl-3-200", Version: "3.7.0",
		Purl: "pkg:deb/debian/libnl@3.7.0",
	}
	if _, err := db.DB.NewInsert().Model(component).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return &split{
		db: db, rights: access.NewStore(db.DB), product: product.ID, target: target,
		issue: named["CVE-2026-4242"], component: component.ID,
	}
}

// person records somebody holding these roles on the product.
func (s *split) person(t *testing.T, name string, roles ...access.Role) int64 {
	t.Helper()
	who, err := s.rights.Ensure(t.Context(), name+"@example.com", name, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		if err := s.rights.GrantRole(t.Context(), who.ID, s.product, role); err != nil {
			t.Fatal(err)
		}
	}
	return who.ID
}

// decision writes one decision straight to the tables, with a row per occurrence at each
// visibility, shaped by the two functions.
func (s *split) decision(t *testing.T, by int64, public, private int,
	argue func(*triage.Decision), occurrence func(*triage.DecisionOccurrence)) {
	t.Helper()
	ctx := t.Context()
	at := time.Now().UTC().Add(-10 * 24 * time.Hour).Truncate(time.Microsecond)
	reason := string(triage.CodeNotPresent)
	decision := &triage.Decision{
		Kind: triage.FindingDecision, ProposedBy: by, ProposedAt: at,
		Outcome: triage.NotApplicable, Justification: &reason,
	}
	argue(decision)
	if _, err := s.db.DB.NewInsert().Model(decision).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	write := func(visibility access.Visibility) {
		s.occurrences++
		row := &triage.DecisionOccurrence{
			DecisionID: decision.ID, ProductID: s.product, VulnerabilityID: s.issue,
			OccurrenceIdentity: fmt.Sprintf("place-%d", s.occurrences), Visibility: visibility,
			NeedsApproval: true, State: triage.Proposed,
			ProposedBy: by, ProposedAt: at,
		}
		occurrence(row)
		if _, err := s.db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for range public {
		write(access.Public)
	}
	for range private {
		write(access.Private)
	}
}

// queued writes one open finding at this visibility, assigned to a team long
// enough ago to count as sitting there.
func (s *split) queued(t *testing.T, team *access.Team, visibility access.Visibility) {
	t.Helper()
	s.occurrences++
	now := time.Now().UTC().Truncate(time.Microsecond)
	routed := now.Add(-5 * 24 * time.Hour)
	row := &finding.Finding{
		TargetID: s.target, Kind: finding.Vulnerable, VulnerabilityID: s.issue,
		Visibility: visibility, ComponentID: s.component,
		OccurrenceIdentity: fmt.Sprintf("place-%d", s.occurrences),
		OpenedAt:           now, AssignedTo: &team.PartyID, AssignedAt: &routed,
	}
	if _, err := s.db.DB.NewInsert().Model(row).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// sweep runs the watch once.
func sweep(t *testing.T, db *database.DB) {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, _, err := notify.NewWatch(db.DB, quiet).Once(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// openFor is what every open condition of one kind written for somebody says.
//
// Read from the table rather than through the notification area. The area
// narrows by the same grants, so it hides a row the sweep had no business
// writing, and the sweep is what these pin.
func openFor(t *testing.T, db *database.DB, who int64, kind notify.Kind) []string {
	t.Helper()
	var rows []notify.Notification
	if err := db.DB.NewSelect().Model(&rows).
		Where(`"person_id" = ?`, who).Where(`"kind" = ?`, kind).
		Where(`"cleared_at" IS NULL`).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	bodies := make([]string, 0, len(rows))
	for _, row := range rows {
		bodies = append(bodies, row.Body)
	}
	return bodies
}

// saying is which of these phrases the bodies contain, in the order asked.
func saying(bodies []string, phrases ...string) []string {
	var found []string
	for _, phrase := range phrases {
		for _, body := range bodies {
			if strings.Contains(body, phrase) {
				found = append(found, phrase)
				break
			}
		}
	}
	return found
}

func TestADecisionWaitingReachesWhoeverMayApproveEveryRowOfIt(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		s := aSplit(t, w)
		proposer := s.person(t, "proposer", access.PublicTriage, access.PrivateTriage)
		privateReader := s.person(t, "private-reader", access.PrivateRead, access.Approver)
		privateTriager := s.person(t, "private-triager", access.PrivateTriage, access.Approver)
		publicReader := s.person(t, "public-reader", access.PublicRead, access.Approver)
		both := s.person(t, "both", access.PublicRead, access.PrivateRead, access.Approver)
		// A triager may approve somebody else's decision, capability or not.
		triager := s.person(t, "triager", access.PublicTriage, access.PrivateTriage)
		undisclosedTriager := s.person(t, "undisclosed-triager", access.PrivateTriage)
		// Reading both and triaging one is not agreeing to the other half.
		halfTriager := s.person(t, "half-triager", access.PublicRead, access.PrivateTriage)

		// Told apart by size: a disclosed decision over one occurrence, an undisclosed
		// one over two, and one over three mixing both.
		waiting := func(*triage.Decision) {}
		asked := func(*triage.DecisionOccurrence) {}
		s.decision(t, proposer, 1, 0, waiting, asked)
		s.decision(t, proposer, 0, 2, waiting, asked)
		s.decision(t, proposer, 1, 2, waiting, asked)
		sweep(t, db)

		all := []string{"covers 1 location", "covers 2 locations", "covers 3 locations"}
		for _, want := range []struct {
			who  string
			id   int64
			told []string
		}{
			{"an approver reading only undisclosed work", privateReader, all[1:2]},
			{"an approver triaging only undisclosed work", privateTriager, all[1:2]},
			{"an approver reading only disclosed work", publicReader, all[0:1]},
			{"an approver reading both", both, all},
			{"a triager of both, holding no capability", triager, all},
			{"a triager of undisclosed work alone", undisclosedTriager, all[1:2]},
			{"a triager of one half reading the other", halfTriager, all[1:2]},
		} {
			bodies := openFor(t, db, want.id, notify.DecisionWaiting)
			if got := saying(bodies, all...); strings.Join(got, "; ") != strings.Join(want.told, "; ") ||
				len(bodies) != len(want.told) {
				t.Errorf("%s was told %q, want %q", want.who, bodies, want.told)
			}
		}
	})
}

func TestADecisionAboutACodeFindingIsToldToItsInternalAudienceAlone(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		s := aSplit(t, w)
		rule, err := finding.NewVulnerabilities(db.DB).Rule(t.Context(), finding.Rule{Name: "clang-tidy/leak"})
		if err != nil {
			t.Fatal(err)
		}
		s.issue = rule
		proposer := s.person(t, "proposer", access.InternalTriage)
		privateApprover := s.person(t, "private-approver", access.PrivateRead, access.Approver)
		internalApprover := s.person(t, "internal-approver", access.InternalRead, access.Approver)

		// A dismissal waiting on a second person, and one sent back and
		// left, each at one internal occurrence.
		dismissed := func(c *triage.Decision) {
			reason := string(triage.FalsePositive)
			c.Outcome, c.Justification = triage.Dismissed, &reason
		}
		back := time.Now().UTC().Add(-7 * 24 * time.Hour).Truncate(time.Microsecond)
		internal := func(d *triage.DecisionOccurrence) { d.Visibility = access.Internal }
		returned := func(d *triage.DecisionOccurrence) { d.Visibility, d.SentBackAt = access.Internal, &back }
		s.decision(t, proposer, 1, 0, dismissed, internal)
		s.decision(t, proposer, 1, 0, dismissed, returned)
		sweep(t, db)

		for _, want := range []struct {
			who  string
			id   int64
			kind notify.Kind
			told int
		}{
			{"the internal approver", internalApprover, notify.DecisionWaiting, 1},
			{"the proposer", proposer, notify.SentBackWaiting, 1},
			{"the proposer", proposer, notify.DecisionWaiting, 0},
			{"an approver of undisclosed work", privateApprover, notify.DecisionWaiting, 0},
			{"an approver of undisclosed work", privateApprover, notify.SentBackWaiting, 0},
			{"the internal approver", internalApprover, notify.SentBackWaiting, 0},
		} {
			if told := openFor(t, db, want.id, want.kind); len(told) != want.told {
				t.Errorf("%s was told %s %q; want %d", want.who, want.kind, told, want.told)
			}
		}
		// Marked as internal work, so the list withholds it from a reader of
		// undisclosed work.
		marked, err := db.DB.NewSelect().Model((*notify.Notification)(nil)).
			Where(`"person_id" IN (?, ?)`, internalApprover, proposer).
			Where(`"internal" = ?`, true).Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if marked != 2 {
			t.Errorf("%d of the lines about the code finding are marked internal; want 2", marked)
		}
	})
}

func TestAProposerWhoReadsOnlyPartOfADecisionIsNotToldItIsTheirTurn(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		s := aSplit(t, w)
		privateOnly := s.person(t, "private-only", access.PrivateTriage)
		both := s.person(t, "both", access.PublicTriage, access.PrivateTriage)

		sentBack := func(*triage.Decision) {}
		back := time.Now().UTC().Add(-7 * 24 * time.Hour).Truncate(time.Microsecond)
		returned := func(d *triage.DecisionOccurrence) { d.SentBackAt = &back }

		until := time.Now().UTC().Add(2 * 24 * time.Hour).Truncate(time.Microsecond)
		deferred := func(c *triage.Decision) {
			c.Outcome, c.Justification, c.DeferredUntil = triage.Deferred, nil, &until
		}
		standing := func(d *triage.DecisionOccurrence) {
			key := fmt.Sprintf("live-%d", s.occurrences)
			d.State, d.LiveKey = triage.Approved, &key
		}

		// Each decision mixes a disclosed occurrence with an undisclosed one.
		for _, by := range []int64{privateOnly, both} {
			s.decision(t, by, 1, 1, sentBack, returned)
			s.decision(t, by, 1, 1, deferred, standing)
		}
		sweep(t, db)

		for _, kind := range []notify.Kind{notify.SentBackWaiting, notify.DeferralEnding} {
			if told := openFor(t, db, privateOnly, kind); len(told) != 0 {
				t.Errorf("a proposer reading only the undisclosed half was told %s: %q", kind, told)
			}
			if told := openFor(t, db, both, kind); len(told) != 1 {
				t.Errorf("a proposer reading every occurrence was told %s %d times, want 1: %q",
					kind, len(told), told)
			}
		}
	})
}

func TestACriticalOnAReleaseIsNotToldToWhoeverTriagesOnlyUndisclosedWork(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		rights := access.NewStore(db.DB)
		product := w.Product
		released := w.TargetFor(w.Tag, w.Customer)
		privateTriager := recordPerson(t, rights, "private@example.com", false,
			product.ID, access.PrivateTriage)
		publicTriager := recordPerson(t, rights, "public@example.com", false,
			product.ID, access.PublicTriage)

		// A disclosed finding.
		critical(t, db, released.ID, "CVE-2026-SHIPPED", "critical")
		sweep(t, db)

		if told := openFor(t, db, privateTriager, notify.CriticalOnRelease); len(told) != 0 {
			t.Errorf("somebody triaging only undisclosed work was told about a disclosed one: %q", told)
		}
		if told := openFor(t, db, publicTriager, notify.CriticalOnRelease); len(told) != 1 {
			t.Errorf("somebody triaging disclosed work was told %d times, want 1: %q", len(told), told)
		}
	})
}

func TestATeamQueueReachesEachMemberAtTheVisibilityTheyRead(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		s := aSplit(t, w)
		privateReader := s.person(t, "private-reader", access.PrivateRead)
		publicReader := s.person(t, "public-reader", access.PublicRead)
		admin := s.person(t, "admin")

		team := func(name string) *access.Team {
			t.Helper()
			made, err := s.rights.DeclareTeam(ctx, name, name)
			if err != nil {
				t.Fatal(err)
			}
			for _, who := range []int64{privateReader, publicReader} {
				if _, err := s.rights.AddToTeam(ctx, made.ID, who, admin); err != nil {
					t.Fatal(err)
				}
			}
			return made
		}
		disclosed, undisclosed := team("Kernel"), team("Embargo")
		s.queued(t, disclosed, access.Public)
		s.queued(t, undisclosed, access.Private)
		sweep(t, db)

		queues := []string{"Kernel has", "Embargo has"}
		// Disclosed work travels with the assignment, so a member reading the
		// product at either visibility is told of it.
		if told := openFor(t, db, privateReader, notify.QueueUntaken); len(told) != 2 ||
			len(saying(told, queues...)) != 2 {
			t.Errorf("a member reading only undisclosed work was told %q, want both queues", told)
		}
		if told := openFor(t, db, publicReader, notify.QueueUntaken); len(told) != 1 ||
			len(saying(told, queues[0])) != 1 {
			t.Errorf("a member reading only disclosed work was told %q, want the disclosed queue alone",
				told)
		}
	})
}

// One issue in one component is one piece of work in a queue, however its
// occurrences differ in visibility, and the queue is undisclosed where any of them
// is.
func TestAnIssueAtOccurrencesOfBothVisibilitiesIsOnePieceOfQueuedWork(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		s := aSplit(t, w)
		privateReader := s.person(t, "private-reader", access.PrivateRead)
		publicReader := s.person(t, "public-reader", access.PublicRead)
		admin := s.person(t, "admin")
		queue, err := s.rights.DeclareTeam(ctx, "Kernel", "Kernel")
		if err != nil {
			t.Fatal(err)
		}
		for _, who := range []int64{privateReader, publicReader} {
			if _, err := s.rights.AddToTeam(ctx, queue.ID, who, admin); err != nil {
				t.Fatal(err)
			}
		}
		s.queued(t, queue, access.Public)
		s.queued(t, queue, access.Private)
		sweep(t, db)

		told := openFor(t, db, privateReader, notify.QueueUntaken)
		if len(told) != 1 || len(saying(told, "1 piece of work")) != 1 {
			t.Errorf("one issue in one component was told as %q, want 1 piece of work", told)
		}
		if told := openFor(t, db, publicReader, notify.QueueUntaken); len(told) != 0 {
			t.Errorf("a member reading only disclosed work was told of a queue holding undisclosed work: %q", told)
		}
	})
}

// Reports a team's queue holds are a condition of their own, told to the
// members who read the product's reports, and a judged report is not
// waiting.
func TestReportsSittingInATeamQueueAreToldToTheMembersWhoReadReports(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		s := aSplit(t, w)
		privateReader := s.person(t, "private-reader", access.PrivateRead)
		publicReader := s.person(t, "public-reader", access.PublicRead)
		admin := s.person(t, "admin")
		queue, err := s.rights.DeclareTeam(ctx, "Intake", "Intake")
		if err != nil {
			t.Fatal(err)
		}
		for _, who := range []int64{privateReader, publicReader} {
			if _, err := s.rights.AddToTeam(ctx, queue.ID, who, admin); err != nil {
				t.Fatal(err)
			}
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		routed := now.Add(-5 * 24 * time.Hour)
		for i, judged := range []bool{false, false, true} {
			row := &finding.FlawReport{
				Reference: fmt.Sprintf("SONIC-R-2026-00000%d", i), ProductID: s.product,
				ReportedProblem: "A claim.", RecordedBy: admin, RecordedAt: now,
				AssignedTo: &queue.PartyID, AssignedAt: &routed,
			}
			if judged {
				row.EvaluatedAt, row.EvaluatedBy = &now, &admin
			}
			if _, err := db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		sweep(t, db)

		told := openFor(t, db, privateReader, notify.QueueUntaken)
		if len(told) != 1 || len(saying(told, "Intake has 2 vulnerability reports waiting")) != 1 {
			t.Errorf("a member who reads reports was told %q, want the two open reports", told)
		}
		if told := openFor(t, db, publicReader, notify.QueueUntaken); len(told) != 0 {
			t.Errorf("a member who reads no reports was told of reports waiting: %q", told)
		}
	})
}
