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
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
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
	db        *database.DB
	rights    *access.Store
	product   int64
	target    int64
	issue     int64
	component int64
	places    int
}

func aSplit(t *testing.T, db *database.DB) *split {
	t.Helper()
	ctx := t.Context()
	dbtest.Reset(t, db)
	target := aScannedTarget(t, db)
	product, err := catalog.NewStore(db.DB).ProductByName(ctx, "sonic")
	if err != nil {
		t.Fatal(err)
	}
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

// claim writes one claim straight to the tables, with a row per place at each
// visibility, shaped by the two functions.
func (s *split) claim(t *testing.T, by int64, public, private int,
	argue func(*triage.Claim), place func(*triage.Decision)) {
	t.Helper()
	ctx := t.Context()
	at := time.Now().UTC().Add(-10 * 24 * time.Hour).Truncate(time.Microsecond)
	reason := string(triage.CodeNotPresent)
	claim := &triage.Claim{
		Kind: triage.FindingClaim, ProposedBy: by, ProposedAt: at,
		Outcome: triage.NotApplicable, Justification: &reason,
	}
	argue(claim)
	if _, err := s.db.DB.NewInsert().Model(claim).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	write := func(visibility access.Visibility) {
		s.places++
		row := &triage.Decision{
			ClaimID: claim.ID, ProductID: s.product, VulnerabilityID: s.issue,
			PlaceIdentity: fmt.Sprintf("place-%d", s.places), Visibility: visibility,
			NeedsApproval: true, State: triage.Proposed,
			ProposedBy: by, ProposedAt: at,
		}
		place(row)
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

// queued writes one open finding at this visibility, routed to a team long
// enough ago to count as sitting there.
func (s *split) queued(t *testing.T, team *access.Team, visibility access.Visibility) {
	t.Helper()
	s.places++
	now := time.Now().UTC().Truncate(time.Microsecond)
	routed := now.Add(-5 * 24 * time.Hour)
	row := &finding.Finding{
		TargetID: s.target, Kind: finding.Vulnerable, VulnerabilityID: s.issue,
		Visibility: visibility, ComponentID: s.component,
		PlaceIdentity: fmt.Sprintf("place-%d", s.places),
		OpenedAt:      now, LastChangedAt: now,
		AssignedTo: &team.PartyID, AssignedAt: &routed,
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
		Where("person_id = ?", who).Where("kind = ?", kind).
		Where("cleared_at IS NULL").Scan(t.Context()); err != nil {
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

func TestAClaimWaitingReachesOnlyApproversWhoReadEveryRowOfIt(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		s := aSplit(t, db)
		proposer := s.person(t, "proposer", access.PublicTriage, access.PrivateTriage)
		privateReader := s.person(t, "private-reader", access.PrivateRead, access.Approver)
		privateTriager := s.person(t, "private-triager", access.PrivateTriage, access.Approver)
		publicReader := s.person(t, "public-reader", access.PublicRead, access.Approver)
		both := s.person(t, "both", access.PublicRead, access.PrivateRead, access.Approver)

		// Told apart by size: a disclosed claim over one place, an undisclosed
		// one over two, and one over three mixing both.
		waiting := func(*triage.Claim) {}
		asked := func(*triage.Decision) {}
		s.claim(t, proposer, 1, 0, waiting, asked)
		s.claim(t, proposer, 0, 2, waiting, asked)
		s.claim(t, proposer, 1, 2, waiting, asked)
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
		} {
			bodies := openFor(t, db, want.id, notify.ClaimWaiting)
			if got := saying(bodies, all...); strings.Join(got, "; ") != strings.Join(want.told, "; ") ||
				len(bodies) != len(want.told) {
				t.Errorf("%s was told %q, want %q", want.who, bodies, want.told)
			}
		}
	})
}

func TestAProposerWhoReadsOnlyPartOfAClaimIsNotToldItIsTheirTurn(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		s := aSplit(t, db)
		privateOnly := s.person(t, "private-only", access.PrivateTriage)
		both := s.person(t, "both", access.PublicTriage, access.PrivateTriage)

		sentBack := func(*triage.Claim) {}
		back := time.Now().UTC().Add(-7 * 24 * time.Hour).Truncate(time.Microsecond)
		returned := func(d *triage.Decision) { d.SentBackAt = &back }

		until := time.Now().UTC().Add(2 * 24 * time.Hour).Truncate(time.Microsecond)
		deferred := func(c *triage.Claim) {
			c.Outcome, c.Justification, c.DeferredUntil = triage.Deferred, nil, &until
		}
		standing := func(d *triage.Decision) {
			key := fmt.Sprintf("live-%d", s.places)
			d.State, d.LiveKey = triage.Approved, &key
		}

		// Each claim mixes a disclosed place with an undisclosed one.
		for _, by := range []int64{privateOnly, both} {
			s.claim(t, by, 1, 1, sentBack, returned)
			s.claim(t, by, 1, 1, deferred, standing)
		}
		sweep(t, db)

		for _, kind := range []notify.Kind{notify.SentBackWaiting, notify.DeferralEnding} {
			if told := openFor(t, db, privateOnly, kind); len(told) != 0 {
				t.Errorf("a proposer reading only the undisclosed half was told %s: %q", kind, told)
			}
			if told := openFor(t, db, both, kind); len(told) != 1 {
				t.Errorf("a proposer reading every place was told %s %d times, want 1: %q",
					kind, len(told), told)
			}
		}
	})
}

func TestACriticalOnAReleaseIsNotToldToWhoeverTriagesOnlyUndisclosedWork(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)
		rights := access.NewStore(db.DB)
		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		branch, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		tag, err := cat.DeclareStream(ctx, product.ID, "v1.0", catalog.Tag, &branch.ID)
		if err != nil {
			t.Fatal(err)
		}
		variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
		if err != nil {
			t.Fatal(err)
		}
		released, err := cat.TargetFor(ctx, tag.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}
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
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		s := aSplit(t, db)
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
				if err := s.rights.AddToTeam(ctx, made.ID, who, admin); err != nil {
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
