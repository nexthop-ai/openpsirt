// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"io"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

func TestAnEmbargoPastItsDateIsToldToAdminsAndWhoeverHoldsIt(t *testing.T) {
	// Reaching the date discloses nothing — it escalates. So this is a
	// condition rather than an event: it holds while the date has passed
	// and nothing has been decided, and it clears when somebody moves the
	// date or discloses, because both of those are answering it.
	//
	// The people who hear about it are the careful part. Every one of these is
	// a finding nobody has announced, so the alert is a disclosure in its own
	// right.
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "admin@example.com", "Admin", new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		owner, err := rights.Ensure(ctx, "owner@example.com", "Owner", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		outsider, err := rights.Ensure(ctx, "public@example.com", "Public", nil, nil)
		if err != nil {
			t.Fatal(err)
		}

		product := w.Product
		if err := rights.GrantRole(ctx, owner.ID, product.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		// Holds the ordinary right and no more, so undisclosed work — and any
		// alert about it — is not theirs to see.
		if err := rights.GrantRole(ctx, outsider.ID, product.ID, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		target := w.Target
		// New, so it is not also quiet — this test is about one condition.
		if _, err := db.DB.NewUpdate().Table("target").
			Set(`"created_at" = ?`, time.Now().UTC()).
			Where(`"id" = ?`, target.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		embargoed(t, db, target.ID, "SONIC-2026-0001", owner.PartyID,
			time.Now().UTC().Add(-24*time.Hour))

		// A second one, held by somebody who may not read undisclosed work
		// here. An assignment can outlive the role that allowed it, and
		// delivering this to them would hand over the thing the role was
		// withdrawn to stop.
		embargoed(t, db, target.ID, "SONIC-2026-0002", outsider.PartyID,
			time.Now().UTC().Add(-24*time.Hour))

		watch := notify.NewWatch(db.DB, quiet)

		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if n := waiting(t, db, admin); n != 2 {
			t.Errorf("the administrator was told %d things about passed dates, want 2", n)
		}
		if n := waiting(t, db, owner); n != 1 {
			t.Errorf("whoever holds one was told %d things, want 1", n)
		}
		// Holding it is not enough. They may not read undisclosed work here,
		// and the alert says an undisclosed finding exists.
		if n := waiting(t, db, outsider); n != 0 {
			t.Errorf("somebody who may not read undisclosed work was told %d things", n)
		}
		// And not held for them either, where the read's own narrowing would
		// hide it: the sweep decides who is told.
		if n, err := db.DB.NewSelect().Model((*notify.Notification)(nil)).
			Where(`"person_id" = ?`, outsider.ID).Count(ctx); err != nil || n != 0 {
			t.Errorf("somebody who may not read undisclosed work holds %d alerts (%v)", n, err)
		}

		// Moving the date answers it, and the alert goes without anybody
		// dismissing anything — which is the whole reason this is a condition.
		if _, err := db.DB.NewUpdate().Table("finding").
			Set(`"disclose_at" = ?`, time.Now().UTC().Add(30*24*time.Hour)).
			Where(`"kind" = ?`, finding.Entered).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		_, cleared, err := watch.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if cleared == 0 {
			t.Error("the date moved and the alert stayed")
		}
		if n := waiting(t, db, admin); n != 0 {
			t.Errorf("the administrator still sees %d after the dates moved", n)
		}
		if n := waiting(t, db, owner); n != 0 {
			t.Errorf("whoever holds it still sees %d after the date moved", n)
		}
	})
}

// embargoed writes one undisclosed finding past its disclosure date, held by
// somebody. The holder is a party, which is what an assignment names; a
// person's own number coincides with it only by accident of insertion order.
func embargoed(t *testing.T, db *database.DB, targetID int64, identifier string,
	owner int64, at time.Time) {
	t.Helper()
	embargoedAt(t, db, targetID, identifier, "sonic", owner, at)
}

// embargoedAt is embargoed at a component of the name given.
func embargoedAt(t *testing.T, db *database.DB, targetID int64, identifier, component string,
	owner int64, at time.Time) {
	t.Helper()
	ctx := t.Context()
	ids, err := finding.NewVulnerabilities(db.DB).Intern(ctx,
		[]finding.Named{{Identifier: identifier, Severity: "high"}})
	if err != nil {
		t.Fatal(err)
	}
	components := graph.NewComponents(db.DB)
	interned, err := components.Intern(ctx, []graph.Described{
		{Purl: "pkg:generic/" + component + "@1.0", Name: component, Version: "1.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var componentID int64
	for _, id := range interned {
		componentID = id
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := &finding.Finding{
		TargetID: targetID, Kind: finding.Entered, Visibility: access.Private,
		VulnerabilityID: ids[identifier], ComponentID: componentID,
		PlaceIdentity: "place-of-" + identifier + "-" + component, OpenedAt: now,
		DiscloseAt: &at, AssignedTo: &owner, AssignedAt: &now,
	}
	if _, err := db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
		t.Fatal(err)
	}
}

// An embargo is one condition per place it sits at, so each alert links the
// place it is about and says the same thing on every sweep.
func TestAnEmbargoAtTwoPlacesIsTwoAlertsEachLinkingItsOwn(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "admin@example.com", "Admin", new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		target := w.Target
		if _, err := db.DB.NewUpdate().Table("target").
			Set(`"created_at" = ?`, time.Now().UTC()).
			Where(`"id" = ?`, target.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		past := time.Now().UTC().Add(-24 * time.Hour)
		embargoedAt(t, db, target.ID, "SONIC-2026-0001", "libfoo", admin.PartyID, past)
		embargoedAt(t, db, target.ID, "SONIC-2026-0001", "libbar", admin.PartyID, past)

		watch := notify.NewWatch(db.DB, quiet)
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		rows, _, err := notify.NewStore(db.DB).Waiting(ctx, asks(t, db, admin), 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		var links []string
		for _, row := range rows {
			if row.Kind == notify.DisclosureDue {
				links = append(links, row.Link)
			}
		}
		sort.Strings(links)
		if len(links) != 2 || !strings.HasSuffix(links[0], "/components/libbar") ||
			!strings.HasSuffix(links[1], "/components/libfoo") {
			t.Fatalf("an embargo at two places was told as %q", links)
		}
		// Nothing moved, so nothing is opened, cleared or rewritten.
		opened, cleared, err := watch.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if opened != 0 || cleared != 0 {
			t.Errorf("a sweep with nothing moved opened %d and cleared %d", opened, cleared)
		}
	})
}

func TestAnEmbargoComingUpClearsForWhoeverStopsHoldingIt(t *testing.T) {
	// The coming and the arrived conditions are one function apart, told apart
	// by a lead time — and it read the people already being told about the
	// arrived one whichever it was computing. Reconcile makes a person's open
	// set exactly what it is handed, so anybody who was neither an
	// administrator nor currently holding the finding was never handed a list
	// for this kind, was never reconciled, and their alert stood indefinitely
	// with nothing able to clear it. That alert names the issue and the
	// product, and the link is the embargoed path.
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "admin@example.com", "Admin", new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		held, err := rights.Ensure(ctx, "held@example.com", "Held", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		next, err := rights.Ensure(ctx, "next@example.com", "Next", nil, nil)
		if err != nil {
			t.Fatal(err)
		}

		product := w.Product
		for _, who := range []*access.Account{held, next} {
			if err := rights.GrantRole(ctx, who.ID, product.ID, access.PrivateTriage); err != nil {
				t.Fatal(err)
			}
		}
		target := w.Target
		if _, err := db.DB.NewUpdate().Table("target").
			Set(`"created_at" = ?`, time.Now().UTC()).
			Where(`"id" = ?`, target.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		// Inside the lead time and not yet arrived, which is the coming
		// condition and not the arrived one.
		embargoed(t, db, target.ID, "SONIC-2026-0003", held.PartyID,
			time.Now().UTC().Add(24*time.Hour))

		watch := notify.NewWatch(db.DB, quiet)

		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if n := waiting(t, db, held); n != 1 {
			t.Fatalf("whoever holds it was told %d things about a date coming, want 1", n)
		}
		if n := waiting(t, db, admin); n != 1 {
			t.Errorf("the administrator was told %d things, want 1", n)
		}

		// The work is handed on. The previous holder is now neither an
		// administrator nor holding it, so nothing else will ever hand them a
		// list for this kind.
		if _, err := db.DB.NewUpdate().Table("finding").
			Set(`"assigned_to" = ?`, next.PartyID).
			Where(`"kind" = ?`, finding.Entered).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if n := waiting(t, db, held); n != 0 {
			t.Errorf("the previous holder still sees %d alerts about an embargo "+
				"that is no longer theirs", n)
		}
		if n := waiting(t, db, next); n != 1 {
			t.Errorf("whoever holds it now was told %d things, want 1", n)
		}
	})
}
