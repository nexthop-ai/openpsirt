package notify_test

import (
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
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

func TestARulingWaitingOnASecondPersonIsRaisedToWhoeverMayApproveIt(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		product, err := catalog.NewStore(db.DB).DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		person := func(identity string, role access.Role) *access.Account {
			t.Helper()
			who, err := rights.Ensure(ctx, identity, identity, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := rights.GrantRole(ctx, who.ID, product.ID, role); err != nil {
				t.Fatal(err)
			}
			return who
		}
		proposer := person("proposer@example.com", access.PrivateTriage)
		second := person("second@example.com", access.PrivateTriage)
		// Approving a ruling asks what reading a report asks, so the approver
		// capability alone and triage of announced work are told nothing.
		approver := person("approver@example.com", access.Approver)
		announced := person("announced@example.com", access.PublicTriage)
		// And somebody who may read undisclosed work and approve it, which
		// is the role the rule turns on: the notice is private, so the two
		// above never read it whoever it is written for.
		reads := person("reads@example.com", access.PrivateRead)
		if err := rights.GrantRole(ctx, reads.ID, product.ID, access.Approver); err != nil {
			t.Fatal(err)
		}

		store := finding.NewStore(db.DB)
		proposing := access.NewPerson(proposer.ID, proposer.Identity, false,
			map[int64][]access.Role{product.ID: {access.PrivateTriage}}, 0)
		var named []string
		for range 2 {
			row, err := store.Record(ctx, proposing, product.ID,
				finding.Claimed{Summary: "Generated text about a function this does not have."})
			if err != nil {
				t.Fatal(err)
			}
			named = append(named, row.Reference)
		}
		ruling, err := store.Rule(ctx, proposing, product.ID, finding.Ruled{
			References: named, Disposition: finding.Rejected, Reasoning: "Slop.",
		})
		if err != nil {
			t.Fatal(err)
		}
		// Older than a claim may wait.
		if _, err := db.DB.NewUpdate().Model((*finding.ReportRuling)(nil)).
			Set("proposed_at = ?", time.Now().UTC().Add(-8*24*time.Hour)).
			Where("id = ?", ruling.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		watch := notify.NewWatch(db.DB, quiet)
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		waitingOn := func(who *access.Account) []notify.Notification {
			t.Helper()
			rows, _, err := notify.NewStore(db.DB).Waiting(ctx, asks(t, db, who), 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			var out []notify.Notification
			for _, row := range rows {
				if row.Kind == notify.ClaimWaiting {
					out = append(out, row)
				}
			}
			return out
		}
		told := waitingOn(second)
		if len(told) != 1 {
			t.Fatalf("somebody who may approve was told %d things, want 1", len(told))
		}
		if !strings.Contains(told[0].Body, "2 reports rejected") {
			t.Errorf("the alert reads %q", told[0].Body)
		}
		if told[0].Link != "/products/sonic/inbox?waiting=1" {
			t.Errorf("the alert points at %q", told[0].Link)
		}
		for _, who := range []*access.Account{proposer, approver, announced, reads} {
			if n := len(waitingOn(who)); n != 0 {
				t.Errorf("%s was told %d things about a ruling they may not approve",
					who.Identity, n)
			}
		}

		// Approving it clears the condition, with nobody dismissing anything.
		approving := access.NewPerson(second.ID, second.Identity, false,
			map[int64][]access.Role{product.ID: {access.PrivateTriage}}, 0)
		if _, err := store.ApproveRuling(ctx, approving, product.ID, ruling.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if n := len(waitingOn(second)); n != 0 {
			t.Errorf("an approved ruling is still raised %d times", n)
		}
	})
}
