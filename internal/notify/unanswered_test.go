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

func TestAClaimNobodyHasJudgedIsStillAnUnansweredLetter(t *testing.T) {
	// The condition is about a letter somebody sent and nobody answered, and
	// a claim nobody has judged is the one most in need of an answer. Derived
	// from the issue alone it fires for none of them, because there is no
	// issue — so the reports the feature exists for are the reports nothing
	// reports.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		product, err := catalog.NewStore(db.DB).DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		// Somebody who may triage work nobody has announced, and somebody who
		// may only triage what has been. The second is told nothing: the
		// claim is one they cannot open, and an alert about a letter you
		// cannot read is one you can do nothing with.
		answers, err := rights.Ensure(ctx, "answers@example.com", "Answers", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, answers.ID, product.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		announced, err := rights.Ensure(ctx, "announced@example.com", "Announced", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, announced.ID, product.ID, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		// And somebody who may read work nobody has announced but not argue
		// about it. They are the role the rule actually turns on: the
		// condition used to be sent to whoever could read the flaw, and a
		// report refuses them, so the notice named a report they cannot open.
		reads, err := rights.Ensure(ctx, "reads@example.com", "Reads", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, reads.ID, product.ID, access.PrivateRead); err != nil {
			t.Fatal(err)
		}

		report := &finding.FlawReport{
			Reference: "SONIC-R-2026-424242", ProductID: product.ID,
			Summary:    "The management socket accepts a request nobody authenticated.",
			ReportedBy: "A Researcher",
			RecordedBy: answers.ID,
			RecordedAt: time.Now().UTC().Truncate(time.Microsecond),
		}
		if _, err := db.DB.NewInsert().Model(report).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		watch := notify.NewWatch(db.DB, quiet)
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		waiting := func(who *access.Account) []notify.Notification {
			t.Helper()
			rows, _, err := notify.NewStore(db.DB).Waiting(ctx, asks(t, db, who), 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			return rows
		}
		told := waiting(answers)
		if len(told) != 1 {
			t.Fatalf("whoever may answer was told %d things, want 1", len(told))
		}
		// Named by the reference, because a claim nobody has judged has no
		// identifier and no finding screen to point at.
		if !strings.Contains(told[0].Body, report.Reference) {
			t.Errorf("the alert reads %q and does not name %q",
				told[0].Body, report.Reference)
		}
		// And it points at the report, which is where it is answered.
		if want := "/products/sonic/inbox/" + report.Reference; told[0].Link != want {
			t.Errorf("the alert points at %q, want %q", told[0].Link, want)
		}
		if n := len(waiting(announced)); n != 0 {
			t.Errorf("somebody who triages only announced work was told %d things", n)
		}
		if n := len(waiting(reads)); n != 0 {
			t.Errorf("somebody who may read but not triage was told %d things", n)
		}

		// Answering it clears the condition, with nobody dismissing anything.
		if _, err := db.DB.NewUpdate().Model((*finding.FlawReport)(nil)).
			Set("acknowledged_at = ?", time.Now().UTC().Truncate(time.Microsecond)).
			Set("acknowledged_by = ?", answers.ID).
			Where("id = ?", report.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, cleared, err := watch.Once(ctx); err != nil || cleared != 1 {
			t.Errorf("answering the letter cleared %d conditions (err %v), want 1",
				cleared, err)
		}
		if n := len(waiting(answers)); n != 0 {
			t.Errorf("the alert should have cleared itself, %d still waiting", n)
		}
	})
}
