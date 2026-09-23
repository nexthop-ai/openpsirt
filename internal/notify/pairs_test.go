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
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// team is a product with people who may approve in it, and the administrator
// the condition is told to.
type team struct {
	db      *database.DB
	product int64
	admin   *access.Account
	people  map[string]*access.Account
	claims  int
}

func aTeam(t *testing.T, db *database.DB, names ...string) *team {
	t.Helper()
	ctx := t.Context()
	dbtest.Reset(t, db)
	rights := access.NewStore(db.DB)
	admin, err := rights.Ensure(ctx, "admin@example.com", "Admin", access.Stated(true), nil)
	if err != nil {
		t.Fatal(err)
	}
	aScannedTarget(t, db)
	product, err := catalog.NewStore(db.DB).ProductByName(ctx, "sonic")
	if err != nil {
		t.Fatal(err)
	}
	tm := &team{db: db, product: product.ID, admin: admin, people: map[string]*access.Account{}}
	for _, name := range names {
		person, err := rights.Ensure(ctx, name+"@example.com", name, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, person.ID, product.ID, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		tm.people[name] = person
	}
	return tm
}

// agreed writes claims one person proposed and another agreed to, straight to
// the tables, proposed a number of days ago.
func (tm *team) agreed(t *testing.T, proposer, approver string, n, daysAgo int) {
	t.Helper()
	ctx := t.Context()
	at := time.Now().UTC().Add(-time.Duration(daysAgo) * 24 * time.Hour).Truncate(time.Microsecond)
	by, with := tm.people[proposer].ID, tm.people[approver].ID
	for range n {
		tm.claims++
		reason := string(triage.CodeNotPresent)
		claim := &triage.Claim{
			Kind: triage.FindingClaim, ProposedBy: by, ProposedAt: at,
			Outcome: triage.NotApplicable, Justification: &reason,
		}
		if _, err := tm.db.DB.NewInsert().Model(claim).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		revision := &triage.Revision{ClaimID: claim.ID, Ordinal: 1, Body: "Not shipped.",
			WrittenBy: by, WrittenAt: at}
		if _, err := tm.db.DB.NewInsert().Model(revision).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		decision := &triage.Decision{
			ClaimID: claim.ID, ProductID: tm.product,
			VulnerabilityID: tm.issue(t),
			PlaceIdentity:   fmt.Sprintf("place-%d", tm.claims), Visibility: access.Public,
			NeedsApproval: true, State: triage.Approved,
			ProposedBy: by, ProposedAt: at,
		}
		if _, err := tm.db.DB.NewInsert().Model(decision).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		approval := &triage.Approval{ClaimID: claim.ID, RevisionID: revision.ID,
			ApprovedBy: with, ApprovedAt: at}
		if _, err := tm.db.DB.NewInsert().Model(approval).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func (tm *team) issue(t *testing.T) int64 {
	t.Helper()
	interned, err := finding.NewVulnerabilities(tm.db.DB).Intern(t.Context(), []finding.Named{
		{Identifier: "CVE-2026-7777", Severity: "high"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return interned["CVE-2026-7777"]
}

// heard is what the condition says to somebody, or empty.
func (tm *team) heard(t *testing.T, who *access.Account) string {
	t.Helper()
	ctx := t.Context()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, _, err := notify.NewWatch(tm.db.DB, quiet).Once(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _, err := notify.NewStore(tm.db.DB).Waiting(ctx, asks(t, tm.db, who), 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Kind == notify.PairsConcentrated {
			return row.Body
		}
	}
	return ""
}

func (tm *team) thresholds(t *testing.T, share, approvers *int) {
	t.Helper()
	if err := catalog.NewStore(tm.db.DB).SetPairThresholds(t.Context(), tm.product,
		share, approvers); err != nil {
		t.Fatal(err)
	}
}

func TestOnePairAgreeingToMostOfAProductsWorkIsRaised(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		tm := aTeam(t, db, "ana", "ben", "cat")
		// Both directions count toward the one pair: nine of ten.
		tm.agreed(t, "ana", "ben", 5, 3)
		tm.agreed(t, "ben", "ana", 4, 3)
		tm.agreed(t, "cat", "ana", 1, 3)

		body := tm.heard(t, tm.admin)
		if body == "" {
			t.Fatal("one pair agreed to nine of ten claims among three approvers and nobody was told")
		}
		for _, want := range []string{"ana@example.com", "ben@example.com", "90%"} {
			if !strings.Contains(body, want) {
				t.Errorf("the alert says %q, want it to say %q", body, want)
			}
		}
		// Every administrator is told, so how much work the product agreed
		// to stays out of it.
		for _, not := range []string{"10", "9 of"} {
			if strings.Contains(body, not) {
				t.Errorf("the alert says %q, which gives the product's volume as %q", body, not)
			}
		}
		if told := tm.heard(t, tm.people["cat"]); told != "" {
			t.Errorf("somebody who administers nothing was told %q", told)
		}
	})
}

func TestAPairIsNotRaisedUnderTheShare(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		tm := aTeam(t, db, "ana", "ben", "cat")
		// Seven of ten, under the four in five that ships.
		tm.agreed(t, "ana", "ben", 7, 3)
		tm.agreed(t, "cat", "ana", 3, 3)
		if body := tm.heard(t, tm.admin); body != "" {
			t.Errorf("a pair under the share raised %q", body)
		}
	})
}

func TestAPairIsNotRaisedInATeamTooSmallForItToBeAChoice(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		tm := aTeam(t, db, "ana", "ben")
		tm.agreed(t, "ana", "ben", 10, 3)
		if body := tm.heard(t, tm.admin); body != "" {
			t.Errorf("two people who are the whole team raised %q", body)
		}
		// A product stating its own floor of two says a pair is worth raising
		// there.
		two := 2
		tm.thresholds(t, nil, &two)
		if body := tm.heard(t, tm.admin); body == "" {
			t.Error("the product lowered its floor to two and the pair was not raised")
		}
	})
}

func TestAProductsOwnShareIsTheOneAsked(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		tm := aTeam(t, db, "ana", "ben", "cat")
		tm.agreed(t, "ana", "ben", 9, 3)
		tm.agreed(t, "cat", "ana", 1, 3)
		share := 95
		tm.thresholds(t, &share, nil)
		if body := tm.heard(t, tm.admin); body != "" {
			t.Errorf("nine of ten under a product's own share of 95 raised %q", body)
		}
	})
}

func TestAPairIsCountedOverTheReportsPeriod(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		tm := aTeam(t, db, "ana", "ben", "cat")
		// A pattern the team has since moved away from is not a control
		// failing today. Counted over the whole record, the old pair is
		// fifty of sixty and past the share.
		tm.agreed(t, "ana", "ben", 50, 120)
		tm.agreed(t, "cat", "ana", 5, 3)
		tm.agreed(t, "ben", "cat", 5, 3)
		if body := tm.heard(t, tm.admin); body != "" {
			t.Errorf("claims proposed four months ago raised %q", body)
		}
	})
}

func TestOldAgreementsDoNotDiluteAPairsShareNow(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		tm := aTeam(t, db, "ana", "ben", "cat")
		// Four months ago the work was spread; this quarter one pair did it.
		tm.agreed(t, "cat", "ben", 20, 120)
		tm.agreed(t, "ana", "ben", 9, 3)
		tm.agreed(t, "cat", "ana", 1, 3)
		if body := tm.heard(t, tm.admin); body == "" {
			t.Error("one pair agreed to nine of this quarter's ten claims and older work hid it")
		}
	})
}

func TestAPairIsNotRaisedOverTooFewClaims(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		tm := aTeam(t, db, "ana", "ben", "cat")
		// Every claim, and a handful of them.
		tm.agreed(t, "ana", "ben", 9, 3)
		if body := tm.heard(t, tm.admin); body != "" {
			t.Errorf("nine claims in a quarter raised %q", body)
		}
		tm.agreed(t, "ben", "ana", 1, 3)
		if body := tm.heard(t, tm.admin); body == "" {
			t.Error("one pair agreed to all of ten claims and nobody was told")
		}
	})
}

func TestAShareOfExactlyTheThresholdIsRaised(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		tm := aTeam(t, db, "ana", "ben", "cat")
		// Eight of ten is the four in five that ships.
		tm.agreed(t, "ana", "ben", 8, 3)
		tm.agreed(t, "cat", "ana", 2, 3)
		if body := tm.heard(t, tm.admin); body == "" {
			t.Error("a pair at exactly the share was not raised")
		}
		// And a product asking for every agreement is told when it is.
		dbtest.Reset(t, db)
		tm = aTeam(t, db, "ana", "ben", "cat")
		tm.agreed(t, "ana", "ben", 10, 3)
		all := 100
		tm.thresholds(t, &all, nil)
		if body := tm.heard(t, tm.admin); body == "" {
			t.Error("one pair gave every agreement under a share of 100 and nobody was told")
		}
	})
}
