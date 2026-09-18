package triage_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestWhatHidesRiskWithNobodyAgreeingIsCountedAndTheRestIsNot(t *testing.T) {
	// The question the second-person rule means. It has to answer correctly
	// about a row the write path should never have produced, so the agreement
	// here goes straight to the table: a count that trusted the write path
	// would be reporting on itself, and this is the one failure nothing else
	// can find afterwards.
	for _, one := range []struct {
		what    string
		outcome triage.Outcome
		agree   agreement
		counts  bool
	}{
		// The three that claim no further work is needed. Each requires a
		// second person, so each standing alone is a control that did not hold.
		{"not applicable, nobody agreeing", triage.NotApplicable, nobody, true},
		{"will not fix, nobody agreeing", triage.WontFix, nobody, true},
		{"already fixed, nobody agreeing", triage.AlreadyFixed, nobody, true},
		// The same claim with somebody else's agreement is the rule working,
		// which is the arm that says this counts the right thing rather than
		// everything.
		{"not applicable, agreed by a second person", triage.NotApplicable, aSecondPerson, false},
		// An agreement from the proposer is not a second person. It is the
		// shape the write path refuses and the one this exists to catch.
		{"not applicable, agreed by its own proposer", triage.NotApplicable, itsOwnProposer, true},
		// An agreement taken back leaves nothing standing behind the claim,
		// which is the whole point of withdrawing one.
		{"not applicable, agreed and then withdrawn", triage.NotApplicable, thenWithdrawn, true},
		// Hides risk and is approved conditionally, on where its date sits
		// against the deadline already set. Standing alone is the ordinary case
		// rather than a failure, so counting it would report a control as
		// broken on the case it was built for.
		{"deferred, nobody agreeing", triage.Deferred, nobody, false},
		// Leaves the issue visible as an issue, so there is nothing to agree to.
		{"affected, nobody agreeing", triage.Affected, nobody, false},
		// Waiting in the queue for its second person, which is the control
		// working rather than failing: it suppresses nothing and hides nothing
		// while it waits, and somebody is looking at it.
		{"not applicable, still waiting for agreement", triage.NotApplicable, stillWaiting, false},
	} {
		t.Run(one.what, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				before, _, err := f.store.HiddenWithNobodyAgreeing(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if before != 0 {
					t.Fatalf("a deployment that has decided nothing counts %d", before)
				}

				f.unagreed(t, one.outcome, one.agree)

				claims, rows, err := f.store.HiddenWithNobodyAgreeing(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				want := 0
				if one.counts {
					want = 1
				}
				if claims != want || rows != want {
					t.Errorf("counted %d claims over %d rows, want %d of each",
						claims, rows, want)
				}
			})
		})
	}
}

// agreement is what stands behind a claim, for the table above.
type agreement int

const (
	nobody agreement = iota
	aSecondPerson
	itsOwnProposer
	thenWithdrawn
	stillWaiting
)

// unagreed records one claim of this outcome and puts the stated agreement
// behind it.
//
// The claim goes through the store, because what is being asked about is a real
// decision in force. The agreement goes to the table directly where it is one
// the store would refuse, which is exactly the row this has to see through.
func (f *fixture) unagreed(t *testing.T, outcome triage.Outcome, behind agreement) {
	t.Helper()
	ctx := t.Context()
	proposal := triage.Proposal{
		Place: f.at(), Outcome: outcome, By: f.proposer,
		Reasoning:     "The parser is never reached: we only call the encoder.",
		NeedsApproval: outcome.HidesRisk(),
	}
	switch outcome {
	case triage.NotApplicable:
		proposal.Justification = triage.CodeNotInExecutePath
	case triage.Deferred:
		until := time.Now().UTC().Add(30 * 24 * time.Hour)
		proposal.DeferredUntil = &until
	case triage.AlreadyFixed:
		proposal.FixedVersion = "1.2.4"
	}
	decision, err := f.store.Propose(ctx, f.triager, proposal)
	if err != nil {
		t.Fatalf("propose %s: %v", outcome, err)
	}

	if behind != stillWaiting {
		now := time.Now().UTC().Truncate(time.Microsecond)
		if behind != nobody {
			approver := f.approver
			if behind == itsOwnProposer {
				approver = f.proposer
			}
			approval := &triage.Approval{
				ClaimID: decision.ClaimID, RevisionID: revisionOf(t, f, decision.ClaimID),
				ApprovedBy: approver, ApprovedAt: now,
			}
			if behind == thenWithdrawn {
				approval.WithdrawnAt, approval.WithdrawnBy = &now, &f.proposer
			}
			if _, err := f.db.DB.NewInsert().Model(approval).Exec(ctx); err != nil {
				t.Fatalf("write the agreement: %v", err)
			}
		}
		// Standing, whatever is or is not behind it. That is the state this
		// asks about: a decision in force suppresses a finding, and one still
		// waiting suppresses nothing.
		if _, err := f.db.DB.NewUpdate().Table("decision").
			Set("state = ?", triage.Approved).
			Where("claim_id = ?", decision.ClaimID).Exec(ctx); err != nil {
			t.Fatalf("stand the decision: %v", err)
		}
	}
}

// revisionOf is the revision a claim's reasoning currently stands at, which an
// agreement points at.
func revisionOf(t *testing.T, f *fixture, claimID int64) int64 {
	t.Helper()
	var revision int64
	if err := f.db.DB.NewSelect().TableExpr(`"claim"`).
		ColumnExpr("revision_id").Where("id = ?", claimID).
		Scan(t.Context(), &revision); err != nil {
		t.Fatalf("read which revision stands: %v", err)
	}
	return revision
}
