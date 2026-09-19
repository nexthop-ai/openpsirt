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
		// putOff is how far ahead a deferral's date is, which is what decides
		// whether the gate asked for a second person at all. Zero everywhere
		// else, and a month where a deferral wants to be the ordinary short
		// one.
		putOff time.Duration
	}{
		// The three that claim no further work is needed. Each requires a
		// second person, so each standing alone is a control that did not hold.
		{"not applicable, nobody agreeing", triage.NotApplicable, nobody, true, 0},
		{"will not fix, nobody agreeing", triage.WontFix, nobody, true, 0},
		{"already fixed, nobody agreeing", triage.AlreadyFixed, nobody, true, 0},
		// The same claim with somebody else's agreement is the rule working,
		// which is the arm that says this counts the right thing rather than
		// everything.
		{"not applicable, agreed by a second person", triage.NotApplicable, aSecondPerson, false, 0},
		// An agreement from the proposer is not a second person. It is the
		// shape the write path refuses and the one this exists to catch.
		{"not applicable, agreed by its own proposer", triage.NotApplicable, itsOwnProposer, true, 0},
		// An agreement taken back leaves nothing standing behind the claim,
		// which is the whole point of withdrawing one.
		{"not applicable, agreed and then withdrawn", triage.NotApplicable, thenWithdrawn, true, 0},
		// Hides risk and is approved conditionally, on where its date sits
		// against the deadline already set. A short one needed nobody, so
		// standing alone is the ordinary case rather than a failure, and
		// counting it would report a control as broken on the case it was
		// built for.
		{"a short deferral, nobody agreeing", triage.Deferred, nobody, false,
			20 * 24 * time.Hour},
		// The same claim put off far enough that the gate asked for a second
		// person. It got one and then it was taken back, so a decision that
		// needed agreement is standing with none — which is the same write
		// path got around that the three above are, and was missed entirely
		// while this asked which outcome it was rather than whether the gate
		// had asked.
		{"a long deferral, agreed and then withdrawn", triage.Deferred, thenWithdrawn, true,
			120 * 24 * time.Hour},
		// And the short one is not caught by the same widening, which is what
		// says this asks the gate's verdict rather than counting everything
		// that hides risk. The report behind the link does count these, and
		// deliberately: it shows them for a person to judge.
		{"a short deferral, agreed and then withdrawn", triage.Deferred, thenWithdrawn, false,
			20 * 24 * time.Hour},
		// Leaves the issue visible as an issue, so there is nothing to agree to.
		{"affected, nobody agreeing", triage.Affected, nobody, false, 0},
		// Waiting in the queue for its second person, which is the control
		// working rather than failing: it suppresses nothing and hides nothing
		// while it waits, and somebody is looking at it.
		{"not applicable, still waiting for agreement", triage.NotApplicable, stillWaiting, false, 0},
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

				f.unagreed(t, one.outcome, one.agree, one.putOff)

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
func (f *fixture) unagreed(t *testing.T, outcome triage.Outcome, behind agreement,
	putOff time.Duration) {

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
		until := time.Now().UTC().Add(putOff)
		proposal.DeferredUntil = &until
	case triage.AlreadyFixed:
		proposal.FixedVersion = "1.2.4"
	}
	decision, err := f.store.Propose(ctx, f.triager, proposal)
	if err != nil {
		t.Fatalf("propose %s: %v", outcome, err)
	}
	// gated is what the gate decided, not what this asked for. Propose
	// re-works it against the policy in force when the write lands, so
	// passing it in says nothing — and the whole widening turns on the
	// gate's own verdict, which would be worth nothing if a caller could
	// assert it.
	var gated bool
	if err := f.db.DB.NewSelect().TableExpr(`"decision"`).
		ColumnExpr("needs_approval").Where("claim_id = ?", decision.ClaimID).
		Limit(1).Scan(ctx, &gated); err != nil {
		t.Fatalf("read whether the gate asked for a second person: %v", err)
	}
	if outcome == triage.Deferred && gated != (putOff > triage.DefaultDeferralThreshold) {
		t.Fatalf("a deferral of %s was gated %v, which is not what the shipped "+
			"threshold of %s decides — the fixture no longer builds the arm it names",
			putOff, gated, triage.DefaultDeferralThreshold)
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
