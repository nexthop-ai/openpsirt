package advisory_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
)

// standingOn is the agreements standing on what the advisory says now.
func standingOn(t *testing.T, f *fixture, named string) ([]advisory.Approval, error) {
	t.Helper()
	where, err := f.store.Where(t.Context(), f.who, named)
	if err != nil {
		return nil, err
	}
	return where.Agreed, nil
}

// TestEditingTakesBackTheAgreementStandingOnWhatItReplaced runs each of the
// three acts that change what a document says.
//
// A rule enforced at one of three sites is a rule that holds until somebody
// does their job: an approver reads a document covering one flaw, and a second
// added under their agreement is one nobody read.
func TestEditingTakesBackTheAgreementStandingOnWhatItReplaced(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		for _, one := range []struct {
			what string
			edit func(t *testing.T, f *fixture, named string)
		}{
			{"retitled", func(t *testing.T, f *fixture, named string) {
				if _, _, err := f.store.Retitle(ctx, f.who, named,
					"Authentication bypass in the recovery console"); err != nil {
					t.Fatalf("retitling: %v", err)
				}
			}},
			{"another flaw named on it", func(t *testing.T, f *fixture, named string) {
				second := f.recorded(t, f.tagged)
				if _, err := f.store.Add(ctx, f.who, named, "sonic", second); err != nil {
					t.Fatalf("naming a second flaw: %v", err)
				}
			}},
			{"a flaw taken off it", func(t *testing.T, f *fixture, named string) {
				// Two flaws, so taking one off leaves a document that still
				// states something. One would leave nothing to read.
				second := f.recorded(t, f.tagged)
				if _, err := f.store.Add(ctx, f.who, named, "sonic", second); err != nil {
					t.Fatalf("naming a second flaw: %v", err)
				}
				f.agreed(t, named)
				if err := f.store.Drop(ctx, f.who, named, "sonic", second); err != nil {
					t.Fatalf("taking a flaw off: %v", err)
				}
			}},
		} {
			t.Run(one.what, func(t *testing.T) {
				identifier := f.recorded(t, f.master)
				named := f.covering(t, [2]string{"sonic", identifier})
				f.agreed(t, named)

				standing, err := standingOn(t, f, named)
				if err != nil {
					t.Fatal(err)
				}
				if len(standing) != 1 {
					t.Fatalf("%d agreements stand before the edit", len(standing))
				}

				one.edit(t, f, named)

				standing, err = standingOn(t, f, named)
				if err != nil {
					t.Fatal(err)
				}
				if len(standing) != 0 {
					t.Errorf("%d agreements still stand after it was %s", len(standing), one.what)
				}
				// And the document it would publish is one nobody has agreed
				// to, which is the consequence the agreement exists for.
				if _, err := f.store.Issued(ctx, f.who, issuer, named, ""); !errors.Is(err, advisory.ErrNotAgreed) {
					t.Errorf("issuing after it was %s answered %v", one.what, err)
				}
				// The agreement it replaced is marked as taken back rather
				// than left looking standing. Two things stop a superseded
				// agreement counting — it names the edition, and it is
				// withdrawn — and this is the half the edition cannot say:
				// taking one back finds nothing to take, which it would find
				// if the row were still open.
				if err := f.store.Withdraw(ctx, f.approver, named); !errors.Is(err, advisory.ErrNothingAgreed) {
					t.Errorf("taking back an agreement after it was %s answered %v",
						one.what, err)
				}
			})
		}
	})
}

// TestWhoeverWroteWhatAnAdvisorySaysMayNotAgreeToIt is the control, watched
// from both sides.
//
// The person who started it and the person who wrote the edition standing are
// both refused, because the value of a second pair of eyes is that they are
// the second pair. Whoever started an advisory chose the name a reader cites
// it by and, in the ordinary case, the flaws it covers — so retitling it for
// them would otherwise leave them agreeing to a document that is theirs but
// for its title.
func TestWhoeverWroteWhatAnAdvisorySaysMayNotAgreeToIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		identifier := f.recorded(t, f.master)
		named := f.covering(t, [2]string{"sonic", identifier})

		// Whoever minted it, which is also who named the flaw on it.
		if _, err := f.store.Approve(ctx, f.who, named); !errors.Is(err, advisory.ErrSamePerson) {
			t.Errorf("the person who started it agreeing to it answered %v", err)
		}

		// And whoever wrote the edition standing, who is somebody else. The
		// minter is not this person, so only the edition's author refuses it
		// — which is the arm the check on the minter cannot reach.
		if _, _, err := f.store.Retitle(ctx, f.approver, named,
			"Authentication bypass in the recovery console"); err != nil {
			t.Fatalf("retitling as the second person: %v", err)
		}
		if _, err := f.store.Approve(ctx, f.approver, named); !errors.Is(err, advisory.ErrSamePerson) {
			t.Errorf("the person who wrote the words agreeing to them answered %v", err)
		}
		// And the person who started it, now that somebody else wrote the
		// words standing. This is the only input that reaches that arm: while
		// the minter wrote the edition too, the check on the author answers
		// first and either one alone would look like the rule.
		if _, err := f.store.Approve(ctx, f.who, named); !errors.Is(err, advisory.ErrSamePerson) {
			t.Errorf("the person who started it agreeing to somebody else's words answered %v", err)
		}
		// Whoever wrote neither the advisory nor the words standing may, which
		// is what says the two refusals above are the rule rather than the
		// whole path being shut. The minter writes the edition this time, so
		// the second person is reading somebody else's words again.
		if _, _, err := f.store.Retitle(ctx, f.who, named,
			"Authentication bypass in the recovery console, on every release"); err != nil {
			t.Fatalf("retitling as the person who started it: %v", err)
		}
		if _, err := f.store.Approve(ctx, f.approver, named); err != nil {
			t.Errorf("somebody who wrote neither could not agree: %v", err)
		}
	})
}

// TestAgreeingTwiceIsRefusedAndTakingItBackIsNot pins the two ends of one
// agreement.
func TestAgreeingTwiceIsRefusedAndTakingItBackIsNot(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		identifier := f.recorded(t, f.master)
		named := f.covering(t, [2]string{"sonic", identifier})

		if err := f.store.Withdraw(ctx, f.approver, named); !errors.Is(err, advisory.ErrNothingAgreed) {
			t.Errorf("taking back an agreement nobody gave answered %v", err)
		}
		f.agreed(t, named)
		if _, err := f.store.Approve(ctx, f.approver, named); !errors.Is(err, advisory.ErrAlreadyAgreed) {
			t.Errorf("agreeing twice answered %v", err)
		}
		if err := f.store.Withdraw(ctx, f.approver, named); err != nil {
			t.Fatalf("taking an agreement back: %v", err)
		}
		standing, err := standingOn(t, f, named)
		if err != nil {
			t.Fatal(err)
		}
		if len(standing) != 0 {
			t.Errorf("%d agreements stand after it was taken back", len(standing))
		}
		// And the same person may agree again, because what they took back
		// was the agreement rather than their standing to give one.
		if _, err := f.store.Approve(ctx, f.approver, named); err != nil {
			t.Errorf("agreeing again after taking it back: %v", err)
		}
	})
}

// TestTheDocumentSaysWhereItIsInItsLifeRatherThanWhetherItIsEmbargoed walks
// the three statuses.
//
// Read from the embargo, the third could not be expressed at all, and the
// other two answered a question a reader was not asking: whether the flaws
// behind the document are public, rather than whether this is the publisher's
// settled word.
func TestTheDocumentSaysWhereItIsInItsLifeRatherThanWhetherItIsEmbargoed(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		identifier := f.recorded(t, f.master)
		named := f.covering(t, [2]string{"sonic", identifier})
		says := func(t *testing.T, when, want string) {
			t.Helper()
			doc, err := f.store.ForAdvisory(ctx, f.who, issuer, named)
			if err != nil {
				t.Fatal(err)
			}
			if doc.Document.Tracking.Status != want {
				t.Errorf("%s the document says %q, want %q",
					when, doc.Document.Tracking.Status, want)
			}
		}

		says(t, "with nobody agreeing and nothing published", "draft")

		// Final before it has gone out, because this is the file the operator
		// sends. Asked the other way round the one document that actually
		// leaves says it is a draft.
		f.agreed(t, named)
		says(t, "agreed to and not yet published", "final")

		if _, err := f.store.Issued(ctx, f.who, issuer, named, "First"); err != nil {
			t.Fatal(err)
		}
		says(t, "published, with the agreement standing", "final")

		if _, _, err := f.store.Retitle(ctx, f.who, named,
			"Authentication bypass in the recovery console"); err != nil {
			t.Fatal(err)
		}
		says(t, "published and edited since", "interim")

		f.agreed(t, named)
		says(t, "published and agreed to again", "final")

		// And taking the agreement back reaches interim without a word
		// moving, which is the arm the edit above cannot tell apart.
		if err := f.store.Withdraw(ctx, f.approver, named); err != nil {
			t.Fatal(err)
		}
		says(t, "published with the agreement taken back", "interim")
	})
}

// TestAnEmbargoedAdvisoryTravelsNoFurtherWhateverItSaysAboutItself is the
// half the tracking status was doing before and no longer does.
//
// Reading both off one fact made them move together. Apart, the label has to
// be asked of the embargo directly, and this is the case that says it is: a
// document about a flaw still held back, published to a coordinating body, at
// every editorial state there is.
func TestAnEmbargoedAdvisoryTravelsNoFurtherWhateverItSaysAboutItself(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// Held back, which is what recording a flaw does until somebody
		// discloses it.
		identifier := f.recorded(t, f.master)
		named := f.covering(t, [2]string{"sonic", identifier})
		red := func(t *testing.T, when string) {
			t.Helper()
			doc, err := f.store.ForAdvisory(ctx, f.who, issuer, named)
			if err != nil {
				t.Fatal(err)
			}
			if doc.Document.Distribution == nil || doc.Document.Distribution.TLP == nil {
				t.Fatalf("%s the document says nothing about how far it may travel", when)
			}
			if label := doc.Document.Distribution.TLP.Label; label != "RED" {
				t.Errorf("%s a document about a flaw still held back is labelled %q", when, label)
			}
		}

		red(t, "as a draft,")
		f.agreed(t, named)
		if _, err := f.store.Issued(ctx, f.who, issuer, named, "To the coordinator"); err != nil {
			t.Fatalf("publishing an embargoed advisory to a coordinating body: %v", err)
		}
		// Final, and still not somewhere it may be passed on. This is the
		// pair that moved together before.
		doc, err := f.store.ForAdvisory(ctx, f.who, issuer, named)
		if err != nil {
			t.Fatal(err)
		}
		if doc.Document.Tracking.Status != "final" {
			t.Fatalf("the published document says %q", doc.Document.Tracking.Status)
		}
		red(t, "once published,")
	})
}

// TestWhatWentOutKeepsTheTitleItWentOutWith pins the issuance against the
// advisory moving on.
//
// A record of what was published says what was published. Read through the
// advisory, a record of March's document answers with June's title, and
// "is what is published still what we would generate" becomes a question
// about a document nobody sent.
func TestWhatWentOutKeepsTheTitleItWentOutWith(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// Disclosed, so that the reader below is narrowed by the product
		// rather than by the embargo.
		identifier := f.disclosed(t, f.master)
		named := f.covering(t, [2]string{"sonic", identifier})
		if _, _, err := f.store.Retitle(ctx, f.who, named, "What it said then"); err != nil {
			t.Fatal(err)
		}
		f.agreed(t, named)
		if _, err := f.store.Issued(ctx, f.who, issuer, named, "First"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.store.Retitle(ctx, f.who, named, "What it says now"); err != nil {
			t.Fatal(err)
		}

		rows, err := f.store.Published(ctx, f.who, nil, time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("%d rows came back for one issuance", len(rows))
		}
		if rows[0].Title != "What it said then" {
			t.Errorf("what went out is recorded as %q", rows[0].Title)
		}
	})
}

// TestChangingWhatAnAdvisorySaysNeedsTheRoleOnEveryProductItCovers is the
// authorization half.
//
// An advisory is read whole or not at all, and what it says about one product
// is part of the same document as what it says about another. Somebody who
// triages one of two would otherwise retitle a document published about both,
// or agree to it on behalf of a product they only read.
func TestChangingWhatAnAdvisorySaysNeedsTheRoleOnEveryProductItCovers(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		here := f.recorded(t, f.master)
		there := f.recorded(t, f.other)
		named := f.covering(t,
			[2]string{"sonic", here}, [2]string{"switchd", there})

		// Reading both, so the advisory resolves and nothing but the missing
		// role refuses what follows. Triage on one of the two, which is the
		// rule being pinned.
		partly := access.NewPerson(f.second.ID, f.second.Identity, false,
			map[int64][]access.Role{
				f.product:      {access.PublicRead, access.PrivateRead, access.PrivateTriage},
				f.otherProduct: {access.PublicRead, access.PrivateRead},
			}, 0)

		// They may read it, which is what makes the refusals below about the
		// role rather than about the advisory being out of reach.
		if _, _, err := f.store.Covers(ctx, partly, named); err != nil {
			t.Fatalf("reading an advisory they hold both products on: %v", err)
		}
		if _, err := f.store.Approve(ctx, partly, named); !errors.Is(err, access.ErrDenied) {
			t.Errorf("agreeing with triage on one of two products answered %v", err)
		}
		if _, _, err := f.store.Retitle(ctx, partly, named, "Something else"); !errors.Is(
			err, access.ErrDenied) {
			t.Errorf("retitling with triage on one of two products answered %v", err)
		}
		if err := f.store.Withdraw(ctx, partly, named); !errors.Is(err, access.ErrDenied) {
			t.Errorf("taking an agreement back with triage on one of two answered %v", err)
		}
		// Naming a flaw and taking one off are on this list because both open
		// an edition and take back every agreement standing on the whole
		// advisory. Checked against the product in the request alone, the
		// person above could undo a second person's agreement to a document
		// about a product they only read — by acting on the one they triage.
		another := f.recorded(t, f.master)
		if _, err := f.store.Add(ctx, partly, named, "sonic", another); !errors.Is(
			err, access.ErrDenied) {
			t.Errorf("naming a flaw with triage on one of two products answered %v", err)
		}
		if err := f.store.Drop(ctx, partly, named, "sonic", here); !errors.Is(
			err, access.ErrDenied) {
			t.Errorf("taking a flaw off with triage on one of two products answered %v", err)
		}

		// And somebody holding it on both may, which says the refusals are
		// the missing role rather than the path being shut.
		if _, err := f.store.Approve(ctx, f.approver, named); err != nil {
			t.Errorf("somebody triaging both products could not agree: %v", err)
		}
	})
}

// TestRetitlingRunsTheSubmissionPolicyBeforeStoring holds the invariant every
// path that stores typed text is held to.
//
// A title is our own prose and it reaches the published document verbatim.
// Retitling is a new such path, and the policy is enforced at submission
// rather than at render because nothing on the server renders.
func TestRetitlingRunsTheSubmissionPolicyBeforeStoring(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		identifier := f.recorded(t, f.master)
		named := f.covering(t, [2]string{"sonic", identifier})
		if _, _, err := f.store.Retitle(ctx, f.who, named, "What it is called"); err != nil {
			t.Fatal(err)
		}

		if _, _, err := f.store.Retitle(ctx, f.who, named,
			"Slipping <script>alert(1)</script> past it"); err == nil {
			t.Error("raw HTML in a title was stored")
		}
		// And the title it had is the title it still has, which is what says
		// the refusal happened before the write rather than after it.
		row, _, err := f.store.Covers(ctx, f.who, named)
		if err != nil {
			t.Fatal(err)
		}
		if row.Title != "What it is called" {
			t.Errorf("the advisory is called %q after a refused retitle", row.Title)
		}
	})
}
