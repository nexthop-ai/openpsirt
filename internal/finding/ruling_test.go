package finding_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// claims records n claims and returns their references.
func (f *fixture) claims(t *testing.T, who access.Subject, n int) []string {
	t.Helper()
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		row, err := f.store.Record(t.Context(), who, f.productID,
			finding.Claimed{Summary: "A claim that is not what it says."})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, row.Reference)
	}
	return out
}

// reportNamed reads one report back as the store holds it.
func (f *fixture) reportNamed(t *testing.T, who access.Subject, reference string) *finding.FlawReport {
	t.Helper()
	row, err := f.store.ReportBy(t.Context(), who, f.productID, reference)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func TestADispositionNobodyElseAgreesToTakesEffectAtOnce(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PrivateTriage)
		named := f.claims(t, who, 1)
		ruling, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: named, Disposition: finding.NotReproducible,
			Reasoning: "Three of us tried on two builds and nothing happened.",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !ruling.InForce() || ruling.ApprovedBy != nil {
			t.Errorf("not reproducible waited for somebody: settled %v, approved by %v",
				ruling.SettledAt, ruling.ApprovedBy)
		}
		row := f.reportNamed(t, who, named[0])
		if row.RulingID == nil || *row.RulingID != ruling.ID {
			t.Errorf("the report points at ruling %v, want %d", row.RulingID, ruling.ID)
		}
		if row.EvaluatedBy == nil || *row.EvaluatedBy != who.ID || row.EvaluatedAt == nil {
			t.Errorf("a ruling in force says it was judged by %v at %v",
				row.EvaluatedBy, row.EvaluatedAt)
		}

		// Answered, so it is neither accepted as an issue nor ruled on again
		// until somebody withdraws what was said.
		issue := f.anIssueHereShipped(t, who)
		if _, err := f.store.JudgeAsIssue(t.Context(), who, f.productID, named[0],
			issue); !errors.Is(err, finding.ErrAlreadyJudged) {
			t.Errorf("accepting a report already ruled on was answered %v", err)
		}
		if _, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: named, Disposition: finding.Rejected, Reasoning: "Twice.",
		}); !errors.Is(err, finding.ErrAlreadyJudged) {
			t.Errorf("ruling on a report twice was answered %v", err)
		}
	})
}

func TestSettingAClaimAsideWaitsForASecondPerson(t *testing.T) {
	for _, disposition := range []finding.Disposition{finding.Rejected, finding.OutOfScope} {
		t.Run(string(disposition), func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				proposer := f.planner(t, access.PrivateTriage)
				second := f.somebody(t, "second@example.com", access.PrivateTriage)
				named := f.claims(t, proposer, 2)

				ruling, err := f.store.Rule(t.Context(), proposer, f.productID, finding.Ruled{
					References: named, Disposition: disposition,
					Reasoning: "Generated text describing a function this product does not have.",
				})
				if err != nil {
					t.Fatal(err)
				}
				if !ruling.Waiting() {
					t.Fatalf("%s took effect with nobody else agreeing", disposition)
				}
				// Waiting is not judged. A report that read as answered while
				// nobody had agreed would be set aside by one person.
				if row := f.reportNamed(t, proposer, named[0]); row.EvaluatedAt != nil {
					t.Errorf("a waiting ruling already says the claim was judged at %v",
						row.EvaluatedAt)
				}

				if _, err := f.store.ApproveRuling(t.Context(), proposer, f.productID,
					ruling.ID); !errors.Is(err, finding.ErrOwnRuling) {
					t.Errorf("the proposer approving their own was answered %v", err)
				}

				approved, err := f.store.ApproveRuling(t.Context(), second, f.productID, ruling.ID)
				if err != nil {
					t.Fatal(err)
				}
				if !approved.InForce() || approved.ApprovedBy == nil ||
					*approved.ApprovedBy != second.ID {
					t.Errorf("approved, it reads settled %v by %v", approved.SettledAt,
						approved.ApprovedBy)
				}
				if len(approved.References) != 2 {
					t.Errorf("one approval covered %v, want both reports", approved.References)
				}
				// Who judged is who proposed, and when; the ruling says who
				// agreed.
				for _, reference := range named {
					row := f.reportNamed(t, proposer, reference)
					if row.EvaluatedBy == nil || *row.EvaluatedBy != proposer.ID ||
						row.EvaluatedAt == nil || !row.EvaluatedAt.Equal(ruling.ProposedAt) {
						t.Errorf("%s says it was judged by %v at %v, want the proposer at %v",
							reference, row.EvaluatedBy, row.EvaluatedAt, ruling.ProposedAt)
					}
				}

				if _, err := f.store.ApproveRuling(t.Context(), second, f.productID,
					ruling.ID); !errors.Is(err, finding.ErrNotWaiting) {
					t.Errorf("approving twice was answered %v", err)
				}
			})
		})
	}
}

func TestAWaitingRulingHoldsItsReports(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PrivateTriage)
		named := f.claims(t, who, 1)
		if _, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: named, Disposition: finding.Rejected, Reasoning: "Not a flaw.",
		}); err != nil {
			t.Fatal(err)
		}
		// Accepted as an issue by whoever gets there first, a report waiting
		// to be rejected would be both at once when the approval lands.
		issue := f.anIssueHereShipped(t, who)
		if _, err := f.store.JudgeAsIssue(t.Context(), who, f.productID, named[0],
			issue); !errors.Is(err, finding.ErrAlreadyJudged) {
			t.Errorf("accepting a report waiting to be rejected was answered %v", err)
		}
		if row := f.reportNamed(t, who, named[0]); row.VulnerabilityID != nil {
			t.Errorf("the report now points at issue %d", *row.VulnerabilityID)
		}
	})
}

func TestWithdrawingARulingReturnsItsReportsToTheInbox(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		proposer := f.planner(t, access.PrivateTriage)
		second := f.somebody(t, "second@example.com", access.PrivateTriage)

		// In force and waiting are one act to withdraw: undoing and sending
		// back are the same thing seen at two moments.
		for _, approve := range []bool{true, false} {
			named := f.claims(t, proposer, 2)
			ruling, err := f.store.Rule(t.Context(), proposer, f.productID, finding.Ruled{
				References: named, Disposition: finding.Rejected, Reasoning: "Slop.",
			})
			if err != nil {
				t.Fatal(err)
			}
			if approve {
				if _, err := f.store.ApproveRuling(t.Context(), second, f.productID,
					ruling.ID); err != nil {
					t.Fatal(err)
				}
			}
			// The proposer may take back their own; re-exposing needs nobody.
			withdrawn, err := f.store.WithdrawRuling(t.Context(), proposer, f.productID, ruling.ID)
			if err != nil {
				t.Fatal(err)
			}
			if withdrawn.InForce() || withdrawn.Waiting() || withdrawn.WithdrawnBy == nil {
				t.Errorf("withdrawn, it reads in force %v, waiting %v, by %v",
					withdrawn.InForce(), withdrawn.Waiting(), withdrawn.WithdrawnBy)
			}
			// It still says what it was about.
			if len(withdrawn.References) != 2 {
				t.Errorf("a withdrawn ruling lists %v", withdrawn.References)
			}
			for _, reference := range named {
				row := f.reportNamed(t, proposer, reference)
				if row.RulingID != nil || row.EvaluatedAt != nil || row.EvaluatedBy != nil {
					t.Errorf("%s is still answered after the ruling was withdrawn: "+
						"ruling %v, judged %v by %v", reference, row.RulingID,
						row.EvaluatedAt, row.EvaluatedBy)
				}
			}
			if _, err := f.store.ApproveRuling(t.Context(), second, f.productID,
				ruling.ID); !errors.Is(err, finding.ErrNotWaiting) {
				t.Errorf("approving a withdrawn ruling was answered %v", err)
			}
			if _, err := f.store.WithdrawRuling(t.Context(), second, f.productID,
				ruling.ID); !errors.Is(err, finding.ErrWithdrawn) {
				t.Errorf("withdrawing twice was answered %v", err)
			}
			// Back in the inbox means it can be answered again.
			if _, err := f.store.Rule(t.Context(), proposer, f.productID, finding.Ruled{
				References: named, Disposition: finding.NotReproducible, Reasoning: "Tried.",
			}); err != nil {
				t.Errorf("ruling again after a withdrawal: %v", err)
			}
		}
	})
}

func TestADuplicateOfAnIssueThatIsNotOpenIsRefused(t *testing.T) {
	// Duplicate-of-closed buries the report: the work it says exists
	// elsewhere is not there, and nobody else agreed to anything. Refused at
	// submission, pointing at rejection, which a second person agrees to.
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PrivateTriage)
		issue := f.anIssueHereShipped(t, who)
		named := f.claims(t, who, 2)

		if _, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: named[:1], Disposition: finding.Duplicate, DuplicateOf: issue,
		}); err != nil {
			t.Fatalf("a duplicate of an open issue: %v", err)
		}

		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("closed_at = ?", time.Now().UTC()).
			Set("closed_because = ?", finding.Upgraded).
			Where("vulnerability_id = ?", issue).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		_, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: named[1:], Disposition: finding.Duplicate, DuplicateOf: issue,
		})
		if !errors.Is(err, finding.ErrDuplicateOfClosed) {
			t.Fatalf("a duplicate of a closed issue was answered %v", err)
		}
		if row := f.reportNamed(t, who, named[1]); row.RulingID != nil {
			t.Errorf("the refused duplicate still wrote ruling %d", *row.RulingID)
		}
	})
}

func TestADuplicateNamesAnIssueAndNothingElseDoes(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PrivateTriage)
		issue := f.anIssueHereShipped(t, who)
		named := f.claims(t, who, 1)
		if _, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: named, Disposition: finding.Duplicate,
		}); !errors.Is(err, finding.ErrNoDuplicateTarget) {
			t.Errorf("a duplicate of nothing was answered %v", err)
		}
		if _, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: named, Disposition: finding.Rejected, Reasoning: "No.",
			DuplicateOf: issue,
		}); !errors.Is(err, finding.ErrNotADuplicate) {
			t.Errorf("a rejection naming an issue was answered %v", err)
		}
		if _, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: named, Disposition: finding.Accepted, Reasoning: "Yes.",
		}); !errors.Is(err, finding.ErrNotRulable) {
			t.Errorf("accepting through a ruling was answered %v", err)
		}
		// An issue this person may not be told of answers as one that is not
		// here, so a duplicate is not a way to ask what is open.
		if _, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: named, Disposition: finding.Duplicate, DuplicateOf: issue + 1000,
		}); !errors.Is(err, finding.ErrNoSuchIssueHere) {
			t.Errorf("a duplicate of an issue that is not here was answered %v", err)
		}
	})
}

func TestADuplicateIsReadFromTheIssueItPointsAt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PrivateTriage)
		issue := f.anIssueHereShipped(t, who)
		named := f.claims(t, who, 3)

		if _, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: named[:1], Disposition: finding.Duplicate, DuplicateOf: issue,
		}); err != nil {
			t.Fatal(err)
		}
		withdrawn, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: named[1:2], Disposition: finding.Duplicate, DuplicateOf: issue,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.WithdrawRuling(t.Context(), who, f.productID,
			withdrawn.ID); err != nil {
			t.Fatal(err)
		}

		found, err := f.store.DuplicatesOf(t.Context(), who, f.productID, issue)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 1 || found[0].Reference != named[0] {
			got := make([]string, 0, len(found))
			for _, row := range found {
				got = append(got, row.Reference)
			}
			t.Errorf("the issue shows duplicates %v, want only %s", got, named[0])
		}

		// Read under the report's rule, not the issue's. Whoever triages
		// announced work reads the issue and not what a stranger sent;
		// whoever reads undisclosed work reads both.
		public := f.somebody(t, "public@example.com", access.PublicTriage)
		if _, err := f.store.DuplicatesOf(t.Context(), public, f.productID,
			issue); !errors.Is(err, access.ErrDenied) {
			t.Errorf("somebody who may not read reports read a duplicate: %v", err)
		}
		reader := f.somebody(t, "reader@example.com", access.PrivateRead)
		if _, err := f.store.DuplicatesOf(t.Context(), reader, f.productID, issue); err != nil {
			t.Errorf("somebody who reads undisclosed work could not read a duplicate: %v", err)
		}
	})
}

func TestTheBulkCapCountsReportsWrittenRatherThanNamesGiven(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PrivateTriage)
		if err := f.setting(t, setting.TogetherCap, "2"); err != nil {
			t.Fatal(err)
		}
		named := f.claims(t, who, 3)

		// Five names, two reports: two rows written, which the cap allows.
		// A reference typed in another case is the same report.
		repeated := []string{named[0], named[0], strings.ToLower(named[0]), named[1], named[1]}
		ruling, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: repeated, Disposition: finding.Rejected, Reasoning: "Slop.",
		})
		if err != nil {
			t.Fatalf("two reports named five times: %v", err)
		}
		if len(ruling.References) != 2 {
			t.Errorf("it covers %v, want two reports", ruling.References)
		}

		third := f.claims(t, who, 2)
		if _, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: append(third, named[2]), Disposition: finding.Rejected,
			Reasoning: "Slop.",
		}); !errors.Is(err, finding.ErrTooManyReports) {
			t.Errorf("three reports under a cap of two was answered %v", err)
		}
		if row := f.reportNamed(t, who, named[2]); row.RulingID != nil {
			t.Errorf("a refused bulk ruling still wrote ruling %d", *row.RulingID)
		}
	})
}

func TestSettingAClaimAsideNeedsAReason(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PrivateTriage)
		named := f.claims(t, who, 1)
		for _, disposition := range []finding.Disposition{
			finding.Rejected, finding.OutOfScope, finding.NotReproducible,
		} {
			if _, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
				References: named, Disposition: disposition, Reasoning: "  ",
			}); !errors.Is(err, finding.ErrNoReasoning) {
				t.Errorf("%s with no reason was answered %v", disposition, err)
			}
		}
		_, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: named, Disposition: finding.Rejected,
			Reasoning: "Nothing here\n<img src=x onerror=alert(1)>\n",
		})
		var faults markdown.Faults
		if !errors.As(err, &faults) {
			t.Errorf("raw HTML in a reason was answered %v", err)
		}
	})
}

func TestARulingNamingOneReportItCannotWriteWritesNothing(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PrivateTriage)
		named := f.claims(t, who, 2)

		// A name nobody minted.
		if _, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: []string{named[0], "SONIC-R-2026-1"}, Disposition: finding.Rejected,
			Reasoning: "Slop.",
		}); !errors.Is(err, finding.ErrNoSuchReport) ||
			!strings.Contains(err.Error(), "SONIC-R-2026-1") ||
			strings.Contains(err.Error(), named[0]) {
			t.Errorf("a ruling naming a report nobody minted was answered %v", err)
		}

		// A report in another product, named from this one.
		other, err := catalog.NewStore(f.db.DB).DeclareProduct(t.Context(), "other", "Other")
		if err != nil {
			t.Fatal(err)
		}
		both := access.NewPerson(who.ID, "them@example.com", false, map[int64][]access.Role{
			f.productID: {access.PrivateTriage}, other.ID: {access.PrivateTriage},
		}, 0)
		elsewhere, err := f.store.Record(t.Context(), both, other.ID,
			finding.Claimed{Summary: "Sent to another product."})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Rule(t.Context(), both, f.productID, finding.Ruled{
			References: []string{named[0], elsewhere.Reference}, Disposition: finding.Rejected,
			Reasoning: "Slop.",
		}); !errors.Is(err, finding.ErrNoSuchReport) {
			t.Errorf("a ruling reaching into another product was answered %v", err)
		}

		// One already accepted as an issue, which the write itself refuses.
		issue := f.anIssueHereShipped(t, who)
		if _, err := f.store.JudgeAsIssue(t.Context(), who, f.productID, named[1],
			issue); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
			References: named, Disposition: finding.Rejected, Reasoning: "Slop.",
		}); !errors.Is(err, finding.ErrAlreadyJudged) ||
			!strings.HasSuffix(err.Error(), ": "+named[1]) {
			t.Errorf("a ruling covering an accepted report was answered %v, want it named", err)
		}
		if row := f.reportNamed(t, who, named[0]); row.RulingID != nil {
			t.Errorf("the other report in a refused ruling was written: ruling %d", *row.RulingID)
		}
	})
}

func TestRulingsAreProposedByWhoWorksReportsAndAgreedByWhoMayApprove(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		owner := f.planner(t, access.PrivateTriage)
		named := f.claims(t, owner, 1)
		ruling, err := f.store.Rule(t.Context(), owner, f.productID, finding.Ruled{
			References: named, Disposition: finding.Rejected, Reasoning: "Slop.",
		})
		if err != nil {
			t.Fatal(err)
		}
		// Proposing and withdrawing are working reports; reading a ruling is
		// reading them; agreeing is the approver capability or working them,
		// over reading them.
		for _, held := range [][]access.Role{
			{access.PublicTriage}, {access.PrivateRead}, {access.Approver, access.PrivateRead},
		} {
			stranger := f.somebody(t, "stranger@example.com", held...)
			if _, err := f.store.Rule(t.Context(), stranger, f.productID, finding.Ruled{
				References: named, Disposition: finding.NotReproducible, Reasoning: "No.",
			}); !errors.Is(err, access.ErrDenied) {
				t.Errorf("%v ruled on a report: %v", held, err)
			}
			// Somebody who can read the ruling is refused in words; somebody
			// who cannot is told there is no such ruling.
			want := finding.ErrNoSuchRuling
			if slices.Contains(held, access.PrivateRead) {
				want = access.ErrDenied
			}
			if _, err := f.store.WithdrawRuling(t.Context(), stranger, f.productID,
				ruling.ID); !errors.Is(err, want) {
				t.Errorf("%v withdrew a ruling: %v, want %v", held, err, want)
			}
		}
		for _, held := range [][]access.Role{{access.PublicTriage}, {access.Approver}} {
			stranger := f.somebody(t, "outside@example.com", held...)
			if _, _, err := f.store.RulingsIn(t.Context(), stranger, f.productID, false,
				50, 0); !errors.Is(err, access.ErrDenied) {
				t.Errorf("%v listed the rulings: %v", held, err)
			}
			if _, err := f.store.ApproveRuling(t.Context(), stranger, f.productID,
				ruling.ID); !errors.Is(err, finding.ErrNoSuchRuling) {
				t.Errorf("%v approved a ruling: %v", held, err)
			}
		}
		reader := f.somebody(t, "reader@example.com", access.PrivateRead)
		if _, _, err := f.store.RulingsIn(t.Context(), reader, f.productID, false,
			50, 0); err != nil {
			t.Errorf("somebody who reads undisclosed work could not list the rulings: %v", err)
		}
		// Refused in words rather than as a ruling that is not there, since
		// they can list it.
		if _, err := f.store.ApproveRuling(t.Context(), reader, f.productID,
			ruling.ID); !errors.Is(err, access.ErrDenied) {
			t.Errorf("somebody who only reads was answered %v approving a ruling, want a refusal", err)
		}
		lead := f.somebody(t, "lead@example.com", access.Approver, access.PrivateRead)
		if _, err := f.store.ApproveRuling(t.Context(), lead, f.productID, ruling.ID); err != nil {
			t.Errorf("an approver who reads undisclosed work could not agree to a ruling: %v", err)
		}

		// A ruling is reached in its own product and nowhere else.
		other, err := catalog.NewStore(f.db.DB).DeclareProduct(t.Context(), "other", "Other")
		if err != nil {
			t.Fatal(err)
		}
		elsewhere := access.NewPerson(f.somebody(t, "second@example.com").ID,
			"second@example.com", false, map[int64][]access.Role{
				f.productID: {access.PrivateTriage}, other.ID: {access.PrivateTriage},
			}, 0)
		if _, err := f.store.ApproveRuling(t.Context(), elsewhere, other.ID,
			ruling.ID); !errors.Is(err, finding.ErrNoSuchRuling) {
			t.Errorf("a ruling was approved through another product: %v", err)
		}
	})
}

// anIssueHereShipped records a flaw by hand against a build that ships the
// component it is filed on.
func (f *fixture) anIssueHereShipped(t *testing.T, who access.Subject) int64 {
	t.Helper()
	f.shipped(t, twoConsumers())
	return f.anIssueHere(t, who, "The management socket accepts a request nobody authenticated.")
}

func TestADuplicateOfAnIssueDismissedOrSuppressedEverywhereIsRefused(t *testing.T) {
	// A dismissal and a suppression leave the row open and close the
	// question. A new claim pointed at one as a duplicate reaches nobody who
	// is looking, which is the burying the closed-issue rule stops.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.RecordClaims(ctx, f.target, f.lastScan,
			[]sbom.Suppression{aClaim("CVE-2026-1", sbom.NotAffected, libnl, sbom.FromStatement)},
			everyOrigin); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss), found("CVE-2026-3", swss),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.planner(t, access.PrivateTriage)
		named := f.claims(t, who, 3)
		duplicate := func(reference, issue string) error {
			t.Helper()
			_, err := f.store.Rule(ctx, who, f.productID, finding.Ruled{
				References: []string{reference}, Disposition: finding.Duplicate,
				DuplicateOf: f.issueID(t, issue),
			})
			return err
		}

		// Suppressed at both places by what the build said.
		if err := duplicate(named[0], "CVE-2026-1"); !errors.Is(err, finding.ErrDuplicateOfClosed) {
			t.Errorf("a duplicate of an issue suppressed everywhere was answered %v", err)
		}

		// Dismissed at its one place by a decision in force.
		place := finding.PlaceIdentity(swss.Name, "")
		dismissed := map[string]any{
			"claim_id":   claimSaying(t, f.db, who.ID, "not-applicable"),
			"product_id": f.productID, "vulnerability_id": f.issueID(t, "CVE-2026-2"),
			"place_identity": place, "visibility": "public", "state": "approved",
			"needs_approval": true, "proposed_by": who.ID, "proposed_at": time.Now().UTC(),
			"live_key": "dismissed-key", "component_upstream_version": swss.Version,
		}
		if _, err := f.db.DB.NewInsert().Model(&dismissed).TableExpr(`"decision"`).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if err := duplicate(named[1], "CVE-2026-2"); !errors.Is(err, finding.ErrDuplicateOfClosed) {
			t.Errorf("a duplicate of an issue dismissed everywhere was answered %v", err)
		}

		// Deferred is work that comes back, so it is still open.
		deferred := map[string]any{
			"claim_id":   claimSaying(t, f.db, who.ID, "deferred"),
			"product_id": f.productID, "vulnerability_id": f.issueID(t, "CVE-2026-3"),
			"place_identity": place, "visibility": "public", "state": "approved",
			"needs_approval": true, "proposed_by": who.ID, "proposed_at": time.Now().UTC(),
			"live_key": "deferred-key", "component_upstream_version": swss.Version,
		}
		if _, err := f.db.DB.NewInsert().Model(&deferred).TableExpr(`"decision"`).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if err := duplicate(named[2], "CVE-2026-3"); err != nil {
			t.Errorf("a duplicate of a deferred issue was refused: %v", err)
		}
	})
}

func TestRulingsAcrossProductsReachOnlyTheProductsTheReaderWorksReportsIn(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		other, err := catalog.NewStore(f.db.DB).DeclareProduct(ctx, "other", "Other")
		if err != nil {
			t.Fatal(err)
		}
		// One person working reports in both, who records a ruling in each.
		both := access.NewPerson(f.planner(t).ID, "them@example.com", false,
			map[int64][]access.Role{
				f.productID: {access.PrivateTriage}, other.ID: {access.PrivateTriage},
			}, 0)
		rule := func(productID int64) *finding.ReportRuling {
			t.Helper()
			row, err := f.store.Record(ctx, both, productID,
				finding.Claimed{Summary: "Generated text."})
			if err != nil {
				t.Fatal(err)
			}
			ruling, err := f.store.Rule(ctx, both, productID, finding.Ruled{
				References: []string{row.Reference}, Disposition: finding.Rejected,
				Reasoning: "Slop.",
			})
			if err != nil {
				t.Fatal(err)
			}
			return ruling
		}
		here := rule(f.productID)
		there := rule(other.ID)
		withdrawn := rule(f.productID)
		if _, err := f.store.WithdrawRuling(ctx, both, f.productID, withdrawn.ID); err != nil {
			t.Fatal(err)
		}
		if here.Product != "sonic" || there.Product != "other" {
			t.Errorf("proposed, the rulings name %q and %q", here.Product, there.Product)
		}

		ids := func(rows []finding.ReportRuling) []int64 {
			out := make([]int64, 0, len(rows))
			for _, row := range rows {
				out = append(out, row.ID)
			}
			return out
		}
		across := func(who access.Subject, asked finding.RulingsAsked) ([]int64, int) {
			t.Helper()
			asked.Limit = 50
			rows, total, err := f.store.RulingsAcross(ctx, who, asked)
			if err != nil {
				t.Fatal(err)
			}
			return ids(rows), total
		}

		// Somebody working reports in one product reads and counts that
		// product's alone.
		one := f.somebody(t, "one@example.com", access.PrivateTriage)
		if got, total := across(one, finding.RulingsAsked{}); total != 2 ||
			slices.Contains(got, there.ID) {
			t.Errorf("a reader of one product reads %v of %d", got, total)
		}
		// Naming the other product asks for nothing they may read.
		if got, total := across(one, finding.RulingsAsked{ProductIDs: []int64{other.ID}}); total != 0 {
			t.Errorf("naming a product they do not work reports in reads %v of %d", got, total)
		}
		// Somebody working both reads both, narrowed when they name one.
		if _, total := across(both, finding.RulingsAsked{}); total != 3 {
			t.Errorf("a reader of both products counts %d, want 3", total)
		}
		if got, _ := across(both, finding.RulingsAsked{ProductIDs: []int64{other.ID}}); len(got) != 1 ||
			got[0] != there.ID {
			t.Errorf("narrowed to the other product, it reads %v", got)
		}
		// Waiting leaves out the withdrawn one.
		if got, total := across(both, finding.RulingsAsked{Waiting: true}); total != 2 ||
			slices.Contains(got, withdrawn.ID) {
			t.Errorf("waiting reads %v of %d", got, total)
		}
		// The period is when it was proposed, the end exclusive.
		now := time.Now().UTC()
		later, earlier := now.Add(time.Hour), now.Add(-time.Hour)
		if _, total := across(both, finding.RulingsAsked{Since: &earlier, Until: &later}); total != 3 {
			t.Errorf("the hour around now holds %d, want 3", total)
		}
		if _, total := across(both, finding.RulingsAsked{Until: &earlier}); total != 0 {
			t.Errorf("before an hour ago holds %d, want 0", total)
		}
		if _, total := across(both, finding.RulingsAsked{Since: &later}); total != 0 {
			t.Errorf("after an hour from now holds %d, want 0", total)
		}
	})
}

func TestTheRulingsSomebodyMayApproveAreWaitingOthersInProductsTheyMayAgreeIn(t *testing.T) {
	// The count a queue of what is pending your approval adds: not your own,
	// not settled, and only where you may agree to a ruling at all.
	each(t, func(t *testing.T, f *fixture) {
		owner := f.planner(t, access.PrivateTriage)
		named := f.claims(t, owner, 3)
		for _, reference := range named {
			if _, err := f.store.Rule(t.Context(), owner, f.productID, finding.Ruled{
				References: []string{reference}, Disposition: finding.Rejected, Reasoning: "Slop.",
			}); err != nil {
				t.Fatal(err)
			}
		}
		approvable := func(who access.Subject) int {
			t.Helper()
			_, total, err := f.store.RulingsAcross(t.Context(), who, finding.RulingsAsked{
				Approvable: true, Limit: 50,
			})
			if err != nil {
				t.Fatal(err)
			}
			return total
		}
		if n := approvable(owner); n != 0 {
			t.Errorf("the proposer may approve %d of their own rulings", n)
		}
		lead := f.somebody(t, "lead@example.com", access.Approver, access.PrivateRead)
		if n := approvable(lead); n != 3 {
			t.Errorf("an approver who reads undisclosed work may approve %d, want 3", n)
		}
		reader := f.somebody(t, "reader@example.com", access.PrivateRead)
		if n := approvable(reader); n != 0 {
			t.Errorf("somebody who only reads may approve %d", n)
		}
	})
}
