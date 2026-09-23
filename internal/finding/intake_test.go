// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

func TestAClaimIsRecordedWithoutMintingAnIssue(t *testing.T) {
	// The case the decoupling exists for. Somebody sends a claim, it is
	// written down, it is answered — and none of that requires anybody to
	// have decided it is a flaw. Recorded only by minting an issue, a claim
	// nobody believes either fills the findings with one or goes unrecorded,
	// and an unrecorded claim destroys the evidence that it was answered.
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PrivateTriage)
		row, err := f.store.Record(t.Context(), who, f.productID, finding.Claimed{
			Summary: "The management socket accepts a request nobody authenticated.",
			Told: finding.Told{
				ReportedBy: "A Researcher", Contact: "them@example.org",
				Credit: "anonymous", Received: "2026-06-01",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if row.VulnerabilityID != nil {
			t.Errorf("a claim nobody judged points at issue %d", *row.VulnerabilityID)
		}
		if !referenceFor(row.Reference, "SONIC", 2026) {
			t.Errorf("filed under %q, want the product's name, an R, the year and a number",
				row.Reference)
		}
		if row.ReceivedOn == nil || row.ReceivedOn.Format("2006-01-02") != "2026-06-01" {
			t.Errorf("the day it arrived came back as %v", row.ReceivedOn)
		}
		if row.EvaluatedAt != nil {
			t.Error("a claim nobody judged says when it was judged")
		}

		// Nothing was minted. A claim is not a flaw until somebody says so,
		// and a findings list that fills with claims is one nobody reads.
		var issues int
		if err := f.db.DB.NewSelect().Model((*finding.Vulnerability)(nil)).
			ColumnExpr("COUNT(*)").Scan(t.Context(), &issues); err != nil {
			t.Fatal(err)
		}
		if issues != 0 {
			t.Errorf("recording a claim minted %d issues", issues)
		}

		back, err := f.store.ReportBy(t.Context(), who, f.productID, row.Reference)
		if err != nil {
			t.Fatal(err)
		}
		if back.Summary != row.Summary || back.Contact != "them@example.org" {
			t.Errorf("read back as %q from %q", back.Summary, back.Contact)
		}
		// A reference is a name somebody types, so it matches without regard
		// to capitals. The stored form is the minted one and the typed one is
		// folded to it, which compares the same under every engine.
		if _, err := f.store.ReportBy(t.Context(), who, f.productID,
			strings.ToLower(row.Reference)); err != nil {
			t.Errorf("a reference typed in lower case did not resolve: %v", err)
		}
	})
}

func TestAClaimWithNothingInItIsRefused(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PrivateTriage)
		_, err := f.store.Record(t.Context(), who, f.productID,
			finding.Claimed{Summary: "   "})
		if !errors.Is(err, finding.ErrNothingClaimed) {
			t.Errorf("a claim saying nothing was answered %v", err)
		}

		// The submission policy typed text goes through, because the summary
		// quotes somebody outside this deployment and is rendered as markdown
		// where it is read back.
		_, err = f.store.Record(t.Context(), who, f.productID, finding.Claimed{
			Summary: "It crashes\n<script>alert(1)</script>\n",
		})
		var faults markdown.Faults
		if !errors.As(err, &faults) {
			t.Errorf("raw HTML in a claim was answered %v", err)
		}
	})
}

func TestAClaimIsReadWithPrivateReadAndWorkedWithPrivateTriage(t *testing.T) {
	// A claim nobody has judged is undisclosed by definition: there is no
	// issue to be public about, and nobody has decided it is safe to repeat.
	// So reading one and listing them ask for the right to read work nobody
	// has announced, and recording one, answering one or judging one ask for
	// the right to triage it.
	each(t, func(t *testing.T, f *fixture) {
		owner := f.planner(t, access.PrivateTriage)
		row, err := f.store.Record(t.Context(), owner, f.productID,
			finding.Claimed{Summary: "A claim nobody has judged."})
		if err != nil {
			t.Fatal(err)
		}

		for _, held := range []access.Role{access.PublicRead, access.PublicTriage} {
			stranger := f.somebody(t, "stranger@example.com", held)
			if _, err := f.store.ReportBy(t.Context(), stranger, f.productID,
				row.Reference); !errors.Is(err, finding.ErrNoSuchReport) {
				t.Errorf("%s read a claim nobody has judged: %v", held, err)
			}
			if _, _, err := f.store.ReportsIn(t.Context(), stranger, f.productID,
				50, 0); !errors.Is(err, access.ErrDenied) {
				t.Errorf("%s listed the claims: %v", held, err)
			}
		}

		reader := f.somebody(t, "reader@example.com", access.PrivateRead)
		if _, err := f.store.ReportBy(t.Context(), reader, f.productID,
			row.Reference); err != nil {
			t.Errorf("somebody who reads undisclosed work could not read the claim: %v", err)
		}
		if _, _, err := f.store.ReportsIn(t.Context(), reader, f.productID,
			50, 0); err != nil {
			t.Errorf("somebody who reads undisclosed work could not list the claims: %v", err)
		}

		for _, held := range []access.Role{
			access.PublicRead, access.PublicTriage, access.PrivateRead,
		} {
			stranger := f.somebody(t, "writer@example.com", held)
			if _, err := f.store.Record(t.Context(), stranger, f.productID,
				finding.Claimed{Summary: "Theirs."}); !errors.Is(err, access.ErrDenied) {
				t.Errorf("%s recorded a claim: %v", held, err)
			}
			// Somebody who may not read the claim is told it is not here;
			// somebody who reads it is refused in words.
			want := finding.ErrNoSuchReport
			if held == access.PrivateRead {
				want = access.ErrDenied
			}
			if err := f.store.AcknowledgeReport(t.Context(), stranger, f.productID,
				row.Reference); !errors.Is(err, want) {
				t.Errorf("%s answering a claim was answered %v, want %v", held, err, want)
			}
			if _, err := f.store.JudgeAsIssue(t.Context(), stranger, f.productID,
				row.Reference, 1); !errors.Is(err, want) {
				t.Errorf("%s judging a claim was answered %v, want %v", held, err, want)
			}
		}

		// A reference is reached in the product it was recorded against and
		// nowhere else. Told apart, the pair of answers says which products
		// hold claims.
		elsewhere, err := catalog.NewStore(f.db.DB).DeclareProduct(t.Context(),
			"edge-router", "Edge")
		if err != nil {
			t.Fatal(err)
		}
		everywhere := access.NewPerson(owner.ID, "them@example.com", false,
			map[int64][]access.Role{
				f.productID: {access.PrivateTriage}, elsewhere.ID: {access.PrivateTriage},
			}, 0)
		if _, err := f.store.ReportBy(t.Context(), everywhere, elsewhere.ID,
			row.Reference); !errors.Is(err, finding.ErrNoSuchReport) {
			t.Errorf("a claim recorded against one product was read from another: %v", err)
		}
	})
}

func TestAClaimIsJudgedOnceAndSaysWhoJudgedIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PrivateTriage)
		_, identifier, err := f.store.Enter(t.Context(), who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "high",
			Summary: "The management socket accepts a request nobody authenticated.",
		})
		if err != nil {
			t.Fatal(err)
		}
		issue, err := finding.NewVulnerabilities(f.db.DB).ByName(t.Context(), identifier)
		if err != nil {
			t.Fatal(err)
		}

		row, err := f.store.Record(t.Context(), who, f.productID,
			finding.Claimed{Summary: "The management socket lets anybody in."})
		if err != nil {
			t.Fatal(err)
		}
		judged, err := f.store.JudgeAsIssue(t.Context(), who, f.productID, row.Reference, issue)
		if err != nil {
			t.Fatal(err)
		}
		if judged.VulnerabilityID == nil || *judged.VulnerabilityID != issue {
			t.Errorf("judging pointed the report at %v, want issue %d",
				judged.VulnerabilityID, issue)
		}
		if judged.EvaluatedAt == nil || judged.EvaluatedBy == nil ||
			*judged.EvaluatedBy != who.ID {
			t.Errorf("judging recorded %v at %v, want who did it and when",
				judged.EvaluatedBy, judged.EvaluatedAt)
		}
		// The person who wrote it down and the person who judged it are told
		// apart, which is the whole reason the second pair of columns exists.
		if judged.RecordedAt.Equal(*judged.EvaluatedAt) {
			t.Error("the moment it was written down and the moment it was judged are one value")
		}

		// A judgment is made once. Plainly, first.
		if _, err := f.store.JudgeAsIssue(t.Context(), who, f.productID,
			row.Reference, issue); !errors.Is(err, finding.ErrAlreadyJudged) {
			t.Errorf("judging twice was answered %v", err)
		}

		// And then the case the condition on the write exists for, which a
		// repeat does not reach: judged by somebody else between this
		// judgment reading the row and writing to it.
		third, err := f.store.Record(t.Context(), who, f.productID,
			finding.Claimed{Summary: "Judged by somebody else mid-flight."})
		if err != nil {
			t.Fatal(err)
		}
		another := f.anIssueHere(t, who, "A second flaw, for the racing judgment.")
		racing := finding.NewStore(f.db.DB)
		racing.JudgingAfter(func() {
			if _, err := f.store.JudgeAsIssue(t.Context(), who, f.productID,
				third.Reference, another); err != nil {
				t.Errorf("the other writer could not judge it: %v", err)
			}
		})
		if _, err := racing.JudgeAsIssue(t.Context(), who, f.productID,
			third.Reference, issue); !errors.Is(err, finding.ErrAlreadyJudged) {
			t.Errorf("judging a claim somebody judged mid-flight was answered %v", err)
		}

		// One report is one issue's record. A second pointed at the same
		// issue is a duplicate, which is a judgment of its own.
		second, err := f.store.Record(t.Context(), who, f.productID,
			finding.Claimed{Summary: "Somebody else says the same thing."})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.JudgeAsIssue(t.Context(), who, f.productID,
			second.Reference, issue); !errors.Is(err, finding.ErrIssueReported) {
			t.Errorf("a second report at one issue was answered %v", err)
		}
	})
}

func TestAClaimCannotBePointedAtAnIssueTheJudgeCannotBeToldOf(t *testing.T) {
	// Resolving first and refusing after would make the refusal informative:
	// an identifier nobody has filed and one filed on work this person cannot
	// see would come back differently, which turns this into a way to ask
	// which identifiers are open here.
	each(t, func(t *testing.T, f *fixture) {
		owner := f.planner(t, access.PrivateTriage)
		row, err := f.store.Record(t.Context(), owner, f.productID,
			finding.Claimed{Summary: "A claim about something undisclosed."})
		if err != nil {
			t.Fatal(err)
		}

		// The judge holds this product's reports, so the report gate lets
		// them through and only the issue gate is left to refuse. Held the
		// other way round — somebody holding nothing here — the report gate
		// refuses first and the issue gate is never reached, so deleting it
		// leaves the test green.
		judge := f.somebody(t, "judge@example.com", access.PrivateTriage)
		elsewhere, err := catalog.NewStore(f.db.DB).DeclareProduct(t.Context(),
			"edge-router", "Edge")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := catalog.NewStore(f.db.DB).DeclareVariant(t.Context(),
			elsewhere.ID, "broadcom", true); err != nil {
			t.Fatal(err)
		}
		theirs := f.anotherBranchOf(t, elsewhere.ID, "master")
		f.shippedTo(t, theirs, twoConsumers())
		holder := access.NewPerson(owner.ID, "them@example.com", false,
			map[int64][]access.Role{elsewhere.ID: {access.PrivateTriage}}, 0)
		_, name, err := f.store.Enter(t.Context(), holder, finding.Entering{
			TargetIDs: []int64{theirs}, Component: swss.Name, Severity: "high",
			Summary: "A flaw in a product this judge holds nothing on.",
		})
		if err != nil {
			t.Fatal(err)
		}
		far, err := finding.NewVulnerabilities(f.db.DB).ByName(t.Context(), name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.JudgeAsIssue(t.Context(), judge, f.productID,
			row.Reference, far); !errors.Is(err, finding.ErrNoSuchIssueHere) {
			t.Errorf("a claim was pointed at an issue the judge cannot be told of: %v", err)
		}
		// And the issue is genuinely there, so the refusal is about who is
		// asking rather than about a row that does not exist.
		if _, err := f.store.JudgeAsIssue(t.Context(), holder, elsewhere.ID,
			row.Reference, far); !errors.Is(err, finding.ErrNoSuchReport) {
			t.Errorf("the report was reachable from another product: %v", err)
		}
	})
}

func TestAnsweringAClaimKeepsTheFirstDate(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PrivateTriage)
		row, err := f.store.Record(t.Context(), who, f.productID,
			finding.Claimed{Summary: "Somebody wrote in."})
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.AcknowledgeReport(t.Context(), who, f.productID,
			row.Reference); err != nil {
			t.Fatal(err)
		}
		first, err := f.store.ReportBy(t.Context(), who, f.productID, row.Reference)
		if err != nil {
			t.Fatal(err)
		}
		if first.AcknowledgedAt == nil || first.AcknowledgedBy == nil {
			t.Fatal("acknowledging recorded neither a moment nor a person")
		}
		if err := f.store.AcknowledgeReport(t.Context(), who, f.productID,
			row.Reference); err != nil {
			t.Fatal(err)
		}
		again, err := f.store.ReportBy(t.Context(), who, f.productID, row.Reference)
		if err != nil {
			t.Fatal(err)
		}
		// When somebody was answered is a fact about the past, and the second
		// person to press it did not change it.
		if !again.AcknowledgedAt.Equal(*first.AcknowledgedAt) {
			t.Errorf("answering twice moved the date from %v to %v",
				first.AcknowledgedAt, again.AcknowledgedAt)
		}
	})
}

func TestAProductsClaimsArePagedNewestFirst(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PrivateTriage)
		var references []string
		for i := range 5 {
			row, err := f.store.Record(t.Context(), who, f.productID,
				finding.Claimed{Summary: fmt.Sprintf("Claim number %d.", i)})
			if err != nil {
				t.Fatal(err)
			}
			references = append(references, row.Reference)
		}
		rows, total, err := f.store.ReportsIn(t.Context(), who, f.productID, 2, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 5 {
			t.Errorf("%d claims counted, want 5", total)
		}
		if len(rows) != 2 {
			t.Fatalf("a page of two came back with %d", len(rows))
		}
		// Newest first, and the identifier breaks a tie: five recorded in one
		// test land in the same microsecond on an engine whose clock is
		// coarse, and a page boundary falling between two of them would
		// otherwise repeat one row and drop another.
		if rows[0].Reference != references[4] || rows[1].Reference != references[3] {
			t.Errorf("the first page is %q and %q", rows[0].Reference, rows[1].Reference)
		}
		next, _, err := f.store.ReportsIn(t.Context(), who, f.productID, 2, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(next) != 2 || next[0].Reference != references[2] {
			t.Errorf("the second page opens at %q", next[0].Reference)
		}
	})
}

func TestAReferenceIsDrawnRatherThanCounted(t *testing.T) {
	// Counted from one, the reference is a running total of how many claims
	// this product has received and when the last one arrived. That is a
	// disclosure made by the name alone, before any route is asked anything.
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PrivateTriage)
		seen := map[string]bool{}
		numbers := make([]int, 0, 6)
		for range 6 {
			row, err := f.store.Record(t.Context(), who, f.productID,
				finding.Claimed{Summary: "One of several."})
			if err != nil {
				t.Fatal(err)
			}
			if seen[row.Reference] {
				t.Fatalf("%q was issued twice", row.Reference)
			}
			seen[row.Reference] = true
			numbers = append(numbers, drawn(t, row.Reference))
		}
		ascending := true
		for i := 1; i < len(numbers); i++ {
			ascending = ascending && numbers[i] == numbers[i-1]+1
		}
		if ascending {
			t.Errorf("the references run consecutively: %v", numbers)
		}
	})
}

func TestAFlawRecordedByHandCarriesAReportThatWasJudgedAsItWasWrittenDown(t *testing.T) {
	// The other way a report is made. Whoever typed the flaw in said what it
	// is in the same act, so all three roles are filled at once — and the row
	// is reachable by its reference like any other, rather than only through
	// the issue it was minted with.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PrivateTriage)
		_, identifier, err := f.store.Enter(t.Context(), who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "high",
			Summary: "The management socket accepts a request nobody authenticated.",
			Told: finding.Told{
				ReportedBy: "A Researcher", Contact: "them@example.org",
				Credit: "anonymous", Received: "2026-06-01",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		issue, err := finding.NewVulnerabilities(f.db.DB).ByName(t.Context(), identifier)
		if err != nil {
			t.Fatal(err)
		}
		row, err := f.store.ReportFor(t.Context(), who, issue)
		if err != nil || row == nil {
			t.Fatalf("the report on a recorded flaw: %v %v", row, err)
		}
		if !referenceFor(row.Reference, "SONIC", 2026) {
			t.Errorf("it was filed under %q", row.Reference)
		}
		if row.VulnerabilityID == nil || *row.VulnerabilityID != issue {
			t.Errorf("it points at %v, want issue %d", row.VulnerabilityID, issue)
		}
		if row.EvaluatedAt == nil || row.EvaluatedBy == nil || *row.EvaluatedBy != who.ID {
			t.Errorf("whoever recorded the flaw said what it is and the row says %v at %v",
				row.EvaluatedBy, row.EvaluatedAt)
		}
		// Reachable both ways, because it is one row. Read only through the
		// issue, a report made this way would be the one kind nothing on the
		// reports surface could answer for.
		back, err := f.store.ReportBy(t.Context(), who, f.productID, row.Reference)
		if err != nil || back.ID != row.ID {
			t.Errorf("reading it by reference answered %v (%v)", back, err)
		}
	})
}

func TestAReferenceFitsAProductNamedAtTheFullWidth(t *testing.T) {
	// A reference is a product's name and twelve more characters, and a
	// product may be named at the full width of a name. Sized as a name, the
	// longest one mints a reference PostgreSQL and MySQL refuse with a fault
	// out of an ordinary request — and SQLite stores it, so the quick loop
	// would never see it.
	each(t, func(t *testing.T, f *fixture) {
		widest := strings.Repeat("a", database.NameWidth)
		product, err := catalog.NewStore(f.db.DB).DeclareProduct(t.Context(), widest, "Wide")
		if err != nil {
			t.Fatal(err)
		}
		who := access.NewPerson(f.planner(t).ID, "them@example.com", false,
			map[int64][]access.Role{product.ID: {access.PrivateTriage}}, 0)
		row, err := f.store.Record(t.Context(), who, product.ID,
			finding.Claimed{Summary: "Reported against a product with a very long name."})
		if err != nil {
			t.Fatalf("recording against the widest product name: %v", err)
		}
		if len(row.Reference) <= database.NameWidth {
			t.Fatalf("the reference is %d characters, which does not reach the width "+
				"this is about", len(row.Reference))
		}
		// Read back, because storing and returning are two things: a column
		// too narrow truncates on one engine and refuses on another.
		back, err := f.store.ReportBy(t.Context(), who, product.ID, row.Reference)
		if err != nil {
			t.Fatalf("reading it back: %v", err)
		}
		if back.Reference != row.Reference {
			t.Errorf("it was stored as %q and minted as %q", back.Reference, row.Reference)
		}
	})
}

// anIssueHere records a flaw by hand and returns the issue it minted.
func (f *fixture) anIssueHere(t *testing.T, who access.Subject, summary string) int64 {
	t.Helper()
	_, identifier, err := f.store.Enter(t.Context(), who, finding.Entering{
		TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "high",
		Summary: summary,
	})
	if err != nil {
		t.Fatal(err)
	}
	issue, err := finding.NewVulnerabilities(f.db.DB).ByName(t.Context(), identifier)
	if err != nil {
		t.Fatal(err)
	}
	return issue
}

// somebody is a second person holding roles on this fixture's product.
func (f *fixture) somebody(t *testing.T, identity string, roles ...access.Role) access.Subject {
	t.Helper()
	person, err := access.NewStore(f.db.DB).Ensure(t.Context(), identity, identity, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return access.NewPerson(person.ID, identity, false,
		map[int64][]access.Role{f.productID: roles}, 0)
}

// referenceFor reports whether a reference is shaped the way a report's name
// is: the product, an R, the year and a number.
func referenceFor(reference, product string, year int) bool {
	prefix := fmt.Sprintf("%s-R-%d-", product, year)
	if !strings.HasPrefix(reference, prefix) {
		return false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(reference, prefix))
	return err == nil && n > 0
}

func TestAFlawRecordedFromAReportIsThatReportsIssue(t *testing.T) {
	// The claim was a flaw nobody had recorded yet. Recording it from the
	// report writes one report rather than two, accepts that report as the
	// flaw in the same act, and counts the embargo from the day the report
	// says it arrived.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PrivateTriage)
		claim, err := f.store.Record(t.Context(), who, f.productID, finding.Claimed{
			Summary: "The management socket lets anybody in.",
			Told:    finding.Told{ReportedBy: "A Researcher", Received: "2026-06-01"},
		})
		if err != nil {
			t.Fatal(err)
		}
		entering := finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "high",
			Summary:    "The management socket accepts a request nobody authenticated.",
			FromReport: strings.ToLower(claim.Reference),
		}
		_, identifier, err := f.store.Enter(t.Context(), who, entering)
		if err != nil {
			t.Fatal(err)
		}
		issue, err := finding.NewVulnerabilities(f.db.DB).ByName(t.Context(), identifier)
		if err != nil {
			t.Fatal(err)
		}
		back, err := f.store.ReportBy(t.Context(), who, f.productID, claim.Reference)
		if err != nil {
			t.Fatal(err)
		}
		if back.VulnerabilityID == nil || *back.VulnerabilityID != issue {
			t.Errorf("the report points at %v, want the flaw it was recorded as, %d",
				back.VulnerabilityID, issue)
		}
		if back.EvaluatedBy == nil || *back.EvaluatedBy != who.ID {
			t.Errorf("the report was judged by %v", back.EvaluatedBy)
		}
		var reports int
		if err := f.db.DB.NewSelect().TableExpr(`"flaw_report" AS "fr"`).
			ColumnExpr("COUNT(*)").Where("fr.product_id = ?", f.productID).
			Scan(t.Context(), &reports); err != nil {
			t.Fatal(err)
		}
		if reports != 1 {
			t.Errorf("recording from a report left %d reports, want the one", reports)
		}
		var disclose *time.Time
		if err := f.db.DB.NewSelect().TableExpr(`"finding" AS "f"`).
			ColumnExpr("MIN(f.disclose_at)").Where("f.vulnerability_id = ?", issue).
			Scan(t.Context(), &disclose); err != nil {
			t.Fatal(err)
		}
		want := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Add(setting.DefaultDiscloseAfter)
		if disclose == nil || !disclose.Equal(want) {
			t.Errorf("the embargo ends %v, want %v: counted from the day the report arrived",
				disclose, want)
		}

		// Once accepted it is judged, and a second flaw from it is refused.
		entering.Summary = "A second flaw from the same claim."
		if _, _, err := f.store.Enter(t.Context(), who, entering); !errors.Is(err,
			finding.ErrAlreadyJudged) {
			t.Errorf("recording a second flaw from a judged report answered %v", err)
		}

		// A report that says nothing about when it arrived was here no later
		// than when it was recorded, so the embargo counts from then.
		undated, err := f.store.Record(t.Context(), who, f.productID, finding.Claimed{
			Summary: "The console accepts a password it never checks.",
		})
		if err != nil {
			t.Fatal(err)
		}
		recorded := time.Date(2026, 6, 3, 9, 30, 0, 0, time.UTC)
		if _, err := f.db.DB.NewUpdate().TableExpr(`"flaw_report"`).
			Set(`"recorded_at" = ?`, recorded).
			Where(`"id" = ?`, undated.ID).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		_, identifier, err = f.store.Enter(t.Context(), who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "high",
			Summary:    "The console accepts any password.",
			FromReport: undated.Reference,
		})
		if err != nil {
			t.Fatal(err)
		}
		if issue, err = finding.NewVulnerabilities(f.db.DB).ByName(t.Context(), identifier); err != nil {
			t.Fatal(err)
		}
		disclose = nil
		if err := f.db.DB.NewSelect().TableExpr(`"finding" AS "f"`).
			ColumnExpr("MIN(f.disclose_at)").Where("f.vulnerability_id = ?", issue).
			Scan(t.Context(), &disclose); err != nil {
			t.Fatal(err)
		}
		if want := recorded.Add(setting.DefaultDiscloseAfter); disclose == nil || !disclose.Equal(want) {
			t.Errorf("an undated report's embargo ends %v, want %v: counted from when it was recorded",
				disclose, want)
		}
	})
}

func TestAFlawRecordedFromAReportIsRefusedWhatTheReportAlreadySays(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PrivateTriage)
		claim, err := f.store.Record(t.Context(), who, f.productID,
			finding.Claimed{Summary: "A claim."})
		if err != nil {
			t.Fatal(err)
		}
		base := finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "high",
			Summary: "A flaw.", FromReport: claim.Reference,
		}
		twice := base
		twice.Told = finding.Told{ReportedBy: "Somebody else"}
		if _, _, err := f.store.Enter(t.Context(), who, twice); !errors.Is(err, finding.ErrToldTwice) {
			t.Errorf("naming a reporter beside a report answered %v", err)
		}
		missing := base
		missing.FromReport = "SONIC-R-2026-100000"
		if _, _, err := f.store.Enter(t.Context(), who, missing); !errors.Is(err, finding.ErrNoSuchReport) {
			t.Errorf("a reference nobody minted answered %v", err)
		}
		// A reader of undisclosed work who triages announced work may record a
		// disclosed flaw, and may not judge a report while doing it.
		reader := f.somebody(t, "reader@example.com", access.PrivateRead, access.PublicTriage)
		public := base
		public.Disclosed = true
		if _, _, err := f.store.Enter(t.Context(), reader, public); !errors.Is(err, access.ErrDenied) {
			t.Errorf("somebody who may not work reports judged one by recording a flaw: %v", err)
		}
	})
}
