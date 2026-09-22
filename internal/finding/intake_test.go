package finding_test

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
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
		if row.Judged() {
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

func TestOnlySomebodyWhoTriagesUnannouncedWorkReachesAClaim(t *testing.T) {
	// A claim nobody has judged is undisclosed by definition: there is no
	// issue to be public about, and nobody has decided it is safe to repeat.
	// So reading one, listing them and recording one all ask for the right to
	// triage work nobody has announced.
	each(t, func(t *testing.T, f *fixture) {
		owner := f.planner(t, access.PrivateTriage)
		row, err := f.store.Record(t.Context(), owner, f.productID,
			finding.Claimed{Summary: "A claim nobody has judged."})
		if err != nil {
			t.Fatal(err)
		}

		for _, held := range []access.Role{
			access.PublicRead, access.PublicTriage, access.PrivateRead,
		} {
			stranger := f.somebody(t, "stranger@example.com", held)
			if _, err := f.store.ReportBy(t.Context(), stranger, f.productID,
				row.Reference); !errors.Is(err, finding.ErrNoSuchReport) {
				t.Errorf("%s read a claim nobody has judged: %v", held, err)
			}
			if _, _, err := f.store.ReportsIn(t.Context(), stranger, f.productID,
				50, 0); !errors.Is(err, access.ErrDenied) {
				t.Errorf("%s listed the claims: %v", held, err)
			}
			if _, err := f.store.Record(t.Context(), stranger, f.productID,
				finding.Claimed{Summary: "Theirs."}); !errors.Is(err, access.ErrDenied) {
				t.Errorf("%s recorded a claim: %v", held, err)
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
		if !judged.Judged() || *judged.VulnerabilityID != issue {
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

		// A judgment is made once. Two people judging at the same moment
		// would otherwise both succeed, and the second would overwrite who
		// decided.
		if _, err := f.store.JudgeAsIssue(t.Context(), who, f.productID,
			row.Reference, issue); !errors.Is(err, finding.ErrAlreadyJudged) {
			t.Errorf("judging twice was answered %v", err)
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
		f.shipped(t, twoConsumers())
		owner := f.planner(t, access.PrivateTriage)
		_, identifier, err := f.store.Enter(t.Context(), owner, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "high",
			Summary: "Undisclosed, and recorded by somebody who may see it.",
		})
		if err != nil {
			t.Fatal(err)
		}
		issue, err := finding.NewVulnerabilities(f.db.DB).ByName(t.Context(), identifier)
		if err != nil {
			t.Fatal(err)
		}
		row, err := f.store.Record(t.Context(), owner, f.productID,
			finding.Claimed{Summary: "A claim about something undisclosed."})
		if err != nil {
			t.Fatal(err)
		}

		// A different product's rights reach neither the report nor the
		// issue, and the refusal names neither.
		elsewhere, err := catalog.NewStore(f.db.DB).DeclareProduct(t.Context(),
			"edge-router", "Edge")
		if err != nil {
			t.Fatal(err)
		}
		outsider := access.NewPerson(owner.ID, "them@example.com", false,
			map[int64][]access.Role{elsewhere.ID: {access.PrivateTriage}}, 0)
		if _, err := f.store.JudgeAsIssue(t.Context(), outsider, f.productID,
			row.Reference, issue); !errors.Is(err, finding.ErrNoSuchReport) {
			t.Errorf("somebody holding nothing here judged a claim: %v", err)
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
