package finding

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// Claimed is a claim that arrived, as somebody types it in.
//
// The summary is what was claimed, and it is the one thing required: a report
// that says nothing records only that a mail arrived, which nobody can
// evaluate, answer or find again. Everything about the reporter stays
// optional, because a claim arriving anonymously is an ordinary claim.
type Claimed struct {
	Summary string
	Told    Told
}

// ErrNoSuchReport is the one answer for a report that is not here, one
// nobody may see, and a product that is neither.
var ErrNoSuchReport = errors.New("no report here goes by that name")

// ErrAlreadyJudged, ErrIssueReported and ErrNothingClaimed are the three ways
// recording or judging a claim is refused.
var (
	ErrAlreadyJudged = errors.New(
		"that report has already been judged, or a ruling on it is waiting for a second person")
	ErrIssueReported  = errors.New("another report is already the record of that issue")
	ErrNothingClaimed = errors.New(
		"say what was claimed — a report with nothing in it records only that a mail arrived")
)

// mayHandle reports whether this subject may work a product's reports.
//
// The right to triage work nobody has announced, because that is what a
// report is: nobody has judged it, so nobody has decided it is safe to
// repeat. Asked of the product before any reference in the request is
// resolved, so a refusal says nothing about which references exist.
func mayHandle(subject access.Subject, productID int64) error {
	if subject.Kind != access.Person {
		return access.Denied("work a product's reports without being a person")
	}
	if !subject.Triages(access.Private, productID) {
		return access.Denied(fmt.Sprintf("work the reports in product %d", productID))
	}
	return nil
}

// MayWorkReports reports whether this subject may work a product's reports,
// for a caller that has a name to resolve before it reaches the store and
// has to authorize first.
func MayWorkReports(subject access.Subject, productID int64) error {
	return mayHandle(subject, productID)
}

// Record writes down a claim that arrived.
//
// It mints no issue. What arrived is a claim, and whether it is a flaw is a
// judgment somebody makes afterwards — so the record stands on its own, and a
// claim nobody believes is answered and filed rather than either minting a
// flaw nobody believes or going unrecorded.
func (s *Store) Record(ctx context.Context, subject access.Subject,
	productID int64, in Claimed) (*FlawReport, error) {

	if err := mayHandle(subject, productID); err != nil {
		return nil, err
	}
	summary := strings.TrimSpace(in.Summary)
	if summary == "" {
		return nil, ErrNothingClaimed
	}
	// The same submission policy a justification goes through. It is rendered
	// as markdown where it is read back, and it quotes somebody outside this
	// deployment, which is the case the policy exists for: raw HTML refused,
	// link schemes limited, and a bound on how long a rendered field may be.
	if err := markdown.Check(summary); err != nil {
		return nil, err
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	var row *FlawReport
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		// Read inside, because a retry runs against a database where a
		// product may have been renamed, and a reference minted from a name
		// that is gone reads as another product's.
		product, err := productNameOf(ctx, tx, productID)
		if err != nil {
			return err
		}
		reference, err := mintReference(ctx, tx, product, now.Year())
		if err != nil {
			return err
		}
		// Built inside, because an insert writes the generated identifier
		// back into the model, and a retry would re-insert a model already
		// carrying the rolled-back attempt's key.
		row = &FlawReport{
			Reference: reference, ProductID: productID, Summary: summary,
			ReportedBy: strings.TrimSpace(in.Told.ReportedBy),
			Contact:    strings.TrimSpace(in.Told.Contact),
			Credit:     strings.TrimSpace(in.Told.Credit),
			ReceivedOn: in.Told.When(),
			RecordedBy: subject.ID, RecordedAt: now,
		}
		_, err = tx.NewInsert().Model(row).Exec(ctx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("record what arrived: %w", err)
	}
	return row, nil
}

// ReportBy reads one report by the name it is reached by.
//
// A reference nobody minted and one the subject may not read answer alike, so
// asking is not a way to find out which references exist.
func (s *Store) ReportBy(ctx context.Context, subject access.Subject,
	productID int64, reference string) (*FlawReport, error) {

	if err := mayHandle(subject, productID); err != nil {
		return nil, ErrNoSuchReport
	}
	row := new(FlawReport)
	err := s.db.NewSelect().Model(row).
		// Against the stored form, which is the minted one: a reference is
		// uppercase by construction, so the value typed is folded to match
		// rather than the column being compared loosely. The engines default
		// differently on that, and a folded value compares the same under
		// any of them.
		Where("fr.reference = ?", foldReference(reference)).
		Where("fr.product_id = ?", productID).
		Scan(ctx)
	switch {
	case database.IsNoRows(err):
		return nil, ErrNoSuchReport
	case err != nil:
		return nil, fmt.Errorf("read a report: %w", err)
	}
	return row, nil
}

// foldReference is a report's name as it is stored and compared.
func foldReference(typed string) string {
	return strings.ToUpper(strings.TrimSpace(typed))
}

// ReportsIn is one product's reports, newest first, with how many there are.
//
// Every report, judged or not. What somebody works through is the list of
// claims, and one already turned into an issue is the evidence that the issue
// came from outside.
func (s *Store) ReportsIn(ctx context.Context, subject access.Subject,
	productID int64, limit, offset int) ([]FlawReport, int, error) {

	if err := mayHandle(subject, productID); err != nil {
		return nil, 0, err
	}
	var rows []FlawReport
	total, err := s.db.NewSelect().Model(&rows).
		Where("fr.product_id = ?", productID).
		// The identifier as well as the moment, because two reports recorded
		// in the same microsecond are otherwise ordered by whatever the
		// engine returned, and a page boundary falling between them repeats
		// one row and drops another.
		Order("fr.recorded_at DESC", "fr.id DESC").
		Limit(limit).Offset(offset).
		ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("read a product's reports: %w", err)
	}
	return rows, total, nil
}

// AcknowledgeReport records that somebody answered the reporter of one
// report, by the name the report is reached by.
//
// The same act as acknowledging an issue's report, reached the other way: a
// claim nobody has judged has no issue to be reached through, and it is the
// one most in need of an answer.
func (s *Store) AcknowledgeReport(ctx context.Context, subject access.Subject,
	productID int64, reference string) error {

	row, err := s.ReportBy(ctx, subject, productID, reference)
	if err != nil {
		return err
	}
	return s.answered(ctx, subject, row.ID)
}

// JudgeAsIssue says what a claim turned out to be, and records who said so.
//
// The issue is one that already exists here: a report becomes evidence for an
// issue rather than minting one, because minting is the act of recording a
// flaw and that carries the builds it ships in, the severity and the embargo.
// Two acts, so that agreeing a claim is real is not the same keystroke as
// declaring where it lives.
func (s *Store) JudgeAsIssue(ctx context.Context, subject access.Subject,
	productID int64, reference string, vulnerabilityID int64) (*FlawReport, error) {

	row, err := s.ReportBy(ctx, subject, productID, reference)
	if err != nil {
		return nil, err
	}
	if s.afterReadingReport != nil {
		s.afterReadingReport()
	}
	// The issue has to be one this subject may already be told of here.
	// Without it, pointing a report at an identifier would say whether that
	// identifier is open in this product — which is the lookup every other
	// route here refuses to be.
	reachable, err := s.MayBeToldOfIn(ctx, subject, productID, vulnerabilityID)
	if err != nil {
		return nil, err
	}
	if !reachable {
		return nil, ErrNoSuchIssueHere
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	err = database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		res, err := tx.NewUpdate().Model((*FlawReport)(nil)).
			Set("vulnerability_id = ?", vulnerabilityID).
			Set("evaluated_at = ?", now).
			Set("evaluated_by = ?", subject.ID).
			Where("id = ?", row.ID).
			// Whether it is still unjudged is asked here and nowhere else.
			// Asked before the write as well, the answer read a row that may
			// have moved since — and the second guard was unreachable by any
			// input a single caller can produce, so it was a rule with no
			// test rather than a second line of defense.
			Where("vulnerability_id IS NULL").
			// A report under a ruling is answered, or about to be. Accepting
			// it as well would leave it two things at once.
			Where("ruling_id IS NULL").
			Exec(ctx)
		if err != nil {
			return err
		}
		changed, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("judge that report: %w", err)
		}
		if changed == 0 {
			return ErrAlreadyJudged
		}
		return nil
	})
	switch {
	case errors.Is(err, ErrAlreadyJudged):
		return nil, err
	case database.IsDuplicate(err):
		// One report is the record of an issue. A second pointed at the same
		// issue is a duplicate, which is a judgment of its own rather than
		// this one.
		return nil, ErrIssueReported
	case err != nil:
		return nil, fmt.Errorf("judge that report: %w", err)
	}
	row.VulnerabilityID = &vulnerabilityID
	row.EvaluatedAt, row.EvaluatedBy = &now, &subject.ID
	return row, nil
}

// ErrNoSuchIssueHere is the one answer for an issue that is not in this
// product and one the subject may not be told of.
var ErrNoSuchIssueHere = errors.New("no issue here goes by that name")

// mintReference issues the name a report is reached by.
//
// Shaped like the identifier a recorded flaw gets, with a letter between the
// product and the year so the two namespaces cannot be read for each other.
// The number is drawn rather than counted, for the same reason: counted from
// one it is a running total of how many claims this product has received and
// when the last one arrived, which is a disclosure made by the name alone.
func mintReference(ctx context.Context, tx bun.IDB, product string, year int) (string, error) {
	prefix := strings.ToUpper(strings.TrimSpace(product))
	if prefix == "" {
		return "", fmt.Errorf("a product with no name cannot issue a reference")
	}
	return drawIdentifier(ctx, fmt.Sprintf("reports of %s in %d", prefix, year),
		func(number int64) string {
			return fmt.Sprintf("%s-R-%d-%d", prefix, year, number)
		},
		func(ctx context.Context, candidate string) (bool, error) {
			taken, err := tx.NewSelect().
				TableExpr(`"flaw_report" AS "fr"`).
				Where("fr.reference = ?", candidate).
				Count(ctx)
			if err != nil {
				return false, fmt.Errorf(
					"read whether that reference is spoken for: %w", err)
			}
			return taken > 0, nil
		})
}
