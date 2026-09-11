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
)

// Assessment is what we think of an issue, as against what was published.
//
// Against the issue rather than against a place: a published rating being
// wrong is one statement about the vulnerability, true wherever it appears and
// in products it has not reached yet, and it does not stop being true because
// somebody rebuilt something.
type Assessment struct {
	bun.BaseModel `bun:"table:assessment,alias:asm"`

	ID              int64  `bun:"id,pk,autoincrement"`
	VulnerabilityID int64  `bun:"vulnerability_id,notnull"`
	Severity        string `bun:"severity,notnull"`
	// Published is what the world said when this was made, kept so a reader
	// can see what we were disagreeing with rather than inferring it from a
	// feed that has since moved on.
	Published     string     `bun:"published"`
	Reasoning     string     `bun:"reasoning,notnull"`
	State         string     `bun:"state,notnull"`
	NeedsApproval bool       `bun:"needs_approval,notnull"`
	ProposedBy    int64      `bun:"proposed_by,notnull"`
	ProposedAt    time.Time  `bun:"proposed_at,notnull"`
	DecidedBy     *int64     `bun:"decided_by"`
	DecidedAt     *time.Time `bun:"decided_at"`
	// LiveVulnerabilityID is the issue this is a claim about while it is
	// still a live claim, and null once it is withdrawn. Under a unique
	// constraint that is what enforces one live claim per issue in the
	// database rather than in a check — nulls do not collide, so any
	// number of withdrawn claims sit beside the live one.
	LiveVulnerabilityID *int64 `bun:"live_vulnerability_id"`
}

// The states an assessment passes through. Live is the one that ranks.
const (
	AssessmentProposed  = "proposed"
	AssessmentLive      = "live"
	AssessmentWithdrawn = "withdrawn"
)

// ErrAlreadyAssessed is returned where a claim already stands about an issue.
var ErrAlreadyAssessed = errors.New("this issue is already assessed")

// ErrNoSuchAssessment is returned where a claim is missing or is about an
// issue this subject may not be told about. One error for both, because
// telling them apart is what turns a claim identifier into a directory.
var ErrNoSuchAssessment = errors.New("no assessment is recorded there")

// Assess records what somebody thinks of an issue.
//
// Rating something **worse** than published takes effect at once: nobody needs
// protecting from being told something is worse than the world says. Rating it
// **milder** waits for a second person, because that is the direction that
// hides things — and it hides more than a position in a list. Severity sets
// the deadline, so calling a high a low pushes its deadline out by months
// , and where a product has said what is worth triaging at all, a
// downgrade below that line takes the finding off the working list and off any
// clock entirely. That is the same shape as every other act
// that hides risk, and it is gated the same way.
func (s *Store) Assess(ctx context.Context, subject access.Subject, vulnerabilityID int64,
	severity, reasoning string) (*Assessment, error) {

	if subject.Kind != access.Person || subject.ID == 0 {
		return nil, errors.New("an assessment is recorded as made by whoever made it")
	}
	// Triage somewhere, rather than merely being signed in. A rating here
	// moves deadlines and can take a finding off the working list
	// altogether, in every product at once, and being able to read one
	// product is not a reason to be trusted with that.
	if !subject.HoldsAnywhere(access.PublicTriage, access.PrivateTriage) {
		return nil, access.Denied("say what we think of an issue")
	}
	severity = strings.TrimSpace(strings.ToLower(severity))
	if Band(severity) != severity || severity == "" {
		return nil, fmt.Errorf("%q is not a rating — write one of %s",
			severity, strings.Join(ranked, ", "))
	}
	if strings.TrimSpace(reasoning) == "" {
		return nil, errors.New(
			"say why. An assessment outlives the version it was made about and reaches " +
				"products it has not met yet, so the next person needs the argument")
	}

	var recorded *Assessment
	err := database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		// Inside the transaction, because a retry re-runs this closure
		// against a database that has moved and an authorization
		// answered against the old one describes a world that is gone.
		told, err := mayBeToldOf(ctx, tx, subject, vulnerabilityID)
		if err != nil {
			return err
		}
		if !told {
			return ErrUnknownIssue
		}
		var issue struct {
			Published string `bun:"severity"`
		}
		err = tx.NewSelect().
			TableExpr("vulnerability AS v").
			ColumnExpr("COALESCE(v.severity, '') AS severity").
			Where("v.id = ?", vulnerabilityID).
			Scan(ctx, &issue)
		if err != nil {
			return fmt.Errorf("read what was published about this: %w", err)
		}

		// Milder than what the world says is the direction that hides things.
		// Compared on the folded band rather than the raw word, so that
		// disagreeing with an unrated issue is judged against the medium it
		// is already treated as rather than against nothing.
		milder := rank(severity) < rank(Band(issue.Published))
		now := s.now().UTC().Truncate(time.Microsecond)
		live := vulnerabilityID
		recorded = &Assessment{
			VulnerabilityID: vulnerabilityID,
			Severity:        severity,
			Published:       issue.Published,
			Reasoning:       reasoning,
			State:           AssessmentProposed,
			NeedsApproval:   milder,
			ProposedBy:      subject.ID,
			ProposedAt:      now,
			// Held from the moment it is proposed. A claim waiting for a
			// second person is still a claim standing about this issue, so a
			// rival one is refused while it waits rather than only once it is
			// in force.
			LiveVulnerabilityID: &live,
		}
		if !milder {
			recorded.State = AssessmentLive
			recorded.DecidedAt = &now
		}
		if _, err := tx.NewInsert().Model(recorded).Exec(ctx); err != nil {
			if database.IsDuplicate(err) {
				// The unique constraint over the live issue
				// refused it, which is the only thing that
				// could: two proposals arriving together both
				// walk through any check made before the write
				// .
				return ErrAlreadyAssessed
			}
			return fmt.Errorf("record what we think of this: %w", err)
		}
		if recorded.State == AssessmentLive {
			return liveRating(ctx, tx, vulnerabilityID, severity)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return recorded, nil
}

// Agree puts a milder assessment into force.
//
// Somebody other than whoever proposed it, for the same reason every other
// second person here is somebody else: a control one person can complete alone
// is not a control.
func (s *Store) Agree(ctx context.Context, subject access.Subject, id int64) (*Assessment, error) {
	if subject.Kind != access.Person || subject.ID == 0 {
		return nil, errors.New("agreeing is something a person does")
	}
	// The same people who may agree to a decision, and for the same
	// reason: agreeing is what puts a milder rating into force.
	if !subject.HoldsAnywhere(access.Approver, access.PublicTriage, access.PrivateTriage) {
		return nil, access.Denied("agree to a rating")
	}
	var agreed *Assessment
	err := database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		claim := new(Assessment)
		if err := tx.NewSelect().Model(claim).Where("id = ?", id).Scan(ctx); err != nil {
			// A claim nobody may be told about and a claim that was never
			// recorded answer alike, so an identifier cannot be walked.
			return ErrNoSuchAssessment
		}
		told, err := mayBeToldOf(ctx, tx, subject, claim.VulnerabilityID)
		if err != nil {
			return err
		}
		if !told {
			return ErrNoSuchAssessment
		}
		if claim.State != AssessmentProposed {
			return fmt.Errorf("this claim is %s rather than waiting", claim.State)
		}
		if claim.ProposedBy == subject.ID {
			return errors.New(
				"somebody else has to agree — a control one person completes alone is not one")
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		claim.State = AssessmentLive
		claim.DecidedBy = &subject.ID
		claim.DecidedAt = &now
		if _, err := tx.NewUpdate().Model(claim).
			Column("state", "decided_by", "decided_at").
			WherePK().Exec(ctx); err != nil {
			return fmt.Errorf("agree to the claim: %w", err)
		}
		agreed = claim
		return liveRating(ctx, tx, claim.VulnerabilityID, claim.Severity)
	})
	if err != nil {
		return nil, err
	}
	return agreed, nil
}

// Withdraw takes an assessment out of force, and the published rating back.
func (s *Store) Withdraw(ctx context.Context, subject access.Subject, id int64) error {
	if subject.Kind != access.Person || subject.ID == 0 {
		return errors.New("withdrawing is something a person does")
	}
	// Taking a rating back is making one: the published severity returns,
	// and everything reading it follows.
	if !subject.HoldsAnywhere(access.PublicTriage, access.PrivateTriage) {
		return access.Denied("take a rating back")
	}
	return database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		claim := new(Assessment)
		if err := tx.NewSelect().Model(claim).Where("id = ?", id).Scan(ctx); err != nil {
			return ErrNoSuchAssessment
		}
		told, err := mayBeToldOf(ctx, tx, subject, claim.VulnerabilityID)
		if err != nil {
			return err
		}
		if !told {
			return ErrNoSuchAssessment
		}
		if claim.State == AssessmentWithdrawn {
			return nil
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		claim.State = AssessmentWithdrawn
		claim.DecidedBy = &subject.ID
		claim.DecidedAt = &now
		// Released, so a fresh claim may be made about the issue. A withdrawn
		// claim is history and does not stand in the way of one.
		claim.LiveVulnerabilityID = nil
		if _, err := tx.NewUpdate().Model(claim).
			Column("state", "decided_by", "decided_at", "live_vulnerability_id").
			WherePK().Exec(ctx); err != nil {
			return fmt.Errorf("withdraw the claim: %w", err)
		}
		return liveRating(ctx, tx, claim.VulnerabilityID, "")
	})
}

// liveRating writes the rating in force onto the issue, or clears it.
//
// One column read through one expression, rather than a join everything has to
// remember: what ranks, what the line compares, and what sets the deadline all
// read the same fact, and this project's bugs have all come from letting one
// fact into two rules.
func liveRating(ctx context.Context, tx bun.Tx, vulnerabilityID int64, severity string) error {
	q := tx.NewUpdate().
		Table("vulnerability").
		Where("id = ?", vulnerabilityID)
	if severity == "" {
		q = q.Set("assessed_severity = NULL")
	} else {
		q = q.Set("assessed_severity = ?", severity)
	}
	if _, err := q.Exec(ctx); err != nil {
		return fmt.Errorf("put the rating in force: %w", err)
	}
	// The rating in force decides where these sit and how long they have,
	// so both follow it.
	if err := rerank(ctx, tx, vulnerabilityID, severity); err != nil {
		return err
	}
	return redue(ctx, tx, vulnerabilityID)
}

// rank orders the four words that rank. Anything else folds to medium first,
// so an unrated issue is compared as what it is already treated as.
func rank(word string) int {
	for i, each := range ranked {
		if each == word {
			return i
		}
	}
	return 1
}

// rerank rewrites where an issue's findings sit in the list.
//
// The order is a packed number written when a scan is applied (see Rank), so a
// rating that did not reach it would be a note nobody acts on: the criticals
// somebody believes are noise would still sit at the top of everyone's list.
// An assessment changes the order, which means it has to change this.
//
// The score for a word comes from SeverityScore, in Go, rather than being
// spelled again as SQL — the mapping is one fact and this project's bugs have
// all come from letting one fact into two rules. What the statement carries is
// the number that fact produced.
func rerank(ctx context.Context, tx bun.Tx, vulnerabilityID int64, assessed string) error {
	var issue struct {
		Severity   string `bun:"severity"`
		ScoreCenti int    `bun:"score_centi"`
		Likelihood int    `bun:"likelihood_ppm"`
	}
	err := tx.NewSelect().
		TableExpr("vulnerability AS v").
		ColumnExpr("COALESCE(v.severity, '') AS severity").
		ColumnExpr("COALESCE(v.score_centi, 0) AS score_centi").
		ColumnExpr("COALESCE(v.likelihood_ppm, 0) AS likelihood_ppm").
		Where("v.id = ?", vulnerabilityID).
		Scan(ctx, &issue)
	if err != nil {
		return fmt.Errorf("read what is published about this: %w", err)
	}

	// What the order compares, worked out by the same type a scan ranks
	// through — the rule for which of a published score, a published word and
	// a rating of ours decides the number is one fact, and this project's bugs
	// have all come from letting one fact into two rules.
	rating := Rating{
		Published: issue.Severity, Assessed: assessed,
		ScoreCenti: issue.ScoreCenti, LikelihoodPPM: issue.Likelihood,
	}

	// Everything below the two flags, packed by the same function that packs
	// it at ingest. The flags themselves are per finding, so they stay in the
	// statement.
	rest := Ranked{ScoreCenti: rating.Score(), LikelihoodPPM: rating.LikelihoodPPM}.Rank()
	_, err = tx.NewUpdate().
		Model((*Finding)(nil)).
		Set("urgency = (CASE WHEN urgency_exploited THEN ? ELSE 0 END)"+
			" + (CASE WHEN urgency_shipped THEN ? ELSE 0 END) + ?",
			int64(exploitedBand), int64(shippedBand), int64(rest)).
		Where("vulnerability_id = ?", vulnerabilityID).
		Where("closed_at IS NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("move this issue in the order: %w", err)
	}
	return nil
}

// Reranked puts every open finding of these issues back where the signals now
// say it belongs.
//
// **Three of the four signals the order is worked out from are properties of
// the issue** — known exploitation, exploitation likelihood, and the score —
// and a report raises them for the issue wherever it appears. The order is
// stored per finding and was rewritten only for the build being scanned, so
// every other build kept a number computed from a world that had moved: a
// known-exploited issue in a shipped tag sat below the triage line, answered
// no exploited filter, got no exploited deadline and sorted at the bottom,
// until somebody rescanned that tag — which for a tag is never.
//
// It is not a cache being refreshed. The stored order describes an issue
// rather than a moment, so it is rewritten when the signals move; what is
// stored because it cannot be worked out again is a different thing and is
// not this.
//
// **Only the exploited flag moves a deadline**, and only for the rows it was
// raised on, counted from when this was learned — the same rule and the same
// moment the scanned build's own rows are clocked by. A score or a likelihood
// moving deliberately changes no clock: neither is in the deadline, and a
// clock reset by a revised number would never arrive.
//
// Takes the handle because the caller writes inside its own transaction: the
// scan that raised the signal and the re-ranking it forces are one act.
func Reranked(ctx context.Context, tx bun.Tx, issues []int64, learnedAt time.Time) error {
	if len(issues) == 0 {
		return nil
	}
	windows, err := LoadWindows(ctx, tx)
	if err != nil {
		return err
	}
	for _, id := range issues {
		var issue struct {
			Exploited bool   `bun:"exploited"`
			Assessed  string `bun:"assessed"`
		}
		if err := tx.NewSelect().
			TableExpr("vulnerability AS v").
			ColumnExpr("COALESCE(v.exploited, ?) AS exploited", false).
			ColumnExpr("COALESCE(v.assessed_severity, '') AS assessed").
			Where("v.id = ?", id).Scan(ctx, &issue); err != nil {
			return fmt.Errorf("read what is known about this issue: %w", err)
		}

		if issue.Exploited {
			// Which rows are learning it now, read before the flag is
			// raised: afterwards there is nothing to tell them from the
			// ones that already carried it.
			var learning []int64
			if err := tx.NewSelect().Model((*Finding)(nil)).
				ColumnExpr("id").
				Where("vulnerability_id = ?", id).
				Where("closed_at IS NULL").
				Where("urgency_exploited = ?", false).
				Scan(ctx, &learning); err != nil {
				return fmt.Errorf("read what is learning this: %w", err)
			}
			if len(learning) > 0 {
				if _, err := tx.NewUpdate().Model((*Finding)(nil)).
					Set("urgency_exploited = ?", true).
					// Counted from this moment rather than from when the
					// finding opened. Counted from the opening, an issue
					// that became exploited after six months would land
					// three days before it was known — a deadline nobody
					// could have met.
					Set("due_at = ?", learnedAt.Add(windows.Exploited)).
					Where("id IN (?)", bun.List(learning)).Exec(ctx); err != nil {
					return fmt.Errorf("mark what is being exploited: %w", err)
				}
			}
		}

		// The order itself, from the rating in force and the flags each row
		// now carries.
		if err := rerank(ctx, tx, id, issue.Assessed); err != nil {
			return err
		}
	}
	return nil
}

// redue rewrites the deadline on an issue's open findings.
//
// Severity sets how long something may stay open, so a rating of ours that did
// not reach the deadline would leave a finding shown as one thing and clocked
// as another — a third answer nobody chose. And where the rating drops below
// what a product triages, the deadline goes entirely, because below that line
// nothing is on a clock.
//
// Written per group rather than per finding: a deadline is a run's start plus
// a fixed number of days, so every finding of one issue opened by one run,
// rated the same way, in one product, lands on the same instant.
func redue(ctx context.Context, tx bun.Tx, vulnerabilityID int64) error {
	windows, err := LoadWindows(ctx, tx)
	if err != nil {
		return err
	}

	// Grouped on when each finding opened, which the row carries. It used to
	// group on the run and join it for the timestamp — one join to read one
	// column, and an inner one, so a finding a person opened was left out of
	// its own recount.
	var groups []struct {
		Exploited bool      `bun:"exploited"`
		OpenedAt  time.Time `bun:"opened_at"`
		ProductID int64     `bun:"product_id"`
		Severity  string    `bun:"severity"`
	}
	err = tx.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN target AS tg ON tg.id = f.target_id").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
		ColumnExpr("f.urgency_exploited AS exploited").
		ColumnExpr("f.opened_at AS opened_at").
		ColumnExpr("st.product_id AS product_id").
		ColumnExpr(EffectiveSeverityExpr+" AS severity").
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where("f.closed_at IS NULL").
		GroupExpr("f.urgency_exploited, f.opened_at, st.product_id, "+
			EffectiveSeverityExpr).
		Scan(ctx, &groups)
	if err != nil {
		return fmt.Errorf("read what this issue is open against: %w", err)
	}

	floors := map[int64]Floor{}
	for _, group := range groups {
		floor, held := floors[group.ProductID]
		if !held {
			floor, err = FloorFor(ctx, tx, group.ProductID)
			if err != nil {
				return err
			}
			floors[group.ProductID] = floor
		}

		q := tx.NewUpdate().
			Model((*Finding)(nil)).
			Where("vulnerability_id = ?", vulnerabilityID).
			Where("closed_at IS NULL").
			Where("urgency_exploited = ?", group.Exploited).
			Where("opened_at = ?", group.OpenedAt).
			Where(`target_id IN (SELECT tg.id FROM "target" AS tg
				JOIN "stream" AS st ON st.id = tg.stream_id
				WHERE st.product_id = ?)`, group.ProductID)
		if floor.Admits(group.Exploited, group.Severity) {
			q = q.Set("due_at = ?", group.OpenedAt.Add(windows.For(group.Exploited, group.Severity)))
		} else {
			q = q.Set("due_at = NULL")
		}
		if _, err := q.Exec(ctx); err != nil {
			return fmt.Errorf("move this issue's deadline: %w", err)
		}
	}
	return nil
}

// Assessments lists what has been said about issues, newest first.
//
// Narrowed to the issues the reader may be told about, which is the same rule
// the counts beside each row already followed. A claim carries the severity
// recorded against the issue and the argument somebody wrote about it, so a
// row about an undisclosed flaw is that flaw's disclosure — reached by a route
// that reads as a list of opinions rather than as a finding.
func (s *Store) Assessments(ctx context.Context, subject access.Subject, state string,
	limit int) ([]Assessment, map[int64]string, error) {

	if subject.Kind != access.Person {
		return nil, nil, nil
	}
	limit = database.AList.Of(limit)
	q := s.db.NewSelect().Model((*Assessment)(nil)).
		OrderExpr("proposed_at DESC, id DESC").
		Limit(limit)
	if state != "" {
		q = q.Where("state = ?", state)
	}
	products, all := subject.Products()
	if !all {
		// The row-by-row form of mayBeToldOf: a claim is shown where its issue
		// reaches something the reader may read, or reaches nothing at all.
		readable := onlyReadable(s.db.NewSelect().
			ColumnExpr("1").
			TableExpr("finding AS f").
			Join("JOIN target AS tg ON tg.id = f.target_id").
			Join("JOIN stream AS st ON st.id = tg.stream_id").
			Where("f.vulnerability_id = asm.vulnerability_id"),
			subject, products, all)
		anywhere := s.db.NewSelect().
			ColumnExpr("1").
			TableExpr("finding AS reach").
			Where("reach.vulnerability_id = asm.vulnerability_id")
		q = q.Where("(EXISTS (?) OR NOT EXISTS (?))", readable, anywhere)
	}
	var claims []Assessment
	if err := q.Scan(ctx, &claims); err != nil {
		return nil, nil, fmt.Errorf("read what we have said: %w", err)
	}

	ids := make([]int64, 0, len(claims))
	for _, claim := range claims {
		ids = append(ids, claim.VulnerabilityID)
	}
	named := map[int64]string{}
	if len(ids) > 0 {
		var issues []Vulnerability
		if err := s.db.NewSelect().Model(&issues).
			Column("id", "identifier").
			Where("id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
			return nil, nil, fmt.Errorf("read what these issues are called: %w", err)
		}
		for _, issue := range issues {
			named[issue.ID] = issue.Identifier
		}
	}
	return claims, named, nil
}

// Consequence is what agreeing to a milder rating would do, beyond moving
// things down a list.
//
// a downgrade needing a second person gates a downgrade on a second person because it pushes a deadline
// out. Since a product may say what it considers worth triaging at all
// , a downgrade that crosses that line does something different in
// kind: the finding stops being work rather than becoming later work, and it
// loses its deadline entirely. Those are two different things to
// agree to, and an approver was told neither.
type Consequence struct {
	// Findings is how many open findings of this issue the reader may see.
	// Named so the two numbers below are read against something rather than
	// being counts of an unstated whole.
	Findings int
	// Products is how many products those sit in. An assessment is about an
	// issue and a line is per product, so "below the line" has as many answers
	// as there are products holding the issue.
	Products int
	// OffTheList is how many of those findings the proposed rating would put
	// below their product's line — where they stop being work rather than
	// becoming later work.
	OffTheList int
	// ProductsAffected is how many products that happens in.
	ProductsAffected int
}

// WhatAgreeingWouldDo works out what putting a proposed rating in force would
// take off a working list.
//
// Asked of what the reader may see, like everything else here: an approver who
// cannot see a product is not told how many of its findings this would hide.
// That understates the effect for them, which is the right way for it to be
// wrong — the alternative discloses a count of undisclosed work.
func (s *Store) WhatAgreeingWouldDo(ctx context.Context, subject access.Subject,
	assessmentID int64) (Consequence, error) {

	if subject.Kind != access.Person {
		return Consequence{}, nil
	}
	claim := new(Assessment)
	if err := s.db.NewSelect().Model(claim).Where("id = ?", assessmentID).
		Scan(ctx); err != nil {
		return Consequence{}, ErrNoSuchAssessment
	}
	// Enforced here as well as on the list that reaches it, because this
	// is the layer that answers and a caller that arrived another way
	// would otherwise be told the shape of an issue it may not be told
	// about.
	told, err := mayBeToldOf(ctx, s.db, subject, claim.VulnerabilityID)
	if err != nil {
		return Consequence{}, err
	}
	if !told {
		return Consequence{}, ErrNoSuchAssessment
	}

	products, all := subject.Products()
	if !all && len(products) == 0 {
		return Consequence{}, nil
	}

	// Grouped rather than row by row: what decides the answer is the product,
	// whether the finding is exploited and what it is rated now, and a build
	// carries thousands of findings of one issue.
	var rows []struct {
		ProductID int64  `bun:"product_id"`
		Exploited bool   `bun:"exploited"`
		Severity  string `bun:"severity"`
		Open      int    `bun:"open"`
	}
	q := s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN target AS tg ON tg.id = f.target_id").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
		ColumnExpr("st.product_id AS product_id").
		ColumnExpr("f.urgency_exploited AS exploited").
		ColumnExpr(EffectiveSeverityExpr+" AS severity").
		ColumnExpr("COUNT(*) AS open").
		Where("f.vulnerability_id = ?", claim.VulnerabilityID).
		Where("f.closed_at IS NULL").
		GroupExpr("st.product_id, f.urgency_exploited, " + EffectiveSeverityExpr)
	// Both halves. The visibility half alone admits every disclosed finding in
	// the deployment, so an approver holding one product was told how many
	// findings this issue has in products they hold nothing on — and how many
	// products those are, which is a count of what somebody else ships.
	q = onlyReadable(q, subject, products, all)
	if err := q.Scan(ctx, &rows); err != nil {
		return Consequence{}, fmt.Errorf("read what this issue is open against: %w", err)
	}

	held := Consequence{}
	floors := map[int64]Floor{}
	affected := map[int64]bool{}
	seen := map[int64]bool{}
	for _, row := range rows {
		held.Findings += row.Open
		if !seen[row.ProductID] {
			seen[row.ProductID] = true
			held.Products++
		}
		floor, known := floors[row.ProductID]
		if !known {
			var err error
			floor, err = FloorFor(ctx, s.db, row.ProductID)
			if err != nil {
				return Consequence{}, err
			}
			floors[row.ProductID] = floor
		}
		// Only what the line admits today and would not admit after. A finding
		// already below it is not taken off anything by this, and saying it
		// was would inflate the number an approver is being asked to weigh.
		if floor.Admits(row.Exploited, row.Severity) &&
			!floor.Admits(row.Exploited, claim.Severity) {
			held.OffTheList += row.Open
			affected[row.ProductID] = true
		}
	}
	held.ProductsAffected = len(affected)
	return held, nil
}
