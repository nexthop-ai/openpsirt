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
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// Assessment is what one product thinks of an issue, as against what was
// published.
//
// Against the issue rather than against a place: a published rating being
// wrong is one statement about the vulnerability wherever it appears in this
// product, including in builds it has not reached yet, and it does not stop
// being true because somebody rebuilt something.
//
// Against one product rather than against the deployment: a rating is a
// judgment about how a component is used, and two products do not use one the
// same way. One product may ship the vulnerable configuration and another may
// not, and then it is not one fact.
type Assessment struct {
	bun.BaseModel `bun:"table:assessment,alias:asm"`

	ID              int64 `bun:"id,pk,autoincrement"`
	VulnerabilityID int64 `bun:"vulnerability_id,notnull"`
	// ProductID is whose rating this is. Recording, agreeing to and
	// withdrawing one all ask for triage on this product: a rating sets the
	// deadline and can push a finding below the line the product triages at,
	// so somebody who cannot see the product has no business moving either.
	ProductID int64  `bun:"product_id,notnull"`
	Severity  string `bun:"severity,notnull"`
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
	// still a live claim, and null once it is withdrawn. Paired with the
	// product under a unique constraint, that is what enforces one live
	// claim per issue and product in the database rather than in a check —
	// nulls do not collide, so any number of withdrawn claims sit beside
	// the live one.
	LiveVulnerabilityID *int64 `bun:"live_vulnerability_id"`
}

// The states an assessment passes through. Live is the one that ranks.
const (
	AssessmentProposed  = "proposed"
	AssessmentLive      = "live"
	AssessmentWithdrawn = "withdrawn"
)

// ErrAlreadyAssessed is returned where a claim already stands about an issue
// in this product. Another product's claim is not in the way of one.
var ErrAlreadyAssessed = errors.New("this issue is already assessed in this product")

// ErrNoSuchAssessment is returned where a claim is missing or is about an
// issue this subject may not be told about. One error for both, because
// telling them apart is what turns a claim identifier into a directory.
var ErrNoSuchAssessment = errors.New("no assessment is recorded there")

// Assess records what one product thinks of an issue.
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
//
// Asked of triage **on this product**. A rating moves this product's deadlines
// and can take its findings off its working list, and holding a role somewhere
// else is not a reason to be trusted with either — which is what a single
// deployment-wide rating let anybody with triage anywhere do.
func (s *Store) Assess(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64, severity, reasoning string) (*Assessment, error) {

	if subject.Kind != access.Person || subject.ID == 0 {
		return nil, errors.New("an assessment is recorded as made by whoever made it")
	}
	// Triage on this product, rather than triage somewhere. Asked before
	// anything in the request is resolved, so a product somebody holds
	// nothing on refuses in the same words whether or not the issue is there.
	if !subject.Triages(access.Public, productID) {
		return nil, access.Denied("say what this product thinks of an issue")
	}
	severity = strings.TrimSpace(strings.ToLower(severity))
	if Band(severity) != severity || severity == "" {
		return nil, fmt.Errorf("%q is not a rating — write one of %s",
			severity, strings.Join(ranked, ", "))
	}
	if strings.TrimSpace(reasoning) == "" {
		return nil, errors.New(
			"say why. An assessment outlives the version it was made about and reaches " +
				"every build of this product, so the next person needs the argument")
	}
	// The same policy every other typed field goes through, run before the
	// text is stored rather than when it is read back — which is what the
	// policy says it is for, and what makes the column known to hold text that
	// passed what was in force when it arrived.
	if err := markdown.Check(reasoning); err != nil {
		return nil, err
	}

	var recorded *Assessment
	err := database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		// Inside the transaction, because a retry re-runs this closure
		// against a database that has moved and an authorization
		// answered against the old one describes a world that is gone.
		told, err := MayBeToldOfWithin(ctx, tx, subject, productID, vulnerabilityID)
		if err != nil {
			return err
		}
		if !told {
			return ErrUnknownIssue
		}
		var issue struct {
			Published string `bun:"published"`
		}
		// The published word, aliased as what it is. Named "severity" it read
		// as *the* severity of the issue here, which it is not — what the
		// product holds is what everything else judges by — and the two sites
		// below that do want the effective rating are a join away.
		err = tx.NewSelect().
			TableExpr(`vulnerability AS "v"`).
			ColumnExpr(`COALESCE(v.severity, '') AS "published"`).
			Where("v.id = ?", vulnerabilityID).
			Scan(ctx, &issue)
		if err != nil {
			return fmt.Errorf("read what was published about this: %w", err)
		}

		// Milder than what the world says is the direction that hides things.
		// Compared on the folded band rather than the raw word, so that
		// disagreeing with an unrated issue is judged against the medium it
		// is already treated as rather than against nothing.
		//
		// Compared against the published rating rather than against whatever
		// this product holds now: what needs a second person is hiding
		// something the world called bad, and a product that already rated it
		// milder would otherwise let the next step down through unwatched.
		milder := rank(severity) < rank(Band(issue.Published))
		now := s.now().UTC().Truncate(time.Microsecond)
		live := vulnerabilityID
		recorded = &Assessment{
			VulnerabilityID: vulnerabilityID,
			ProductID:       productID,
			Severity:        severity,
			Published:       issue.Published,
			Reasoning:       reasoning,
			State:           AssessmentProposed,
			NeedsApproval:   milder,
			ProposedBy:      subject.ID,
			ProposedAt:      now,
			// Held from the moment it is proposed. A claim waiting for a
			// second person is still a claim standing about this issue here,
			// so a rival one in this product is refused while it waits rather
			// than only once it is in force. Another product's is not a rival.
			LiveVulnerabilityID: &live,
		}
		if !milder {
			recorded.State = AssessmentLive
			recorded.DecidedAt = &now
		}
		if _, err := tx.NewInsert().Model(recorded).Exec(ctx); err != nil {
			if database.IsDuplicate(err) {
				// The unique constraint over the live issue and
				// product refused it, which is the only thing
				// that could: two proposals arriving together
				// both walk through any check made before the
				// write.
				return ErrAlreadyAssessed
			}
			return fmt.Errorf("record what we think of this: %w", err)
		}
		if recorded.State == AssessmentLive {
			return liveRating(ctx, tx, productID, vulnerabilityID, severity)
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
//
// The second person holds their role **on the product the rating belongs to**.
// Agreeing is what puts a milder rating into force, so it moves that product's
// deadlines and its triage line, and a role held elsewhere buys nothing here.
func (s *Store) Agree(ctx context.Context, subject access.Subject, id int64) (*Assessment, error) {
	if subject.Kind != access.Person || subject.ID == 0 {
		return nil, errors.New("agreeing is something a person does")
	}
	// Asked before the identifier is resolved, so somebody holding nothing
	// anywhere cannot walk claim identifiers. The narrower question — the
	// role on this claim's own product — is asked below, once the claim is in
	// hand, and it answers in the same words as a claim that is not there.
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
		// The role on the claim's own product. Refused in the words a missing
		// claim gets rather than as a denial: "you may not agree to this"
		// about a product somebody holds nothing on says the claim is there.
		if !subject.Holds(access.Approver, claim.ProductID) &&
			!subject.Triages(access.Public, claim.ProductID) {
			return ErrNoSuchAssessment
		}
		told, err := MayBeToldOfWithin(ctx, tx, subject, claim.ProductID, claim.VulnerabilityID)
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
		return liveRating(ctx, tx, claim.ProductID, claim.VulnerabilityID, claim.Severity)
	})
	if err != nil {
		return nil, err
	}
	return agreed, nil
}

// Withdraw takes an assessment out of force, and the published rating back.
//
// Asked of triage on the claim's own product, because taking a rating back is
// making one: the published severity returns in that product, and everything
// reading it follows.
func (s *Store) Withdraw(ctx context.Context, subject access.Subject, id int64) error {
	if subject.Kind != access.Person || subject.ID == 0 {
		return errors.New("withdrawing is something a person does")
	}
	// Before the identifier is resolved, for the reason Agree gives.
	if !subject.HoldsAnywhere(access.PublicTriage, access.PrivateTriage) {
		return access.Denied("take a rating back")
	}
	return database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		claim := new(Assessment)
		if err := tx.NewSelect().Model(claim).Where("id = ?", id).Scan(ctx); err != nil {
			return ErrNoSuchAssessment
		}
		if !subject.Triages(access.Public, claim.ProductID) {
			return ErrNoSuchAssessment
		}
		told, err := MayBeToldOfWithin(ctx, tx, subject, claim.ProductID, claim.VulnerabilityID)
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
		return liveRating(ctx, tx, claim.ProductID, claim.VulnerabilityID, "")
	})
}

// liveRating writes the rating in force for one product, or clears it.
//
// One row read through one expression, rather than a join everything has to
// remember: what ranks, what the line compares, and what sets the deadline all
// read the same fact, and this project's bugs have all come from letting one
// fact into two rules.
//
// The row's presence is the whole of "this product rates it differently", so
// clearing a rating deletes it rather than writing an empty word — a row
// holding nothing would read as a rating of nothing in every expression that
// coalesces onto the published one.
func liveRating(ctx context.Context, tx bun.Tx, productID, vulnerabilityID int64,
	severity string) error {

	if severity == "" {
		if _, err := tx.NewDelete().Model((*IssueRating)(nil)).
			Where("vulnerability_id = ?", vulnerabilityID).
			Where("product_id = ?", productID).Exec(ctx); err != nil {
			return fmt.Errorf("take the rating out of force: %w", err)
		}
	} else {
		// Read, then written, rather than written and caught: the four engines
		// spell "upsert" four ways, and no statement in this transaction is
		// allowed to fail, because PostgreSQL leaves a transaction aborted
		// after one and every statement after it in the same transaction
		// fails too. The two other answers to this question here — recording
		// a setting, adding somebody to a team — are the same shape for the
		// same reason.
		//
		// Both halves in one transaction, so what the read saw is what the
		// write writes against. The whole closure is retried, so a rival
		// writer between the two re-runs it rather than being missed.
		held, err := tx.NewSelect().Model((*IssueRating)(nil)).
			Where("vulnerability_id = ?", vulnerabilityID).
			Where("product_id = ?", productID).Count(ctx)
		if err != nil {
			return fmt.Errorf("read what this product rates it now: %w", err)
		}
		if held > 0 {
			_, err = tx.NewUpdate().Model((*IssueRating)(nil)).
				Set("severity = ?", severity).
				Where("vulnerability_id = ?", vulnerabilityID).
				Where("product_id = ?", productID).Exec(ctx)
		} else {
			_, err = tx.NewInsert().Model(&IssueRating{
				VulnerabilityID: vulnerabilityID, ProductID: productID,
				Severity: severity,
			}).Exec(ctx)
		}
		if err != nil {
			return fmt.Errorf("put the rating in force: %w", err)
		}
	}
	// The rating in force decides where this product's findings sit and how
	// long they have, so both follow it — and only this product's, because
	// nothing else read this rating.
	if err := rerank(ctx, tx, productID, vulnerabilityID, severity); err != nil {
		return err
	}
	return redue(ctx, tx, productID, vulnerabilityID)
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
//
// Written for one product, because the rating it was worked out from is one
// product's. The same issue in another product keeps the order its own rating
// gives it.
func rerank(ctx context.Context, tx bun.Tx, productID, vulnerabilityID int64,
	assessed string) error {

	var issue struct {
		Published  string `bun:"published"`
		ScoreCenti int    `bun:"score_centi"`
		Likelihood int    `bun:"likelihood_ppm"`
	}
	// The published word, aliased as what it is: this product's own rating
	// arrives as the assessed argument, and Rating is what decides between
	// them. Named "severity" it read as the rating in force, which is the one
	// thing it must not be taken for here.
	err := tx.NewSelect().
		TableExpr(`vulnerability AS "v"`).
		ColumnExpr(`COALESCE(v.severity, '') AS "published"`).
		ColumnExpr(`COALESCE(v.score_centi, 0) AS "score_centi"`).
		ColumnExpr(`COALESCE(v.likelihood_ppm, 0) AS "likelihood_ppm"`).
		Where("v.id = ?", vulnerabilityID).
		Scan(ctx, &issue)
	if err != nil {
		return fmt.Errorf("read what is published about this: %w", err)
	}

	// What the order compares, worked out by the same type a scan ranks
	// through — the rule for which of a published score, a published word and
	// a rating of ours decides the number is one fact, and this project's bugs
	// have all come from letting one fact into two rules.
	inForce := Rating{
		Published: issue.Published, Assessed: assessed,
		ScoreCenti: issue.ScoreCenti, LikelihoodPPM: issue.Likelihood,
	}

	// Everything below the two flags, packed by the same function that packs
	// it at ingest. The flags themselves are per finding, so they stay in the
	// statement.
	rest := Ranked{ScoreCenti: inForce.Score(), LikelihoodPPM: inForce.LikelihoodPPM}.Rank()
	_, err = tx.NewUpdate().
		Model((*Finding)(nil)).
		Set("urgency = (CASE WHEN urgency_exploited THEN ? ELSE 0 END)"+
			" + (CASE WHEN urgency_shipped THEN ? ELSE 0 END) + ?",
			int64(exploitedBand), int64(shippedBand), int64(rest)).
		Where("vulnerability_id = ?", vulnerabilityID).
		Where("closed_at IS NULL").
		// This product's findings alone. The number being written was worked
		// out from this product's rating, and writing it over another
		// product's rows is the deployment-wide rating arriving by the back
		// door.
		Where(inThisProduct, productID).
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
// and a report raises them for the issue wherever it appears. The fourth, the
// rating, belongs to a product, so the order is worked out once per product
// holding the issue rather than once for the deployment. The order is
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
			Exploited bool `bun:"exploited"`
		}
		if err := tx.NewSelect().
			TableExpr(`vulnerability AS "v"`).
			ColumnExpr(`COALESCE(v.exploited, ?) AS "exploited"`, false).
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
			// Batched. This is every open finding of one issue across the
			// deployment — a kernel flaw carries 45 places each across
			// thousands of issues — and one statement binding that many
			// parameters is refused by two of the four engines, inside the
			// transaction a scan applies in, so the whole upload fails and
			// retries into the same refusal.
			if err := database.IDsInBatches(ctx, learning,
				func(ctx context.Context, batch []int64) error {
					_, err := tx.NewUpdate().Model((*Finding)(nil)).
						Set("urgency_exploited = ?", true).
						// Counted from this moment rather than from when the
						// finding opened. Counted from the opening, an issue
						// that became exploited after six months would land
						// three days before it was known — a deadline nobody
						// could have met.
						//
						// The moment is kept on the row as well as spent here,
						// because every later recount has to arrive at the same
						// answer and nothing else holds it.
						Set("exploited_learned_at = ?", learnedAt).
						Set("due_at = ?", learnedAt.Add(windows.Exploited)).
						Where("id IN (?)", bun.List(batch)).Exec(ctx)
					return err
				}); err != nil {
				return fmt.Errorf("mark what is being exploited: %w", err)
			}
		}

		// The order itself, product by product, from each one's own rating
		// and the flags each row now carries. The signal that moved is the
		// issue's and reaches every product holding it; what it is combined
		// with is that product's rating, so the same report leaves two
		// products ordering the issue differently — which is the point of a
		// rating belonging to one.
		products, err := productsHolding(ctx, tx, id)
		if err != nil {
			return err
		}
		// What each of them rates it, in one statement rather than one per
		// product. The batched read is what RatingsIn is for, and a
		// deployment with a dozen products would otherwise ask twelve
		// questions to answer one.
		rated, err := RatingsIn(ctx, tx, products, []int64{id})
		if err != nil {
			return err
		}
		for _, productID := range products {
			if err := rerank(ctx, tx, productID, id,
				rated[RatedKey{ProductID: productID, VulnerabilityID: id}]); err != nil {
				return err
			}
		}
	}
	return nil
}

// redue rewrites the deadline on an issue's open findings in one product.
//
// Severity sets how long something may stay open, so a rating that did not
// reach the deadline would leave a finding shown as one thing and clocked as
// another — a third answer nobody chose. And where the rating drops below what
// the product triages, the deadline goes entirely, because below that line
// nothing is on a clock.
//
// One product, because the rating that moved is one product's and the line it
// is compared against is the same product's. Another product's findings of the
// same issue keep the clock their own rating gives them.
//
// Written per group rather than per finding: a deadline is a run's start plus
// a fixed number of days, so every finding of one issue opened by one run,
// rated the same way, in this product, lands on the same instant.
func redue(ctx context.Context, tx bun.Tx, productID, vulnerabilityID int64) error {
	windows, err := LoadWindows(ctx, tx)
	if err != nil {
		return err
	}
	floor, err := FloorFor(ctx, tx, productID)
	if err != nil {
		return err
	}

	// Grouped on when each finding opened, which the row carries. It used to
	// group on the run and join it for the timestamp — one join to read one
	// column, and an inner one, so a finding a person opened was left out of
	// its own recount.
	var groups []struct {
		Exploited bool       `bun:"exploited"`
		OpenedAt  time.Time  `bun:"opened_at"`
		LearnedAt *time.Time `bun:"learned_at"`
		Severity  string     `bun:"severity"`
	}
	err = tx.NewSelect().
		TableExpr(`finding AS "f"`).
		Join(`JOIN target AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN stream AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN vulnerability AS "v" ON v.id = f.vulnerability_id`).
		Join(rating.Here, productID).
		ColumnExpr(`f.urgency_exploited AS "exploited"`).
		ColumnExpr(`f.opened_at AS "opened_at"`).
		// Grouped on the learning as well, because it is the base an
		// exploited deadline is counted from: grouped without it, the
		// recount fell back to the opening and moved every exploited
		// deadline back to a date that was already in the past.
		ColumnExpr(`f.exploited_learned_at AS "learned_at"`).
		ColumnExpr(rating.EffectiveExpr+` AS "severity"`).
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where("f.closed_at IS NULL").
		Where("st.product_id = ?", productID).
		GroupExpr("f.urgency_exploited, f.opened_at, f.exploited_learned_at, "+
			rating.EffectiveExpr).
		Scan(ctx, &groups)
	if err != nil {
		return fmt.Errorf("read what this issue is open against: %w", err)
	}

	for _, group := range groups {
		q := tx.NewUpdate().
			Model((*Finding)(nil)).
			Where("vulnerability_id = ?", vulnerabilityID).
			Where("closed_at IS NULL").
			Where("urgency_exploited = ?", group.Exploited).
			Where("opened_at = ?", group.OpenedAt).
			Where(inThisProduct, productID)
		if group.LearnedAt != nil {
			q = q.Where("exploited_learned_at = ?", *group.LearnedAt)
		} else {
			q = q.Where("exploited_learned_at IS NULL")
		}
		if floor.Admits(group.Exploited, group.Severity) {
			q = q.Set("due_at = ?", clockedFrom(group.Exploited, group.OpenedAt, group.LearnedAt).
				Add(windows.For(group.Exploited, group.Severity)))
		} else {
			q = q.Set("due_at = NULL")
		}
		if _, err := q.Exec(ctx); err != nil {
			return fmt.Errorf("move this issue's deadline: %w", err)
		}
	}
	return nil
}

// clockedFrom is the moment a deadline is counted from.
//
// The opening for everything but an exploited finding, and the moment
// exploitation was learned for one of those: an issue that becomes exploited
// six months in has a few days from the learning, and counting those days from
// the opening lands the deadline before the day it was written. A row marked
// exploited with no moment recorded falls back to the opening, because there
// is nothing better to count from.
func clockedFrom(exploited bool, openedAt time.Time, learnedAt *time.Time) time.Time {
	if exploited && learnedAt != nil {
		return *learnedAt
	}
	return openedAt
}

// Assessments lists what has been said about issues, newest first.
//
// Narrowed to the issues the reader may be told about **in the product the
// claim belongs to**, which is the same rule the counts beside each row
// already followed. A claim carries the severity recorded against the issue
// and the argument somebody wrote about it, so a row about an undisclosed flaw
// is that flaw's disclosure — reached by a route that reads as a list of
// opinions rather than as a finding. Correlated by product as well as by
// issue, because the same issue read in one product says nothing about whether
// it may be read in another.
//
// Narrowed to one product where the caller names one, which is how the screen
// reaches a product's own ratings.
//
// Paged, with the total counted over the same narrowing rather than summed
// from the page. Capped at two hundred with no offset and no total, a
// deployment past that could not read the rest through the API at all and the
// screen showed a subset and reported it as the list.
func (s *Store) Assessments(ctx context.Context, subject access.Subject, productID int64,
	state string, limit, offset int) ([]Assessment, map[int64]string, int, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are
	// different statements, and this is the second.
	if subject.Kind != access.Person {
		return nil, nil, 0, access.Denied("read what has been assessed")
	}
	if productID != 0 && !subject.Sees(productID) {
		// A product somebody holds nothing on does not exist as far as they
		// are concerned, and an empty list is a different statement from a
		// refusal.
		return nil, nil, 0, access.Denied(fmt.Sprintf("read ratings in product %d", productID))
	}
	limit = database.AList.Of(limit)
	products, all := subject.Products()
	if !all && len(products) == 0 {
		return nil, map[int64]string{}, 0, nil
	}
	// The narrowing, written once so that the page and the count cannot come
	// to answer different questions: a total summed from the page is the
	// length of the page.
	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		if state != "" {
			q = q.Where("state = ?", state)
		}
		if productID != 0 {
			q = q.Where("asm.product_id = ?", productID)
		}
		if !all {
			// The row-by-row form of mayBeToldOfHere: a claim is shown where
			// its issue reaches something the reader may read in the claim's
			// own product.
			readable := onlyReadable(s.db.NewSelect().
				ColumnExpr("1").
				TableExpr(`finding AS "f"`).
				Join(`JOIN target AS "tg" ON tg.id = f.target_id`).
				Join(`JOIN stream AS "st" ON st.id = tg.stream_id`).
				Where("f.vulnerability_id = asm.vulnerability_id").
				Where("st.product_id = asm.product_id"),
				subject, products, all)
			q = q.Where("EXISTS (?)", readable)
		}
		return q
	}

	total, err := narrow(s.db.NewSelect().Model((*Assessment)(nil))).Count(ctx)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("count what we have said: %w", err)
	}
	var claims []Assessment
	if err := narrow(s.db.NewSelect().Model(&claims)).
		OrderExpr("proposed_at DESC, id DESC").
		Limit(limit).Offset(offset).
		Scan(ctx); err != nil {
		return nil, nil, 0, fmt.Errorf("read what we have said: %w", err)
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
			return nil, nil, 0, fmt.Errorf("read what these issues are called: %w", err)
		}
		for _, issue := range issues {
			named[issue.ID] = issue.Identifier
		}
	}
	return claims, named, total, nil
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
//
// Counted inside the rating's own product. A rating reaches nothing outside
// it, so a count that spanned products would describe work this decision does
// not touch.
type Consequence struct {
	// Findings is how many open findings of this issue the reader may see in
	// the rating's product. Named so the number below is read against
	// something rather than being a count of an unstated whole.
	Findings int
	// OffTheList is how many of those findings the proposed rating would put
	// below the product's line — where they stop being work rather than
	// becoming later work.
	OffTheList int
}

// WhatAgreeingWouldDo works out what putting a proposed rating in force would
// take off a working list.
//
// Asked of what the reader may see, like everything else here: an approver who
// cannot see what a finding says is not told how many of them this would hide.
// That understates the effect for them, which is the right way for it to be
// wrong — the alternative discloses a count of undisclosed work.
//
// Asked inside the rating's own product, because that is everywhere the rating
// reaches.
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
	// about. Asked of the claim's own product, which is the only place this
	// rating reaches.
	told, err := MayBeToldOfWithin(ctx, s.db, subject, claim.ProductID, claim.VulnerabilityID)
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

	floor, err := FloorFor(ctx, s.db, claim.ProductID)
	if err != nil {
		return Consequence{}, err
	}

	// Grouped rather than row by row: what decides the answer is whether the
	// finding is exploited and what it is rated now, and a build carries
	// thousands of findings of one issue.
	var rows []struct {
		Exploited bool   `bun:"exploited"`
		Severity  string `bun:"severity"`
		Open      int    `bun:"open"`
	}
	q := s.db.NewSelect().
		TableExpr(`finding AS "f"`).
		Join(`JOIN target AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN stream AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN vulnerability AS "v" ON v.id = f.vulnerability_id`).
		Join(rating.Here, claim.ProductID).
		ColumnExpr(`f.urgency_exploited AS "exploited"`).
		ColumnExpr(rating.EffectiveExpr+` AS "severity"`).
		ColumnExpr(`COUNT(*) AS "open"`).
		Where("f.vulnerability_id = ?", claim.VulnerabilityID).
		Where("f.closed_at IS NULL").
		Where("st.product_id = ?", claim.ProductID).
		GroupExpr("f.urgency_exploited, " + rating.EffectiveExpr)
	// The visibility half as well as the product. The visibility half alone
	// admits every disclosed finding in the deployment, so an approver holding
	// one product was told how many findings this issue has in products they
	// hold nothing on.
	q = onlyReadable(q, subject, products, all)
	if err := q.Scan(ctx, &rows); err != nil {
		return Consequence{}, fmt.Errorf("read what this issue is open against: %w", err)
	}

	held := Consequence{}
	for _, row := range rows {
		held.Findings += row.Open
		// Only what the line admits today and would not admit after. A finding
		// already below it is not taken off anything by this, and saying it
		// was would inflate the number an approver is being asked to weigh.
		if floor.Admits(row.Exploited, row.Severity) &&
			!floor.Admits(row.Exploited, claim.Severity) {
			held.OffTheList += row.Open
		}
	}
	return held, nil
}
