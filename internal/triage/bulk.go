// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/rating"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// One decision covering everything at one component.
//
// A distinct act with its own resolution: the occurrences are worked out from a
// component and a build rather than named, the bounds are on how many issues
// a reviewer reads and how many findings are written, and what comes back is
// one decision however many it reached.

// DefaultBulkDecisionCap is how many occurrences one answer about one issue may cover
// when nobody has set a limit, read from where the setting itself is declared.
const DefaultBulkDecisionCap = setting.DefaultBulkDecisionCap

// allowed is what every proposal in a bulk decision has to satisfy before
// any of them is written.
//
// Checked over the whole set first, because refusing halfway is the failure
// these actions exist to avoid — and the bound is on the rows about to be
// written rather than on what a caller named, since one name expands into as
// many occurrences as the issue sits at.
//
// Called inside the transaction that writes them, so the limit is the one in
// force when the rows land and a retry reads it again.
func (s *Store) allowed(ctx context.Context, subject access.Subject, proposals []Proposal) error {
	cap, err := setting.NewStore(s.db).Count(ctx, setting.BulkDecisionCap, DefaultBulkDecisionCap)
	if err != nil {
		return fmt.Errorf("read how many findings one action may write: %w", err)
	}
	if len(proposals) > cap {
		return refusal.Errorf("that is %d findings and the limit here is %d: narrow it, "+
			"or raise the limit deliberately", len(proposals), cap)
	}
	return permitted(subject, proposals, s.now())
}

// Bounds are the limits on one act that answers many issues at once
// (REQ-27): a new answer about many issues, a re-confirmation of answers that
// lapsed, and answers carried onto another line.
//
// Issues are counted where occurrences are not, because a reviewer reads issues: a
// kernel issue sits at about 45 occurrences, so a limit of 2,000 occurrences is 44
// issues. Occurrences are bounded separately, by a ceiling that guards the write
// rather than the reader.
//
// A limit left at zero is the deployment's setting, read inside the
// transaction the act writes in.
type Bounds struct {
	// Review is how many issues an act may answer where anything in it goes
	// to a second person.
	Review int
	// Agreed is how many issues an act may answer where nothing in it does:
	// every row carries an agreement already given.
	Agreed int
	// Occurrences is how many findings any such act may write.
	Occurrences int
}

// DefaultBounds is the shipped limits, for where nobody has said.
func DefaultBounds() Bounds {
	return Bounds{
		Review: setting.DefaultReviewIssues, Agreed: setting.DefaultAgreedIssues,
		Occurrences: setting.DefaultWriteCeiling,
	}
}

// orDefaults fills in a limit left unset. Zero is not unbounded: an act that
// answers many issues is always bounded.
func (b Bounds) orDefaults() Bounds {
	shipped := DefaultBounds()
	if b.Review <= 0 {
		b.Review = shipped.Review
	}
	if b.Agreed <= 0 {
		b.Agreed = shipped.Agreed
	}
	if b.Occurrences <= 0 {
		b.Occurrences = shipped.Occurrences
	}
	return b
}

// Limits is every limit on an act answering many issues at once, as the
// deployment sets them, read through db.
func Limits(ctx context.Context, db bun.IDB) (Bounds, error) {
	return Bounds{}.within(ctx, db)
}

// within fills each limit left unset from the deployment's settings, read
// through the transaction the act writes in. A limit read before the
// transaction opened describes a deployment a retry may no longer be running
// against; one a caller set is kept.
func (b Bounds) within(ctx context.Context, db bun.IDB) (Bounds, error) {
	settings := setting.NewStore(db)
	for _, each := range []struct {
		key      string
		fallback int
		into     *int
	}{
		{setting.ReviewIssues, setting.DefaultReviewIssues, &b.Review},
		{setting.AgreedIssues, setting.DefaultAgreedIssues, &b.Agreed},
		{setting.WriteCeiling, setting.DefaultWriteCeiling, &b.Occurrences},
	} {
		if *each.into > 0 {
			continue
		}
		n, err := settings.Count(ctx, each.key, each.fallback)
		if err != nil {
			return b, fmt.Errorf("read the limits on one action: %w", err)
		}
		*each.into = n
	}
	return b, nil
}

// check refuses an act past its bounds, counted over what it is about to
// write. The issue limit is the reviewer's where any row goes to a second
// person, and the larger one only where none does.
func (b Bounds) check(proposals []Proposal) error {
	issues := map[[2]int64]bool{}
	review := false
	for _, p := range proposals {
		issues[[2]int64{p.Occurrence.ProductID, p.Occurrence.VulnerabilityID}] = true
		review = review || p.NeedsApproval
	}
	return b.counted(len(issues), len(proposals), review)
}

// counted is check over counts already taken.
func (b Bounds) counted(issues, occurrences int, review bool) error {
	b = b.orDefaults()
	if occurrences > b.Occurrences {
		return refusal.Errorf("that is %d findings and one action here writes at most %d: narrow "+
			"the selection, or raise the limit deliberately", occurrences, b.Occurrences)
	}
	if review && issues > b.Review {
		return refusal.Errorf("that is %d issues and a second person is asked to read at most %d "+
			"in one action: split it, or raise the limit deliberately", issues, b.Review)
	}
	if !review && issues > b.Agreed {
		return refusal.Errorf("that is %d issues and one action here re-confirms at most %d: "+
			"split it, or raise the limit deliberately", issues, b.Agreed)
	}
	return nil
}

// permitted is everything except the bound: may this subject decide here, is
// each proposal well formed, and is it recorded as made by whoever made it.
//
// Split out because a bulk promise carries no bound. What the cap is for is
// reviewability — one sentence answering a thousand findings has to stay a size
// a reviewer can follow, because nothing re-checks a dismissal afterwards. A
// promise to upgrade is the one bulk write that verifies itself: the next scan
// re-checks every row it names, and narrowing it makes the record false, since
// the bump closes what it closes. The distinction is reversibility, not size.
func permitted(subject access.Subject, proposals []Proposal, now time.Time) error {
	for _, p := range proposals {
		if !mayDecideOn(subject, p.Occurrence.ProductID, p.Occurrence.VulnerabilityID, visibilityOf(p.Occurrence)) {
			return ErrNotTheirs
		}
		if err := p.valid(now); err != nil {
			return err
		}
		if p.By != subject.ID {
			return refusal.Errorf("a decision is recorded as made by whoever made it")
		}
	}
	return nil
}

// BulkDecisionAt names what one decision covers: some issues, and the build and
// component they sit at.
//
// The occurrences themselves are not named. A caller free to name an occurrence would be
// choosing which decisions apply where, and would be naming rows it read
// before this ran — so they are resolved here, inside the transaction that
// writes.
//
// The component names a fold, not a package. Naming any binary of a source
// package reaches all of them, which is the grain the list somebody picked from
// already shows and the grain a bump is done at: one vim row on that list is
// four packages at sixty-one occurrences, and keyed on one binary it took four
// decisions and four approvals to answer what reads as one thing.
type BulkDecisionAt struct {
	TargetID         int64
	ComponentID      int64
	VulnerabilityIDs []int64
	// Contains is the text the candidate list was narrowed by, empty where it
	// was not. Re-run here rather than believed: what is recorded beside the
	// proposer's prose is how many issues that narrowing reaches, against how
	// many were named.
	Contains string
	// SkipDecided leaves out every occurrence a live decision already covers,
	// where the proposer asked for that. Unset, a selection covering one is
	// refused whole, naming the decision, because it is a selection somebody
	// should look at again.
	SkipDecided bool
}

// Skipped is an occurrence a bulk decision left out because a live decision already
// covers it, and the row that does.
type Skipped struct {
	VulnerabilityID      int64
	OccurrenceIdentity   string
	DecisionOccurrenceID int64
	State                State
}

// resolved is an occurrence a decision is about to be written against, with how bad
// the issue there is judged to be.
type resolved struct {
	Occurrence
	SeverityCenti int
}

// BulkDecision records the same decision against many issues at one component.
//
// The transpose of grouping. One issue across many occurrences is what a decision
// already covers; a component carrying thousands of issues — a kernel, most of
// them in drivers a given image never builds — has no answer at all, and
// without one the choices are answering two thousand findings individually,
// which nobody does, or hiding them, which is refused.
//
// One outcome, one justification, one reasoning, one approval, and a separate
// record per issue and per occurrence. Each is keyed and expires on its own,
// which is what makes one action across many findings defensible rather than a
// blanket decision — and covering every occurrence is what stops it reporting that it
// answered a consumer it left open.
//
// Everything authorization turns on is read inside the transaction that writes
// . Which product these sit in, and whether any of them is undisclosed, decide
// whether this person may make the decision at all; read before the transaction,
// they would be answers about a database that has since moved.
//
// Bounded twice, over what this actually resolves to rather than the names
// typed: by how many issues a second person is asked to read, and by how many
// findings one action may write.
//
// What is skipped where the proposer asked for occurrences already decided to be
// left out is said rather than dropped: a decision covering less than was
// selected is one the proposer has to be able to see is smaller, and which
// decision stands at each occurrence is where they go next.
func (s *Store) BulkDecision(ctx context.Context, subject access.Subject, at BulkDecisionAt,
	p Proposal, bounds Bounds) (decisionID int64, recorded []int64, skipped []Skipped, err error) {

	if len(at.VulnerabilityIDs) == 0 {
		return 0, nil, nil, refusal.Errorf("nothing was selected, so there is nothing to decide")
	}
	if p.By != subject.ID {
		return 0, nil, nil, refusal.Errorf("a decision is recorded as made by whoever made it")
	}

	// attempted is what the write was about, kept so a refusal can be read
	// back after the transaction has unwound. Inside it the row that
	// collided is the row this attempt cannot see, so the sentence naming
	// it is built afterwards.
	var attempted []Proposal

	err = s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		// Cleared on every attempt. A retry re-runs this against a database
		// that has moved, and carrying identifiers over from the attempt that
		// failed would report decisions that no longer exist.
		recorded = recorded[:0]
		attempted = nil
		skipped = nil
		decisionID = 0

		// The fold, resolved inside the transaction that writes like
		// everything else this turns on. The list somebody picked from folds
		// the source package, so keying the write on one binary of it wrote a
		// decision covering part of what the screen said it covered.
		fold, err := finding.InTheFold(ctx, tx, at.ComponentID)
		if err != nil {
			return err
		}

		occurrences, err := occurrencesWithin(ctx, tx, subject, at, fold)
		if err != nil {
			return err
		}
		if len(occurrences) == 0 {
			return fmt.Errorf("%w against that component", ErrNothingOpen)
		}
		if at.SkipDecided {
			if occurrences, skipped, err = within.leavingDecided(ctx, occurrences); err != nil {
				return err
			}
			if len(occurrences) == 0 {
				return ErrAllDecided
			}
		}
		// Bounded over what is about to be written: the occurrences resolved,
		// less any skipped, and the issues they sit under. Always the
		// reviewer's issue limit, because this always goes to a second
		// person.
		limits, err := bounds.within(ctx, tx)
		if err != nil {
			return err
		}
		if err := limits.counted(issuesIn(occurrences), len(occurrences), true); err != nil {
			return err
		}

		// The narrowing as something other than the proposer's word for it,
		// re-run against the same rows the write is about to land on.
		narrowing, err := finding.NarrowedWithin(ctx, tx, subject, at.TargetID, fold,
			at.Contains, len(at.VulnerabilityIDs))
		if err != nil {
			return err
		}

		// Made on the build the selection was made in.
		claimed := p
		claimed.MadeOn = []int64{at.TargetID}
		decision, err := within.newDecisionNarrowed(ctx, BulkDecision, subject.ID, nil,
			p.SelectedBy, &narrowing, claimed)
		if err != nil {
			return err
		}
		decisionID = decision.ID
		each := make([]Proposal, 0, len(occurrences))
		for _, occurrence := range occurrences {
			if !mayDecide(subject, occurrence.ProductID, visibilityOf(occurrence.Occurrence)) {
				return ErrNotTheirs
			}
			one := p
			one.Occurrence = occurrence.Occurrence
			one.SeverityCenti = occurrence.SeverityCenti
			if err := one.valid(s.now()); err != nil {
				return err
			}
			each = append(each, one)
		}
		attempted = each
		// One live decision per combination of code holds here too. A selection
		// covering something already decided is a selection somebody should
		// look at again rather than one to write around, and the sentinel is
		// carried out whole so the refusal outside can name which decision
		// stands. Replaced here with "something in this selection is already
		// decided", it tells a reader holding five hundred rows nothing they
		// can act on.
		made, err := within.proposeAll(ctx, decision, each)
		if err != nil {
			return err
		}
		for _, one := range made {
			recorded = append(recorded, one.ID)
		}
		return nil
	})
	if err != nil {
		return 0, nil, nil, s.alreadyDecided(ctx, err, occurrencesOf(attempted))
	}
	return decisionID, recorded, skipped, nil
}

// ErrAllDecided says a bulk decision asked to skip what is decided found
// nothing else to decide.
var ErrAllDecided = refusal.New("a live decision already covers every occurrence selected")

// leavingDecided splits the occurrences into those nothing stands at and those a
// live decision covers, naming the row.
//
// Asked in one statement over both keys an occurrence can be held under, the
// question Undecided asks, so an occurrence this keeps is one the unique index will
// accept. Two proposals arriving together can still both pass it, and the
// index refuses the second as it would without skipping.
func (s *Store) leavingDecided(ctx context.Context, occurrences []resolved) ([]resolved,
	[]Skipped, error) {

	keys := make([]string, 0, len(occurrences)*2)
	for _, at := range occurrences {
		keys = append(keys, liveKeysFor(at.Occurrence)...)
	}
	type row struct {
		ID      int64  `bun:"id"`
		LiveKey string `bun:"live_key"`
		State   State  `bun:"state"`
	}
	// In chunks, because two keys per occurrence across a kernel selection is a
	// statement past what an engine accepts in one packet.
	var standing []row
	for from := 0; from < len(keys); from += database.BatchSize {
		chunk := keys[from:min(from+database.BatchSize, len(keys))]
		var some []row
		if err := s.db.NewSelect().Model((*DecisionOccurrence)(nil)).
			ColumnExpr(`"de"."id", "de"."live_key", "de"."state"`).
			Where(`"de"."live_key" IN (?)`, bun.List(chunk)).
			Scan(ctx, &some); err != nil {
			return nil, nil, fmt.Errorf("read what already stands: %w", err)
		}
		standing = append(standing, some...)
	}
	// The earliest row at a key is the one named, as a refusal names it.
	sort.Slice(standing, func(i, j int) bool { return standing[i].ID < standing[j].ID })
	held := make(map[string]int, len(standing))
	for i := len(standing) - 1; i >= 0; i-- {
		held[standing[i].LiveKey] = i
	}
	left := make([]resolved, 0, len(occurrences))
	var skipped []Skipped
	for _, at := range occurrences {
		found := -1
		for _, key := range liveKeysFor(at.Occurrence) {
			if i, ok := held[key]; ok && (found < 0 || i < found) {
				found = i
			}
		}
		if found < 0 {
			left = append(left, at)
			continue
		}
		skipped = append(skipped, Skipped{
			VulnerabilityID: at.VulnerabilityID, OccurrenceIdentity: at.OccurrenceIdentity,
			DecisionOccurrenceID: standing[found].ID, State: standing[found].State,
		})
	}
	return left, skipped, nil
}

// issuesIn is how many distinct issues a set of occurrences sits under.
func issuesIn(occurrences []resolved) int {
	issues := map[[2]int64]bool{}
	for _, at := range occurrences {
		issues[[2]int64{at.ProductID, at.VulnerabilityID}] = true
	}
	return len(issues)
}

// occurrencesWithin reads every open occurrence the named issues occupy at one
// component, in the transaction that is about to write against them.
//
// Narrowed to what this subject may read, like every other query here. A decision
// therefore covers every occurrence the person making it can see, and the occurrences
// they cannot are left open for whoever can — which is the ordinary division
// of work rather than a gap. The alternative, refusing the whole action
// because something undisclosed sits at the same component, answers a person
// who picked from the list they were shown with a bare "not found" and no way
// to tell why.
func occurrencesWithin(ctx context.Context, tx bun.Tx, subject access.Subject,
	at BulkDecisionAt, fold []int64) ([]resolved, error) {

	var rows []struct {
		ProductID          int64  `bun:"product_id"`
		VulnerabilityID    int64  `bun:"vulnerability_id"`
		OccurrenceIdentity string `bun:"occurrence_identity"`
		Visibility         string `bun:"visibility"`
		ComponentUpstream  string `bun:"component_upstream"`
		ConsumerUpstream   string `bun:"consumer_upstream"`
		Published          string `bun:"published_severity"`
		Assessed           string `bun:"assessed_severity"`
		ScoreCenti         int    `bun:"score_centi"`
		OnTag              int    `bun:"on_tag"`
	}
	query := tx.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "f"."vulnerability_id"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		// This product's rating of the issue, which is the rating in force
		// here. The read spans products, so each row reads its own stream's.
		Join(rating.For(rating.OnStream)).
		ColumnExpr(`"st"."product_id" AS "product_id"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"f"."occurrence_identity" AS "occurrence_identity"`).
		ColumnExpr(`"f"."visibility" AS "visibility"`).
		ColumnExpr(finding.ComponentUpstreamExpr+` AS "component_upstream"`).
		ColumnExpr(finding.ConsumerUpstreamExpr+` AS "consumer_upstream"`).
		// The three parts of a rating rather than the published score alone.
		// The baseline stored with a decision is what a re-affirmation compares
		// today's rating against, so storing the published number where this
		// product has rated the issue lower left the comparison asking whether
		// the severity had risen past a figure nobody was working to.
		ColumnExpr(`COALESCE("v"."severity", '') AS "published_severity"`).
		ColumnExpr(`COALESCE("ir"."severity", '') AS "assessed_severity"`).
		ColumnExpr(`COALESCE("v"."score_centi", 0) AS "score_centi"`).
		// A release built once, which decides what may be said
		// about it. As an integer rather than a boolean: the four engines
		// spell a boolean three ways.
		ColumnExpr(`MAX(CASE WHEN "st"."kind" = ? THEN 1 ELSE 0 END) AS "on_tag"`, catalog.Tag).
		Where(`"f"."target_id" = ?`, at.TargetID).
		Where(`"f"."component_id" IN (?)`, bun.List(fold)).
		Where(`"f"."closed_at" IS NULL`).
		Apply(ofKinds(kind.Triage, "f")).
		Where(`"f"."vulnerability_id" IN (?)`, bun.List(at.VulnerabilityIDs)).
		GroupExpr(`"st"."product_id", "f"."vulnerability_id", "f"."occurrence_identity", "f"."visibility", ` +
			`"c"."upstream_version", "c"."version", "uc"."upstream_version", "uc"."version", ` +
			`"v"."severity", "ir"."severity", "v"."score_centi"`).
		OrderExpr(`"f"."vulnerability_id", "f"."occurrence_identity"`)
	if err := onlyDecidable(query, subject).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read where these issues sit: %w", err)
	}

	occurrences := make([]resolved, 0, len(rows))
	for _, row := range rows {
		occurrences = append(occurrences, resolved{
			Occurrence: Occurrence{
				ProductID: row.ProductID, VulnerabilityID: row.VulnerabilityID,
				OccurrenceIdentity: row.OccurrenceIdentity,
				Visibility:         access.AsVisibility(row.Visibility),
				ComponentUpstream:  row.ComponentUpstream,
				ConsumerUpstream:   row.ConsumerUpstream,
				OnTag:              row.OnTag == 1,
			},
			SeverityCenti: finding.Rating{
				Published: row.Published, Assessed: row.Assessed, ScoreCenti: row.ScoreCenti,
			}.Score(),
		})
	}
	return occurrences, nil
}
