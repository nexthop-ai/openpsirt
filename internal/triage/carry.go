// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/filed"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// ErrNotOffered refuses carrying a decision occurrence the preview did not offer this
// line: one that already applies here, or one covering nothing here.
var ErrNotOffered = refusal.New("is not one this line was offered")

// Carry takes chosen decisions onto a new line as decisions waiting for
// agreement.
//
// It carries reasoning forward and never conclusions. Each one arrives as
// a decision needing approval, with the words from the old line to start from
// rather than to start without. A version moved, which is exactly what makes
// the old decision stop applying — so somebody has to look at it again, and
// what is inherited is the thinking rather than the answer.
//
// Only what was offered. A caller naming a decision occurrence the preview classified
// as already applying, or as covering nothing here, is choosing something it
// was not asked about: the first has already happened and the second has
// nothing to happen to. Both are refused rather than quietly skipped, because
// a caller that got the set wrong should hear so.
//
// Bounded, like every other act answering many issues at once.
func (s *Store) Carry(ctx context.Context, subject access.Subject, fromBuild, toBuild int64,
	chosen []int64, bounds Bounds) (int, error) {

	if len(chosen) == 0 {
		return 0, nil
	}

	carried := 0
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		carried = 0

		// The decisions the new line inherits, read through the same rule
		// that shows it — so a caller cannot carry something the
		// preview would not offer, and the two cannot come to disagree
		// about which those are.
		//
		// Read inside the transaction, and this is the read that most
		// needed to be. It decides every row written below: what each
		// decision says, which occurrence it is about, and whether it may be
		// carried at all. Read before the transaction began, a retry —
		// or a first attempt that merely waited — carried a decision
		// somebody withdrew in the meantime, onto a line the old decision
		// no longer applies to, with the words from a decision that has
		// since been revised. The offer and the writing have to see
		// the same database or the rule "only what was offered" is
		// about a world that has moved.
		offered, err := within.WouldCarry(ctx, subject, fromBuild, toBuild)
		if err != nil {
			return err
		}
		available := make(map[int64]Inherited, len(offered.Moved)+len(offered.Postponed))
		for _, one := range append(append([]Inherited{}, offered.Moved...), offered.Postponed...) {
			available[one.DecisionOccurrenceID] = one
		}
		wanted := make([]Inherited, 0, len(chosen))
		for _, id := range chosen {
			one, ok := available[id]
			if !ok {
				return fmt.Errorf("decision occurrence %d %w", id, ErrNotOffered)
			}
			wanted = append(wanted, one)
		}

		// Bounded by the reviewer's issue limit, because every decision
		// carried waits for a second person. One chosen row is one
		// occurrence on the new line.
		issues := map[string]bool{}
		for _, one := range wanted {
			issues[one.Vulnerability] = true
		}
		limits, err := bounds.within(ctx, tx)
		if err != nil {
			return err
		}
		if err := limits.counted(len(issues), len(wanted), true); err != nil {
			return err
		}

		for _, one := range wanted {
			// The occurrence is read from the new line's own findings rather than
			// copied from the old decision: the versions are what a row is
			// keyed on and they are the thing that moved, so copying them
			// would write a decision keyed to a build it is not about.
			occurrence, err := within.occurrenceOnLine(ctx, toBuild, one.DecisionOccurrenceID)
			if err != nil {
				return err
			}
			old, err := within.oldDecision(ctx, one.DecisionOccurrenceID)
			if err != nil {
				return err
			}
			// How bad the issue is judged to be here now, which is what a
			// later rise is measured from. Without it a carried decision reads
			// as made about an unrated issue.
			severity, err := within.severityOf(ctx, occurrence.ProductID, occurrence.VulnerabilityID)
			if err != nil {
				return err
			}
			proposal := Proposal{
				Occurrence: *occurrence, Outcome: old.Outcome,
				Reasoning: one.Reasoning, By: subject.ID,
				SeverityCenti: severity,
				// Always. A decision whose versions moved is a
				// fresh decision about code nobody has looked at,
				// however confident whoever carried it was —
				// and seeding a new line says reasoning
				// travels and conclusions do not.
				NeedsApproval: true,
				SelectedBy:    "carried from another line",
				// The line it is carried to is the build somebody chose.
				MadeOn: []int64{toBuild},
			}
			if old.Justification != nil {
				proposal.Justification = Justification(*old.Justification)
			}
			if old.Mitigation != nil {
				proposal.Mitigation = *old.Mitigation
			}
			proposal.Scope = scopeOf(old.Scope)
			if old.FixedVersion != nil {
				proposal.FixedVersion = *old.FixedVersion
			}
			if old.DeferredUntil != nil {
				// Carried as it was, not extended. Somebody agreeing to this
				// is agreeing to a date, and quietly moving it forward would
				// be the tool making the decision it is asking for.
				until := *old.DeferredUntil
				proposal.DeferredUntil = &until
			}
			// A patch promise travels with its date, carried as it was for
			// the same reason a deferral's date is. An upgrade is never
			// offered, so there is no version to carry.
			if old.CommittedTo != nil {
				by := *old.CommittedTo
				proposal.CommittedTo = &by
			}
			// The same checks every other write path makes, asked of the
			// occurrence it lands at: the visibility there is the new line's,
			// which may be undisclosed where the old line's was not, and a
			// dated decision is refused on a line built once, as it is when
			// proposed there. The offer read above already leaves out an
			// occurrence the carrier may not argue about, so the visibility arm
			// is a backstop no request reaches.
			if err := permitted(subject, []Proposal{proposal}, s.now()); err != nil {
				return fmt.Errorf("carry decision occurrence %d: %w", one.DecisionOccurrenceID, err)
			}
			// The inner form, because this is already inside a transaction:
			// carrying six decisions is one act, and half of it landing is a
			// line nobody can tell from one somebody chose that way.
			decision, err := within.newDecision(ctx, FindingDecision, subject.ID, nil,
				"carried from another line", proposal)
			if err != nil {
				return fmt.Errorf("carry decision occurrence %d: %w", one.DecisionOccurrenceID, err)
			}
			if _, err := within.propose(ctx, decision, proposal); err != nil {
				return fmt.Errorf("carry decision occurrence %d: %w", one.DecisionOccurrenceID, err)
			}
			carried++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return carried, nil
}

// occurrenceOnLine is where a carried decision lands: the same issue at the same
// occurrence, at whatever versions the new line holds.
func (s *Store) occurrenceOnLine(ctx context.Context, toBuild, occurrenceID int64) (*Occurrence, error) {
	var row struct {
		ProductID          int64  `bun:"product_id"`
		VulnerabilityID    int64  `bun:"vulnerability_id"`
		OccurrenceIdentity string `bun:"occurrence_identity"`
		Visibility         string `bun:"visibility"`
		Component          string `bun:"component_now"`
		Consumer           string `bun:"consumer_now"`
		// OnTag as an integer, because the four engines spell a boolean
		// three ways and a CASE returning 1 or 0 reads the same on all of
		// them.
		OnTag int `bun:"on_tag"`
	}
	// Undisclosed where any open finding there is, disclosed where there are
	// findings and none is, and nothing where there are none. The kinds a
	// version carries hold no other visibility.
	undisclosed, private := access.AnyPrivate(`"f"."visibility"`)
	kinds, kindArgs := kindsOf(kind.VersionCarry, "f")
	err := s.db.NewSelect().
		TableExpr(`"decision_occurrence" AS "de"`).
		// The issue the row is read as, which is the one the new line holds.
		Join(finding.DecisionOccurrenceIssue).
		ColumnExpr(`"de"."product_id" AS "product_id"`).
		ColumnExpr(`"dv"."issue_id" AS "vulnerability_id"`).
		ColumnExpr(`"de"."occurrence_identity" AS "occurrence_identity"`).
		ColumnExpr(`COALESCE((SELECT CASE WHEN COUNT(*) = 0 THEN NULL
				WHEN `+undisclosed+` THEN ? ELSE ? END
			FROM "finding" AS "f"
			WHERE "f"."build_id" = ? AND `+finding.DecisionOccurrenceOf("f")+` AND "f"."closed_at" IS NULL
				AND `+kinds+`), '')
			AS "visibility"`, append([]any{private, string(access.Private), string(access.Public), toBuild},
			kindArgs...)...).
		Apply(versionsOnLine(toBuild, "component_now", "consumer_now")).
		// A line carried onto that was built once. It is a fact about the
		// build rather than about the decision, and the rule that refuses a
		// dated decision on a tag reads it.
		ColumnExpr(`(SELECT CASE WHEN "st"."kind" = ? THEN 1 ELSE 0 END
			FROM "build" AS "tg" JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"
			WHERE "tg"."id" = ?) AS "on_tag"`, catalog.Tag, toBuild).
		Where(`"de"."id" = ?`, occurrenceID).
		Scan(ctx, &row)
	if err != nil {
		return nil, fmt.Errorf("read where a carried decision lands: %w", err)
	}
	return &Occurrence{
		ProductID: row.ProductID, VulnerabilityID: row.VulnerabilityID,
		OccurrenceIdentity: row.OccurrenceIdentity,
		Visibility:         access.AsVisibility(row.Visibility),
		ComponentUpstream:  row.Component, ConsumerUpstream: row.Consumer,
		OnTag: row.OnTag == 1,
	}, nil
}

// versionsOnLine adds the versions a row's occurrence sits at on a line, as
// the two named columns: the component's and its consumer's upstream
// versions, empty where the line holds nothing open there.
//
// Both come from one finding: the first open at the occurrence in the order both
// versions sort as text. A row is keyed on the pair, and an occurrence can hold
// two findings — one library vendored twice — so a minimum taken of each
// version alone can pair versions no finding holds together. Ordered on both
// and taken once, both columns read the same row.
func versionsOnLine(toBuild int64, componentAs, consumerAs string) func(*bun.SelectQuery) *bun.SelectQuery {
	kinds, kindArgs := kindsOf(kind.VersionCarry, "f")
	first := func(expr string) string {
		return `COALESCE((SELECT ` + expr + ` FROM "finding" AS "f"
			JOIN "component" AS "c" ON "c"."id" = "f"."component_id"
			LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"
			WHERE "f"."build_id" = ? AND ` + finding.DecisionOccurrenceOf("f") + ` AND "f"."closed_at" IS NULL
				AND ` + kinds + `
			ORDER BY ` + finding.ComponentUpstreamExpr + `, ` + finding.ConsumerUpstreamExpr + `
			LIMIT 1), '')`
	}
	as := func(name string) []any {
		args := append([]any{toBuild}, kindArgs...)
		return append(args, bun.Ident(name))
	}
	return func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.
			ColumnExpr(first(finding.ComponentUpstreamExpr)+` AS ?`, as(componentAs)...).
			ColumnExpr(first(finding.ConsumerUpstreamExpr)+` AS ?`, as(consumerAs)...)
	}
}

// oldDecision is what the decision being carried actually said.
func (s *Store) oldDecision(ctx context.Context, occurrenceID int64) (*Decision, error) {
	row := new(DecisionOccurrence)
	// With its argument, which is what is being carried: the row says where
	// the old decision landed, and the decision says what it was.
	if err := s.db.NewSelect().Model(row).Relation("Decision").
		Where(`"de"."id" = ?`, occurrenceID).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the decision being carried: %w", err)
	}
	return row.Decision, nil
}

// Carried is what a new line would inherit from an existing one.
//
// Six buckets, because they need different things from a person. What
// already applies needs nothing. What moved needs a fresh answer, and gets the
// old reasoning to start from. A postponement is a scheduling decision about a
// release rather than a decision about code, so it is offered separately. A
// decision whose date has gone by sits at an occurrence the new line still has and
// cannot be carried. A promised upgrade is planned from its component. And
// what covers nothing there is left behind.
type Carried struct {
	// Applying reach the new line by matching. Nothing to choose.
	Applying int
	// Moved held a decision at a version the new line does not have. Each comes
	// across as a proposal carrying the old words — never as a decision,
	// because the version moved and the old conclusion is not a conclusion
	// about the new code.
	Moved []Inherited
	// Postponed were deferrals. "Not this sprint" was about that sprint, and
	// carrying it silently gives a new line expiry dates nobody chose.
	Postponed []Inherited
	// Expired is how many sit at an occurrence the new line still holds, as a
	// deferral or a promise whose date has gone by. Carried keeps the date,
	// so none of them can be carried, and each leaves a finding there with
	// no answer.
	Expired int
	// Upgrades is how many promised upgrades moved. An upgrade covers a
	// component in the releases it names and records what each of them is
	// waiting on, which a decision carried onto one occurrence cannot write, so each
	// is planned again from the component.
	Upgrades int
	// Absent is how many cover nothing in the new line at all.
	Absent int
}

// Inherited is one decision a new line could take on.
type Inherited struct {
	DecisionOccurrenceID int64
	Vulnerability        string
	Component            string
	Outcome              Outcome
	Was                  string
	Now                  string
	Reasoning            string
	// DeferredDays is how long this has already been put off, across every
	// line it has been carried through. The number that decides whether
	// carrying it again is reasonable.
	DeferredDays int
}

// WouldCarry reports what a new line would inherit from an existing one,
// without changing anything.
//
// Asked before a line is created, because the answer is what somebody is
// agreeing to — and a carry that happened silently is the one nobody reviews.
func (s *Store) WouldCarry(ctx context.Context, subject access.Subject,
	fromBuild, toBuild int64) (*Carried, error) {

	if subject.Kind != access.Person {
		return nil, ErrNotTheirs
	}

	// productID is which product this is about, read from the build rather
	// than taken from the caller. Rows are selected by product as well as
	// by live key and occurrence: an occurrence is a hash of component names carrying no
	// product, so a shared distribution package matches across products, and
	// the reasoning of undisclosed decisions elsewhere would come back.
	var productID int64
	if err := s.db.NewSelect().
		TableExpr(`"build" AS "tg"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		ColumnExpr(`"st"."product_id"`).
		Where(`"tg"."id" = ?`, toBuild).
		Scan(ctx, &productID); err != nil {
		return nil, fmt.Errorf("look up which product this line belongs to: %w", err)
	}
	// Public and private only: a version carries decisions about the kinds
	// VersionCarry reads, and those hold no security testing finding.
	var readable []access.Visibility
	for _, v := range []access.Visibility{access.Public, access.Private} {
		if mayDecide(subject, productID, v) {
			readable = append(readable, v)
		}
	}
	if len(readable) == 0 {
		return nil, ErrNotTheirs
	}

	var rows []struct {
		DecisionOccurrenceID int64  `bun:"decision_occurrence_id"`
		Vulnerability        string `bun:"vulnerability"`
		Component            string `bun:"component"`
		Outcome              string `bun:"outcome"`
		Was                  string `bun:"was"`
		Now                  string `bun:"now_at"`
		ConsumerWas          string `bun:"consumer_was"`
		ConsumerNow          string `bun:"consumer_now"`
		Reasoning            string `bun:"reasoning"`
		StillThere           bool   `bun:"still_there"`
		RanOut               bool   `bun:"ran_out"`
		// Carried so a postponement can be told how long it has already run.
		VulnerabilityID    int64  `bun:"vulnerability_id"`
		OccurrenceIdentity string `bun:"occurrence_identity"`
		// Landing is the visibility the occurrence has on the new line, which is
		// what a carried decision would be written at.
		Landing string `bun:"landing"`
	}
	undisclosed, private := access.AnyPrivate(`"f"."visibility"`)
	kinds, kindArgs := kindsOf(kind.VersionCarry, "f")
	gKinds, gKindArgs := kindsOf(kind.VersionCarry, "g")
	err := s.db.NewSelect().
		TableExpr(`"decision_occurrence" AS "de"`).
		// The issue each row is read as, which is the one the new line holds.
		Join(finding.DecisionOccurrenceIssue).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "dv"."issue_id"`).
		// The argument, which is where the outcome lives.
		Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
		Join(`LEFT JOIN "decision_revision" AS "dr" ON "dr"."id" = "cl"."revision_id"`).
		ColumnExpr(`"de"."id" AS "decision_occurrence_id"`).
		ColumnExpr(`"dv"."issue_id" AS "vulnerability_id"`).
		ColumnExpr(`"de"."occurrence_identity" AS "occurrence_identity"`).
		ColumnExpr(`"v"."identifier" AS "vulnerability"`).
		ColumnExpr(`COALESCE("de"."component_upstream_version", '') AS "was"`).
		ColumnExpr(`"cl"."outcome" AS "outcome"`).
		ColumnExpr(`COALESCE("dr"."body", '') AS "reasoning"`).
		// The new line's contents at that occurrence, if anything.
		ColumnExpr(`COALESCE((SELECT MIN("c"."name") FROM "finding" AS "f"
			JOIN "component" AS "c" ON "c"."id" = "f"."component_id"
			WHERE "f"."build_id" = ? AND `+finding.DecisionOccurrenceOf("f")+` AND "f"."closed_at" IS NULL
				AND `+kinds+`), '')
			AS "component"`, append([]any{toBuild}, kindArgs...)...).
		// Both versions, because a row is keyed on both: a build whose
		// consumer alone has moved is one the decision does not reach, and the
		// finding surfaces unanswered.
		Apply(versionsOnLine(toBuild, "now_at", "consumer_now")).
		ColumnExpr(`COALESCE("de"."consumer_upstream_version", '') AS "consumer_was"`).
		ColumnExpr(`EXISTS (SELECT 1 FROM "finding" AS "f"
			WHERE "f"."build_id" = ? AND `+finding.DecisionOccurrenceOf("f")+` AND "f"."closed_at" IS NULL
				AND `+kinds+`)
			AS "still_there"`, append([]any{toBuild}, kindArgs...)...).
		// The visibility the occurrence lands at, read as occurrenceOnLine reads it.
		ColumnExpr(`COALESCE((SELECT CASE WHEN COUNT(*) = 0 THEN NULL
				WHEN `+undisclosed+` THEN ? ELSE ? END
			FROM "finding" AS "f"
			WHERE "f"."build_id" = ? AND `+finding.DecisionOccurrenceOf("f")+` AND "f"."closed_at" IS NULL
				AND `+kinds+`), '')
			AS "landing"`, append([]any{private, string(access.Private), string(access.Public), toBuild},
			kindArgs...)...).
		// A date it carries that has already gone by, either of them.
		ColumnExpr(`(COALESCE("cl"."deferred_until", "cl"."committed_to") IS NOT NULL
			AND COALESCE("cl"."deferred_until", "cl"."committed_to") <= ?) AS "ran_out"`, s.now()).
		Where(`"de"."live_key" IS NOT NULL`).
		Where(`"de"."product_id" = ?`, productID).
		Where(`"de"."visibility" IN (?)`, bun.List(readable)).
		Where(`EXISTS (SELECT 1 FROM "finding" AS "g"
			WHERE "g"."build_id" = ? AND `+finding.DecisionOccurrenceOf("g")+` AND `+gKinds+`)`,
			append([]any{fromBuild}, gKindArgs...)...).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what a new line would inherit: %w", err)
	}

	carried := &Carried{}
	var postponed []at
	for _, row := range rows {
		if !row.StillThere {
			carried.Absent++
			continue
		}
		// An occurrence this subject may not argue about on the new line is not
		// theirs to carry onto, and not theirs to count: the new line's
		// contents there are undisclosed to them.
		if !mayDecideOn(subject, productID, row.VulnerabilityID, access.AsVisibility(row.Landing)) {
			continue
		}
		if Outcome(row.Outcome).StandsAtAnyVersion() ||
			(row.Was == row.Now && row.ConsumerWas == row.ConsumerNow) {
			// The versions match, or the outcome stands at any version, so it
			// reaches the new line by matching. Offering it would ask somebody
			// to agree to something that has already happened, and carrying a
			// correction is refused as the occurrence already decided.
			carried.Applying++
			continue
		}
		one := Inherited{
			DecisionOccurrenceID: row.DecisionOccurrenceID, Vulnerability: row.Vulnerability,
			Component: row.Component, Outcome: Outcome(row.Outcome),
			Was: row.Was, Now: row.Now, Reasoning: row.Reasoning,
		}
		// Anything the write would refuse is not offered. A carried decision
		// keeps its date rather than having it quietly moved forward, so a
		// deferral that has already run out and a promise whose date has
		// gone by cannot be carried at all — and offering one is offering
		// something the act behind the button turns down.
		if row.RanOut {
			carried.Expired++
			continue
		}
		if Outcome(row.Outcome) == UpgradeNeeded {
			carried.Upgrades++
			continue
		}
		if Outcome(row.Outcome) == Deferred {
			postponed = append(postponed, at{row.VulnerabilityID, row.OccurrenceIdentity})
			carried.Postponed = append(carried.Postponed, one)
			continue
		}
		carried.Moved = append(carried.Moved, one)
	}

	// The length each postponement has already run. Somebody agreeing to carry
	// a deferral into a new line is agreeing to however long it has been put
	// off in total, not to the months the new one asks for — and four
	// consecutive carries of "not this release" are a decision nobody made.
	already, err := s.deferredSoFarAt(ctx, productID, postponed)
	if err != nil {
		return nil, err
	}
	for i := range carried.Postponed {
		carried.Postponed[i].DeferredDays = int(already[postponed[i]].Hours() / 24)
	}
	return carried, nil
}

// at is one occurrence a decision was made about.
type at struct {
	vulnerability int64
	occurrence    string
}

// deferredSoFarAt totals how long each of these occurrences has been put off, in
// one statement rather than one per row.
//
// The arithmetic happens here rather than in SQL: subtracting one timestamp
// from another and summing the result has no portable spelling, and the rows
// are already being read.
func (s *Store) deferredSoFarAt(ctx context.Context, productID int64, occurrences []at) (map[at]time.Duration, error) {
	total := map[at]time.Duration{}
	if len(occurrences) == 0 {
		return total, nil
	}
	issues := make([]int64, 0, len(occurrences))
	identities := make([]string, 0, len(occurrences))
	wanted := make(map[at]bool, len(occurrences))
	for _, occurrence := range occurrences {
		if wanted[occurrence] {
			continue
		}
		wanted[occurrence] = true
		issues = append(issues, occurrence.vulnerability)
		identities = append(identities, occurrence.occurrence)
	}

	var deferrals []DecisionOccurrence
	if err := s.db.NewSelect().Model(&deferrals).Relation("Decision").
		Column("vulnerability_id", "occurrence_identity", "proposed_at", "state", "ended_at").
		Where(`"de"."product_id" = ?`, productID).
		Where(finding.FiledUnderAny(filed.DecisionOccurrenceIssue), bun.List(issues)).
		Where(`"de"."occurrence_identity" IN (?)`, bun.List(identities)).
		Where(`"decision"."outcome" = ?`, Deferred).
		// Withdrawn and lapsed ones for the span they were in force, as the
		// threshold counts them.
		Where(`"decision"."deferred_until" IS NOT NULL`).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read how long these have been put off: %w", err)
	}
	// Keyed by the issue each deferral is read as, which is how the occurrences
	// were asked for.
	filed := make([]int64, 0, len(deferrals))
	for _, deferral := range deferrals {
		filed = append(filed, deferral.VulnerabilityID)
	}
	issueOf, err := finding.IssuesOf(ctx, s.db, filed)
	if err != nil {
		return nil, err
	}
	held := spans[at]{}
	for _, deferral := range deferrals {
		deferral.VulnerabilityID = issueOf[deferral.VulnerabilityID]
		key := at{deferral.VulnerabilityID, deferral.OccurrenceIdentity}
		// The pair of lists matches more combinations than were asked for, so
		// what was not asked for is dropped here.
		if !wanted[key] {
			continue
		}
		if one, ok := heldDeferral(deferral); ok {
			held[key] = append(held[key], one)
		}
	}
	for key := range held {
		total[key] = held.total(key)
	}
	return total, nil
}
