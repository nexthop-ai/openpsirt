package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/rating"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// place is one finding's position: the component, and what pulled it in.
type place struct {
	componentID int64
	consumerID  int64 // zero where the thing above is the product itself
}

// key identifies a finding within a variant.
type key struct {
	vulnerabilityID int64
	place           place
}

// at identifies a finding by where it sits rather than by what sits there.
//
// The place identity is built from names alone, so it survives a version
// change where the component identity does not. Comparing the two is what
// distinguishes a version moving under a finding from the finding going away.
type at struct {
	vulnerabilityID int64
	placeIdentity   string
}

// Apply records what a run found, writing only the difference.
//
// A scanner reports a package at a version. Fanning that out across the places
// the package occupies is done here, from the graph the inventory described —
// it is the step where one line in a report becomes the number of decisions
// somebody actually has to make.
//
// Re-running against a database that moved slightly must write only what
// changed, for the same reason the graph does: a nightly re-scan that found
// the same things should cost nothing.
func (s *Store) Apply(ctx context.Context, targetID, runID int64, reported []Reported) (Applied, error) {
	var applied Applied

	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		// Taken first, before anything is read, exactly as applying a graph
		// does. Two runs against one target can be in flight at once — the
		// queue hands different jobs to different workers by design — and
		// without this both read the same open findings, both compute the same
		// difference, and both write it, leaving two open rows where
		// everything downstream assumes one. An ordinary row update is a lock
		// every engine honors, so the second worker waits instead of racing.
		if _, err := tx.NewUpdate().Table("target").
			Set("last_run_id = ?", runID).
			Where("id = ?", targetID).Exec(ctx); err != nil {
			return fmt.Errorf("take the target: %w", err)
		}

		issues := make([]Named, 0, len(reported))
		for _, r := range reported {
			issues = append(issues, r.Issue)
		}
		interned := NewVulnerabilities(tx)
		vulnerabilities, err := interned.Intern(ctx, issues)
		if err != nil {
			return err
		}
		// The product this build belongs to, read before anything is
		// ranked. A rating belongs to a product, so what ranks here is
		// this product's rating and not a word somebody working on
		// another one wrote.
		productID, err := productOf(ctx, tx, targetID)
		if err != nil {
			return err
		}
		// The record for each issue: the rating in force —
		// this product's where somebody here has made one, the
		// published one otherwise — and the signals that rank it. What
		// a finding is ordered, admitted and clocked by has to be what
		// every later reading uses, or a finding opened after a rating
		// arrives on the published word's deadline while the ones
		// beside it sit on the product's.
		//
		// Read at this moment rather than copied onto the finding, so a
		// place that newly pulls a library in tomorrow picks the
		// product's rating up without anything having to remember to
		// go and fetch it.
		ratings, err := ratingsInForce(ctx, tx, productID, vulnerabilities)
		if err != nil {
			return err
		}

		// Whether this build reaches customers, read once. A critical in
		// something only the build system runs matters less than a medium in
		// what people install, and that is a property of the build rather than
		// of any finding in it.
		shipped, err := shippedToCustomers(ctx, tx, targetID)
		if err != nil {
			return err
		}

		present, err := openComponents(ctx, tx, targetID)
		if err != nil {
			return err
		}
		places, err := openPlaces(ctx, tx, targetID)
		if err != nil {
			return err
		}
		// The build's own claims about what it ships. Applied here
		// rather than upstream of us, so a suppressed finding is something
		// that can be seen and accounted for instead of one that never
		// arrived.
		claims, err := openClaims(ctx, tx, targetID)
		if err != nil {
			return err
		}
		// Those that reached anything are worked out against what the target
		// contains, not against what was reported: a claim covering a
		// component nothing was found in has still done its job, while one
		// covering nothing the build ships has not.
		applied.ClaimsReaching, applied.ClaimsReachingNothing = claimsReaching(claims, present)

		// The two halves of a deadline: how long each kind of thing
		// may stay open, and when this run started. Read once for the
		// whole apply rather than per finding, and read here rather
		// than by the caller so that what is stored and what the
		// screen later compares against come from the same place.
		windows, err := LoadWindows(ctx, tx)
		if err != nil {
			return err
		}
		var startedAt time.Time
		if err := tx.NewSelect().
			TableExpr(`"scan_run" AS "r"`).
			ColumnExpr("r.started_at").
			Where("r.id = ?", runID).
			Scan(ctx, &startedAt); err != nil {
			return fmt.Errorf("read when this run started: %w", err)
		}

		// The product's triage line. Below that line
		// nothing carries a deadline: a line says "this is not work"
		// and a deadline says "this is work, and it is late", and
		// holding both means one of them is lying — within a year the
		// overdue figure would be thousands of things nobody ever
		// intended to look at.
		floor, err := FloorFor(ctx, tx, productID)
		if err != nil {
			return err
		}

		// And whether this build is still supported. Past its
		// end-of-life date nothing on it carries a deadline: the
		// overdue figure and the escalation view would otherwise fill
		// permanently with releases nobody will ever fix, and both
		// stop being read. It is the same statement the triage line
		// makes from another direction — "this is not work" — and it
		// is applied the same way.
		//
		// Nothing is hidden or deleted by it. The findings are still
		// recorded, still counted and still reportable; what ends is
		// what is expected of us.
		supported, err := catalog.NewStore(tx).EndOfLifeForTarget(ctx, targetID)
		if err != nil {
			return err
		}
		// And whether the release can change at all. A tag was built once and
		// is what somebody received, so a deadline on it is unmeetable by
		// construction — no work will land there whatever the date says.
		//
		// It takes precedence over end-of-life because it is the more
		// fundamental statement: a supported tag is as unfixable as a retired
		// one. Real deployments accumulate tags while branches do not, so a
		// deadline on every one of them inflates every overdue figure with
		// work nobody could ever have done.
		moves, err := catalog.NewStore(tx).TargetMoves(ctx, targetID)
		if err != nil {
			return err
		}
		onTheClock := moves && !supported.Past(s.now().UTC())

		wanted := map[key]Finding{}
		// The time each of them has, where it is on the clock at all. Carried
		// beside the finding rather than on it: a deadline is worked out from
		// the finding's own opening, and one already open opened before this
		// run — so the window has to reach the loop below, where that is
		// known. Absent means nothing on this build carries a deadline.
		windowFor := map[key]time.Duration{}
		for _, r := range reported {
			component, held := present.byIdentity[r.Component.Identity()]
			if !held {
				// Reported against something this variant does not contain.
				// It has no place, so it cannot become a finding at one, and
				// silently dropping it would hide a report that does not match
				// the inventory it was produced from.
				applied.Unplaced++
				continue
			}
			vulnerabilityID, known := vulnerabilities[normalize(r.Issue.Identifier)]
			if !known {
				return fmt.Errorf("issue %q was not recorded", r.Issue.Identifier)
			}

			covering := coveringClaim(claims, r.Issue, component)
			for _, consumerID := range places.of(component.ID) {
				at := place{componentID: component.ID, consumerID: consumerID}
				wanted[key{vulnerabilityID, at}] = Finding{
					TargetID: targetID, Kind: Vulnerable,
					// A scanner's finding in a shipped component is public
					// knowledge by the time it reaches us: the advisory it
					// matched is published. What is not disclosed is a finding
					// somebody entered here.
					Visibility:      access.Public,
					VulnerabilityID: vulnerabilityID,
					ComponentID:     component.ID,
					ConsumerID:      optional(consumerID),
					PlaceIdentity:   PlaceIdentity(component.Name, present.nameOf(consumerID)),
					FixState:        r.FixState, FixedIn: r.FixedIn, FixedAt: r.FixedAt,
					Matched: r.Matched, MatchedFrom: r.MatchedFrom,
					MatchedIn: r.MatchedIn, MatchedRange: r.MatchedRange,
					SuppressedBy: covering,
					OpenedAt:     startedAt,
					OpenedRunID:  &runID,
				}
				rated := ratings[vulnerabilityID]
				ranked := Ranked{
					Exploited: rated.Exploited, Shipped: shipped,
					LikelihoodPPM: rated.LikelihoodPPM,
					ScoreCenti:    rated.Score(),
				}
				entry := wanted[key{vulnerabilityID, at}]
				entry.Urgency = int64(ranked.Rank())
				entry.RankExploited, entry.RankShipped = ranked.Exploited, ranked.Shipped
				// A finding that opens already exploited was learned about
				// when it opened, and every later recount has to reach the
				// same answer.
				entry.ExploitedLearnedAt = learnedExploitation(entry, startedAt)
				severity := rated.Severity()
				if onTheClock && floor.Admits(rated.Exploited, severity) {
					window := windows.For(rated.Exploited, severity)
					windowFor[key{vulnerabilityID, at}] = window
					// From this run, which for a new finding is when it was
					// first seen. One already open is answered in the loop
					// below, from its own opening.
					entry.DueAt = Deadline(entry.FixState, startedAt, startedAt,
						entry.ExploitedLearnedAt, entry.FixedAt, window)
				}
				wanted[key{vulnerabilityID, at}] = entry
			}
		}

		// open is what is already open **that a scan governs**. A run
		// is the authority on what it found, and everything it no
		// longer reports is closed below — so without this narrowing,
		// the first nightly scan after somebody records a finding by
		// hand closes it, with a reason that reads like the issue went
		// away. Nothing would report that: the row looks exactly like
		// a component that stopped shipping.
		var open []Finding
		err = tx.NewSelect().Model(&open).
			Where("target_id = ?", targetID).
			Where("kind = ?", Vulnerable).
			Where("closed_at IS NULL").Scan(ctx)
		if err != nil {
			return fmt.Errorf("read what is already open: %w", err)
		}

		held := map[key]Finding{}
		// A second index, by place *name* rather than by component. A version
		// change makes a different component and therefore a different key, so
		// the two indexes disagree exactly where a version moved — which is
		// the case worth telling apart from every other kind of closure.
		heldAt := map[at]Finding{}
		for _, f := range open {
			held[key{f.VulnerabilityID, place{f.ComponentID, value(f.ConsumerID)}}] = f
			heldAt[at{f.VulnerabilityID, f.PlaceIdentity}] = f
		}
		// The subject of those findings, so a version can be named rather
		// than merely known to have changed.
		before, err := componentsByID(ctx, tx, open)
		if err != nil {
			return err
		}

		now := s.now().UTC().Truncate(time.Microsecond)

		var opening []Finding
		for k, f := range wanted {
			if f.SuppressedBy != nil {
				applied.Suppressed++
			}
			already, open := held[k]
			if !open {
				f.LastChangedAt = now
				// The same issue at the same place a moment ago, on a
				// different component, means the version moved and the issue
				// came with it. Recorded on the way in, because this is the
				// only point where both versions are in hand.
				if was, moved := heldAt[at{f.VulnerabilityID, f.PlaceIdentity}]; moved &&
					was.ComponentID != f.ComponentID {
					f.ArrivedFrom = upstreamOf(before[was.ComponentID])
				}
				opening = append(opening, f)
				continue
			}
			// A finding that is already open still moves. A fix
			// appears, or the build answers it — and somebody
			// waiting for a fix is waiting for exactly that.
			// Leaving the row as first written would report last
			// month's answer indefinitely. The same goes for how
			// urgent it is: what is known about an issue changes
			// under a finding that has not.
			moved, exploitationMoved := ranking(already, f)
			// From its own opening rather than from this run, and from what
			// the row already knows about when exploitation was learned — a
			// recount that re-learned it nightly would move the deadline
			// forward every night and never arrive.
			learned := already.ExploitedLearnedAt
			if exploitationMoved {
				learned = learnedExploitation(f, startedAt)
			}
			window, onClock := windowFor[k]
			if onClock {
				f.DueAt = Deadline(f.FixState, already.OpenedAt, startedAt,
					learned, f.FixedAt, window)
			}
			// Asked of the answer rather than of what moved. A fix appearing
			// upstream starts a clock that was not running, and one being
			// withdrawn stops it — and a row written under an earlier rule
			// carries an answer nothing else corrects.
			clockMoved := !sameDate(already.DueAt, f.DueAt)
			if same(already, f) && !moved && !clockMoved {
				continue
			}
			update := tx.NewUpdate().Model((*Finding)(nil)).
				Set("fix_state = ?", f.FixState).
				Set("fixed_in = ?", f.FixedIn).
				Set("fixed_at = ?", f.FixedAt).
				Set("matched = ?", f.Matched).
				Set("matched_from = ?", f.MatchedFrom).
				Set("matched_in = ?", f.MatchedIn).
				Set("matched_range = ?", f.MatchedRange).
				Set("suppressed_by = ?", f.SuppressedBy).
				Set("last_changed_at = ?", now)
			if moved {
				update = update.
					Set("urgency = ?", f.Urgency).
					Set("urgency_exploited = ?", f.RankExploited).
					Set("urgency_shipped = ?", f.RankShipped)
			}
			if exploitationMoved {
				// The moment, kept beside the deadline it produced. Every
				// later recount counts from it, and nothing else on the row
				// holds it — so without this the recount fell back to the
				// opening and moved the deadline into the past.
				update = update.Set("exploited_learned_at = ?", learned)
			}
			if clockMoved {
				update = update.Set("due_at = ?", f.DueAt)
			}
			if _, err := update.Where("id = ?", already.ID).Exec(ctx); err != nil {
				return fmt.Errorf("update a finding that moved: %w", err)
			}
			applied.Updated++
		}
		if len(opening) > 0 {
			if err := database.InBatches(ctx, tx, opening); err != nil {
				return fmt.Errorf("open %d findings: %w", len(opening), err)
			}
			applied.Opened = len(opening)
		}

		var closing []Finding
		// Where the same issue is still wanted at the same place, this row is
		// being superseded by one against a new version rather than resolved.
		wantedAt := map[at]bool{}
		for _, f := range wanted {
			wantedAt[at{f.VulnerabilityID, f.PlaceIdentity}] = true
		}
		for k, f := range held {
			if _, still := wanted[k]; still {
				continue
			}
			closing = append(closing, f)
		}
		// A closing finding's subject is read from the component
		// catalog rather than from what the variant currently contains — the
		// whole reason it is closing is usually that it is no longer there.
		departed, err := componentsByID(ctx, tx, closing)
		if err != nil {
			return err
		}
		// Grouped by the explanation *and* the version it moved to, because
		// two findings closing for the same reason rarely moved to the same
		// version — one write per group rather than one per finding, which at
		// a kernel's fan-out is the difference that matters.
		type closure struct {
			Reason  Closure
			MovedTo string
		}
		byReason := map[closure][]int64{}
		for _, f := range closing {
			reason, movedTo := present.why(departed[f.ComponentID])
			// Asked before anything else, because every other explanation is
			// about a finding that went away and this one did not. Recording
			// it as an upgrade would say a bump fixed something it did not,
			// in a report that goes to customers.
			if wantedAt[at{f.VulnerabilityID, f.PlaceIdentity}] {
				reason, movedTo = Superseded, ""
			}
			key := closure{reason, movedTo}
			byReason[key] = append(byReason[key], f.ID)
			if reason == Unexplained {
				applied.Unexplained++
			}
			applied.Closed++
		}
		for key, ids := range byReason {
			err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
				_, err := tx.NewUpdate().Model((*Finding)(nil)).
					// The run's own moment, which is what the opening side
					// dates a finding by: a finding's life is measured
					// against the runs that observed it, not against when
					// the write happened to land. The run stays beside it as
					// provenance, and is what "what did this run change" is
					// counted by.
					Set("closed_at = ?", startedAt).
					Set("closed_run_id = ?", runID).
					Set("closed_because = ?", key.Reason).
					Set("moved_to = ?", key.MovedTo).
					Where("id IN (?)", bun.List(batch)).Exec(ctx)
				return err
			})
			if err != nil {
				return fmt.Errorf("close %d findings: %w", len(ids), err)
			}
		}

		// Last, and over every build rather than this one. Three of the four
		// signals the order is worked out from are properties of the issue,
		// so a report raising one here leaves every open finding of it in
		// every build nothing rescanned carrying a number worked out from a
		// world that has moved — a known-exploited issue in a shipped tag
		// below the triage line, answering no exploited filter, on no
		// exploited clock, at the bottom of the list, until somebody
		// rescans a tag, which for a tag is never.
		//
		// After this build's own rows are written, so what the scan changed
		// here is counted as the scan's; the rows this corrects are the ones
		// no scan was going to touch.
		return Reranked(ctx, tx, interned.Moved(), startedAt)
	})
	return applied, err
}

// same reports whether what a scan found about a finding matches what is
// already recorded. Only what the fix half of the update writes is compared;
// how urgent it is has its own comparison, because the two write different
// columns and a deadline moves on a narrower condition than a rank does.
//
// Everything else is what makes it that finding rather than another, and
// comparing something no update writes would count the finding as changed
// every night and move its last change forward with nothing having moved.
func same(held, found Finding) bool {
	return held.FixState == found.FixState &&
		held.FixedIn == found.FixedIn &&
		sameDate(held.FixedAt, found.FixedAt) &&
		// The match method moves for a real reason: a distribution
		// recording an advisory for something reached only by an upstream
		// identifier changes the answer from "somebody has to look"
		// to "the people who package this said so". A night where that is all
		// that moved is a night worth recording.
		held.Matched == found.Matched &&
		held.MatchedFrom == found.MatchedFrom &&
		held.MatchedIn == found.MatchedIn &&
		held.MatchedRange == found.MatchedRange &&
		equalRef(held.SuppressedBy, found.SuppressedBy)
}

// learnedExploitation is the moment to record beside a clock that just moved,
// or nothing where the row is no longer exploited.
//
// The run's start rather than the wall clock, because that is what the
// deadline beside it was counted from and the two have to agree.
func learnedExploitation(f Finding, startedAt time.Time) *time.Time {
	if !f.RankExploited {
		return nil
	}
	return &startedAt
}

// ranking reports whether an open finding's place in the order has moved, and
// whether exploitation is what moved it.
//
// The two are separate, and deliberately: **every** ranking signal moves the
// order, and exploitation is the only one that starts a clock over. A score
// somebody revised upward is worth reordering the list for and is not worth
// resetting a deadline over — likelihood and score are not in the deadline at
// all, and a deadline recounted whenever a number was revised would never
// arrive, which is the same failure as recounting it nightly.
//
// It does not answer whether the deadline moved. That is asked of the deadline
// itself, because a fix appearing upstream moves it and touches no ranking
// signal at all.
func ranking(held, found Finding) (moved, exploitationMoved bool) {
	moved = held.Urgency != found.Urgency ||
		held.RankExploited != found.RankExploited ||
		held.RankShipped != found.RankShipped
	exploitationMoved = held.RankExploited != found.RankExploited
	return moved, exploitationMoved
}

// ratingsInForce reads what is on record about each interned issue.
//
// Read back from the issue rather than taken from the report that is being
// applied, and that is the point of it. A report is one source's account of
// one moment: it may omit that something is being exploited, or carry a score
// lower than a report last week gave. What is stored is the worst anybody has
// claimed, moving only toward worse, plus this product's rating where somebody
// here has made one — so the issue is the one place that knows everything
// known about it, and ranking from anywhere else makes the order depend on
// which scan ran last.
//
// The rating is this build's product's. Another product's rating of the same
// issue reaches nothing here, which is what makes two products able to hold
// different ones.
//
// Interning has already folded this report into the row, so what comes back
// includes whatever this report knew that the row did not.
func ratingsInForce(ctx context.Context, tx bun.IDB, productID int64,
	interned map[string]int64) (map[int64]Rating, error) {

	ids := make([]int64, 0, len(interned))
	seen := map[int64]bool{}
	for _, id := range interned {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	ratings := map[int64]Rating{}
	if len(ids) == 0 {
		return ratings, nil
	}
	var rows []struct {
		ID            int64  `bun:"id"`
		Published     string `bun:"published"`
		Assessed      string `bun:"assessed"`
		Exploited     bool   `bun:"exploited"`
		ScoreCenti    int    `bun:"score_centi"`
		LikelihoodPPM int    `bun:"likelihood_ppm"`
	}
	err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		var found []struct {
			ID            int64  `bun:"id"`
			Published     string `bun:"published"`
			Assessed      string `bun:"assessed"`
			Exploited     bool   `bun:"exploited"`
			ScoreCenti    int    `bun:"score_centi"`
			LikelihoodPPM int    `bun:"likelihood_ppm"`
		}
		err := tx.NewSelect().
			TableExpr(`"vulnerability" AS "v"`).
			Join(rating.Here, productID).
			ColumnExpr(`v.id AS "id"`).
			ColumnExpr(`COALESCE(v.severity, ?) AS "published"`, "").
			ColumnExpr(`COALESCE(ir.severity, ?) AS "assessed"`, "").
			ColumnExpr(`v.exploited AS "exploited"`).
			ColumnExpr(`COALESCE(v.score_centi, 0) AS "score_centi"`).
			ColumnExpr(`COALESCE(v.likelihood_ppm, 0) AS "likelihood_ppm"`).
			Where("v.id IN (?)", bun.List(batch)).
			Scan(ctx, &found)
		rows = append(rows, found...)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("read what is on record about these issues: %w", err)
	}
	for _, row := range rows {
		ratings[row.ID] = Rating{
			Published: row.Published, Assessed: row.Assessed,
			Exploited: row.Exploited, ScoreCenti: row.ScoreCenti,
			LikelihoodPPM: row.LikelihoodPPM,
		}
	}
	return ratings, nil
}

// equalRef compares two references that may be absent.
func equalRef(a, b *int64) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
	}
}

// claimsReaching counts how many of a build's arguments land on something it
// actually ships.
//
// A claim that reached nothing is the ordinary case rather than the
// exceptional one — a producer's automatically-extracted claims name source
// trees rather than packages — and it means a finding the build believes it
// has answered will come back as noise. Nothing distinguishes that from a
// finding nobody has looked at, so the count is reported rather than left to
// be inferred.
func claimsReaching(claims []Claim, present inventory) (reaching, reachingNothing int) {
	for _, claim := range claims {
		found := false
		for _, component := range present.byID {
			if claim.covers(describedOf(component)) {
				found = true
				break
			}
		}
		if found {
			reaching++
		} else {
			reachingNothing++
		}
	}
	return reaching, reachingNothing
}

// describedOf reads a stored component back into the shape a claim matches
// against.
func describedOf(c graph.Component) graph.Described {
	return graph.Described{
		Purl: c.Purl, CPE: c.CPE, Name: c.Name, Version: c.Version,
		UpstreamName: c.UpstreamName, UpstreamVersion: c.UpstreamVersion,
	}
}

// coveringClaim finds the build's argument that covers a reported issue, if it
// made one.
//
// A claim that arrived attached to the component is preferred over one that
// named something we had to match: the first knows exactly what it is about,
// while the second may name a whole source tree.
func coveringClaim(claims []Claim, issue Named, component graph.Component) *int64 {
	names := map[string]bool{normalize(issue.Identifier): true}
	for _, alias := range issue.Aliases {
		names[normalize(alias)] = true
	}

	described := describedOf(component)

	var found *int64
	for _, claim := range claims {
		if !names[normalize(claim.Vulnerability)] || !claim.suppresses() || !claim.covers(described) {
			continue
		}
		id := claim.ID
		if claim.Origin == string(sbom.FromPedigree) {
			return &id
		}
		if found == nil {
			// The first in a stable order, so the answer does not move
			// between runs.
			found = &id
		}
	}
	return found
}

// inventory is what a target currently contains, as far as findings care.
type inventory struct {
	byID       map[int64]graph.Component
	byIdentity map[string]graph.Component
	byName     map[string][]graph.Component
}

// nameOf names a consumer, or nothing where the consumer is the product.
func (i inventory) nameOf(consumerID int64) string {
	if consumerID == 0 {
		return ""
	}
	return i.byID[consumerID].Name
}

// why explains a finding that is no longer reported, and says what it moved to
// where moving is the explanation.
//
// The component being gone, its upstream version having moved, and a
// downstream revision having landed are three different things to whoever
// reads the report later. What is left over — the component still present and
// unchanged, and the scanner no longer reporting it — is the case that must
// never be quietly dropped.
//
// The version returned alongside is what the place moved to. It is available
// only here, because the component that carried the issue is gone from the
// inventory the moment this run is over, so anything asking later has one
// version and not two — which is why a release note could say a component was
// upgraded and never say to what.
func (i inventory) why(gone graph.Component) (Closure, string) {
	if _, present := i.byID[gone.ID]; present {
		return Unexplained, ""
	}
	for _, now := range i.byName[gone.Name] {
		switch {
		case upstreamOf(now) != upstreamOf(gone):
			return Upgraded, upstreamOf(now)
		case now.Version != gone.Version:
			return Revised, now.Version
		}
	}
	// Something of that name is still here, unchanged in both the version that
	// ships and the version vulnerabilities are matched against. Nothing about
	// the component explains the finding going away, so it is not explained.
	if len(i.byName[gone.Name]) > 0 {
		return Unexplained, ""
	}
	return Removed, ""
}

// upstreamOf is the version a vulnerability is actually matched against: what
// a fork was made from, where there is one, and otherwise what shipped.
func upstreamOf(c graph.Component) string {
	if c.UpstreamVersion != "" {
		return c.UpstreamVersion
	}
	return c.Version
}

// componentsByID reads what a set of findings was about.
func componentsByID(ctx context.Context, db bun.IDB, findings []Finding) (map[int64]graph.Component, error) {
	if len(findings) == 0 {
		return nil, nil
	}
	ids := make([]int64, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.ComponentID)
	}
	byID := map[int64]graph.Component{}
	err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		var rows []graph.Component
		if err := db.NewSelect().Model(&rows).Where("id IN (?)", bun.List(batch)).Scan(ctx); err != nil {
			return err
		}
		for _, row := range rows {
			byID[row.ID] = row
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read what closing findings were about: %w", err)
	}
	return byID, nil
}

// openComponents reads what a variant currently contains.
func openComponents(ctx context.Context, db bun.IDB, targetID int64) (inventory, error) {
	var rows []graph.Component
	err := db.NewSelect().Model(&rows).
		Join(`JOIN "graph_node" AS "n" ON n.component_id = c.id`).
		Where("n.target_id = ?", targetID).
		Where("n.closed_scan_id IS NULL").
		Scan(ctx)
	if err != nil {
		return inventory{}, fmt.Errorf("read what the variant contains: %w", err)
	}

	held := inventory{
		byID:       make(map[int64]graph.Component, len(rows)),
		byIdentity: make(map[string]graph.Component, len(rows)),
		byName:     map[string][]graph.Component{},
	}
	for _, row := range rows {
		held.byID[row.ID] = row
		held.byIdentity[row.Identity] = row
		held.byName[row.Name] = append(held.byName[row.Name], row)
	}
	return held, nil
}

// consumers maps a component to everything that directly pulled it in.
type consumers map[int64][]int64

// of returns where a component sits. A component nothing leads to still has a
// place — itself — because it ships whether or not the producer could say what
// pulled it in.
func (c consumers) of(componentID int64) []int64 {
	if at, held := c[componentID]; held {
		return at
	}
	return []int64{0}
}

// openPlaces reads every place in a variant.
func openPlaces(ctx context.Context, db bun.IDB, targetID int64) (consumers, error) {
	return placeEdges(ctx, db, targetID, 0)
}

// sits is one place a component occupies: what pulls it in, by identifier and
// by name. A component sitting directly under the build is pulled in by
// nothing and its consumer has no name, for the reason PlaceIdentity gives.
type sits struct {
	consumerID int64
	consumer   string
}

// sittingsOf reads where one component sits, with the name of each thing
// that pulls it in.
//
// For a finding somebody records by hand: a person names a component and the
// places are derived from the build's own graph, exactly as a scan's are. A
// component can sit in more than one place at once, which is why the answer is
// a list — and which is why a form asking "where does it sit" could not
// express it.
func sittingsOf(ctx context.Context, db bun.IDB, targetID, componentID int64) ([]sits, error) {
	at, err := placeEdges(ctx, db, targetID, componentID)
	if err != nil {
		return nil, err
	}
	ids := at.of(componentID)
	names, err := componentNames(ctx, db, ids)
	if err != nil {
		return nil, err
	}
	places := make([]sits, 0, len(ids))
	for _, id := range ids {
		places = append(places, sits{consumerID: id, consumer: names[id]})
	}
	return places, nil
}

// componentNames names components by identifier, leaving out the one that is
// no component at all.
func componentNames(ctx context.Context, db bun.IDB, ids []int64) (map[int64]string, error) {
	wanted := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id != 0 {
			wanted = append(wanted, id)
		}
	}
	names := map[int64]string{}
	if len(wanted) == 0 {
		return names, nil
	}
	var rows []struct {
		ID   int64  `bun:"id"`
		Name string `bun:"name"`
	}
	if err := db.NewSelect().
		TableExpr(`"component" AS "c"`).
		ColumnExpr(`c.id AS "id"`).
		ColumnExpr(`c.name AS "name"`).
		Where("c.id IN (?)", bun.List(wanted)).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what pulls it in: %w", err)
	}
	for _, row := range rows {
		names[row.ID] = row.Name
	}
	return names, nil
}

// placeEdges reads where things sit in a variant, all of them or one of them.
//
// A component under the product itself is recorded as being under nothing: the
// product's name differs per variant, so keying on it would stop the same
// place being recognized across them.
func placeEdges(ctx context.Context, db bun.IDB, targetID, componentID int64) (consumers, error) {
	var edges []struct {
		ChildComponentID  int64 `bun:"child_component_id"`
		ParentComponentID int64 `bun:"parent_component_id"`
		ParentIsRoot      bool  `bun:"parent_is_root"`
	}
	err := db.NewSelect().
		TableExpr(`"graph_edge" AS "e"`).
		Join(`JOIN "graph_node" AS "child" ON child.id = e.child_id`).
		Join(`JOIN "graph_node" AS "parent" ON parent.id = e.parent_id`).
		ColumnExpr(`child.component_id AS "child_component_id"`).
		ColumnExpr(`parent.component_id AS "parent_component_id"`).
		ColumnExpr(`parent.is_root AS "parent_is_root"`).
		Where("e.target_id = ?", targetID).
		Where("e.closed_scan_id IS NULL").
		Apply(func(q *bun.SelectQuery) *bun.SelectQuery {
			if componentID == 0 {
				return q
			}
			return q.Where("child.component_id = ?", componentID)
		}).
		Scan(ctx, &edges)
	if err != nil {
		return nil, fmt.Errorf("read where things sit: %w", err)
	}

	at := consumers{}
	seen := map[[2]int64]bool{}
	for _, e := range edges {
		consumer := e.ParentComponentID
		if e.ParentIsRoot {
			consumer = 0
		}
		pair := [2]int64{e.ChildComponentID, consumer}
		if seen[pair] {
			continue
		}
		seen[pair] = true
		at[e.ChildComponentID] = append(at[e.ChildComponentID], consumer)
	}
	return at, nil
}

// optional turns a consumer into something that can be absent.
func optional(id int64) *int64 {
	if id == 0 {
		return nil
	}
	return &id
}

// value reads a consumer that may be absent.
func value(id *int64) int64 {
	if id == nil {
		return 0
	}
	return *id
}

// sameDate compares two dates that may be absent.
//
// Absent and present are different, and two absences are the same — the
// distinction matters because this decides whether a finding changed, and a
// finding that appears to change every scan writes rows every night.
func sameDate(a, b *time.Time) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.Equal(*b)
	}
}

// shippedToCustomers reports whether the build a scan is for reaches
// customers.
//
// Read from the variant, because that is where it is recorded: what a product
// is built as is what decides whether anybody outside runs it.
func shippedToCustomers(ctx context.Context, tx bun.IDB, targetID int64) (bool, error) {
	var shipped bool
	err := tx.NewSelect().
		TableExpr(`"target" AS "t"`).
		Join(`JOIN "variant" AS "v" ON v.id = t.variant_id`).
		Column("v.customer_facing").
		Where("t.id = ?", targetID).
		Scan(ctx, &shipped)
	if err != nil {
		return false, fmt.Errorf("read whether this build reaches customers: %w", err)
	}
	return shipped, nil
}
