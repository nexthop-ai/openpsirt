// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/rating"
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
		// A retry re-runs this against a database that has moved, and what an
		// attempt that rolled back counted is not what was applied.
		applied = Applied{}
		// Taken first, before anything is read, exactly as applying a graph
		// does. Two runs against one target can be in flight at once — the
		// queue hands different jobs to different workers by design — and
		// without this both read the same open findings, both compute the same
		// difference, and both write it, leaving two open rows where
		// everything downstream assumes one. An ordinary row update is a lock
		// every engine honors, so the second worker waits instead of racing.
		if _, err := tx.NewUpdate().Table("target").
			Set(`"last_run_id" = ?`, runID).
			Where(`"id" = ?`, targetID).Exec(ctx); err != nil {
			return fmt.Errorf("take the target: %w", err)
		}

		run, err := s.readRun(ctx, tx, targetID, runID, reported)
		if err != nil {
			return err
		}
		want, err := run.wanted(reported)
		if err != nil {
			return err
		}
		held, heldAt, err := heldOpen(ctx, tx, targetID)
		if err != nil {
			return err
		}
		plan := diffOpen(run, want, held, heldAt)
		wrote, err := writePlan(ctx, tx, run, want, plan)
		if err != nil {
			return err
		}
		applied = Applied{
			Opened:                wrote.opened,
			Closed:                wrote.closed,
			Unexplained:           wrote.unexplained,
			Updated:               plan.updated,
			Suppressed:            plan.suppressed,
			Patched:               wrote.patched,
			Unaffected:            wrote.unaffected,
			Disclaimed:            wrote.disclaimed,
			ClaimsReaching:        run.claimsReaching,
			ClaimsReachingNothing: run.claimsReachingNothing,
			Unplaced:              want.unplaced,
			Merged:                len(run.interned.absorbed),
			Displaced:             run.interned.displaced,
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
		return Reranked(ctx, tx, run.interned.Moved(), run.startedAt, targetID)
	})
	return applied, err
}

// applyRun is what applying one scan reads before it works anything out: the
// issues the report names and what is on record about them, what the build
// holds and where, the build's claims and its suppliers' statements, and the
// clock.
type applyRun struct {
	targetID, runID int64
	interned        *Vulnerabilities
	vulnerabilities map[string]int64
	ratings         map[int64]Rating
	shipped         bool
	present         inventory
	places          consumers
	claims          []Claim
	placed          *placer
	suppliers       *disclaiming
	byName          claimsByName
	fixing          map[int64]bool
	windows         Windows
	startedAt       time.Time
	floor           Floor
	onTheClock      bool
	// claimsReaching and claimsReachingNothing say how many of the build's
	// claims land on something it ships.
	claimsReaching, claimsReachingNothing int
}

// readRun reads what applying a scan works from, inside the transaction that
// writes.
func (s *Store) readRun(ctx context.Context, tx bun.IDB, targetID, runID int64,
	reported []Reported) (*applyRun, error) {

	run := &applyRun{targetID: targetID, runID: runID}
	issues := make([]Named, 0, len(reported))
	for _, r := range reported {
		issues = append(issues, r.Issue)
	}
	run.interned = NewVulnerabilities(tx)
	run.interned.run = runID
	vulnerabilities, err := run.interned.Intern(ctx, issues)
	if err != nil {
		return nil, err
	}
	run.vulnerabilities = vulnerabilities
	// The product this build belongs to, read before anything is ranked. A
	// rating belongs to a product, so what ranks here is this product's
	// rating and not a word somebody working on another one wrote.
	productID, err := productOf(ctx, tx, targetID)
	if err != nil {
		return nil, err
	}
	// The record for each issue: the rating in force — this product's where
	// somebody here has made one, the published one otherwise — and the
	// signals that rank it. What a finding is ordered, admitted and clocked by
	// has to be what every later reading uses, or a finding opened after a
	// rating arrives on the published word's deadline while the ones beside it
	// sit on the product's.
	//
	// Read at this moment rather than copied onto the finding, so a place that
	// newly pulls a library in tomorrow picks the product's rating up without
	// anything having to remember to go and fetch it.
	if run.ratings, err = ratingsInForce(ctx, tx, productID, vulnerabilities); err != nil {
		return nil, err
	}

	// This build's reach to customers, read once. A critical in something
	// only the build system runs matters less than a medium in what people
	// install, and that is a property of the build rather than of any finding
	// in it.
	if run.shipped, err = shippedToCustomers(ctx, tx, targetID); err != nil {
		return nil, err
	}

	if run.present, err = openComponents(ctx, tx, targetID); err != nil {
		return nil, err
	}
	if run.places, err = openPlaces(ctx, tx, targetID); err != nil {
		return nil, err
	}
	// The build's own claims about what it ships. Applied here rather than
	// upstream of us, so a suppressed finding is something that can be seen
	// and accounted for instead of one that never arrived.
	//
	// What a document uploaded on its own says about the build's root is the
	// build's claim too, brought up to date first.
	if err := publishedForBuild(ctx, tx, productID, targetID); err != nil {
		return nil, err
	}
	if run.claims, err = openClaims(ctx, tx, targetID); err != nil {
		return nil, err
	}
	// What suppliers say about their own products, where it can close a
	// finding here (REQ-31): read once, and placed in this build's graph once
	// per product it names.
	issueIDs := make([]int64, 0, len(vulnerabilities))
	for _, id := range vulnerabilities {
		issueIDs = append(issueIDs, id)
	}
	// Where each product a claim or a statement names sits in this build,
	// worked out once per product.
	if run.placed, err = placing(ctx, tx, targetID, run.present, run.places); err != nil {
		return nil, err
	}
	if run.suppliers, err = disclaimers(ctx, tx, productID, issues, issueIDs, run.placed); err != nil {
		return nil, err
	}
	// Those that reached anything are worked out against what the target
	// contains, not against what was reported: a claim covering a component
	// nothing was found in has still done its job, while one covering nothing
	// the build ships has not.
	run.claimsReaching, run.claimsReachingNothing = claimsReaching(run.claims, run.present,
		run.places, run.placed)
	// The claims that fix what they cover, as against those that argue it
	// does not apply. The first close a finding and the second mark it.
	run.byName = indexClaims(run.claims)
	run.fixing = map[int64]bool{}
	for _, claim := range run.claims {
		if claim.fixes() {
			run.fixing[claim.ID] = true
		}
	}

	// The two halves of a deadline: how long each kind of thing may stay
	// open, and when this run started. Read once for the whole apply rather
	// than per finding, and read here rather than by the caller so that what
	// is stored and what the screen later compares against come from the same
	// place.
	if run.windows, err = LoadWindows(ctx, tx); err != nil {
		return nil, err
	}
	if err := tx.NewSelect().
		TableExpr(`"scan_run" AS "r"`).
		ColumnExpr(`"r"."started_at"`).
		Where(`"r"."id" = ?`, runID).
		Scan(ctx, &run.startedAt); err != nil {
		return nil, fmt.Errorf("read when this run started: %w", err)
	}

	// The product's triage line. Below that line nothing carries a deadline:
	// a line says "this is not work" and a deadline says "this is work, and
	// it is late", and holding both means one of them is lying — within a
	// year the overdue figure would be thousands of things nobody ever
	// intended to look at.
	if run.floor, err = FloorFor(ctx, tx, productID); err != nil {
		return nil, err
	}

	// And whether this build is still supported. Past its end-of-life date
	// nothing on it carries a deadline: the overdue figure and the escalation
	// view would otherwise fill permanently with releases nobody will ever
	// fix, and both stop being read. It is the same statement the triage line
	// makes from another direction — "this is not work" — and it is applied
	// the same way.
	//
	// Nothing is hidden or deleted by it. The findings are still recorded,
	// still counted and still reportable; what ends is what is expected of
	// us.
	supported, err := catalog.NewStore(tx).EndOfLifeForTarget(ctx, targetID)
	if err != nil {
		return nil, err
	}
	// And whether the release can change at all. A tag was built once and is
	// what somebody received, so a deadline on it is unmeetable by
	// construction — no work will land there whatever the date says.
	//
	// It takes precedence over end-of-life because it is the more fundamental
	// statement: a supported tag is as unfixable as a retired one. Real
	// deployments accumulate tags while branches do not, so a deadline on
	// every one of them inflates every overdue figure with work nobody could
	// ever have done.
	moves, err := catalog.NewStore(tx).TargetMoves(ctx, targetID)
	if err != nil {
		return nil, err
	}
	run.onTheClock = moves && !supported.Past(s.now().UTC())
	return run, nil
}

// wantedSet is every finding a report places in the build, and how each of
// them stands.
type wantedSet struct {
	findings map[key]Finding
	// patched is those a patch the build declares has fixed. They are wanted,
	// because the scanner still matches the component, and they close rather
	// than open.
	patched map[key]bool
	// cleared is those the issue's CVE record states are unaffected, by the
	// lines that say so. Wanted for the same reason, and closing for a
	// different one: the release never held the issue.
	cleared map[key]string
	// disclaimed is those a supplier's statement answers on every route up
	// the tree, by the statement. Wanted, and closing: the supplier says the
	// product they sit in is not affected.
	disclaimed map[key]int64
	// windowFor is the time each of them has, where it is on the clock at
	// all. Carried beside the finding rather than on it: a deadline is worked
	// out from the finding's own opening, and one already open opened before
	// this run — so the window has to reach the comparison with what is held,
	// where that is known. Absent means nothing on this build carries a
	// deadline.
	windowFor map[key]time.Duration
	// unplaced is how many reports named something the build does not hold.
	unplaced int
}

// wanted places each reported issue at every place its component sits.
func (run *applyRun) wanted(reported []Reported) (wantedSet, error) {
	w := wantedSet{
		findings: map[key]Finding{}, patched: map[key]bool{}, cleared: map[key]string{},
		disclaimed: map[key]int64{}, windowFor: map[key]time.Duration{},
	}
	for _, r := range reported {
		component, held := run.present.byIdentity[r.Component.Identity()]
		if !held {
			// Reported against something this variant does not contain. It
			// has no place, so it cannot become a finding at one, and silently
			// dropping it would hide a report that does not match the
			// inventory it was produced from.
			w.unplaced++
			continue
		}
		vulnerabilityID, known := run.vulnerabilities[normalize(r.Issue.Identifier)]
		if !known {
			return wantedSet{}, fmt.Errorf("issue %q was not recorded", r.Issue.Identifier)
		}
		naming := run.byName.naming(run.claims, r.Issue)

		for _, consumerID := range run.places.of(component.ID) {
			k := key{vulnerabilityID, place{componentID: component.ID, consumerID: consumerID}}
			// Asked per place: a claim about a component inside one of the
			// build's products reaches only the places beneath it.
			covering, claimedBy := coveringClaim(naming, component, consumerID, run.placed)
			// Set on every report rather than only when true, because a later
			// report at the same key replaces the finding below and the claim
			// it names with it.
			w.patched[k] = covering != nil && run.fixing[*covering]
			// A patch the build declares is asked first. Both close the
			// finding, and the build's word about its own code is the one
			// already on record.
			w.cleared[k] = ""
			if !w.patched[k] {
				w.cleared[k] = r.Unaffected
			}
			// A supplier's statement is asked last. A patch and a record both
			// say the code is not vulnerable here, which is the stronger of the
			// answers.
			delete(w.disclaimed, k)
			var answeredBy *int64
			if !w.patched[k] && w.cleared[k] == "" {
				statement, how := run.suppliers.answering(r.Issue, vulnerabilityID, component, consumerID)
				switch how {
				case answersAll:
					w.disclaimed[k] = *statement
				case answersSome:
					answeredBy = statement
				}
			}
			entry := Finding{
				TargetID: run.targetID, Kind: Vulnerable,
				// A scanner's finding in a shipped component is public
				// knowledge by the time it reaches us: the advisory it matched
				// is published. What is not disclosed is a finding somebody
				// entered here.
				Visibility:      access.Public,
				VulnerabilityID: vulnerabilityID,
				ComponentID:     component.ID,
				ConsumerID:      optional(consumerID),
				PlaceIdentity:   PlaceIdentity(component.Name, run.present.nameOf(consumerID)),
				FixState:        r.FixState, FixedIn: r.FixedIn, FixedAt: r.FixedAt,
				Matched: r.Matched, MatchedFrom: r.MatchedFrom,
				MatchedIn: r.MatchedIn, MatchedRange: r.MatchedRange,
				SuppressedBy: covering,
				StatedBy:     answeredBy,
				ClaimedBy:    claimedBy,
				OpenedAt:     run.startedAt,
				OpenedRunID:  &run.runID,
			}
			rated := run.ratings[vulnerabilityID]
			ranked := Ranked{
				ExploitedHere: rated.ExploitedHere,
				Exploited:     rated.Exploited, Shipped: run.shipped,
				LikelihoodPPM: rated.LikelihoodPPM,
				ScoreCenti:    rated.Score(),
			}
			entry.Urgency = int64(ranked.Rank())
			entry.RankExploited, entry.RankShipped = ranked.Exploited, ranked.Shipped
			entry.RankExploitedHere = ranked.ExploitedHere
			// A finding that opens already exploited was learned about when it
			// opened, and every later recount has to reach the same answer.
			entry.ExploitedLearnedAt = learnedExploitation(entry, rated.ExploitedOn, run.startedAt)
			severity := rated.Severity()
			// The line admits either exploitation signal; the window reads
			// only the world's. How long a fix may take is a question about
			// upstream, and this product having been attacked says nothing
			// about that — what it says is that the finding is not one to put
			// below the line.
			// A place a supplier answers on some routes is not work, so it
			// carries no deadline: every count of what is late then agrees
			// about it without each having to ask.
			if run.onTheClock && answeredBy == nil &&
				run.floor.Admits(rated.Exploited || rated.ExploitedHere, severity) {
				window := run.windows.For(rated.Exploited, severity)
				w.windowFor[k] = window
				// From this run, which for a new finding is when it was first
				// seen. One already open is answered against what is held,
				// from its own opening.
				entry.DueAt = Deadline(entry.FixState,
					rated.Exploited || rated.ExploitedHere, run.startedAt, run.startedAt,
					entry.ExploitedLearnedAt, entry.FixedAt, window)
			}
			w.findings[k] = entry
		}
	}
	return w, nil
}

// heldOpen reads what is already open that a scan governs, by component and
// by place name.
//
// A run is the authority on what it found, and everything it no longer
// reports is closed — so without narrowing to what a scan opened, the first
// nightly scan after somebody records a finding by hand closes it, with a
// reason that reads like the issue went away. Nothing would report that: the
// row looks exactly like a component that stopped shipping.
//
// Only the columns the difference reads. A large image holds hundreds of
// thousands of open rows, and every one of them is read here.
//
// The second index is by place *name* rather than by component. A version
// change makes a different component and therefore a different key, so the
// two indexes disagree exactly where a version moved — which is the case worth
// telling apart from every other kind of closure.
func heldOpen(ctx context.Context, tx bun.IDB, targetID int64) (map[key]heldFinding,
	map[at]heldFinding, error) {

	var open []heldFinding
	if err := tx.NewSelect().Model(&open).
		Where(`"target_id" = ?`, targetID).
		Where(`"kind" = ?`, Vulnerable).
		Where(`"closed_at" IS NULL`).Scan(ctx); err != nil {
		return nil, nil, fmt.Errorf("read what is already open: %w", err)
	}
	held := make(map[key]heldFinding, len(open))
	heldAt := make(map[at]heldFinding, len(open))
	for _, f := range open {
		held[key{f.VulnerabilityID, place{f.ComponentID, value(f.ConsumerID)}}] = f
		heldAt[at{f.VulnerabilityID, f.PlaceIdentity}] = f
	}
	return held, heldAt, nil
}

// applyPlan is the difference between what a report wants and what is held:
// every write applying it makes, not yet made.
type applyPlan struct {
	opening []Finding
	// movedFrom is, where a version moved under an opening finding, the
	// component it moved from, by its position in opening, so the version can
	// be named rather than merely known to have changed.
	movedFrom map[int]int64
	// updates is the open findings that moved, grouped by exactly what each
	// update writes, so a group is one statement over its identifiers.
	updates map[changeKey]*moving
	// patching is the open findings a patch now fixes, by the claim that fixes
	// them; clearing is those the issue's record states unaffected, by the
	// lines that say so; disclaiming is those a supplier's statement answers
	// on every route, by the statement.
	patching    map[int64][]int64
	clearing    map[string][]int64
	disclaiming map[int64][]int64
	// The same three first seen closed, whose record is read before they are
	// written.
	arrivedPatched, arrivedCleared, arrivedDisclaimed []key
	// departing is the open findings no longer wanted for any of those
	// reasons, whose explanation is read from what departed.
	departing []departure
	// updated and suppressed count the open findings that moved, and the
	// wanted findings the build argues do not apply.
	updated, suppressed int
}

// departure is an open finding closing because it is no longer reported.
type departure struct {
	f heldFinding
	// superseded says the same issue is still wanted at the same place: the
	// row is being superseded by one against a new version rather than
	// resolved.
	superseded bool
}

// diffOpen works out what applying a report writes, from what it wants and
// what is held. It reads nothing and writes nothing.
func diffOpen(run *applyRun, want wantedSet, held map[key]heldFinding,
	heldAt map[at]heldFinding) applyPlan {

	plan := applyPlan{
		movedFrom: map[int]int64{}, updates: map[changeKey]*moving{},
		patching: map[int64][]int64{}, clearing: map[string][]int64{},
		disclaiming: map[int64][]int64{},
	}
	for k, f := range want.findings {
		if want.patched[k] {
			if already, open := held[k]; open {
				plan.patching[*f.SuppressedBy] = append(plan.patching[*f.SuppressedBy], already.ID)
			} else {
				plan.arrivedPatched = append(plan.arrivedPatched, k)
			}
			continue
		}
		if lines := want.cleared[k]; lines != "" {
			if already, open := held[k]; open {
				plan.clearing[lines] = append(plan.clearing[lines], already.ID)
			} else {
				plan.arrivedCleared = append(plan.arrivedCleared, k)
			}
			continue
		}
		if statement, answered := want.disclaimed[k]; answered {
			if already, open := held[k]; open {
				plan.disclaiming[statement] = append(plan.disclaiming[statement], already.ID)
			} else {
				plan.arrivedDisclaimed = append(plan.arrivedDisclaimed, k)
			}
			continue
		}
		if f.SuppressedBy != nil {
			plan.suppressed++
		}
		already, open := held[k]
		if !open {
			// The same issue at the same place a moment ago, on a different
			// component, means the version moved and the issue came with it.
			// Recorded on the way in, because this is the only point where
			// both versions are in hand.
			if was, moved := heldAt[at{f.VulnerabilityID, f.PlaceIdentity}]; moved &&
				was.ComponentID != f.ComponentID {
				plan.movedFrom[len(plan.opening)] = was.ComponentID
			}
			plan.opening = append(plan.opening, f)
			continue
		}
		// A finding that is already open still moves. A fix appears, or the
		// build answers it — and somebody waiting for a fix is waiting for
		// exactly that. Leaving the row as first written would report last
		// month's answer indefinitely. The same goes for how urgent it is:
		// what is known about an issue changes under a finding that has not.
		moved, exploitationMoved := ranking(already, f)
		// From its own opening rather than from this run, and from what the
		// row already knows about when exploitation was learned — a recount
		// that re-learned it nightly would move the deadline forward every
		// night and never arrive.
		learned := already.ExploitedLearnedAt
		if exploitationMoved {
			learned = learnedExploitation(f, run.ratings[f.VulnerabilityID].ExploitedOn, run.startedAt)
		}
		if window, onClock := want.windowFor[k]; onClock {
			f.DueAt = Deadline(f.FixState, f.RankExploited || f.RankExploitedHere,
				already.OpenedAt, run.startedAt, learned, f.FixedAt, window)
		}
		// Asked of the answer rather than of what moved. A fix appearing
		// upstream starts a clock that was not running, and one being
		// withdrawn stops it — and a row written under an earlier rule
		// carries an answer nothing else corrects.
		clockMoved := !sameDate(already.DueAt, f.DueAt)
		described := !same(already, f)
		if !described && !moved && !clockMoved {
			continue
		}
		change := moving{f: f, described: described, moved: moved,
			exploitationMoved: exploitationMoved, learned: learned, clockMoved: clockMoved}
		group, grouped := plan.updates[change.key()]
		if !grouped {
			group = &change
			plan.updates[change.key()] = group
		}
		group.add(already.ID, f.Urgency)
		plan.updated++
	}

	// With the same issue still wanted at the same place, a row closing is
	// being superseded by one against a new version rather than resolved.
	wantedAt := map[at]bool{}
	// And where what is wanted at that place is patched, the row closes as
	// patched: the version moved and the issue did not come with it.
	patchedAt := map[at]int64{}
	// And where a supplier's statement answers what is wanted at that place on
	// every route, the row closes as disclaimed: the version moved and the
	// supplier says the new one is not affected.
	disclaimedAt := map[at]int64{}
	for k, f := range want.findings {
		// A release the record states is unaffected is not one the issue came
		// with: the row before it closes for what moved, which is the version
		// reaching past the issue.
		if want.cleared[k] != "" {
			continue
		}
		if statement, answered := want.disclaimed[k]; answered {
			disclaimedAt[at{f.VulnerabilityID, f.PlaceIdentity}] = statement
			continue
		}
		wantedAt[at{f.VulnerabilityID, f.PlaceIdentity}] = true
		if want.patched[k] {
			patchedAt[at{f.VulnerabilityID, f.PlaceIdentity}] = *f.SuppressedBy
		}
	}
	for k, f := range held {
		if _, still := want.findings[k]; still {
			continue
		}
		where := at{f.VulnerabilityID, f.PlaceIdentity}
		if claimID, ok := patchedAt[where]; ok {
			plan.patching[claimID] = append(plan.patching[claimID], f.ID)
			continue
		}
		if statement, ok := disclaimedAt[where]; ok {
			plan.disclaiming[statement] = append(plan.disclaiming[statement], f.ID)
			continue
		}
		plan.departing = append(plan.departing, departure{f: f, superseded: wantedAt[where]})
	}
	return plan
}

// applyWritten is what writing a plan did, counted from the rows each
// statement matched.
type applyWritten struct {
	opened, closed, unexplained, patched, unaffected, disclaimed int
}

// writePlan makes the writes a plan holds, reading only what the writes
// themselves need.
func writePlan(ctx context.Context, tx bun.IDB, run *applyRun, want wantedSet,
	plan applyPlan) (applyWritten, error) {

	var wrote applyWritten
	for _, group := range plan.updates {
		for first := 0; first < len(group.ids); first += database.BatchSize {
			last := min(first+database.BatchSize, len(group.ids))
			if _, err := group.update(tx, first, last).Exec(ctx); err != nil {
				return wrote, fmt.Errorf("update %d findings that moved: %w", len(group.ids), err)
			}
		}
	}

	opening := plan.opening
	// The subject each moved-from finding was about.
	movedIDs := make([]int64, 0, len(plan.movedFrom))
	for _, componentID := range plan.movedFrom {
		movedIDs = append(movedIDs, componentID)
	}
	before, err := componentsByID(ctx, tx, run.targetID, movedIDs)
	if err != nil {
		return wrote, err
	}
	for i, componentID := range plan.movedFrom {
		opening[i].ArrivedFrom = upstreamOf(before[componentID])
	}
	// What closed before at each place something opens or arrives closed: the
	// latest row per component and consumer, which says whether that closure
	// is already recorded there, and the latest per place name, which says
	// what version the place held when a patch closed it.
	var reading []int64
	for _, f := range opening {
		reading = append(reading, f.VulnerabilityID)
	}
	for _, keys := range [][]key{plan.arrivedPatched, plan.arrivedCleared, plan.arrivedDisclaimed} {
		for _, k := range keys {
			reading = append(reading, k.vulnerabilityID)
		}
	}
	latest, latestAt, err := latestClosed(ctx, tx, run.targetID, reading)
	if err != nil {
		return wrote, err
	}
	// A place whose patch was dropped as its version moved. The patched row is
	// closed, so the open index never sees it, and the version the place held
	// is what the new finding arrived from.
	patchedBefore := map[int]int64{}
	for i, f := range opening {
		if was, ok := latestAt[at{f.VulnerabilityID, f.PlaceIdentity}]; ok &&
			f.ArrivedFrom == "" && was.ClosedBecause == Patched && was.ComponentID != f.ComponentID {
			patchedBefore[i] = was.ComponentID
		}
	}
	carriedIDs := make([]int64, 0, len(patchedBefore))
	for i := range opening {
		if componentID, ok := patchedBefore[i]; ok {
			carriedIDs = append(carriedIDs, componentID)
		}
	}
	carried, err := componentsByID(ctx, tx, run.targetID, carriedIDs)
	if err != nil {
		return wrote, err
	}
	for i, componentID := range patchedBefore {
		opening[i].ArrivedFrom = upstreamOf(carried[componentID])
	}
	if len(opening) > 0 {
		if err := database.InBatches(ctx, tx, opening); err != nil {
			return wrote, fmt.Errorf("open %d findings: %w", len(opening), err)
		}
		wrote.opened = len(opening)
	}

	// A finding first seen already patched is recorded, closed, so the patch
	// is accounted for: in a release comparison against a build that lacked
	// it, and in the document saying this build is fixed. Recorded once. Where
	// the latest row at that place already says patched, a re-scan writes
	// nothing but the claim it now stands on.
	recorded, err := recordArrived(ctx, tx, plan.arrivedPatched, want.findings, latest, arrivedAs[int64]{
		reason: Patched,
		by:     func(k key) int64 { return *want.findings[k].SuppressedBy },
		set:    func(*Finding, int64) {},
		same:   func(was Finding, claimID int64) bool { return equalRef(was.SuppressedBy, &claimID) },
		repoint: func(q *bun.UpdateQuery, claimID int64) *bun.UpdateQuery {
			return q.Set(`"suppressed_by" = ?`, claimID).Set(`"claimed_by" = ?`, claimID)
		},
		recording:  "record %d patched findings",
		repointing: "point %d patched findings at their claim",
	}, run.startedAt, run.runID)
	if err != nil {
		return wrote, err
	}
	wrote.patched += recorded
	// A finding first seen with its record stating it unaffected is recorded,
	// closed, for the same reason: a release comparison against a build that
	// held the issue says this one never did. Recorded once, and where the
	// record's lines move, the row is pointed at the new ones.
	recorded, err = recordArrived(ctx, tx, plan.arrivedCleared, want.findings, latest, arrivedAs[string]{
		reason: Unaffected,
		by:     func(k key) string { return want.cleared[k] },
		set:    func(f *Finding, lines string) { f.UnaffectedBy = lines },
		same:   func(was Finding, lines string) bool { return was.UnaffectedBy == lines },
		repoint: func(q *bun.UpdateQuery, lines string) *bun.UpdateQuery {
			return q.Set(`"unaffected_by" = ?`, lines)
		},
		recording:  "record %d findings their records state are unaffected",
		repointing: "point %d unaffected findings at their record's lines",
	}, run.startedAt, run.runID)
	if err != nil {
		return wrote, err
	}
	wrote.unaffected += recorded
	// A finding first seen with a supplier's statement answering it on every
	// route is recorded, closed, for the same reason: a release comparison and
	// the register have the statement to read. Recorded once, and where the
	// statement is revised, the row is pointed at the new one.
	recorded, err = recordArrived(ctx, tx, plan.arrivedDisclaimed, want.findings, latest, arrivedAs[int64]{
		reason: Disclaimed,
		by:     func(k key) int64 { return want.disclaimed[k] },
		set:    func(f *Finding, statement int64) { f.StatedBy = &statement },
		same: func(was Finding, statement int64) bool {
			return was.StatedBy != nil && *was.StatedBy == statement
		},
		repoint: func(q *bun.UpdateQuery, statement int64) *bun.UpdateQuery {
			return q.Set(`"stated_by" = ?`, statement)
		},
		recording:  "record %d findings their suppliers state are not affected",
		repointing: "point %d disclaimed findings at their statement",
	}, run.startedAt, run.runID)
	if err != nil {
		return wrote, err
	}
	wrote.disclaimed += recorded

	// A departing finding's subject is read from the component catalog rather
	// than from what the variant currently contains — the whole reason it is
	// closing is usually that it is no longer there.
	gone := make([]int64, 0, len(plan.departing))
	for _, d := range plan.departing {
		gone = append(gone, d.f.ComponentID)
	}
	departed, err := componentsByID(ctx, tx, run.targetID, gone)
	if err != nil {
		return wrote, err
	}
	// Grouped by the explanation *and* the version it moved to, because two
	// findings closing for the same reason rarely moved to the same version —
	// one write per group rather than one per finding, which at a kernel's
	// fan-out is the difference that matters.
	type closure struct {
		Reason  Closure
		MovedTo string
	}
	byReason := map[closure][]int64{}
	for _, d := range plan.departing {
		reason, movedTo := run.present.why(departed[d.f.ComponentID])
		// Asked before anything else, because every other explanation is
		// about a finding that went away and this one did not. Recording it as
		// an upgrade would say a bump fixed something it did not, in a report
		// that goes to customers.
		if d.superseded {
			reason, movedTo = Superseded, ""
		}
		key := closure{reason, movedTo}
		byReason[key] = append(byReason[key], d.f.ID)
	}
	// A supplier's answer on some routes goes with the place, wherever a row
	// closes for anything but a supplier's statement.
	for key, ids := range byReason {
		n, err := closeIDs(ctx, tx, ids, run.startedAt, run.runID, key.Reason,
			func(q *bun.UpdateQuery) *bun.UpdateQuery {
				return q.Set(`"stated_by" = NULL`).Set(`"moved_to" = ?`, key.MovedTo)
			})
		if err != nil {
			return wrote, fmt.Errorf("close %d findings: %w", len(ids), err)
		}
		wrote.closed += n
		if key.Reason == Unexplained {
			wrote.unexplained += n
		}
	}
	for lines, ids := range plan.clearing {
		n, err := closeIDs(ctx, tx, ids, run.startedAt, run.runID, Unaffected,
			func(q *bun.UpdateQuery) *bun.UpdateQuery {
				return q.Set(`"stated_by" = NULL`).Set(`"moved_to" = ?`, "").Set(`"unaffected_by" = ?`, lines)
			})
		if err != nil {
			return wrote, fmt.Errorf("close %d findings their records state are unaffected: %w", len(ids), err)
		}
		wrote.closed += n
		wrote.unaffected += n
	}
	for statement, ids := range plan.disclaiming {
		n, err := closeIDs(ctx, tx, ids, run.startedAt, run.runID, Disclaimed,
			func(q *bun.UpdateQuery) *bun.UpdateQuery {
				return q.Set(`"moved_to" = ?`, "").Set(`"stated_by" = ?`, statement)
			})
		if err != nil {
			return wrote, fmt.Errorf("close %d findings their suppliers state are not affected: %w", len(ids), err)
		}
		wrote.closed += n
		wrote.disclaimed += n
	}
	for claimID, ids := range plan.patching {
		n, err := closeIDs(ctx, tx, ids, run.startedAt, run.runID, Patched,
			func(q *bun.UpdateQuery) *bun.UpdateQuery {
				return q.Set(`"stated_by" = NULL`).Set(`"moved_to" = ?`, "").
					Set(`"suppressed_by" = ?`, claimID).Set(`"claimed_by" = ?`, claimID)
			})
		if err != nil {
			return wrote, fmt.Errorf("close %d patched findings: %w", len(ids), err)
		}
		wrote.closed += n
		wrote.patched += n
	}
	return wrote, nil
}

// arrivedAs is how a finding first seen closed for one reason is recorded,
// and how a row already recorded closed for it is pointed at what closes it
// now. By is what closes it: the claim that patches it, the record's lines,
// or the supplier's statement.
type arrivedAs[By comparable] struct {
	reason Closure
	// by is what closes the finding wanted at k.
	by func(k key) By
	// set writes it onto a row being recorded.
	set func(f *Finding, by By)
	// same reports whether a row already recorded closed for this reason
	// names it.
	same func(was Finding, by By) bool
	// repoint writes it onto rows already recorded.
	repoint func(q *bun.UpdateQuery, by By) *bun.UpdateQuery
	// recording and repointing name the two writes in an error, each with
	// the number of rows.
	recording, repointing string
}

// recordArrived records, closed, each finding first seen closed for one
// reason, and answers how many it recorded.
//
// Recorded once. Where the latest row at that place already closed for the
// reason, nothing is recorded, and the row is pointed at what closes it now
// where that moved. Never open, so never due.
func recordArrived[By comparable](ctx context.Context, tx bun.IDB, keys []key,
	wanted, latest map[key]Finding, as arrivedAs[By], startedAt time.Time, runID int64) (int, error) {

	var recording []Finding
	repointing := map[By][]int64{}
	for _, k := range keys {
		f := wanted[k]
		by := as.by(k)
		if was, recorded := latest[k]; recorded && was.ClosedBecause == as.reason {
			if !as.same(was, by) {
				repointing[by] = append(repointing[by], was.ID)
			}
			continue
		}
		f.ClosedAt = &startedAt
		f.ClosedRunID = &runID
		f.ClosedBecause = as.reason
		as.set(&f, by)
		f.DueAt = nil
		recording = append(recording, f)
	}
	if len(recording) > 0 {
		if err := database.InBatches(ctx, tx, recording); err != nil {
			return 0, fmt.Errorf(as.recording+": %w", len(recording), err)
		}
	}
	for by, ids := range repointing {
		err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
			_, err := as.repoint(tx.NewUpdate().Model((*Finding)(nil)), by).
				Where(`"id" IN (?)`, bun.List(batch)).Exec(ctx)
			return err
		})
		if err != nil {
			return 0, fmt.Errorf(as.repointing+": %w", len(ids), err)
		}
	}
	return len(recording), nil
}

// closeIDs closes open findings for one reason, writing what rest adds beside
// it.
//
// Dated at the run's own moment, which is what the opening side dates a
// finding by: a finding's life is measured against the runs that observed it,
// not against when the write happened to land. The run stays beside it as
// provenance, and is what "what did this run change" is counted by.
//
// It answers how many rows the statements matched. Every identifier is a row
// read open in the same transaction, and a finding is never deleted, so that
// is every identifier given.
func closeIDs(ctx context.Context, tx bun.IDB, ids []int64, startedAt time.Time, runID int64,
	reason Closure, rest func(*bun.UpdateQuery) *bun.UpdateQuery) (int, error) {

	matched := 0
	err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		res, err := rest(tx.NewUpdate().Model((*Finding)(nil)).
			Set(`"closed_at" = ?`, startedAt).
			Set(`"closed_run_id" = ?`, runID).
			Set(`"closed_because" = ?`, reason)).
			Where(`"id" IN (?)`, bun.List(batch)).Exec(ctx)
		if err != nil {
			return err
		}
		n, err := database.Affected(res)
		matched += int(n)
		return err
	})
	return matched, err
}

// latestClosed reads the most recent closed row of these issues, at each
// component and consumer and at each place name.
func latestClosed(ctx context.Context, db bun.IDB, targetID int64,
	vulnerabilities []int64) (map[key]Finding, map[at]Finding, error) {

	byKey, byAt := map[key]Finding{}, map[at]Finding{}
	if len(vulnerabilities) == 0 {
		return byKey, byAt, nil
	}
	seen := map[int64]bool{}
	var issues []int64
	for _, id := range vulnerabilities {
		if !seen[id] {
			seen[id] = true
			issues = append(issues, id)
		}
	}
	err := database.IDsInBatches(ctx, issues, func(ctx context.Context, batch []int64) error {
		// The latest row of each grouping, by identifier, rather than every
		// closed row ever recorded: a place whose version moves gathers a
		// closed row at every move.
		latest := func(grouping string) *bun.SelectQuery {
			return db.NewSelect().
				TableExpr(`"finding" AS "lf"`).
				ColumnExpr(`MAX("lf"."id")`).
				Where(`"lf"."target_id" = ?`, targetID).
				Where(`"lf"."kind" = ?`, Vulnerable).
				Where(`"lf"."closed_at" IS NOT NULL`).
				Where(`"lf"."vulnerability_id" IN (?)`, bun.List(batch)).
				GroupExpr(grouping)
		}
		var rows []Finding
		err := db.NewSelect().Model(&rows).
			Column("id", "vulnerability_id", "component_id", "consumer_id",
				"place_identity", "closed_because", "suppressed_by", "unaffected_by", "stated_by").
			// The range again outside the two arms: a membership test under OR
			// is never a semi-join on PostgreSQL or MySQL, so without it the
			// read walks every finding in the deployment.
			Where(`"target_id" = ?`, targetID).
			Where(`"kind" = ?`, Vulnerable).
			Where(`"closed_at" IS NOT NULL`).
			Where(`"vulnerability_id" IN (?)`, bun.List(batch)).
			WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
				return q.
					WhereOr(`"id" IN (?)`, latest(`"lf"."vulnerability_id", "lf"."component_id", "lf"."consumer_id"`)).
					WhereOr(`"id" IN (?)`, latest(`"lf"."vulnerability_id", "lf"."place_identity"`))
			}).
			// Ascending, so the last row read at a place is its latest.
			OrderExpr(`"id" ASC`).
			Scan(ctx)
		if err != nil {
			return err
		}
		for _, row := range rows {
			byKey[key{row.VulnerabilityID, place{row.ComponentID, value(row.ConsumerID)}}] = row
			byAt[at{row.VulnerabilityID, row.PlaceIdentity}] = row
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("read what these places last closed as: %w", err)
	}
	return byKey, byAt, nil
}

// same reports whether what a scan found about a finding matches what is
// already recorded. Only what the fix half of the update writes is compared;
// how urgent it is has its own comparison, because the two write different
// columns and a deadline moves on a narrower condition than a rank does.
//
// Everything else is what makes it that finding rather than another, and
// comparing something no update writes would count the finding as changed
// every night and write it with nothing having moved.
func same(held heldFinding, found Finding) bool {
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
		equalRef(held.SuppressedBy, found.SuppressedBy) &&
		equalRef(held.StatedBy, found.StatedBy) &&
		equalRef(held.ClaimedBy, found.ClaimedBy)
}

// learnedExploitation is the moment to record beside a clock that just moved,
// or nothing where the row is no longer exploited.
//
// The day the known-exploited catalog listed the issue, or the run's start
// where that is earlier or no day is known. The run's start rather than the
// wall clock, because that is what the deadline beside it was counted from and
// the two have to agree. A finding first seen after the listing still counts
// from when it was seen, which Deadline answers by counting from the later of
// this and the opening.
func learnedExploitation(f Finding, listedOn *time.Time, startedAt time.Time) *time.Time {
	if !f.RankExploited {
		return nil
	}
	return exploitationKnown(listedOn, startedAt)
}

// exploitationKnown is when exploitation counts from: the day the catalog
// listed the issue, or the moment it was learned here where that is earlier or
// no day is known.
func exploitationKnown(listedOn *time.Time, learnedAt time.Time) *time.Time {
	if listedOn != nil && listedOn.Before(learnedAt) {
		at := listedOn.UTC()
		return &at
	}
	return &learnedAt
}

// ranking reports whether an open finding's place in the order has moved, and
// whether exploitation is what moved it.
//
// The two are separate, and deliberately: every ranking signal moves the
// order, and exploitation is the only one that starts a clock over. A score
// somebody revised upward is worth reordering the list for and is not worth
// resetting a deadline over — likelihood and score are not in the deadline at
// all, and a deadline recounted whenever a number was revised would never
// arrive, which is the same failure as recounting it nightly.
//
// It does not answer whether the deadline moved. That is asked of the deadline
// itself, because a fix appearing upstream moves it and touches no ranking
// signal at all.
func ranking(held heldFinding, found Finding) (moved, exploitationMoved bool) {
	moved = held.Urgency != found.Urgency ||
		held.RankExploited != found.RankExploited ||
		held.RankShipped != found.RankShipped
	exploitationMoved = held.RankExploited != found.RankExploited
	return moved, exploitationMoved
}

// ratingRow is one issue as ratingsInForce reads it.
type ratingRow struct {
	ID            int64      `bun:"id"`
	Published     string     `bun:"published"`
	Assessed      string     `bun:"assessed"`
	Exploited     bool       `bun:"exploited"`
	ExploitedHere int        `bun:"exploited_here"`
	ScoreCenti    int        `bun:"score_centi"`
	LikelihoodPPM int        `bun:"likelihood_ppm"`
	ExploitedOn   *time.Time `bun:"exploited_on"`
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
	var rows []ratingRow
	err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		var found []ratingRow
		err := tx.NewSelect().
			TableExpr(`"vulnerability" AS "v"`).
			Join(rating.Here, productID).
			// Whether this product has been recorded as attacked through the
			// issue. A left join on the standing record rather than a column
			// on the issue, because the record belongs to one product and the
			// issue is shared by all of them.
			Join(standingExploitationHere, productID).
			ColumnExpr(`"v"."id" AS "id"`).
			ColumnExpr(`COALESCE("v"."severity", ?) AS "published"`, "").
			ColumnExpr(`COALESCE("ir"."severity", ?) AS "assessed"`, "").
			ColumnExpr(`"v"."exploited" AS "exploited"`).
			ColumnExpr(`CASE WHEN "eh"."id" IS NULL THEN 0 ELSE 1 END AS "exploited_here"`).
			ColumnExpr(`COALESCE("v"."score_centi", 0) AS "score_centi"`).
			ColumnExpr(`COALESCE("v"."likelihood_ppm", 0) AS "likelihood_ppm"`).
			ColumnExpr(`"v"."exploited_on" AS "exploited_on"`).
			Where(`"v"."id" IN (?)`, bun.List(batch)).
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
			Exploited: row.Exploited, ExploitedHere: row.ExploitedHere == 1,
			ScoreCenti:    row.ScoreCenti,
			LikelihoodPPM: row.LikelihoodPPM,
			ExploitedOn:   row.ExploitedOn,
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
		Join(`JOIN "variant" AS "v" ON "v"."id" = "t"."variant_id"`).
		Column("v.customer_facing").
		Where(`"t"."id" = ?`, targetID).
		Scan(ctx, &shipped)
	if err != nil {
		return false, fmt.Errorf("read whether this build reaches customers: %w", err)
	}
	return shipped, nil
}
