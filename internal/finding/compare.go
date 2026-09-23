// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// Changed is one issue that differs between two builds.
type Changed struct {
	Vulnerability string `bun:"vulnerability"`
	Component     string `bun:"component"`
	Severity      string `bun:"severity"`
	// Because says why it went, for something that is no longer there. The
	// four explanations are different sentences to whoever reads a release
	// note: upgraded, patched, the component removed, and superseded — which
	// is a bump that did not reach the fix and is not a fix at all.
	Because Closure `bun:"because"`
	// ArrivedFrom is the version this place held before, where the version
	// moved and the issue came with it. Set on still-present entries,
	// which is where it says something a reader cannot get any other way:
	// this was bumped, and the bump fell short.
	ArrivedFrom string `bun:"arrived_from"`
	// FromVersion and MovedTo are what a fix moved between, on a fixed entry
	// and nowhere else. Without them a release note says a component was
	// upgraded and never says to what, which is the one thing whoever reads it
	// is trying to find out.
	FromVersion string `bun:"from_version"`
	MovedTo     string `bun:"moved_to"`
	// ClosedRun is the run that stopped reporting it, on an entry that left
	// the affected list. An unexplained closure is a scanner fault to
	// investigate rather than a fix, and the first question about one is which
	// run it was — without that the reader is told something is wrong and
	// given nowhere to look. Zero where a person closed it, which is the other
	// way a finding closes.
	ClosedRun int64 `bun:"closed_run"`
	// ScoreCenti is what a reader of a release note acts on, beyond the
	// identifier and the word: the number, whether somebody is known to be
	// exploiting it, and where it is written up.
	//
	// Not the description. One upgrade closes hundreds of issues and the
	// note lists them under it, so a sentence apiece is a document nobody
	// reads to the end — and the description is behind the link, which is
	// what the link is for.
	ScoreCenti int    `bun:"score_centi"`
	Exploited  bool   `bun:"exploited"`
	Advisory   string `bun:"advisory"`
	// State is what stands about it in the later build, on a still-present
	// entry and nowhere else. This is the sign-off half: shipping with
	// a known issue is a decision somebody made, and a list of what is
	// still there with no way to tell an approved not-applicable from
	// something nobody has looked at is not a list anybody can sign.
	//
	// The outcome and its reason are stated only where every standing
	// decision over the row's places says the same thing, which is the rule
	// the VEX document already publishes under: a row decided one way at one
	// place and another way at a second is not one claim, and stating either
	// over both would be a claim nobody made.
	State         string
	Outcome       string
	Justification string
	// Due is the soonest deadline among the places still open, which is the
	// date a coordinator is reading against. Absent where none of them
	// carries one.
	Due *time.Time
}

// Comparison is what changed between two builds.
//
// Two sets leave the affected list, not one. An upgrade, a carried
// patch, a component no longer shipped and a flaw declared fixed are fixes. A
// bump that carried the issue with it, a record taken back, and a closure
// nothing explains are not — the last of those means the scanner stopped
// reporting an unchanged component, which is a fault to investigate. Counted
// together, a release coordinator quotes a number of fixes that includes them.
type Comparison struct {
	Fixed []Changed
	// Closed left the affected list without being fixed.
	Closed []Changed
	Newly  []Changed
	Still  []Changed
}

// Compare reports what was fixed, what is newly present, and what is still
// there between two builds.
//
// Between any two, not only adjacent ones: the question a release note answers
// is usually about the last release a customer has, which is rarely the
// previous one.
//
// Each fixed entry says why it went. "Fixed by upgrading to 2.4" and
// "fixed by a carried patch" are different things to a reader, and a bump that
// did not reach the fix is not a fix — it appears as superseded rather than as
// something resolved.
func (s *Store) Compare(ctx context.Context, subject access.Subject, fromTarget, toTarget int64,
	includePrivate bool) (*Comparison, error) {

	// Both builds, not one. The first version authorized the later target and
	// applied that answer to the earlier one as well, so a caller who could
	// reach one product could read findings out of another through the
	// comparison — enforcement lives in the data layer precisely so the next
	// caller of this cannot open that.
	toProduct, visible, err := s.mayCompare(ctx, subject, toTarget)
	if err != nil {
		return nil, err
	}
	fromProduct, earlier, err := s.mayCompare(ctx, subject, fromTarget)
	if err != nil {
		return nil, err
	}
	// What may be read at both ends. Each visibility is its own grant, so
	// neither answer contains the other.
	var both []access.Visibility
	for _, v := range visible {
		if slices.Contains(earlier, v) {
			// Its destination is usually a public document, so including
			// something undisclosed is a deliberate act rather than something
			// somebody pastes in without noticing.
			if v == access.Private && !includePrivate {
				continue
			}
			both = append(both, v)
		}
	}
	// Disclosed work is what a release note is. Somebody reading only
	// undisclosed work at either end is refused rather than handed a note
	// reading "nothing fixed, nothing new", which looks complete.
	if !slices.Contains(both, access.Public) {
		return nil, access.Denied("read disclosed work in both builds")
	}
	visible = both

	at := func(productID, targetID int64) *bun.SelectQuery {
		q := s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
			Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
			// The rating this product holds where it has stated one. Read
			// from the published word alone, a release note contradicted the
			// findings list it was written from: a product that had re-rated
			// an issue said one thing on screen and another in the document
			// it publishes, which is the copy that leaves the building.
			Join(rating.Here, productID).
			ColumnExpr(`v.identifier AS "vulnerability"`).
			ColumnExpr(`c.name AS "component"`).
			ColumnExpr(rating.EffectiveExpr+` AS "severity"`).
			ColumnExpr(`COALESCE(f.closed_because, '') AS "because"`).
			ColumnExpr(`MIN(COALESCE(f.arrived_from, '')) AS "arrived_from"`).
			// Properties of the issue rather than of the place, so they are
			// grouped on rather than aggregated: every row of a group carries
			// the same three.
			ColumnExpr(`COALESCE(v.score_centi, 0) AS "score_centi"`).
			ColumnExpr(`v.exploited AS "exploited"`).
			ColumnExpr(`COALESCE(v.advisory, '') AS "advisory"`).
			Where("f.target_id = ?", targetID).
			Where("f.visibility IN (?)", bun.List(visible)).
			GroupExpr("v.identifier, c.name, " + rating.EffectiveExpr +
				", f.closed_because, v.score_centi, v.exploited, v.advisory")
		return q.Where("f.closed_at IS NULL")
	}

	var was, now []Changed
	if err := at(fromProduct, fromTarget).Scan(ctx, &was); err != nil {
		return nil, fmt.Errorf("read what the earlier build had: %w", err)
	}
	if err := at(toProduct, toTarget).Scan(ctx, &now); err != nil {
		return nil, fmt.Errorf("read what the later build has: %w", err)
	}

	key := func(c Changed) string { return pairKey(c.Vulnerability, c.Component) }
	here := map[string]Changed{}
	for _, c := range now {
		here[key(c)] = c
	}

	comparison := &Comparison{}
	for _, c := range was {
		if standing, still := here[key(c)]; still {
			// The later build's row, not the earlier one: what a reader wants
			// to know about something still present is whether somebody tried
			// to move it since, and that is recorded where it landed.
			c.ArrivedFrom = standing.ArrivedFrom
			comparison.Still = append(comparison.Still, c)
			continue
		}
		comparison.Fixed = append(comparison.Fixed, c)
	}

	// The reason each of them went, read from the rows that closed in the later
	// build — the earlier build's rows are still open in its own history.
	//
	// One read per batch rather than one per entry. A comparison against a
	// release a customer has been on for a year has as many fixed entries as
	// the release note is long, and asking about each separately made the
	// screen's cost a count of round trips.
	gone, err := s.whyGone(ctx, toTarget, comparison.Fixed)
	if err != nil {
		return nil, err
	}
	for i := range comparison.Fixed {
		went := gone[key(comparison.Fixed[i])]
		comparison.Fixed[i].Because = went.Because
		comparison.Fixed[i].ClosedRun = went.ClosedRun
		// Only where moving is what closed it. On a component that was removed
		// or a finding nothing explains, a pair of versions would be a
		// sentence about a bump that did not happen.
		if went.MovedTo != "" {
			comparison.Fixed[i].FromVersion = went.FromVersion
			comparison.Fixed[i].MovedTo = went.MovedTo
		}
	}
	// Split once the reasons are in hand, through the one function that
	// decides what counts as a fix. A screen making that judgment a second
	// time, in a column heading, disagrees with this one.
	comparison.Fixed, comparison.Closed = partition(comparison.Fixed)

	// Judgments standing over what is still there. Read only for the
	// still-present entries, because that is the list somebody signs a release
	// off against — what was fixed needs no justification and what is newly
	// present has not been looked at yet.
	if len(comparison.Still) > 0 {
		stands, err := s.whatStands(ctx, toProduct, toTarget, visible)
		if err != nil {
			return nil, err
		}
		for i := range comparison.Still {
			held := stands[key(comparison.Still[i])]
			comparison.Still[i].State = held.State
			comparison.Still[i].Outcome = held.Outcome
			comparison.Still[i].Justification = held.Justification
			comparison.Still[i].Due = held.Due
		}
	}

	had := map[string]bool{}
	for _, c := range was {
		had[key(c)] = true
	}
	for _, c := range now {
		if !had[key(c)] {
			comparison.Newly = append(comparison.Newly, c)
		}
	}
	return comparison, nil
}

// OmittedFixes counts the fixes a public-only comparison of two builds leaves
// out, for the caller who asked for one and may read more.
//
// A count and never the entries. What is left out has not been announced, so
// naming any of it in a document bound for a customer is the disclosure the
// public-only default exists to prevent — while saying nothing at all leaves a
// reader unable to tell a release that fixed nothing undisclosed from one
// whose undisclosed fixes were taken off the page.
//
// Zero where the caller could not have read them anyway, which is the ordinary
// case: there is nothing being kept from somebody who was never going to see
// it, and a count would be an oracle for whether embargoed work exists.
func (s *Store) OmittedFixes(ctx context.Context, subject access.Subject,
	fromTarget, toTarget int64) (int, error) {

	for _, targetID := range []int64{toTarget, fromTarget} {
		_, visible, err := s.mayCompare(ctx, subject, targetID)
		if err != nil {
			return 0, err
		}
		if !slices.Contains(visible, access.Private) {
			return 0, nil
		}
	}

	at := func(targetID int64) ([]Changed, error) {
		var rows []Changed
		err := s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
			Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
			ColumnExpr(`v.identifier AS "vulnerability"`).
			ColumnExpr(`c.name AS "component"`).
			Where("f.target_id = ?", targetID).
			Where("f.visibility = ?", access.Private).
			Where("f.closed_at IS NULL").
			GroupExpr("v.identifier, c.name").
			Scan(ctx, &rows)
		return rows, err
	}
	was, err := at(fromTarget)
	if err != nil {
		return 0, fmt.Errorf("read what the earlier build had undisclosed: %w", err)
	}
	now, err := at(toTarget)
	if err != nil {
		return 0, fmt.Errorf("read what the later build has undisclosed: %w", err)
	}
	here := make(map[string]bool, len(now))
	for _, c := range now {
		here[pairKey(c.Vulnerability, c.Component)] = true
	}
	gone := make([]Changed, 0, len(was))
	for _, c := range was {
		if !here[pairKey(c.Vulnerability, c.Component)] {
			gone = append(gone, c)
		}
	}
	if len(gone) == 0 {
		return 0, nil
	}

	// Only the ones that were actually fixed, by the same rule and the same
	// two functions the listed entries go through. A pair open in one build
	// and not in the next has left the affected list; it has not necessarily
	// been fixed. A record taken back as invalid means the build was never
	// affected, a superseded row means a bump carried the issue along with it,
	// and a closure nothing explains says nothing at all — while the sentence
	// this number is printed in tells a customer that every one of them is a
	// security fix we have chosen not to name.
	//
	// Counted through whyGone and onlyFixes rather than by a filter of its
	// own, because a second spelling of "what counts as a fix" is how the
	// listed half and the counted half came to disagree in the first place.
	why, err := s.whyGone(ctx, toTarget, gone)
	if err != nil {
		return 0, err
	}
	for i := range gone {
		gone[i].Because = why[pairKey(gone[i].Vulnerability, gone[i].Component)].Because
	}
	return len(onlyFixes(gone)), nil
}

// mayCompare reports what a subject may read of one build, refusing where they
// may read nothing.
func (s *Store) mayCompare(ctx context.Context, subject access.Subject, targetID int64) (int64, []access.Visibility, error) {
	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return 0, nil, err
	}
	visible := access.Visible(subject, productID)
	if !subject.Sees(productID) || len(visible) == 0 {
		return 0, nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	// The product comes back with it, because the rating a row is reported at
	// is that product's. The two builds compared can be in two products, and
	// each half of the comparison is rated by its own.
	return productID, visible, nil
}

// whyGone reads the explanations recorded when these findings closed in the
// later build, by issue and component.
//
// Narrowed by the two lists rather than by the pairs. No engine here
// spells a comparison against a pair of columns the same way, and building one
// out of concatenated strings is a portability trap of its own — so the
// statement asks for the issues and the components separately, which is a
// superset, and the pairing is done on the way back. The superset is the
// entries that share an issue *and* a component with something fixed without
// being that pair, which on a release note is a handful.
//
// A pair the later build never carried at all is absent from the answer, and
// the caller reads that as unexplained. That is the ordinary case when a fix
// landed before that line was first scanned: saying "removed" would publish
// "we dropped the component" into a release note about a component that is
// still there at a newer version.
func (s *Store) whyGone(ctx context.Context, targetID int64, fixed []Changed) (map[string]Gone, error) {
	why := make(map[string]Gone, len(fixed))
	if len(fixed) == 0 {
		return why, nil
	}
	wanted := make(map[string]bool, len(fixed))
	for _, c := range fixed {
		wanted[pairKey(c.Vulnerability, c.Component)] = true
		why[pairKey(c.Vulnerability, c.Component)] = Gone{Because: Unexplained}
	}

	for start := 0; start < len(fixed); start += database.BatchSize {
		end := min(start+database.BatchSize, len(fixed))
		batch := fixed[start:end]
		issues := make([]string, 0, len(batch))
		components := make([]string, 0, len(batch))
		seenIssue, seenComponent := map[string]bool{}, map[string]bool{}
		for _, c := range batch {
			if !seenIssue[c.Vulnerability] {
				seenIssue[c.Vulnerability] = true
				issues = append(issues, c.Vulnerability)
			}
			if !seenComponent[c.Component] {
				seenComponent[c.Component] = true
				components = append(components, c.Component)
			}
		}

		var rows []struct {
			Vulnerability string `bun:"vulnerability"`
			Component     string `bun:"component"`
			Because       string `bun:"because"`
			FromVersion   string `bun:"from_version"`
			MovedTo       string `bun:"moved_to"`
			ClosedRun     int64  `bun:"closed_run"`
		}
		err := s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
			Join(`JOIN "component" AS "cp" ON cp.id = f.component_id`).
			ColumnExpr(`v.identifier AS "vulnerability"`).
			ColumnExpr(`cp.name AS "component"`).
			ColumnExpr(`COALESCE(f.closed_because, '') AS "because"`).
			// The version it went from is the closed row's own component:
			// what closed is the finding against the version that carried the
			// issue, so that row still names it. Upstream where there is one,
			// because that is the version the match was made against and the
			// one a fix version is comparable to.
			ColumnExpr(`COALESCE(NULLIF(cp.upstream_version, ''), cp.version) AS "from_version"`).
			ColumnExpr(`COALESCE(f.moved_to, '') AS "moved_to"`).
			ColumnExpr(`COALESCE(f.closed_run_id, 0) AS "closed_run"`).
			Where("f.target_id = ?", targetID).
			Where("f.closed_at IS NOT NULL").
			Where("v.identifier IN (?)", bun.List(issues)).
			Where("cp.name IN (?)", bun.List(components)).
			// Ascending, so the last row read for a pair is its highest
			// identifier — the same row the one-at-a-time form took by
			// ordering descending and stopping at the first.
			OrderExpr("f.id ASC").
			Scan(ctx, &rows)
		if err != nil {
			return nil, fmt.Errorf("read why these went: %w", err)
		}
		for _, row := range rows {
			at := pairKey(row.Vulnerability, row.Component)
			if !wanted[at] || row.Because == "" {
				continue
			}
			why[at] = Gone{
				Because:     Closure(row.Because),
				FromVersion: row.FromVersion,
				MovedTo:     row.MovedTo,
				ClosedRun:   row.ClosedRun,
			}
		}
	}
	return why, nil
}

// Gone is why a finding is no longer there, and what the place moved between
// where moving is the reason.
type Gone struct {
	Because     Closure
	FromVersion string
	MovedTo     string
	// ClosedRun is the run that closed it, and zero where a person did.
	ClosedRun int64
}

// pairKey identifies an issue at a component by name, which is what a
// comparison is drawn in: one line per issue in a component, whatever versions
// either side is at.
//
// One spelling, because the entries and the explanations for them are matched
// against each other and two spellings of a key that agree today are two that
// can stop agreeing.
func pairKey(vulnerability, component string) string {
	return vulnerability + "\x00" + component
}

// Stands is what a build has decided about one issue at one component.
type Stands struct {
	State         string
	Outcome       string
	Justification string
	Due           *time.Time
}

// whatStands reads how far the later build has decided each of the things it
// still has, and what it decided.
//
// Two statements over groups rather than one over places. A real build
// holds a quarter of a million places and a few hundred groups, and what is
// wanted is one answer per group — so the counts are aggregated in the
// database and the outcomes are folded here, which is also where the rule
// about disagreement lives.
//
// Read for the whole build rather than for the entries asked about: the
// comparison's still-present list is most of what the build holds, and a
// statement narrowed by a list of hundreds of pairs is a longer statement
// that reads the same rows.
func (s *Store) whatStands(ctx context.Context, productID, targetID int64,
	visible []access.Visibility) (map[string]Stands, error) {

	var counted []struct {
		Vulnerability string     `bun:"vulnerability"`
		Component     string     `bun:"component"`
		Places        int        `bun:"places"`
		Waiting       int        `bun:"waiting_here"`
		Approved      int        `bun:"approved_here"`
		Lapsed        int        `bun:"lapsed_here"`
		Due           *time.Time `bun:"due_at"`
	}
	q := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		ColumnExpr(`v.identifier AS "vulnerability"`).
		ColumnExpr(`c.name AS "component"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		// The soonest of them, which is the date a coordinator reads against.
		ColumnExpr(`MIN(f.due_at) AS "due_at"`)
	// Counted the way the findings list counts them, through the one spelling
	// of each state, so a row here and the same row on the list cannot say
	// different things about how far it has been decided.
	q = decisionCounts(q, "?", []any{productID}, claimWaiting, claimApproved, claimLapsed).
		Where("f.target_id = ?", targetID).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr("v.identifier, c.name")
	if err := q.Scan(ctx, &counted); err != nil {
		return nil, fmt.Errorf("read how far this build has decided what it still has: %w", err)
	}

	out := make(map[string]Stands, len(counted))
	for _, row := range counted {
		out[pairKey(row.Vulnerability, row.Component)] = Stands{
			State: stateWord(row.Places, row.Waiting, row.Approved, row.Lapsed),
			Due:   row.Due,
		}
	}

	// And what was decided, where something stands. One row per claim, so a
	// group answered by two claims comes back as two — which is what says the
	// row has no single judgment behind it.
	//
	// Grouped on the claim rather than on its words. MySQL and MariaDB
	// compare only the first `max_sort_length` bytes of a long text for
	// GROUP BY, and a justification is bounded at sixty-four kilobytes — so
	// two claims whose reasoning differs only past the first kilobyte counted
	// as one there and as two on PostgreSQL. A claim identifier compares the
	// same everywhere.
	var said []struct {
		Vulnerability string `bun:"vulnerability"`
		Component     string `bun:"component"`
		Claim         int64  `bun:"claim"`
		Outcome       string `bun:"outcome"`
		Justification string `bun:"justification"`
	}
	err := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		// The decision at this place, in this product, at the versions the
		// place holds now — the same match the counts above are made with.
		//
		// The match is a condition of the query rather than of the join,
		// because it asks the claim what outcome it is and the claim hangs off
		// the decision: named in the decision's own ON clause it reaches an
		// alias that is joined after it, which SQLite allows and MySQL and
		// MariaDB refuse. Both joins are inner, so the two are the same
		// question asked in the one place every engine agrees on.
		Join(`JOIN "decision" AS "de" ON de.vulnerability_id = f.vulnerability_id
			AND de.place_identity = f.place_identity AND de.product_id = ?
			AND de.state = ? AND de.live_key IS NOT NULL`, productID, "approved").
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		Where(KeyMatches).
		ColumnExpr(`v.identifier AS "vulnerability"`).
		ColumnExpr(`c.name AS "component"`).
		ColumnExpr(`cl.id AS "claim"`).
		ColumnExpr(`cl.outcome AS "outcome"`).
		// One value per group, because the group is one claim: which bytes an
		// engine compares to take the minimum cannot change the answer.
		ColumnExpr(`COALESCE(MIN(cl.justification), '') AS "justification"`).
		Where("f.target_id = ?", targetID).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr("v.identifier, c.name, cl.id, cl.outcome").
		Scan(ctx, &said)
	if err != nil {
		return nil, fmt.Errorf("read what this build decided about what it still has: %w", err)
	}
	// Only where they agree, and agreement is about the outcome. A
	// component argued away at one place and deferred at another is two
	// claims, and stating either over the row would be a claim nobody made —
	// the rule the VEX document publishes under. Two claims reaching the same
	// outcome in different words are not that: they agree, and what the row
	// cannot state is which wording, so it states the outcome and no reason.
	outcomes := map[string]map[string]bool{}
	claims := map[string]int{}
	for _, row := range said {
		at := pairKey(row.Vulnerability, row.Component)
		if outcomes[at] == nil {
			outcomes[at] = map[string]bool{}
		}
		outcomes[at][row.Outcome] = true
		claims[at]++
	}
	for _, row := range said {
		at := pairKey(row.Vulnerability, row.Component)
		if len(outcomes[at]) != 1 {
			continue
		}
		held := out[at]
		held.Outcome = row.Outcome
		if claims[at] == 1 {
			held.Justification = row.Justification
		}
		out[at] = held
	}
	return out, nil
}
