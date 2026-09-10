package finding

import (
	"context"
	"fmt"
	"slices"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
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
}

// Comparison is what changed between two builds.
type Comparison struct {
	Fixed []Changed
	Newly []Changed
	Still []Changed
}

// Compare reports what was fixed, what is newly present, and what is still
// there between two builds.
//
// Between any two, not only adjacent ones: the question a release note answers
// is usually about the last release a customer has, which is rarely the
// previous one.
//
// Each fixed entry says **why** it went. "Fixed by upgrading to 2.4" and
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
	visible, err := s.mayCompare(ctx, subject, toTarget)
	if err != nil {
		return nil, err
	}
	earlier, err := s.mayCompare(ctx, subject, fromTarget)
	if err != nil {
		return nil, err
	}
	// What may be read of the two, which is the narrower of the two answers.
	if len(earlier) < len(visible) {
		visible = earlier
	}
	if !includePrivate {
		// Its destination is usually a public document, so including
		// something undisclosed is a deliberate act rather than something
		// somebody pastes in without noticing.
		visible = []access.Visibility{access.Public}
	}

	at := func(targetID int64) *bun.SelectQuery {
		q := s.db.NewSelect().
			TableExpr("finding AS f").
			Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
			Join("JOIN component AS c ON c.id = f.component_id").
			ColumnExpr("v.identifier AS vulnerability").
			ColumnExpr("c.name AS component").
			ColumnExpr("COALESCE(v.severity, '') AS severity").
			ColumnExpr("COALESCE(f.closed_because, '') AS because").
			ColumnExpr("MIN(COALESCE(f.arrived_from, '')) AS arrived_from").
			Where("f.target_id = ?", targetID).
			Where("f.visibility IN (?)", bun.List(visible)).
			GroupExpr("v.identifier, c.name, v.severity, f.closed_because")
		return q.Where("f.closed_at IS NULL")
	}

	var was, now []Changed
	if err := at(fromTarget).Scan(ctx, &was); err != nil {
		return nil, fmt.Errorf("read what the earlier build had: %w", err)
	}
	if err := at(toTarget).Scan(ctx, &now); err != nil {
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

	// Why each of them went, read from the rows that closed in the later
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
		// Only where moving is what closed it. On a component that was removed
		// or a finding nothing explains, a pair of versions would be a
		// sentence about a bump that did not happen.
		if went.MovedTo != "" {
			comparison.Fixed[i].FromVersion = went.FromVersion
			comparison.Fixed[i].MovedTo = went.MovedTo
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
		visible, err := s.mayCompare(ctx, subject, targetID)
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
			TableExpr("finding AS f").
			Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
			Join("JOIN component AS c ON c.id = f.component_id").
			ColumnExpr("v.identifier AS vulnerability").
			ColumnExpr("c.name AS component").
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
func (s *Store) mayCompare(ctx context.Context, subject access.Subject, targetID int64) ([]access.Visibility, error) {
	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	visible := access.Visible(subject, productID)
	if !subject.Sees(productID) || len(visible) == 0 {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	return visible, nil
}

// whyGone reads the explanations recorded when these findings closed in the
// later build, by issue and component.
//
// **Narrowed by the two lists rather than by the pairs.** No engine here
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
		}
		err := s.db.NewSelect().
			TableExpr("finding AS f").
			Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
			Join("JOIN component AS cp ON cp.id = f.component_id").
			ColumnExpr("v.identifier AS vulnerability").
			ColumnExpr("cp.name AS component").
			ColumnExpr("COALESCE(f.closed_because, '') AS because").
			// The version it went from is the closed row's own component:
			// what closed is the finding against the version that carried the
			// issue, so that row still names it. Upstream where there is one,
			// because that is the version the match was made against and the
			// one a fix version is comparable to.
			ColumnExpr("COALESCE(NULLIF(cp.upstream_version, ''), cp.version) AS from_version").
			ColumnExpr("COALESCE(f.moved_to, '') AS moved_to").
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
