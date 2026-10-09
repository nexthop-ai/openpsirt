// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// Interning many reports at once: what is on record about the issues they name
// is read for all of them together, and a report that would change nothing
// writes nothing and asks nothing more.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// onRecord is what is held about the issues a run of reports names, read in a
// few statements rather than several per report.
//
// It answers for a report only while nothing this interning wrote could have
// changed the answer. A report is resolved one at a time from the database,
// exactly as it would be alone, where one of its names or one of the issues
// it reaches was written by an earlier report in the run: an issue created,
// merged, renamed or filled in has rows this read predates.
type onRecord struct {
	aliases    []Alias
	filed      []Vulnerability
	rows       map[int64]Vulnerability
	ratings    map[int64][]CVSS
	weaknesses map[int64][]Weakness
	references map[int64]map[string]bool

	// What earlier reports in the run wrote, by name and by issue.
	wroteName  map[string]bool
	wroteIssue map[int64]bool
}

// recordOf reads what is held about every issue these reports name.
func (v *Vulnerabilities) recordOf(ctx context.Context, reports []Named) (*onRecord, error) {
	held := &onRecord{
		rows:       map[int64]Vulnerability{},
		ratings:    map[int64][]CVSS{},
		weaknesses: map[int64][]Weakness{},
		references: map[int64]map[string]bool{},
		wroteName:  map[string]bool{},
		wroteIssue: map[int64]bool{},
	}
	var names, folded []string
	seen := map[string]bool{}
	for _, named := range reports {
		_, each, err := prepared(named)
		if err != nil {
			continue
		}
		for _, name := range each {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
				folded = append(folded, FoldIdentifier(name))
			}
		}
	}
	if len(names) == 0 {
		return held, nil
	}
	if err := v.db.NewSelect().Model(&held.aliases).
		Where("identifier IN (?)", bun.List(names)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("look up these vulnerabilities: %w", err)
	}
	if err := v.db.NewSelect().Model(&held.filed).
		Column("id", "identifier_folded", "issue_id").
		Where("vu.identifier_folded IN (?)", bun.List(folded)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("look up these vulnerabilities by the names they are filed under: %w", err)
	}
	reached := map[int64]bool{}
	var ids []int64
	for _, alias := range held.aliases {
		if !reached[alias.VulnerabilityID] {
			reached[alias.VulnerabilityID] = true
			ids = append(ids, alias.VulnerabilityID)
		}
	}
	for _, row := range held.filed {
		if !reached[row.IssueID] {
			reached[row.IssueID] = true
			ids = append(ids, row.IssueID)
		}
	}
	err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		var rows []Vulnerability
		if err := v.db.NewSelect().Model(&rows).Where("id IN (?)", bun.List(batch)).Scan(ctx); err != nil {
			return fmt.Errorf("read these vulnerabilities: %w", err)
		}
		for _, row := range rows {
			held.rows[row.ID] = row
		}
		var ratings []CVSS
		if err := v.db.NewSelect().Model(&ratings).
			Where("vr.vulnerability_id IN (?)", bun.List(batch)).Scan(ctx); err != nil {
			return fmt.Errorf("read how these vulnerabilities are rated: %w", err)
		}
		for _, rating := range ratings {
			held.ratings[rating.VulnerabilityID] = append(held.ratings[rating.VulnerabilityID], rating)
		}
		var weaknesses []Weakness
		if err := v.db.NewSelect().Model(&weaknesses).
			Where("vw.vulnerability_id IN (?)", bun.List(batch)).Scan(ctx); err != nil {
			return fmt.Errorf("read what kind of flaw these are: %w", err)
		}
		for _, weakness := range weaknesses {
			held.weaknesses[weakness.VulnerabilityID] = append(held.weaknesses[weakness.VulnerabilityID],
				weakness)
		}
		var references []Reference
		if err := v.db.NewSelect().Model(&references).
			Column("vulnerability_id", "url_identity").
			Where("vr.vulnerability_id IN (?)", bun.List(batch)).Scan(ctx); err != nil {
			return fmt.Errorf("read what these vulnerabilities point at: %w", err)
		}
		for _, reference := range references {
			if held.references[reference.VulnerabilityID] == nil {
				held.references[reference.VulnerabilityID] = map[string]bool{}
			}
			held.references[reference.VulnerabilityID][reference.URLIdentity] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return held, nil
}

// wrote records that a report's names and the issues it reached were written,
// so later reports reaching either are resolved from the database.
func (held *onRecord) wrote(names []string, issues ...int64) {
	for _, name := range names {
		held.wroteName[strings.ToUpper(name)] = true
	}
	for _, id := range issues {
		held.wroteIssue[id] = true
	}
}

// resolve is the one issue a report's names reach, by what was read, and the
// names on record for it; false where the read cannot answer.
//
// Compared without regard to case, which is never narrower than any engine's
// comparison: a row one engine would not have matched only makes the answer
// one that resolving alone gives. A name outside plain ASCII is left to the
// database, whose comparison of it this cannot reproduce.
func (held *onRecord) resolve(names []string) (int64, []Alias, bool) {
	for _, name := range names {
		if held.wroteName[strings.ToUpper(name)] || !plain(name) {
			return 0, nil, false
		}
	}
	matches := func(stored string) bool {
		for _, name := range names {
			if strings.EqualFold(stored, name) {
				return true
			}
		}
		return false
	}
	existing := map[int64]bool{}
	var known []Alias
	for _, alias := range held.aliases {
		if matches(alias.Identifier) {
			existing[alias.VulnerabilityID] = true
			known = append(known, alias)
		}
	}
	for _, row := range held.filed {
		if matches(row.IdentifierFolded) {
			existing[row.IssueID] = true
		}
	}
	if len(existing) != 1 {
		return 0, nil, false
	}
	var id int64
	for each := range existing {
		id = each
	}
	if held.wroteIssue[id] {
		return 0, nil, false
	}
	if _, read := held.rows[id]; !read {
		return 0, nil, false
	}
	return id, known, true
}

// plain reports whether a name is printable ASCII throughout.
func plain(name string) bool {
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] > 0x7e {
			return false
		}
	}
	return true
}

// interned resolves one report against what was read, writing only the parts
// that would change something, and falls back to resolving it alone wherever
// the read cannot answer.
//
// Its steps are one's, in one's order, each behind the comparison that says
// whether it would write.
//
// Each part is the same statement resolving alone writes, issued where what
// was read says it would match a row and skipped where it says it would match
// none. Every comparison here leans toward issuing the statement: a statement
// issued that matches nothing costs a round trip, and one skipped that would
// have matched loses a write.
func (v *Vulnerabilities) interned(ctx context.Context, named Named, held *onRecord) (int64, error) {
	named, names, err := prepared(named)
	if err != nil {
		return 0, err
	}
	id, known, answered := held.resolve(names)
	if answered {
		row := held.rows[id]
		if wanted := preferred(Named{Identifier: row.Identifier, Aliases: names}); wanted != "" &&
			wanted != row.Identifier {
			answered = false
		}
	}
	if !answered {
		merged := len(v.absorbed)
		id, err := v.one(ctx, named)
		if err != nil {
			return 0, err
		}
		held.wrote(names, id)
		if len(v.absorbed) != merged {
			for gone, kept := range v.absorbed {
				held.wrote(nil, gone, kept)
			}
		}
		return id, nil
	}

	row := held.rows[id]
	wrote := false
	if unfilled(row, named) {
		if err := v.fill(ctx, id, named); err != nil {
			return 0, err
		}
		wrote = true
	}
	ratings := held.ratings[id]
	if unranked(row, ratings, named) {
		moved, err := v.rank(ctx, id, named)
		if err != nil {
			return 0, err
		}
		if moved {
			v.moved[id] = true
		}
		wrote = true
	}
	if unreferenced(held.references[id], named.References) {
		if err := v.reference(ctx, id, named.References); err != nil {
			return 0, err
		}
		wrote = true
	}

	// The names it has not been recorded under, from the names read: the same
	// list resolving alone reads first.
	recorded, err := v.name(ctx, id, named, names, known)
	if err != nil {
		return 0, err
	}
	wrote = wrote || recorded

	if unclassified(held.weaknesses[id], named.Weaknesses, named.PrimaryWeakness) {
		if err := v.classify(ctx, id, named.Weaknesses, named.PrimaryWeakness); err != nil {
			return 0, fmt.Errorf("record what kind of flaw %q is: %w", named.Identifier, err)
		}
		wrote = true
	}
	rerate := unrated(ratings, ratingsOf(named))
	if rerate {
		if err := v.rate(ctx, id, ratingsOf(named)); err != nil {
			return 0, fmt.Errorf("record how %q is rated: %w", named.Identifier, err)
		}
		wrote = true
	}
	// Settled from the database wherever a rating was written above, and from
	// what was read otherwise. Nothing else above writes what settling reads:
	// a score is raised onto the issue only where it holds no rating, and
	// then there is nothing to settle.
	if rerate || unsettled(row, ratings) {
		rerated, err := v.settle(ctx, id)
		if err != nil {
			return 0, fmt.Errorf("record how %q is rated: %w", named.Identifier, err)
		}
		if rerated {
			v.moved[id] = true
		}
		wrote = true
	}
	if wrote {
		held.wrote(names, id)
	}
	return id, nil
}

// unfilled is whether filling the description and the advisory would match
// the row: a value reported where the row holds none.
//
// Spaces alone count as none, because MySQL and MariaDB compare a run of
// spaces equal to the empty string.
func unfilled(row Vulnerability, named Named) bool {
	empty := func(s string) bool { return strings.TrimRight(s, " ") == "" }
	return (named.Description != "" && empty(row.Description)) ||
		(named.Advisory != "" && empty(row.Advisory))
}

// unranked is whether raising the signals the order is worked out from would
// match the row.
func unranked(row Vulnerability, ratings []CVSS, named Named) bool {
	if named.Likelihood > 0 {
		likelihood := perMillion(named.Likelihood)
		if row.LikelihoodPPM == nil {
			return true
		}
		if named.LikelihoodOn != nil {
			if row.LikelihoodOn == nil || !aDay(*named.LikelihoodOn) || !aDay(*row.LikelihoodOn) ||
				row.LikelihoodOn.Before(*named.LikelihoodOn) {
				return true
			}
		} else if row.LikelihoodOn == nil && *row.LikelihoodPPM != likelihood {
			return true
		}
	}
	if named.Exploited && named.ExploitedOn != nil {
		if row.ExploitedOn == nil || !aDay(*named.ExploitedOn) || !aDay(*row.ExploitedOn) ||
			row.ExploitedOn.After(*named.ExploitedOn) {
			return true
		}
	}
	if named.Exploited && !row.Exploited {
		return true
	}
	if named.Score > 0 && len(ratingsOf(named)) == 0 && len(ratings) == 0 {
		if row.ScoreCenti == nil || *row.ScoreCenti < hundredths(named.Score) {
			return true
		}
	}
	return false
}

// aDay is whether a moment is the start of a day in UTC, which is how a day
// is compared both here and by every engine.
func aDay(t time.Time) bool {
	t = t.UTC()
	return t.Equal(time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC))
}

// unreferenced is whether a report points somewhere the issue does not.
func unreferenced(held map[string]bool, references []Reference) bool {
	for _, reference := range references {
		if reference.URL != "" && !held[identity(reference.URL)] {
			return true
		}
	}
	return false
}

// unclassified is whether classifying would write anything: a kind of flaw
// the issue does not hold, or a root cause marked differently.
func unclassified(held []Weakness, cwes []string, primary string) bool {
	kinds := cleaned(cwes)
	if len(kinds) == 0 {
		return false
	}
	have := map[string]bool{}
	for _, weakness := range held {
		have[weakness.CWE] = true
	}
	for _, kind := range kinds {
		if !have[kind] {
			return true
		}
	}
	primary = strings.ToUpper(strings.TrimSpace(primary))
	if primary == "" {
		return false
	}
	for _, weakness := range held {
		if strings.EqualFold(weakness.CWE, primary) && !weakness.Primary {
			return true
		}
		if weakness.CWE != primary && weakness.Primary {
			return true
		}
	}
	return false
}

// unrated is whether recording a report's ratings would write anything: a
// generation the issue holds no rating in, or one it rates lower.
func unrated(held []CVSS, ratings []CVSS) bool {
	scored := map[int]int{}
	for _, rating := range held {
		scored[rating.Generation] = rating.ScoreCenti
	}
	for _, rating := range ratings {
		if rating.Generation <= 0 || rating.ScoreCenti <= 0 || strings.TrimSpace(rating.Vector) == "" {
			continue
		}
		score, known := scored[rating.Generation]
		if !known || score < rating.ScoreCenti {
			return true
		}
	}
	return false
}

// unsettled is whether the issue's number differs from its newest rating,
// which settling would write.
func unsettled(row Vulnerability, held []CVSS) bool {
	if len(held) == 0 {
		return false
	}
	newest := held[0]
	for _, rating := range held[1:] {
		if rating.Generation > newest.Generation {
			newest = rating
		}
	}
	return row.ScoreCenti == nil || *row.ScoreCenti != newest.ScoreCenti ||
		row.Vector != newest.Vector || row.ScoreVersion != newest.Version ||
		row.ScoreSource != newest.Source || row.ScoreKind != newest.Kind
}
