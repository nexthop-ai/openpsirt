// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// The three statuses a statement states, as both formats this deployment
// publishes spell them.
const (
	NotAffected = "not_affected"
	Fixed       = "fixed"
	Affected    = "affected"
)

// The action an affected statement carries where the claim named none. The
// formats ask for one, and these say what is true without promising anything:
// a date this deployment is working to is its own plan rather than something a
// reader may hold it to.
const (
	NoFixPlanned = "No fix is planned for this component in this build."
	NoFixYet     = "No fix is available for this component in this build yet."
)

// Fact is one statement about one issue in one component of one build, before
// a format writes it.
type Fact struct {
	VulnerabilityID int64
	Issue           string
	Aliases         []string
	// Component and Purl are what the statement is about: the name the build
	// calls it, and the package identifier the build stated for it, which is
	// empty where it stated none.
	Component string
	Purl      string
	// Within is the package identifier of the component that pulls this one
	// in, for a statement about one place of it. Empty for a statement about
	// the component wherever the build holds it.
	Within string
	Status string
	// Justification is the reason something is not affected, Impact what
	// stops it where somebody named it, and Action what a holder of an
	// affected build can do.
	Justification string
	Impact        string
	Action        string
	// Scope is whom the statement holds for.
	Scope triage.Scope
	// Since is when the statement was first true: when the claim was made,
	// the patch seen, or the finding opened.
	Since time.Time
}

// Subject is what the fact is about, as a package identifier where the build
// stated one and as the name it calls the component otherwise.
func (f Fact) Subject() string { return subject(f.Purl, f.Component) }

// Built is one build's facts, and what the build calls itself.
type Built struct {
	// Root is the package identifier the build's inventory gave itself, where
	// it gave one that states a version, and empty otherwise.
	Root  string
	Facts []Fact
}

// Public is what this deployment states about one build, for publishing to
// anybody: what somebody decided about an issue in a component of it, at
// disclosed findings only.
//
// It is the document of one build with what it leaves to silence about an
// issue that applies and stays stated outright. An issue nobody has decided
// about gets no statement, so a scanner reports it as it would without this.
//
//   - Not affected and fixed come from the same approved claims and declared
//     patches the document of one build reads.
//   - Affected is a component whose every open place stands under a claim in
//     force that the issue applies, will be fixed, or will not.
//
// Nothing here states that an issue is under investigation. No claim records
// that somebody is looking at an issue, and a deferral says when somebody will
// look again rather than that anybody is looking.
//
// A supplier's statement about its own product is not among them. This
// deployment passes it on only where somebody chose the document carrying
// suppliers' statements.
//
// The subject has to read disclosed work in the product. What it reads is
// never more than that, whoever it is.
func (s *Store) Public(ctx context.Context, subject access.Subject, named *catalog.Named,
	targetID int64) (*Built, error) {

	if !subject.Reads(access.Public, named.ProductID) {
		return nil, access.Denied(fmt.Sprintf("read disclosed findings in product %d", named.ProductID))
	}
	visible := []access.Visibility{access.Public}

	var rows []struct {
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Identifier      string `bun:"identifier"`
		Component       string `bun:"component"`
		Purl            string `bun:"purl"`
		finding.Covering
	}
	if err := finding.WhollyCovered(s.grouped(targetID, visible), named.ProductID, visible,
		finding.ForStatements).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what stands about this build: %w", err)
	}
	var affected []struct {
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Identifier      string `bun:"identifier"`
		Component       string `bun:"component"`
		Purl            string `bun:"purl"`
		finding.Affected
	}
	if err := finding.WhollyAffected(s.grouped(targetID, visible), named.ProductID,
		visible).Scan(ctx, &affected); err != nil {
		return nil, fmt.Errorf("read what applies in this build: %w", err)
	}
	fixed, err := s.patched(ctx, targetID, visible)
	if err != nil {
		return nil, err
	}
	placed, err := finding.CoveredAtPlaces(ctx, s.idb(), named.ProductID, targetID, visible, s.carrying())
	if err != nil {
		return nil, err
	}
	// Refused rather than truncated, for the reason the document of one build
	// is: a document that stopped at a ceiling says nothing about everything
	// past it.
	if len(rows)+len(affected)+len(placed)+len(fixed) > s.carrying() {
		return nil, fmt.Errorf("%w: %s %s %s states more than %d statements",
			ErrTooLarge, named.Product, named.Stream, named.Variant, s.carrying())
	}

	decided := make([]int64, 0, len(rows)+len(placed)+len(affected))
	for _, row := range rows {
		decided = append(decided, row.DecidedBy)
	}
	for _, row := range placed {
		decided = append(decided, row.DecidedBy)
	}
	for _, row := range affected {
		decided = append(decided, row.DecidedBy)
	}
	said, err := finding.StatedBy(ctx, s.idb(), decided)
	if err != nil {
		return nil, err
	}
	issues := make([]int64, 0, len(rows)+len(affected)+len(placed)+len(fixed))
	for _, row := range rows {
		issues = append(issues, row.VulnerabilityID)
	}
	for _, row := range affected {
		issues = append(issues, row.VulnerabilityID)
	}
	for _, row := range fixed {
		issues = append(issues, row.VulnerabilityID)
	}
	for _, row := range placed {
		issues = append(issues, row.VulnerabilityID)
	}
	alsoCalled, err := s.namesOf(ctx, issues)
	if err != nil {
		return nil, err
	}
	// An issue a flaw of ours recorded out of the subject's reach wrote onto
	// publishes none of its other names: one of them is the name minted for
	// it, which is the one thing about it that must not travel.
	withheld, err := finding.RecordedOutOfReach(ctx, s.idb(), subject, issues)
	if err != nil {
		return nil, err
	}
	for issue := range withheld {
		delete(alsoCalled, issue)
	}
	root, err := s.rootOf(ctx, named, targetID)
	if err != nil {
		return nil, err
	}
	built := &Built{}
	if root != build(named) {
		built.Root = root
	}

	type group struct {
		issue         int64
		component, at string
	}
	stated := map[group]bool{}
	for _, row := range rows {
		words := said[row.DecidedBy]
		fact, err := factOf(row.VulnerabilityID, row.Identifier, alsoCalled[row.VulnerabilityID],
			row.Component, row.Purl, "", row.Outcome, words)
		if err != nil {
			return nil, err
		}
		built.Facts = append(built.Facts, fact)
		stated[group{row.VulnerabilityID, row.Component, row.Purl}] = true
	}
	for _, row := range placed {
		fact, err := factOf(row.VulnerabilityID, row.Identifier, alsoCalled[row.VulnerabilityID],
			row.Component, row.Purl, row.ConsumerPurl, row.Outcome, said[row.DecidedBy])
		if err != nil {
			return nil, err
		}
		built.Facts = append(built.Facts, fact)
	}
	for _, row := range fixed {
		built.Facts = append(built.Facts, Fact{
			VulnerabilityID: row.VulnerabilityID, Issue: row.Identifier,
			Aliases: alsoCalled[row.VulnerabilityID], Component: row.Component, Purl: row.Purl,
			Status: Fixed, Scope: triage.BuildSpecific, Since: row.PatchedAt.UTC(),
		})
	}
	for _, row := range affected {
		key := group{row.VulnerabilityID, row.Component, row.Purl}
		if stated[key] {
			continue
		}
		stated[key] = true
		words := said[row.DecidedBy]
		action := NoFixYet
		if row.Least == finding.OutcomeWontFix && row.Greatest == finding.OutcomeWontFix {
			action = NoFixPlanned
		}
		built.Facts = append(built.Facts, Fact{
			VulnerabilityID: row.VulnerabilityID, Issue: row.Identifier,
			Aliases: alsoCalled[row.VulnerabilityID], Component: row.Component, Purl: row.Purl,
			Status: Affected, Action: action,
			Scope: triage.ScopeOf(triage.Outcome(words.Outcome), "", triage.Scope(words.Scope)),
			Since: words.ProposedAt.UTC(),
		})
	}
	sort.Slice(built.Facts, func(i, j int) bool { return built.Facts[i].before(built.Facts[j]) })
	return built, nil
}

// grouped is the findings of one build at the visibilities given, one row per
// issue and component by its name and package identifier, carrying the columns
// every statement about a component reads.
func (s *Store) grouped(targetID int64, visible []access.Visibility) *bun.SelectQuery {
	return s.idb().NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Join(nodeJoin).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "f"."vulnerability_id"`).
		ColumnExpr(`"v"."id" AS "vulnerability_id"`).
		ColumnExpr(`"v"."identifier" AS "identifier"`).
		ColumnExpr(`"c"."name" AS "component"`).
		ColumnExpr(`COALESCE("giv"."purl", "gn"."purl", "c"."purl", '') AS "purl"`).
		Where(`"f"."target_id" = ?`, targetID).
		Where(`"f"."visibility" IN (?)`, bun.List(visible)).
		GroupExpr(`"v"."id", "v"."identifier", "c"."name", "giv"."purl", "gn"."purl", "c"."purl"`).
		Limit(int64(s.carrying() + 1))
}

// factOf is the fact an agreed claim states about one component, beneath one
// consumer where within names one.
func factOf(issueID int64, issue string, aliases []string, component, purl, within,
	outcome string, words finding.Stated) (Fact, error) {

	fact := Fact{
		VulnerabilityID: issueID, Issue: issue, Aliases: aliases,
		Component: component, Purl: purl, Within: within,
		Status: statusOf(outcome), Since: words.ProposedAt.UTC(),
		Scope: triage.ScopeOf(triage.Outcome(outcome), triage.Justification(words.Justification),
			triage.Scope(words.Scope)),
	}
	switch fact.Status {
	case "":
		return Fact{}, fmt.Errorf("outcome %q has no VEX status", outcome)
	case NotAffected:
		fact.Justification = words.Justification
		fact.Impact = words.Mitigation
	case Affected:
		fact.Action = words.Mitigation
	}
	return fact, nil
}

// before orders facts by issue, then by what they are about, then by where.
func (f Fact) before(other Fact) bool {
	if f.Issue != other.Issue {
		return f.Issue < other.Issue
	}
	if f.Subject() != other.Subject() {
		return f.Subject() < other.Subject()
	}
	return f.Within < other.Within
}
