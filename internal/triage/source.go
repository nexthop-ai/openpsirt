// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

// A correction by source paths: one wrong match answering every issue a
// package is matched through its source package for, where the issue's record
// lists only files outside the paths the package is built from (REQ-90).

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/cverecord"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/rating"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// SourceDecision is a correction by source paths: a wrong match answering
// every issue a package is matched through its source for whose record lists
// only files outside the paths the package is built from.
const SourceDecision DecisionKind = "source"

// What one correction by source paths may name.
const (
	// mostSourcePaths is how many paths one correction names. A binary is
	// built from a handful: linux-perf from three.
	mostSourcePaths = 64
	// longestSourcePath is how long one path may be, in bytes, as long as the
	// longest file a record names may be.
	longestSourcePath = 1_024
)

// SourceCorrection is what a correction by source paths names.
type SourceCorrection struct {
	bun.BaseModel `bun:"table:source_correction,alias:sc"`

	ID         int64 `bun:"id,pk,autoincrement"`
	DecisionID int64 `bun:"decision_id,notnull"`
	ProductID  int64 `bun:"product_id,notnull"`
	// Package and Source are in lower case: the package answered, and the
	// source package it is matched through.
	Package string `bun:"package_name,notnull"`
	Source  string `bun:"source_name,notnull"`
	// Paths is the paths within the source the package is built from, one a
	// line in byte order.
	Paths string `bun:"source_paths,notnull"`
}

// PathList is the paths a correction names.
func (c SourceCorrection) PathList() []string {
	return strings.Split(c.Paths, "\n")
}

// sourceAnswer is the files that justified one occurrence a correction by
// source paths answered.
type sourceAnswer struct {
	bun.BaseModel `bun:"table:source_answer,alias:sa"`

	ID                   int64  `bun:"id,pk,autoincrement"`
	DecisionOccurrenceID int64  `bun:"decision_occurrence_id,notnull"`
	Files                string `bun:"files,notnull"`
}

// SourceProposal is somebody proposing a correction by source paths.
type SourceProposal struct {
	ProductID int64
	// Package is the binary package answered, by the name it is identified
	// by; Source is the source package it is matched through.
	Package string
	Source  string
	// Paths is the paths within the source the package is built from.
	Paths         []string
	Justification Justification
	Reasoning     string
	By            int64
}

// SourceProposed is what proposing a correction by source paths recorded.
type SourceProposed struct {
	DecisionID int64
	// Answered is how many occurrences it answered when proposed.
	Answered int
}

// ErrNothingMatchedThrough is returned when a correction by source paths
// proposed now would answer nothing.
var ErrNothingMatchedThrough = refusal.New("nothing open in this product is matched that way with " +
	"every file its record lists outside those paths")

// normalized is a proposal with its names folded and its paths in the one
// spelling they are compared in, or the refusal saying what is wrong with it.
func (p SourceProposal) normalized() (SourceProposal, error) {
	p.Package = graph.Folded(p.Package)
	p.Source = graph.Folded(p.Source)
	switch {
	case p.Package == "":
		return p, refusal.New("a correction by source paths names the package it answers")
	case p.Source == "":
		return p, refusal.New("a correction by source paths names the source package it is matched through")
	case p.Package == p.Source:
		return p, refusal.New("a package matched under its own name is a match on the package itself, " +
			"which a correction by source paths never answers; name the source it is built from")
	case utf8.RuneCountInString(p.Package) > database.NameWidth || utf8.RuneCountInString(p.Source) > database.NameWidth:
		return p, refusal.Errorf("a package name is at most %d characters", database.NameWidth)
	}
	seen := map[string]bool{}
	var paths []string
	for _, stated := range p.Paths {
		if strings.TrimSpace(stated) == "" {
			continue
		}
		cleaned, ok := cverecord.SourcePath(stated)
		switch {
		case !ok:
			return p, refusal.Errorf("%q leaves the source tree; name a path within it, such as tools/perf", stated)
		case cleaned == "":
			return p, refusal.New("the root of the source holds every file, so it answers nothing; " +
				"name the directories the package is built from")
		case len(cleaned) > longestSourcePath:
			return p, refusal.Errorf("a source path is at most %d bytes", longestSourcePath)
		}
		if !seen[cleaned] {
			seen[cleaned] = true
			paths = append(paths, cleaned)
		}
	}
	if len(paths) == 0 {
		return p, refusal.New("a correction by source paths names the paths the package is built from")
	}
	if len(paths) > mostSourcePaths {
		return p, refusal.Errorf("that is %d paths and one correction names at most %d", len(paths), mostSourcePaths)
	}
	sort.Strings(paths)
	p.Paths = paths
	return p, nil
}

// argument is the decision a correction by source paths records: a wrong
// match, for one of the two reasons saying something is not there.
func (p SourceProposal) argument() Proposal {
	return Proposal{
		Outcome: Mismatched, Justification: p.Justification,
		Reasoning: p.Reasoning, By: p.By, NeedsApproval: true,
	}
}

// ProposeBySource records a correction by source paths and answers every
// occurrence in the product it already covers. It waits for a second person
// like any correction, and answers nothing until one agrees.
//
// Refused where it answers nothing now, because a correction nothing stands
// under is one no reviewer can see the reach of.
func (s *Store) ProposeBySource(ctx context.Context, subject access.Subject,
	p SourceProposal) (*SourceProposed, error) {

	p, err := p.normalized()
	if err != nil {
		return nil, err
	}
	if p.By != subject.ID {
		return nil, refusal.Errorf("a decision is recorded as made by whoever made it")
	}
	if !mayDecide(subject, p.ProductID, access.Public) {
		return nil, ErrNotTheirs
	}
	if err := p.argument().valid(s.now()); err != nil {
		return nil, err
	}
	var proposed *SourceProposed
	err = s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		proposed = nil
		decision, err := within.newDecision(ctx, SourceDecision, p.By, nil, "", p.argument())
		if err != nil {
			return err
		}
		rule := &SourceCorrection{
			DecisionID: decision.ID, ProductID: p.ProductID,
			Package: p.Package, Source: p.Source, Paths: strings.Join(p.Paths, "\n"),
		}
		if _, err := tx.NewInsert().Model(rule).Exec(ctx); err != nil {
			return fmt.Errorf("record a correction by source paths: %w", err)
		}
		answered, err := within.answerBy(ctx, decision, *rule, 0)
		if err != nil {
			return err
		}
		if answered == 0 {
			return ErrNothingMatchedThrough
		}
		proposed = &SourceProposed{DecisionID: decision.ID, Answered: answered}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return proposed, nil
}

// AnswerBySource answers, by each correction by source paths standing in the
// build's product, every open finding of the build it covers that nothing
// answers yet. A scan runs it once the findings are written, which is how an
// issue published later is answered.
//
// It reports how many occurrences it answered.
func (s *Store) AnswerBySource(ctx context.Context, buildID int64) (int, error) {
	var answered int
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		answered = 0
		var productID int64
		if err := tx.NewSelect().TableExpr(`"build" AS "b"`).
			Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "b"."branch_or_tag_id"`).
			ColumnExpr(`"st"."product_id"`).
			Where(`"b"."id" = ?`, buildID).Scan(ctx, &productID); err != nil {
			return fmt.Errorf("read the product of build %d: %w", buildID, err)
		}
		rules, err := within.standingBySource(ctx, productID)
		if err != nil {
			return err
		}
		for _, rule := range rules {
			decision := new(Decision)
			if err := tx.NewSelect().Model(decision).Where(`"id" = ?`, rule.DecisionID).Scan(ctx); err != nil {
				return fmt.Errorf("read correction %d: %w", rule.DecisionID, err)
			}
			n, err := within.answerBy(ctx, decision, rule, buildID)
			if err != nil {
				return err
			}
			answered += n
		}
		return nil
	})
	return answered, err
}

// standingBySource is the corrections by source paths in a product that still
// answer: those with a row neither withdrawn nor set aside.
func (s *Store) standingBySource(ctx context.Context, productID int64) ([]SourceCorrection, error) {
	var rules []SourceCorrection
	if err := s.db.NewSelect().Model(&rules).
		Where(`"sc"."product_id" = ?`, productID).
		Where(`EXISTS (SELECT 1 FROM "decision_occurrence" AS "lv" WHERE "lv"."decision_id" = "sc"."decision_id" ` +
			`AND "lv"."live_key" IS NOT NULL)`).
		Order("sc.id").
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the corrections by source paths standing here: %w", err)
	}
	return rules, nil
}

// SourceOf is what a correction by source paths names, or nil where the
// decision is not one. The decision's own reading rights are the caller's to
// have asked.
func (s *Store) SourceOf(ctx context.Context, decisionID int64) (*SourceCorrection, error) {
	var rules []SourceCorrection
	if err := s.db.NewSelect().Model(&rules).Where(`"sc"."decision_id" = ?`, decisionID).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what correction %d names: %w", decisionID, err)
	}
	if len(rules) == 0 {
		return nil, nil
	}
	return &rules[0], nil
}

// AnsweredOn is the files that justified each of these decision occurrences,
// for those a correction by source paths wrote. The rows' own reading rights
// are the caller's to have asked.
func (s *Store) AnsweredOn(ctx context.Context, occurrenceIDs []int64) (map[int64][]string, error) {
	out := map[int64][]string{}
	for start := 0; start < len(occurrenceIDs); start += database.BatchSize {
		end := min(start+database.BatchSize, len(occurrenceIDs))
		var answers []sourceAnswer
		if err := s.db.NewSelect().Model(&answers).
			Where(`"sa"."decision_occurrence_id" IN (?)`, bun.List(occurrenceIDs[start:end])).
			Scan(ctx); err != nil {
			return nil, fmt.Errorf("read the files a correction answered on: %w", err)
		}
		for _, answer := range answers {
			out[answer.DecisionOccurrenceID] = strings.Split(answer.Files, "\n")
		}
	}
	return out, nil
}

// matchedThrough is one open occurrence a correction by source paths covers,
// before its issue's files are read.
type matchedThrough struct {
	resolved
	key string
}

// answerBy writes a row of the decision at every open occurrence in the
// product, or in one build of it where a build is named, that the correction
// covers and no correction answers yet, with the files that justified it.
//
// An occurrence is covered where it is a public finding of a published issue,
// at the package, matched through the source, and the issue's record lists
// files, none of them under the paths. An undisclosed finding is left for a
// person, and so is an issue this product records as attacked through.
//
// A row waits for a second person unless an approval of the reasoning the
// decision rests on stands, which is what a second person agreed to: the
// rule, over whatever it reaches.
func (s *Store) answerBy(ctx context.Context, decision *Decision, rule SourceCorrection, buildID int64) (int, error) {
	covered, err := s.matchedThrough(ctx, rule, buildID)
	if err != nil || len(covered) == 0 {
		return 0, err
	}
	issues := make([]int64, 0, len(covered))
	seenIssue := map[int64]bool{}
	for _, at := range covered {
		if !seenIssue[at.VulnerabilityID] {
			seenIssue[at.VulnerabilityID] = true
			issues = append(issues, at.VulnerabilityID)
		}
	}
	files, err := finding.ProgramFiles(ctx, s.db, issues)
	if err != nil {
		return 0, err
	}
	attacked, err := standsIncident(ctx, s.db, rule.ProductID, issues)
	if err != nil {
		return 0, err
	}
	answered, err := s.unanswered(ctx, covered)
	if err != nil {
		return 0, err
	}
	paths := rule.PathList()
	var proposals []Proposal
	var justified []string
	for _, at := range covered {
		listed := files[at.VulnerabilityID]
		if answered[at.key] || attacked[at.VulnerabilityID] || !outsideAll(listed, paths) {
			continue
		}
		one := decision.argument()
		one.By, one.NeedsApproval = decision.ProposedBy, true
		one.Occurrence, one.SeverityCenti = at.Occurrence, at.SeverityCenti
		proposals = append(proposals, one)
		justified = append(justified, strings.Join(listed, "\n"))
	}
	if len(proposals) == 0 {
		return 0, nil
	}
	written, err := s.proposeAll(ctx, decision, proposals)
	if err != nil {
		return 0, err
	}
	answers := make([]sourceAnswer, 0, len(written))
	ids := make([]int64, 0, len(written))
	for i, row := range written {
		answers = append(answers, sourceAnswer{DecisionOccurrenceID: row.ID, Files: justified[i]})
		ids = append(ids, row.ID)
	}
	if err := database.InBatchesUnkeyed(ctx, s.db, answers); err != nil {
		return 0, fmt.Errorf("record the files a correction answered on: %w", err)
	}
	if err := s.followTheDecision(ctx, decision, ids); err != nil {
		return 0, err
	}
	return len(written), nil
}

// followTheDecision puts rows just written where the decision's other rows
// are: approved while an approval of its current reasoning stands, and with
// its author where every row still waiting was sent back.
func (s *Store) followTheDecision(ctx context.Context, decision *Decision, ids []int64) error {
	if decision.RevisionID == nil {
		return nil
	}
	agreed, err := s.db.NewSelect().Model((*Approval)(nil)).
		Where(`"da"."decision_id" = ?`, decision.ID).
		Where(`"da"."revision_id" = ?`, *decision.RevisionID).
		Where(`"da"."withdrawn_at" IS NULL`).
		Exists(ctx)
	if err != nil {
		return fmt.Errorf("read whether correction %d is agreed to: %w", decision.ID, err)
	}
	if agreed {
		return s.approveWhileRevised(ctx, *decision, ids, "answer by an agreed correction",
			"the reasoning changed while this was being answered; it is answered on the next scan")
	}
	var waiting []struct {
		SentBackAt *time.Time `bun:"sent_back_at"`
	}
	if err := s.db.NewSelect().Model((*DecisionOccurrence)(nil)).
		Column("sent_back_at").
		Where(`"de"."decision_id" = ?`, decision.ID).
		Where(`"de"."state" = ?`, Proposed).
		Where(`"de"."id" NOT IN (?)`, bun.List(ids)).
		Scan(ctx, &waiting); err != nil {
		return fmt.Errorf("read what of correction %d waits: %w", decision.ID, err)
	}
	var sentBack *time.Time
	for _, row := range waiting {
		if row.SentBackAt == nil {
			return nil
		}
		if sentBack == nil || row.SentBackAt.After(*sentBack) {
			sentBack = row.SentBackAt
		}
	}
	if sentBack == nil {
		return nil
	}
	if _, err := s.db.NewUpdate().Model((*DecisionOccurrence)(nil)).
		Set(`"sent_back_at" = ?`, *sentBack).
		Where(`"id" IN (?)`, bun.List(ids)).Exec(ctx); err != nil {
		return fmt.Errorf("return what correction %d answered to its author: %w", decision.ID, err)
	}
	return nil
}

// outsideAll reports whether a record's files are evidence the issue is not in
// the package: at least one file, and none under any of the paths.
func outsideAll(files, paths []string) bool {
	if len(files) == 0 {
		return false
	}
	for _, file := range files {
		for _, path := range paths {
			if cverecord.Under(file, path) {
				return false
			}
		}
	}
	return true
}

// unanswered reads which of these occurrences a correction already answers,
// by the key a correction holds an occurrence under.
func (s *Store) unanswered(ctx context.Context, covered []matchedThrough) (map[string]bool, error) {
	keys := make([]string, 0, len(covered))
	for _, at := range covered {
		keys = append(keys, at.key)
	}
	held := map[string]bool{}
	for start := 0; start < len(keys); start += database.BatchSize {
		var some []string
		if err := s.db.NewSelect().Model((*DecisionOccurrence)(nil)).
			Column("live_key").
			Where(`"de"."live_key" IN (?)`, bun.List(keys[start:min(start+database.BatchSize, len(keys))])).
			Scan(ctx, &some); err != nil {
			return nil, fmt.Errorf("read what is already corrected: %w", err)
		}
		for _, key := range some {
			held[key] = true
		}
	}
	return held, nil
}

// matchedThrough reads the open public findings of published issues at the
// correction's package, matched through its source, once per occurrence and
// filed under the issue each is read as.
func (s *Store) matchedThrough(ctx context.Context, rule SourceCorrection, buildID int64) ([]matchedThrough, error) {
	var rows []struct {
		ProductID          int64  `bun:"product_id"`
		VulnerabilityID    int64  `bun:"vulnerability_id"`
		OccurrenceIdentity string `bun:"occurrence_identity"`
		ComponentUpstream  string `bun:"component_upstream"`
		ConsumerUpstream   string `bun:"consumer_upstream"`
		Published          string `bun:"published_severity"`
		Assessed           string `bun:"assessed_severity"`
		ScoreCenti         int    `bun:"score_centi"`
		OnTag              int    `bun:"on_tag"`
	}
	query := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "build" AS "b" ON "b"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "b"."branch_or_tag_id"`).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "f"."vulnerability_id"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		Join(rating.For(rating.OnBranchOrTag)).
		ColumnExpr(`"st"."product_id" AS "product_id"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"f"."occurrence_identity" AS "occurrence_identity"`).
		ColumnExpr(finding.ComponentUpstreamExpr+` AS "component_upstream"`).
		ColumnExpr(finding.ConsumerUpstreamExpr+` AS "consumer_upstream"`).
		ColumnExpr(`COALESCE("v"."severity", '') AS "published_severity"`).
		ColumnExpr(`COALESCE("ir"."severity", '') AS "assessed_severity"`).
		ColumnExpr(`COALESCE("v"."score_centi", 0) AS "score_centi"`).
		ColumnExpr(`MAX(CASE WHEN "st"."kind" = ? THEN 1 ELSE 0 END) AS "on_tag"`, catalog.Tag).
		Where(`"st"."product_id" = ?`, rule.ProductID).
		Where(`"f"."closed_at" IS NULL`).
		Where(`"f"."kind" = ?`, finding.Vulnerable).
		Where(`"f"."visibility" = ?`, access.Public).
		Where(`"f"."matched_through" = ?`, rule.Source).
		Where(`COALESCE("c"."identifying_folded", "c"."name_folded") = ?`, rule.Package).
		GroupExpr(`"st"."product_id", "f"."vulnerability_id", "f"."occurrence_identity", ` +
			`"c"."upstream_version", "c"."version", "uc"."upstream_version", "uc"."version", ` +
			`"v"."severity", "ir"."severity", "v"."score_centi"`).
		OrderExpr(`"f"."vulnerability_id", "f"."occurrence_identity"`)
	if buildID != 0 {
		query = query.Where(`"f"."build_id" = ?`, buildID)
	}
	if err := query.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what is matched through %s: %w", rule.Source, err)
	}
	occurrences := make([]Occurrence, 0, len(rows))
	for _, row := range rows {
		occurrences = append(occurrences, Occurrence{
			ProductID: row.ProductID, VulnerabilityID: row.VulnerabilityID,
			OccurrenceIdentity: row.OccurrenceIdentity, Visibility: access.Public,
			ComponentUpstream: row.ComponentUpstream, ConsumerUpstream: row.ConsumerUpstream,
			OnTag: row.OnTag == 1,
		})
	}
	stood, err := s.asTheyStand(ctx, occurrences)
	if err != nil {
		return nil, err
	}
	// One row per occurrence: builds holding it at two versions read it twice,
	// and a correction is keyed without the versions.
	seen := map[string]bool{}
	covered := make([]matchedThrough, 0, len(stood))
	for i, at := range stood {
		key := liveKeyFor(at, true)
		if seen[key] {
			continue
		}
		seen[key] = true
		covered = append(covered, matchedThrough{
			resolved: resolved{Occurrence: at, SeverityCenti: finding.Rating{
				Published: rows[i].Published, Assessed: rows[i].Assessed, ScoreCenti: rows[i].ScoreCenti,
			}.Score()},
			key: key,
		})
	}
	return covered, nil
}
