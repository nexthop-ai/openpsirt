// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// ErrRecordedAsFlaw refuses a decision about a code finding recorded as a flaw, and a
// second flaw record of it.
var ErrRecordedAsFlaw = triage.ErrCodeFindingRecordedAsFlaw

// ErrNotConfirmed refuses a flaw record of a code finding nobody confirmed.
var ErrNotConfirmed = refusal.New("only a confirmed code finding is recorded as a flaw: confirm it first")

// ErrNotRecordedAsFlaw refuses an inclusion, a removal or a grant on a code finding that was not
// recorded as a flaw.
var ErrNotRecordedAsFlaw = refusal.New("that code finding was not recorded as a flaw")

// ErrAlreadyIncluded and ErrNotIncluded refuse including a code finding already included in
// its flaw's disclosure and taking out one that is internal only.
var (
	ErrAlreadyIncluded = refusal.New("that code finding is already included in its flaw's disclosure")
	ErrNotIncluded     = refusal.New("that code finding is internal only, so there is nothing to take out of disclosure")
)

// ErrFlawDisclosed refuses including a code finding in or taking it out of a flaw's
// disclosure once the flaw is disclosed, and a change to who is granted it. Disclosure is one way.
var ErrFlawDisclosed = refusal.New("that code finding's flaw is disclosed, so the code finding stays where it is")

// MostSuggestions bounds the components offered as resembling a code finding's
// directory.
const MostSuggestions = 5

// Source is where a component offered when recording a flaw came from.
type Source string

const (
	// FromConfirmed is the component a path prefix holding the code finding was
	// confirmed as when a flaw was recorded earlier.
	FromConfirmed Source = "confirmed"
	// FromPlacement is the component the code finding was placed on as it arrived:
	// the one whose package identifier names the code finding's repository.
	FromPlacement Source = "placed"
	// FromResemblance is a component whose name resembles the code finding's
	// directory, offered and never chosen for the person.
	FromResemblance Source = "resembles"
	// FromBuild is the build itself, for code in no component.
	FromBuild Source = "build"
)

// Sources is every source a suggestion comes from, in the order they rank.
func Sources() []Source { return []Source{FromConfirmed, FromPlacement, FromResemblance, FromBuild} }

// BuildName is one build by the names that address it.
type BuildName struct {
	TargetID int64  `bun:"target_id"`
	Stream   string `bun:"stream"`
	Variant  string `bun:"variant"`
}

// Suggestion is a component offered when recording a flaw. An empty Component is the
// build itself.
type Suggestion struct {
	Component string
	Ecosystem string
	Namespace string
	From      Source
	// Lacking is the builds the code finding was seen in that hold no such
	// component: recording the flaw against them is refused.
	Lacking []BuildName
	// Unanalyzed is the builds that hold the component and that the code finding's
	// series never analyzed. A variant nobody analyzes ships the same code.
	Unanalyzed []BuildName
}

// Note is one piece of writing on a decision about a code finding: a revision of its
// reasoning or a comment.
type Note struct {
	DecisionID int64
	Comment    bool
	Body       string
	WrittenAt  time.Time
}

// Authored is what one person wrote about a code finding, oldest first.
type Authored struct {
	PersonID int64
	Notes    []Note
}

// Said is one message the analyzer wrote at a path.
type Said struct {
	Path    string
	Message string
}

// Disclosure is what including a code finding in its flaw's disclosure discloses with the
// flaw (REQ-40).
type Disclosure struct {
	// Authors is everybody who wrote reasoning or a comment on a decision about
	// the code finding or the code findings linked with it, with what each wrote.
	Authors []Authored
	// Paths is every path the code finding names, and Said every message the
	// analyzer wrote at them.
	Paths []string
	Said  []Said
	// Snippets is how many snippets the product discloses with the flaw,
	// and Stripped how many it strips at disclosure.
	Snippets int
	Stripped int
}

// Offer is what a flaw record of one code finding is offered.
type Offer struct {
	Rule string
	// Seen is every build the code finding was seen in, which the flaw is proposed
	// against.
	Seen        []BuildName
	Suggestions []Suggestion
	// Prefix is the path a confirmed component is learned for: the
	// repository or declared third-party path the code finding is in, or its
	// directory.
	Prefix string
	// ThirdParty says the code finding is under a path its newest run declared as
	// third-party code, so the flaw is reported to the upstream it came from.
	ThirdParty bool
	// Together is how many other code findings the flaw record links to the flaw with
	// this one: the code findings its confirming decision covers, which are included in
	// or taken out of disclosure with it.
	Together  int
	Discloses Disclosure
}

// codeFinding is what a flaw record reads about the code finding at an occurrence.
type codeFinding struct {
	ID          int64  `bun:"id"`
	TargetID    int64  `bun:"target_id"`
	ComponentID int64  `bun:"component_id"`
	Path        string `bun:"path"`
	Rule        string `bun:"rule"`
	LastRunID   int64  `bun:"last_run_id"`
	SeriesID    int64  `bun:"series_id"`
}

// learned is the component a path prefix was confirmed as.
type learned struct {
	bun.BaseModel `bun:"table:code_finding_component,alias:lco"`

	ID             int64     `bun:"id,pk,autoincrement"`
	ProductID      int64     `bun:"product_id,notnull"`
	Prefix         string    `bun:"prefix,notnull"`
	PrefixIdentity string    `bun:"prefix_identity,notnull"`
	Under          string    `bun:"under,notnull"`
	UnderLength    int       `bun:"under_length,notnull"`
	Component      string    `bun:"component,notnull"`
	Ecosystem      string    `bun:"ecosystem,nullzero"`
	Namespace      string    `bun:"namespace,nullzero"`
	ConfirmedBy    int64     `bun:"confirmed_by,notnull"`
	ConfirmedAt    time.Time `bun:"confirmed_at,notnull"`
}

// MayRecordAsFlaw refuses somebody who may not record a code finding as a flaw, include it
// in disclosure or take it out: it takes triage of the internal code finding and of the private
// flaw. Asked before any name a request carries is resolved.
func MayRecordAsFlaw(subject access.Subject, productID int64) error {
	if !subject.Triages(access.Internal, productID) || !subject.Triages(access.Private, productID) {
		return access.Denied(fmt.Sprintf("record as a flaw a code finding in product %d", productID))
	}
	return nil
}

// newestCodeFinding is the newest finding of the code finding at an occurrence in a product that
// the subject reads in full, with what a flaw record needs of it.
func newestCodeFinding(ctx context.Context, db bun.IDB, subject access.Subject, productID int64,
	occurrenceIdentity string) (*codeFinding, error) {

	reach := finding.CodeFindingReach(subject, productID)
	kinds, kindArgs := kind.CodeFindings.Where(`"f"."kind"`)
	var out codeFinding
	err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
		Join(`JOIN "vulnerability" AS "vu" ON "vu"."id" = "f"."vulnerability_id"`).
		Join(`JOIN "target" AS "t" ON "t"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
		ColumnExpr(`"f"."id", "f"."target_id", "f"."component_id", "ar"."path"`).
		ColumnExpr(`"vu"."identifier" AS "rule", "si"."last_run_id", "si"."series_id"`).
		Where(`"s"."product_id" = ?`, productID).
		Where(`"f"."occurrence_identity" = ?`, occurrenceIdentity).
		Where(reach.Full, reach.FullArgs...).
		Where(kinds, kindArgs...).
		OrderExpr(`"f"."id" DESC`).Limit(1).
		Scan(ctx, &out)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, finding.ErrNoOpenFinding
	case err != nil:
		return nil, fmt.Errorf("read the code finding at that occurrence: %w", err)
	}
	return &out, nil
}

// confirmedAt reports whether a decision confirming the code finding at an occurrence stands.
func confirmedAt(ctx context.Context, db bun.IDB, productID, findingID int64) (bool, error) {
	var outcome *string
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		ColumnExpr(standingOutcome+` AS "outcome"`, productID).
		Where(`"f"."id" = ?`, findingID).
		Scan(ctx, &outcome); err != nil {
		return false, fmt.Errorf("read the decision standing at the code finding: %w", err)
	}
	return outcome != nil && *outcome == string(Confirmed), nil
}

// stampedDecision is a decision and the stamp it was read with.
type stampedDecision struct {
	ID    int64 `bun:"id"`
	Stamp int   `bun:"stamp"`
}

// decisionsAt is every decision with a live row at the occurrence of a code finding finding, in
// a product, with the stamp each holds: zero for a decision nobody has stamped.
func decisionsAt(ctx context.Context, db bun.IDB, productID, findingID int64) ([]stampedDecision, error) {
	var out []stampedDecision
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "decision_occurrence" AS "dc" ON `+finding.DecisionOccurrenceFiledAt("dc", "f")).
		Join(`JOIN "decision" AS "sc" ON "sc"."id" = "dc"."decision_id"`).
		Join(`LEFT JOIN "decision_stamp" AS "cst" ON "cst"."decision_id" = "sc"."id"`).
		ColumnExpr(`DISTINCT "sc"."id", COALESCE("cst"."stamp", 0) AS "stamp"`).
		Where(`"f"."id" = ?`, findingID).
		Where(`"dc"."product_id" = ?`, productID).
		Where(`"dc"."live_key" IS NOT NULL`).
		OrderExpr(`"sc"."id" ASC`).
		Scan(ctx, &out); err != nil {
		return nil, fmt.Errorf("read the decisions standing at the code finding: %w", err)
	}
	return out, nil
}

// Propose is what recording as a flaw the code finding at an occurrence in a product is offered:
// the components, ranked, the builds it was seen in, and what including it in
// its flaw's disclosure would disclose.
func Propose(ctx context.Context, db bun.IDB, subject access.Subject, productID int64,
	occurrenceIdentity string) (*Offer, error) {

	if err := MayRecordAsFlaw(subject, productID); err != nil {
		return nil, err
	}
	l, err := newestCodeFinding(ctx, db, subject, productID, occurrenceIdentity)
	if err != nil {
		return nil, err
	}
	run, modules, err := runAndModules(ctx, series.NewStore(db), l.LastRunID)
	if err != nil {
		return nil, err
	}
	declared := declaredThirdParty(run, l.Path)
	out := &Offer{Rule: l.Rule, Prefix: prefixOf(l.Path, modules, declared), ThirdParty: declared != ""}
	if out.Seen, err = seenIn(ctx, db, productID, occurrenceIdentity); err != nil {
		return nil, err
	}

	offered := map[string]bool{}
	offer := func(s Suggestion) {
		key := graph.Folded(s.Component) + "\x00" + s.Ecosystem + "\x00" + s.Namespace
		if offered[key] {
			return
		}
		offered[key] = true
		out.Suggestions = append(out.Suggestions, s)
	}
	if prior, err := learnedFor(ctx, db, productID, l.Path); err != nil {
		return nil, err
	} else if prior != nil {
		offer(Suggestion{Component: prior.Component, Ecosystem: prior.Ecosystem,
			Namespace: prior.Namespace, From: FromConfirmed})
	}
	placed, root, err := componentOf(ctx, db, l.TargetID, l.ComponentID)
	if err != nil {
		return nil, err
	}
	if !root {
		offer(Suggestion{Component: placed.Name, Ecosystem: graph.EcosystemOf(placed.Purl),
			Namespace: graph.NamespaceOf(placed.Purl), From: FromPlacement})
	}
	alike, err := resembling(ctx, db, l.TargetID, out.Prefix)
	if err != nil {
		return nil, err
	}
	for _, c := range alike {
		offer(Suggestion{Component: c.Name, Ecosystem: graph.EcosystemOf(c.Purl),
			Namespace: graph.NamespaceOf(c.Purl), From: FromResemblance})
	}
	offer(Suggestion{From: FromBuild})

	for i := range out.Suggestions {
		s := &out.Suggestions[i]
		if s.Component == "" {
			continue
		}
		choice := graph.Choice{Ecosystem: s.Ecosystem, Namespace: s.Namespace}
		for _, b := range out.Seen {
			_, err := graph.ComponentAsIn(ctx, db, b.TargetID, s.Component, choice)
			var several *graph.Ambiguous
			switch {
			case errors.Is(err, graph.ErrNoComponent):
				s.Lacking = append(s.Lacking, b)
			case errors.As(err, &several), err == nil:
			default:
				return nil, err
			}
		}
		if s.Unanalyzed, err = unanalyzed(ctx, db, productID, l.SeriesID, s.Component, choice); err != nil {
			return nil, err
		}
	}
	together, err := togetherAt(ctx, db, productID, occurrenceIdentity)
	if err != nil {
		return nil, err
	}
	out.Together = len(together) - 1
	if out.Discloses, err = disclosing(ctx, db, subject, productID, together); err != nil {
		return nil, err
	}
	return out, nil
}

// togetherAt is the occurrences of the code findings recorded as a flaw with the code finding at an occurrence,
// that occurrence first. A code finding recorded as a flaw goes with every code finding recorded as its
// flaw; one not recorded as a flaw yet, with every code finding the decision confirming it
// covers that nobody recorded as a flaw.
func togetherAt(ctx context.Context, db bun.IDB, productID int64, occurrenceIdentity string) ([]string, error) {
	recorded, err := finding.CodeFindingFlawAt(ctx, db, productID, occurrenceIdentity)
	if err != nil {
		return nil, err
	}
	var others []string
	if recorded != nil {
		if err := db.NewSelect().Model((*finding.CodeFindingFlaw)(nil)).
			Column("lh.occurrence_identity").
			Where(`"lh"."product_id" = ?`, productID).
			Where(`"lh"."vulnerability_id" = ?`, recorded.VulnerabilityID).
			Where(`"lh"."occurrence_identity" <> ?`, occurrenceIdentity).
			OrderExpr(`"lh"."id" ASC`).
			Scan(ctx, &others); err != nil {
			return nil, fmt.Errorf("read the code findings recorded as the flaw: %w", err)
		}
		return append([]string{occurrenceIdentity}, others...), nil
	}
	if err := db.NewSelect().TableExpr(`"decision_occurrence" AS "dc"`).
		Join(`JOIN "vulnerability" AS "rv" ON "rv"."id" = "dc"."vulnerability_id"`).
		Join(`JOIN "decision" AS "sc" ON "sc"."id" = "dc"."decision_id"`).
		Join(`JOIN "decision_occurrence" AS "od" ON "od"."decision_id" = "dc"."decision_id" AND "od"."product_id" = "dc"."product_id"`).
		Join(`JOIN "vulnerability" AS "ov" ON "ov"."id" = "od"."vulnerability_id"`).
		ColumnExpr(`DISTINCT "od"."occurrence_identity"`).
		Where(`"dc"."product_id" = ?`, productID).
		Where(`"dc"."occurrence_identity" = ?`, occurrenceIdentity).
		Where(`"rv"."kind" = ?`, string(kind.Rule)).
		Where(`"sc"."outcome" = ?`, string(Confirmed)).
		Where(`"dc"."live_key" IS NOT NULL`).
		Where(`("dc"."state" = 'approved' OR ("dc"."needs_approval" = FALSE AND "dc"."sent_back_at" IS NULL))`).
		Where(`"ov"."kind" = ?`, string(kind.Rule)).
		Where(`"od"."live_key" IS NOT NULL`).
		Where(`"od"."occurrence_identity" <> ?`, occurrenceIdentity).
		Where(`NOT EXISTS (SELECT 1 FROM "code_finding_flaw" AS "lh"
			WHERE "lh"."product_id" = "od"."product_id" AND "lh"."occurrence_identity" = "od"."occurrence_identity")`).
		OrderExpr(`"od"."occurrence_identity" ASC`).
		Scan(ctx, &others); err != nil {
		return nil, fmt.Errorf("read the code findings confirmed with the code finding: %w", err)
	}
	return append([]string{occurrenceIdentity}, others...), nil
}

// recordedWith is every flaw record of the flaw a flaw record links, in one product,
// as the transaction reads them: the code findings included in or taken out of disclosure together.
func recordedWith(ctx context.Context, tx bun.IDB, h *finding.CodeFindingFlaw) ([]finding.CodeFindingFlaw, error) {
	var rows []finding.CodeFindingFlaw
	if err := tx.NewSelect().Model(&rows).
		Where(`"lh"."product_id" = ?`, h.ProductID).
		Where(`"lh"."vulnerability_id" = ?`, h.VulnerabilityID).
		OrderExpr(`"lh"."id" ASC`).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the code findings recorded as the flaw: %w", err)
	}
	return rows, nil
}

// prefixOf is the path a component confirmed for a code finding at a path is learned
// for: the innermost of the repositories the run names and the third-party
// path it declared that holds it, or else the file's directory. Empty where
// the file is at the top of the checkout.
//
// A declared path is a prefix in its own right, as a repository is: vendored
// code copied into the tree has no repository of its own, and every file under
// it is the one component.
func prefixOf(at string, modules []series.Module, declared string) string {
	best := declared
	for _, m := range modules {
		if holds(m.Path, at) && len(m.Path) > len(best) {
			best = m.Path
		}
	}
	if best != "" {
		return best
	}
	if dir := path.Dir(at); dir != "." && dir != "/" {
		return dir
	}
	return ""
}

// learnedFor is the component the longest learned prefix holding a path was
// confirmed as, or nil where none holds it.
func learnedFor(ctx context.Context, db bun.IDB, productID int64, at string) (*learned, error) {
	var rows []learned
	if err := db.NewSelect().Model(&rows).
		Where(`"lco"."product_id" = ?`, productID).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the components paths were confirmed as: %w", err)
	}
	var best *learned
	for i, r := range rows {
		if (at == r.Prefix || strings.HasPrefix(at, r.Under)) && (best == nil || len(r.Prefix) > len(best.Prefix)) {
			best = &rows[i]
		}
	}
	return best, nil
}

// named is a component by what a build calls it.
type named struct {
	Name string `bun:"name"`
	Purl string `bun:"purl"`
}

// componentOf is a component, and whether it is what a build is.
func componentOf(ctx context.Context, db bun.IDB, targetID, componentID int64) (named, bool, error) {
	var out named
	if err := db.NewSelect().TableExpr(`"component" AS "c"`).
		ColumnExpr(`"c"."name", "c"."purl"`).
		Where(`"c"."id" = ?`, componentID).
		Scan(ctx, &out); err != nil {
		return out, false, fmt.Errorf("read the component the code finding is on: %w", err)
	}
	root, err := db.NewSelect().TableExpr(`"graph_node" AS "n"`).
		Where(`"n"."target_id" = ?`, targetID).
		Where(`"n"."component_id" = ?`, componentID).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`"n"."is_root" = ?`, true).
		Exists(ctx)
	if err != nil {
		return out, false, fmt.Errorf("read whether the code finding is on the build itself: %w", err)
	}
	return out, root, nil
}

// resembling is the components a build holds whose names resemble the last
// segment of a directory, the closest first.
func resembling(ctx context.Context, db bun.IDB, targetID int64, dir string) ([]named, error) {
	base := strings.ToLower(path.Base(dir))
	if dir == "" || len(base) < 3 {
		return nil, nil
	}
	var held []named
	if err := db.NewSelect().TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "n"."component_id"`).
		ColumnExpr(`DISTINCT "c"."name", "c"."purl"`).
		Where(`"n"."target_id" = ?`, targetID).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`"n"."is_root" = ?`, false).
		Scan(ctx, &held); err != nil {
		return nil, fmt.Errorf("read the components the build holds: %w", err)
	}
	type scored struct {
		named
		distance int
	}
	var alike []scored
	for _, c := range held {
		name := strings.ToLower(c.Name)
		if len(name) < 3 || (!strings.Contains(name, base) && !strings.Contains(base, name)) {
			continue
		}
		distance := len(name) - len(base)
		if distance < 0 {
			distance = -distance
		}
		alike = append(alike, scored{c, distance})
	}
	sort.SliceStable(alike, func(i, j int) bool {
		if alike[i].distance != alike[j].distance {
			return alike[i].distance < alike[j].distance
		}
		return alike[i].Name < alike[j].Name
	})
	out := make([]named, 0, min(len(alike), MostSuggestions))
	for _, a := range alike {
		if len(out) == MostSuggestions {
			break
		}
		out = append(out, a.named)
	}
	return out, nil
}

// seenIn is every build of a product holding a finding of the code finding at an
// occurrence, open or closed.
func seenIn(ctx context.Context, db bun.IDB, productID int64, occurrenceIdentity string) ([]BuildName, error) {
	kinds, kindArgs := kind.CodeFindings.Where(`"f"."kind"`)
	var out []BuildName
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "t" ON "t"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "t"."variant_id"`).
		ColumnExpr(`DISTINCT "t"."id" AS "target_id", "s"."name" AS "stream", "va"."name" AS "variant"`).
		Where(`"s"."product_id" = ?`, productID).
		Where(`"f"."occurrence_identity" = ?`, occurrenceIdentity).
		Where(kinds, kindArgs...).
		OrderExpr(`"s"."name" ASC, "va"."name" ASC`).
		Scan(ctx, &out); err != nil {
		return nil, fmt.Errorf("read the builds the code finding was seen in: %w", err)
	}
	return out, nil
}

// unanalyzed is the builds of a product in use that hold a component and that
// a series never ran against.
func unanalyzed(ctx context.Context, db bun.IDB, productID, seriesID int64, component string,
	choice graph.Choice) ([]BuildName, error) {

	var rows []struct {
		BuildName
		Version string `bun:"version"`
		Purl    string `bun:"purl"`
	}
	if err := db.NewSelect().TableExpr(`"target" AS "t"`).
		Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "t"."variant_id"`).
		Join(`JOIN "graph_node" AS "n" ON "n"."target_id" = "t"."id"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "n"."component_id"`).
		ColumnExpr(`"t"."id" AS "target_id", "s"."name" AS "stream", "va"."name" AS "variant"`).
		ColumnExpr(`"c"."version", "c"."purl"`).
		Where(`"s"."product_id" = ?`, productID).
		Where(`"s"."retired_at" IS NULL`).
		Where(`"va"."retired_at" IS NULL`).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`"c"."name_folded" = ?`, graph.Folded(component)).
		Where(`NOT EXISTS (SELECT 1 FROM "series_run" AS "sr" WHERE "sr"."target_id" = "t"."id" AND "sr"."series_id" = ?)`,
			seriesID).
		OrderExpr(`"s"."name" ASC, "va"."name" ASC`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the builds holding %q that were never analyzed: %w", component, err)
	}
	var out []BuildName
	seen := map[int64]bool{}
	for _, r := range rows {
		if seen[r.TargetID] {
			continue
		}
		if len(graph.Narrowed(choice, []graph.Choice{graph.ChoiceOf(r.Version, r.Purl)})) == 0 {
			continue
		}
		seen[r.TargetID] = true
		out = append(out, r.BuildName)
	}
	return out, nil
}

// disclosing is what disclosing the code findings at these occurrences in a product with
// their flaw discloses. The writing on decisions is read at the visibilities the
// subject reads in the product.
func disclosing(ctx context.Context, db bun.IDB, subject access.Subject, productID int64,
	occurrences []string) (Disclosure, error) {

	var out Disclosure
	visible := []access.Visibility{}
	if subject.Sees(productID) {
		visible = access.Visible(subject, productID)
	}
	if len(visible) > 0 {
		decisions := `SELECT "dc"."decision_id" FROM "decision_occurrence" AS "dc"
			JOIN "vulnerability" AS "rv" ON "rv"."id" = "dc"."vulnerability_id"
			WHERE "dc"."product_id" = ? AND "dc"."occurrence_identity" IN (?) AND "rv"."kind" = ?
			  AND "dc"."visibility" IN (?)`
		decisionArgs := []any{productID, bun.List(occurrences), string(kind.Rule), bun.List(visible)}
		var notes []struct {
			PersonID   int64     `bun:"person_id"`
			DecisionID int64     `bun:"decision_id"`
			Comment    int       `bun:"comment"`
			Body       string    `bun:"body"`
			WrittenAt  time.Time `bun:"written_at"`
		}
		if err := db.NewSelect().
			TableExpr(`(SELECT "cr"."written_by" AS "person_id", "cr"."decision_id", 0 AS "comment", "cr"."body",
					"cr"."written_at" FROM "decision_revision" AS "cr"
				WHERE "cr"."decision_id" IN (`+decisions+`)
				UNION ALL SELECT "cm"."written_by" AS "person_id", "cm"."decision_id", 1 AS "comment", "cm"."body",
					"cm"."written_at" FROM "decision_comment" AS "cm"
				WHERE "cm"."decision_id" IN (`+decisions+`)) AS "w"`, append(decisionArgs, decisionArgs...)...).
			ColumnExpr(`"w"."person_id", "w"."decision_id", "w"."comment", "w"."body", "w"."written_at"`).
			OrderExpr(`"w"."person_id" ASC, "w"."written_at" ASC, "w"."decision_id" ASC, "w"."comment" ASC`).
			Scan(ctx, &notes); err != nil {
			return out, fmt.Errorf("read what was written about the code finding: %w", err)
		}
		for _, n := range notes {
			if len(out.Authors) == 0 || out.Authors[len(out.Authors)-1].PersonID != n.PersonID {
				out.Authors = append(out.Authors, Authored{PersonID: n.PersonID})
			}
			last := &out.Authors[len(out.Authors)-1]
			last.Notes = append(last.Notes, Note{DecisionID: n.DecisionID, Comment: n.Comment == 1, Body: n.Body,
				WrittenAt: n.WrittenAt})
		}
	}

	config, err := sourcelink.NewStore(db).Config(ctx, productID)
	if err != nil {
		return out, err
	}
	kinds, kindArgs := kind.CodeFindings.Where(`"f"."kind"`)
	type spoken struct {
		Path    string `bun:"path"`
		Message string `bun:"message_text"`
		Snippet *bool  `bun:"snippet"`
	}
	var said []spoken
	from := func(table, alias, message string) *bun.SelectQuery {
		return db.NewSelect().TableExpr(`"`+table+`" AS "`+alias+`"`).
			Join(`JOIN "finding" AS "f" ON "f"."id" = "`+alias+`"."finding_id"`).
			Join(`JOIN "target" AS "t" ON "t"."id" = "f"."target_id"`).
			Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
			ColumnExpr(`COALESCE("`+alias+`"."path", '') AS "path", "`+alias+`"."`+message+`" AS "message_text"`).
			ColumnExpr(`CASE WHEN "`+alias+`"."snippet" IS NULL THEN NULL ELSE TRUE END AS "snippet"`).
			Where(`"s"."product_id" = ?`, productID).
			Where(`"f"."occurrence_identity" IN (?)`, bun.List(occurrences)).
			Where(kinds, kindArgs...)
	}
	for _, q := range []*bun.SelectQuery{from("analysis_result", "ar", "message_text"),
		from("analysis_location", "al", "message_text")} {
		var some []spoken
		if err := q.Scan(ctx, &some); err != nil {
			return out, fmt.Errorf("read what the code finding names: %w", err)
		}
		said = append(said, some...)
	}
	paths := map[string]bool{}
	written := map[Said]bool{}
	for _, s := range said {
		if s.Path != "" && !paths[s.Path] {
			paths[s.Path] = true
			out.Paths = append(out.Paths, s.Path)
		}
		if one := (Said{Path: s.Path, Message: s.Message}); s.Message != "" && !written[one] {
			written[one] = true
			out.Said = append(out.Said, one)
		}
		if s.Snippet != nil {
			if s.Path != "" && config.DisclosesSnippets(s.Path) {
				out.Snippets++
			} else {
				out.Stripped++
			}
		}
	}
	sort.Strings(out.Paths)
	sort.Slice(out.Said, func(i, j int) bool {
		if out.Said[i].Path != out.Said[j].Path {
			return out.Said[i].Path < out.Said[j].Path
		}
		return out.Said[i].Message < out.Said[j].Message
	})
	return out, nil
}

// Recording is a flaw record of one code finding: the flaw to record and whether the code finding
// is included in its flaw's disclosure.
type Recording struct {
	ProductID          int64
	OccurrenceIdentity string
	// Flaw is the flaw as the recorded-flaw path takes it, with the builds
	// a person confirmed and the component they chose.
	Flaw                finding.Entering
	IncludeInDisclosure bool
}

// Recorded is a flaw recorded from a code finding: the identifier it was filed under,
// the component carrying it, and how many builds and occurrences it opened at.
type Recorded struct {
	Identifier  string
	Component   string
	Builds      int
	Occurrences int
}

// RecordAsFlaw records a confirmed code finding as a flaw here, through the path every
// recorded flaw takes, and links it and every code finding its confirming decision
// covers to the flaw in the same transaction. The component chosen is learned
// for the code finding's prefix, and the code findings are included in its flaw's disclosure where the person
// asked.
func RecordAsFlaw(ctx context.Context, db bun.IDB, subject access.Subject, in Recording) (*Recorded, error) {
	if err := MayRecordAsFlaw(subject, in.ProductID); err != nil {
		return nil, err
	}
	in.Flaw.Disclosed = false
	in.Flaw.Told = finding.Told{FoundHere: true}
	in.Flaw.FromReport = ""
	in.Flaw.Version = ""
	in.Flaw.Then = func(ctx context.Context, tx bun.IDB, vulnerabilityID int64, now time.Time) error {
		// Read again here: whether the code finding still stands confirmed and
		// not recorded as a flaw is a fact a retry asks again.
		l, err := newestCodeFinding(ctx, tx, subject, in.ProductID, in.OccurrenceIdentity)
		if err != nil {
			return err
		}
		// The decisions standing at the code finding, with the stamps they hold, read
		// before whether one confirms it. Restamped once it does, so a
		// revision or withdrawal of the confirmation committing beside this
		// matches nothing, or makes this match nothing, and is asked again.
		standing, err := decisionsAt(ctx, tx, in.ProductID, l.ID)
		if err != nil {
			return err
		}
		if err := finding.CodeFindingEnded(ctx, tx, in.ProductID, in.OccurrenceIdentity, now); err != nil {
			return err
		}
		if recorded, err := finding.CodeFindingFlawAt(ctx, tx, in.ProductID, in.OccurrenceIdentity); err != nil {
			return err
		} else if recorded != nil {
			return ErrRecordedAsFlaw
		}
		if ok, err := confirmedAt(ctx, tx, in.ProductID, l.ID); err != nil {
			return err
		} else if !ok {
			return ErrNotConfirmed
		}
		for _, c := range standing {
			if err := triage.Restamp(ctx, tx, c.ID, c.Stamp); err != nil {
				return err
			}
		}
		// What the flaw record is offered, read in the transaction recording
		// it: the flaw keeps the component ranked first and the builds
		// proposed beside the code finding it was recorded from.
		offer, err := Propose(ctx, tx, subject, in.ProductID, in.OccurrenceIdentity)
		if err != nil {
			return err
		}
		// Every code finding the confirming decision covers is the one flaw, and is
		// linked to it: a code finding of the group left behind holds a decision
		// nothing may change and no flaw.
		together, err := togetherAt(ctx, tx, in.ProductID, in.OccurrenceIdentity)
		if err != nil {
			return err
		}
		rows := make([]*finding.CodeFindingFlaw, 0, len(together))
		for _, occurrence := range together {
			row := &finding.CodeFindingFlaw{
				ProductID: in.ProductID, OccurrenceIdentity: occurrence, VulnerabilityID: vulnerabilityID,
				Visibility: access.Internal, RecordedBy: subject.ID, RecordedAt: now,
			}
			if _, err := tx.NewInsert().Model(row).Exec(ctx); err != nil {
				if database.IsDuplicate(err) {
					return ErrRecordedAsFlaw
				}
				return fmt.Errorf("link the code finding to its flaw: %w", err)
			}
			rows = append(rows, row)
		}
		run, modules, err := runAndModules(ctx, series.NewStore(tx), l.LastRunID)
		if err != nil {
			return err
		}
		prefix := prefixOf(l.Path, modules, declaredThirdParty(run, l.Path))
		if err := learn(ctx, tx, in.ProductID, prefix, strings.TrimSpace(in.Flaw.Component),
			strings.TrimSpace(in.Flaw.Ecosystem), strings.TrimSpace(in.Flaw.Namespace), subject.ID, now); err != nil {
			return err
		}
		if err := recordOrigin(ctx, tx, in.ProductID, in.OccurrenceIdentity, vulnerabilityID, offer, in.Flaw,
			subject.ID, now); err != nil {
			return err
		}
		if in.IncludeInDisclosure {
			for _, row := range rows {
				if err := includeIn(ctx, tx, subject, row, now); err != nil {
					return err
				}
			}
		}
		return nil
	}
	store := finding.NewStore(db)
	rows, identifier, err := store.Enter(ctx, subject, in.Flaw)
	if err != nil {
		return nil, err
	}
	component, err := store.ComponentName(ctx, rows[0].ComponentID)
	if err != nil {
		return nil, err
	}
	builds := map[int64]bool{}
	for _, row := range rows {
		builds[row.TargetID] = true
	}
	return &Recorded{Identifier: identifier, Component: component, Builds: len(builds), Occurrences: len(rows)}, nil
}

// Answerable refuses a decision about a code finding the subject no longer reads in
// full, or one recorded as a flaw, which is judged instead. Asked inside the
// transaction writing the decision.
func Answerable(ctx context.Context, tx bun.IDB, subject access.Subject, productID int64, codeFinding *finding.Finding) error {
	reach := finding.CodeFindingReach(subject, productID)
	read, err := tx.NewSelect().TableExpr(`"finding" AS "f"`).
		Where(`"f"."id" = ?`, codeFinding.ID).
		Where(reach.Full, reach.FullArgs...).
		Exists(ctx)
	if err != nil {
		return fmt.Errorf("read whether code finding %d may be judged: %w", codeFinding.ID, err)
	}
	if !read {
		return finding.ErrNoOpenFinding
	}
	recorded, err := finding.CodeFindingFlawAt(ctx, tx, productID, codeFinding.OccurrenceIdentity)
	if err != nil {
		return err
	}
	if recorded != nil {
		return ErrRecordedAsFlaw
	}
	return finding.CodeFindingEnded(ctx, tx, productID, codeFinding.OccurrenceIdentity, time.Now().UTC())
}

// learn records the component a path prefix was confirmed as, replacing what
// it was confirmed as before. The build itself is an empty component, and
// leaves the prefix confirmed as nothing.
func learn(ctx context.Context, tx bun.IDB, productID int64, prefix, component, ecosystem, namespace string,
	by int64, now time.Time) error {

	if prefix == "" {
		return nil
	}
	ident := pathIdentity(prefix)
	if _, err := tx.NewDelete().Model((*learned)(nil)).
		Where(`"product_id" = ?`, productID).
		Where(`"prefix_identity" = ?`, ident).
		Exec(ctx); err != nil {
		return fmt.Errorf("let go of what the prefix was confirmed as: %w", err)
	}
	if component == "" {
		return nil
	}
	row := &learned{
		ProductID: productID, Prefix: prefix, PrefixIdentity: ident,
		Under: prefix + "/", UnderLength: len([]rune(prefix)) + 1,
		Component: component, Ecosystem: ecosystem, Namespace: namespace,
		ConfirmedBy: by, ConfirmedAt: now,
	}
	if _, err := tx.NewInsert().Model(row).Exec(ctx); err != nil {
		// Two flaw records under one new prefix at once: the second deleted
		// nothing, and its retry replaces the first's.
		if database.IsDuplicate(err) {
			return database.ErrGoAgain
		}
		return fmt.Errorf("record what the prefix was confirmed as: %w", err)
	}
	return nil
}

// IncludeInDisclosure includes an internal-only code finding in its flaw's disclosure while the flaw is undisclosed,
// and every code finding recorded as the flaw with it.
func IncludeInDisclosure(ctx context.Context, db bun.IDB, subject access.Subject, productID int64, occurrenceIdentity string,
	now time.Time) error {

	if err := MayRecordAsFlaw(subject, productID); err != nil {
		return err
	}
	return database.Within(ctx, db, func(ctx context.Context, tx bun.IDB) error {
		h, err := recordedFor(ctx, tx, subject, productID, occurrenceIdentity)
		if err != nil {
			return err
		}
		switch {
		case h.Disclosed():
			return ErrFlawDisclosed
		case h.Included():
			return ErrAlreadyIncluded
		}
		with, err := recordedWith(ctx, tx, h)
		if err != nil {
			return err
		}
		at := now.UTC().Truncate(time.Microsecond)
		for i := range with {
			if with[i].Included() || with[i].Disclosed() {
				continue
			}
			if err := includeIn(ctx, tx, subject, &with[i], at); err != nil {
				return err
			}
		}
		return nil
	})
}

// ExcludeFromDisclosure takes an included code finding out of its flaw's disclosure while the flaw is
// undisclosed, and every code finding recorded as the flaw with it: the flaw's
// readers who read it only through its disclosure read it no longer.
func ExcludeFromDisclosure(ctx context.Context, db bun.IDB, subject access.Subject, productID int64, occurrenceIdentity string) error {
	if err := MayRecordAsFlaw(subject, productID); err != nil {
		return err
	}
	return database.Within(ctx, db, func(ctx context.Context, tx bun.IDB) error {
		h, err := recordedFor(ctx, tx, subject, productID, occurrenceIdentity)
		if err != nil {
			return err
		}
		switch {
		case h.Disclosed():
			return ErrFlawDisclosed
		case !h.Included():
			return ErrNotIncluded
		}
		with, err := recordedWith(ctx, tx, h)
		if err != nil {
			return err
		}
		for i := range with {
			if !with[i].Included() || with[i].Disclosed() {
				continue
			}
			if err := excludeFrom(ctx, tx, subject, &with[i]); err != nil {
				return err
			}
		}
		return nil
	})
}

// excludeFrom takes an included code finding out of its flaw's disclosure, and the undo is
// recorded as the access change it is. The code finding and the decisions about it stay
// internal throughout, so only the flaw's readers lose it.
func excludeFrom(ctx context.Context, tx bun.IDB, subject access.Subject, h *finding.CodeFindingFlaw) error {
	if err := updateAsRead(ctx, tx.NewUpdate().Model((*finding.CodeFindingFlaw)(nil)).
		Set(`"included_by" = NULL`).Set(`"included_at" = NULL`), h); err != nil {
		return err
	}
	return recordInclusion(ctx, tx, subject, h, false)
}

// includeIn includes a code finding recorded as a flaw in its flaw's disclosure, and the inclusion is
// recorded as the access change it is. The code finding and the decisions about it stay
// internal, so everybody who read it keeps it, and the flaw's readers read it
// as well (finding.CodeFindingReading).
func includeIn(ctx context.Context, tx bun.IDB, subject access.Subject, h *finding.CodeFindingFlaw, now time.Time) error {
	by := subject.ID
	if err := updateAsRead(ctx, tx.NewUpdate().Model((*finding.CodeFindingFlaw)(nil)).
		Set(`"included_by" = ?`, by).Set(`"included_at" = ?`, now), h); err != nil {
		return err
	}
	h.IncludedBy, h.IncludedAt = &by, &now
	return recordInclusion(ctx, tx, subject, h, true)
}

// updateAsRead runs an update of one flaw record matched on what the transaction
// read of it: an inclusion, a removal, a disclosure or a run landing since is a lost
// race, which the retry reads again.
func updateAsRead(ctx context.Context, q *bun.UpdateQuery, h *finding.CodeFindingFlaw) error {
	result, err := h.AsRead(q).Exec(ctx)
	if err != nil {
		return fmt.Errorf("include the code finding in disclosure or take it out: %w", err)
	}
	if n, err := database.Affected(result); err != nil {
		return fmt.Errorf("include the code finding in disclosure or take it out: %w", err)
	} else if n != 1 {
		return fmt.Errorf("include the code finding in disclosure or take it out: %w", database.ErrGoAgain)
	}
	return nil
}

// recordedFor is the flaw record of a code finding the subject reads in full, for an inclusion
// or a removal.
func recordedFor(ctx context.Context, tx bun.IDB, subject access.Subject, productID int64,
	occurrenceIdentity string) (*finding.CodeFindingFlaw, error) {

	if _, err := newestCodeFinding(ctx, tx, subject, productID, occurrenceIdentity); err != nil {
		return nil, err
	}
	h, err := finding.CodeFindingFlawAt(ctx, tx, productID, occurrenceIdentity)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, ErrNotRecordedAsFlaw
	}
	return h, nil
}

// recordInclusion writes an inclusion or its removal in the administration trail.
func recordInclusion(ctx context.Context, tx bun.IDB, subject access.Subject, h *finding.CodeFindingFlaw, included bool) error {
	name, err := CodeFindingName(ctx, tx, h)
	if err != nil {
		return err
	}
	was, became := "internal only", "included in disclosure"
	if !included {
		was, became = became, was
	}
	return recordAccess(ctx, tx, subject, name, &was, &became)
}

// CodeFindingName is what the trail calls a code finding recorded as a flaw: its product, its flaw
// and its analyzer's rule.
func CodeFindingName(ctx context.Context, db bun.IDB, h *finding.CodeFindingFlaw) (string, error) {
	var names struct {
		Product string `bun:"product"`
		Flaw    string `bun:"flaw"`
		Rule    string `bun:"rule"`
	}
	kinds, kindArgs := kind.CodeFindings.Where(`"f"."kind"`)
	if err := db.NewSelect().TableExpr(`"product" AS "p"`).
		Join(`JOIN "vulnerability" AS "fv" ON "fv"."id" = ?`, h.VulnerabilityID).
		ColumnExpr(`"p"."name" AS "product", "fv"."identifier" AS "flaw"`).
		ColumnExpr(`(SELECT MAX("vu"."identifier") FROM "finding" AS "f"
			JOIN "vulnerability" AS "vu" ON "vu"."id" = "f"."vulnerability_id"
			JOIN "target" AS "t" ON "t"."id" = "f"."target_id"
			JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"
			WHERE "s"."product_id" = "p"."id" AND "f"."occurrence_identity" = ? AND `+kinds+`) AS "rule"`,
			append([]any{h.OccurrenceIdentity}, kindArgs...)...).
		Where(`"p"."id" = ?`, h.ProductID).
		Scan(ctx, &names); err != nil {
		return "", fmt.Errorf("read what to call the code finding: %w", err)
	}
	return names.Product + " · " + names.Flaw + " · " + names.Rule, nil
}

// recordAccess writes one change to who reads a code finding recorded as a flaw in the
// administration trail, in the transaction that makes it.
func recordAccess(ctx context.Context, tx bun.IDB, subject access.Subject, name string, was, became *string) error {
	return trail.NewStore(tx).Record(ctx, subject, trail.Case, name, was, became)
}
