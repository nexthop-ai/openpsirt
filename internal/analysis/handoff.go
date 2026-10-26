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

// ErrHandedOff refuses a judgment about a lead handed off as a flaw, and a
// second hand-off of it.
var ErrHandedOff = triage.ErrLeadHandedOff

// ErrNotConfirmed refuses a hand-off of a lead nobody confirmed.
var ErrNotConfirmed = refusal.New("only a confirmed lead is handed off: confirm it first")

// ErrNotHandedOff refuses a move, an undo or a grant on a lead that was not
// handed off.
var ErrNotHandedOff = refusal.New("that lead was not handed off")

// ErrAlreadyMoved and ErrNotMoved refuse a move of a lead already in its case
// and an undo of one that is not.
var (
	ErrAlreadyMoved = refusal.New("that lead is already part of its flaw's case")
	ErrNotMoved     = refusal.New("that lead was kept, so there is no move to undo")
)

// ErrFlawDisclosed refuses moving a lead in or out of a case that is
// disclosed, and a change to who is granted it. Disclosure is one way.
var ErrFlawDisclosed = refusal.New("that lead's flaw is disclosed, so the lead stays where it is")

// MostSuggestions bounds the components offered as resembling a lead's
// directory.
const MostSuggestions = 5

// Source is where a component offered at hand-off came from.
type Source string

const (
	// FromConfirmed is the component a path prefix holding the lead was
	// confirmed as at an earlier hand-off.
	FromConfirmed Source = "confirmed"
	// FromPlacement is the component the lead was placed on as it arrived:
	// the one whose package identifier names the lead's repository.
	FromPlacement Source = "placed"
	// FromResemblance is a component whose name resembles the lead's
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

// Suggestion is a component offered at hand-off. An empty Component is the
// build itself.
type Suggestion struct {
	Component string
	Ecosystem string
	Namespace string
	From      Source
	// Lacking is the builds the lead was seen in that hold no such
	// component: recording the flaw against them is refused.
	Lacking []BuildName
	// Unanalyzed is the builds that hold the component and that the lead's
	// series never analyzed. A variant nobody analyzes ships the same code.
	Unanalyzed []BuildName
}

// Authored is how much one person wrote about a lead.
type Authored struct {
	PersonID int64 `bun:"person_id"`
	Writings int   `bun:"writings"`
}

// Disclosure is what moving a lead into its flaw's case discloses with the
// flaw (REQ-40).
type Disclosure struct {
	// Authors is everybody who wrote reasoning or a comment on a claim about
	// the lead, with how many pieces each wrote.
	Authors []Authored
	// Paths is every path the lead names, and Messages how many messages
	// the analyzer wrote at them.
	Paths    []string
	Messages int
	// Snippets is how many snippets the product discloses with the flaw,
	// and Stripped how many it strips at disclosure.
	Snippets int
	Stripped int
}

// Offer is what a hand-off of one lead is offered.
type Offer struct {
	Rule string
	// Seen is every build the lead was seen in, which the flaw is proposed
	// against.
	Seen        []BuildName
	Suggestions []Suggestion
	// Prefix is the path a confirmed component is learned for: the
	// repository or declared third-party path the lead is in, or its
	// directory.
	Prefix string
	// ThirdParty says the lead is under a path its newest run declared as
	// third-party code, so the flaw is reported to the upstream it came from.
	ThirdParty bool
	// Together is how many other leads the hand-off links to the flaw with
	// this one: the leads its confirming claim covers, which a move moves
	// with it.
	Together  int
	Discloses Disclosure
}

// lead is what a hand-off reads about the lead at a place.
type lead struct {
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
	bun.BaseModel `bun:"table:lead_component,alias:lco"`

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

// MayHandOff refuses somebody who may not record a flaw from a lead, move it
// or take it back out: it takes triage of the internal lead and of the private
// flaw. Asked before any name a request carries is resolved.
func MayHandOff(subject access.Subject, productID int64) error {
	if !subject.Triages(access.Internal, productID) || !subject.Triages(access.Private, productID) {
		return access.Denied(fmt.Sprintf("hand off a lead in product %d", productID))
	}
	return nil
}

// newestLead is the newest finding of the lead at a place in a product that
// the subject reads in full, with what a hand-off needs of it.
func newestLead(ctx context.Context, db bun.IDB, subject access.Subject, productID int64,
	placeIdentity string) (*lead, error) {

	reach := finding.LeadReach(subject, productID)
	kinds, kindArgs := kind.Leads.Where(`"f"."kind"`)
	var out lead
	err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
		Join(`JOIN "vulnerability" AS "vu" ON "vu"."id" = "f"."vulnerability_id"`).
		Join(`JOIN "target" AS "t" ON "t"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
		ColumnExpr(`"f"."id", "f"."target_id", "f"."component_id", "ar"."path"`).
		ColumnExpr(`"vu"."identifier" AS "rule", "si"."last_run_id", "si"."series_id"`).
		Where(`"s"."product_id" = ?`, productID).
		Where(`"f"."place_identity" = ?`, placeIdentity).
		Where(reach.Full, reach.FullArgs...).
		Where(kinds, kindArgs...).
		OrderExpr(`"f"."id" DESC`).Limit(1).
		Scan(ctx, &out)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, finding.ErrNoOpenFinding
	case err != nil:
		return nil, fmt.Errorf("read the lead at that place: %w", err)
	}
	return &out, nil
}

// confirmedAt reports whether a claim confirming the lead at a place stands.
func confirmedAt(ctx context.Context, db bun.IDB, productID, findingID int64) (bool, error) {
	var outcome *string
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		ColumnExpr(standingOutcome+` AS "outcome"`, productID).
		Where(`"f"."id" = ?`, findingID).
		Scan(ctx, &outcome); err != nil {
		return false, fmt.Errorf("read the claim standing at the lead: %w", err)
	}
	return outcome != nil && *outcome == string(Confirmed), nil
}

// stampedClaim is a claim and the stamp it was read with.
type stampedClaim struct {
	ID    int64 `bun:"id"`
	Stamp int   `bun:"stamp"`
}

// claimsAt is every claim with a live row at the place of a lead finding, in
// a product, with the stamp each holds: zero for a claim nobody has stamped.
func claimsAt(ctx context.Context, db bun.IDB, productID, findingID int64) ([]stampedClaim, error) {
	var out []stampedClaim
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "decision" AS "dc" ON `+finding.DecisionFiledAt("dc", "f")).
		Join(`JOIN "claim" AS "sc" ON "sc"."id" = "dc"."claim_id"`).
		Join(`LEFT JOIN "claim_stamp" AS "cst" ON "cst"."claim_id" = "sc"."id"`).
		ColumnExpr(`DISTINCT "sc"."id", COALESCE("cst"."stamp", 0) AS "stamp"`).
		Where(`"f"."id" = ?`, findingID).
		Where(`"dc"."product_id" = ?`, productID).
		Where(`"dc"."live_key" IS NOT NULL`).
		OrderExpr(`"sc"."id" ASC`).
		Scan(ctx, &out); err != nil {
		return nil, fmt.Errorf("read the claims standing at the lead: %w", err)
	}
	return out, nil
}

// Propose is what handing off the lead at a place in a product is offered:
// the components, ranked, the builds it was seen in, and what moving it into
// its case would disclose.
func Propose(ctx context.Context, db bun.IDB, subject access.Subject, productID int64,
	placeIdentity string) (*Offer, error) {

	if err := MayHandOff(subject, productID); err != nil {
		return nil, err
	}
	l, err := newestLead(ctx, db, subject, productID, placeIdentity)
	if err != nil {
		return nil, err
	}
	run, modules, err := runAndModules(ctx, series.NewStore(db), l.LastRunID)
	if err != nil {
		return nil, err
	}
	declared := declaredThirdParty(run, l.Path)
	out := &Offer{Rule: l.Rule, Prefix: prefixOf(l.Path, modules, declared), ThirdParty: declared != ""}
	if out.Seen, err = seenIn(ctx, db, productID, placeIdentity); err != nil {
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
	together, err := togetherAt(ctx, db, productID, placeIdentity)
	if err != nil {
		return nil, err
	}
	out.Together = len(together) - 1
	if out.Discloses, err = disclosing(ctx, db, productID, together); err != nil {
		return nil, err
	}
	return out, nil
}

// togetherAt is the places of the leads handed off with the lead at a place,
// that place first. A lead handed off goes with every lead handed off as its
// flaw; one not handed off yet, with every lead the claim confirming it
// covers that nobody handed off.
func togetherAt(ctx context.Context, db bun.IDB, productID int64, placeIdentity string) ([]string, error) {
	handed, err := finding.HandoffAt(ctx, db, productID, placeIdentity)
	if err != nil {
		return nil, err
	}
	var others []string
	if handed != nil {
		if err := db.NewSelect().Model((*finding.Handoff)(nil)).
			Column("lh.place_identity").
			Where(`"lh"."product_id" = ?`, productID).
			Where(`"lh"."vulnerability_id" = ?`, handed.VulnerabilityID).
			Where(`"lh"."place_identity" <> ?`, placeIdentity).
			OrderExpr(`"lh"."id" ASC`).
			Scan(ctx, &others); err != nil {
			return nil, fmt.Errorf("read the leads handed off as the flaw: %w", err)
		}
		return append([]string{placeIdentity}, others...), nil
	}
	if err := db.NewSelect().TableExpr(`"decision" AS "dc"`).
		Join(`JOIN "vulnerability" AS "rv" ON "rv"."id" = "dc"."vulnerability_id"`).
		Join(`JOIN "claim" AS "sc" ON "sc"."id" = "dc"."claim_id"`).
		Join(`JOIN "decision" AS "od" ON "od"."claim_id" = "dc"."claim_id" AND "od"."product_id" = "dc"."product_id"`).
		Join(`JOIN "vulnerability" AS "ov" ON "ov"."id" = "od"."vulnerability_id"`).
		ColumnExpr(`DISTINCT "od"."place_identity"`).
		Where(`"dc"."product_id" = ?`, productID).
		Where(`"dc"."place_identity" = ?`, placeIdentity).
		Where(`"rv"."kind" = ?`, string(kind.Rule)).
		Where(`"sc"."outcome" = ?`, string(Confirmed)).
		Where(`"dc"."live_key" IS NOT NULL`).
		Where(`("dc"."state" = 'approved' OR ("dc"."needs_approval" = FALSE AND "dc"."sent_back_at" IS NULL))`).
		Where(`"ov"."kind" = ?`, string(kind.Rule)).
		Where(`"od"."live_key" IS NOT NULL`).
		Where(`"od"."place_identity" <> ?`, placeIdentity).
		Where(`NOT EXISTS (SELECT 1 FROM "lead_handoff" AS "lh"
			WHERE "lh"."product_id" = "od"."product_id" AND "lh"."place_identity" = "od"."place_identity")`).
		OrderExpr(`"od"."place_identity" ASC`).
		Scan(ctx, &others); err != nil {
		return nil, fmt.Errorf("read the leads confirmed with the lead: %w", err)
	}
	return append([]string{placeIdentity}, others...), nil
}

// handedWith is every hand-off of the flaw a hand-off links, in one product,
// as the transaction reads them: the leads that move together.
func handedWith(ctx context.Context, tx bun.IDB, h *finding.Handoff) ([]finding.Handoff, error) {
	var rows []finding.Handoff
	if err := tx.NewSelect().Model(&rows).
		Where(`"lh"."product_id" = ?`, h.ProductID).
		Where(`"lh"."vulnerability_id" = ?`, h.VulnerabilityID).
		OrderExpr(`"lh"."id" ASC`).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the leads handed off as the flaw: %w", err)
	}
	return rows, nil
}

// prefixOf is the path a component confirmed for a lead at a path is learned
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
		return out, false, fmt.Errorf("read the component the lead is on: %w", err)
	}
	root, err := db.NewSelect().TableExpr(`"graph_node" AS "n"`).
		Where(`"n"."target_id" = ?`, targetID).
		Where(`"n"."component_id" = ?`, componentID).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`"n"."is_root" = ?`, true).
		Exists(ctx)
	if err != nil {
		return out, false, fmt.Errorf("read whether the lead is on the build itself: %w", err)
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

// seenIn is every build of a product holding a finding of the lead at a
// place, open or closed.
func seenIn(ctx context.Context, db bun.IDB, productID int64, placeIdentity string) ([]BuildName, error) {
	kinds, kindArgs := kind.Leads.Where(`"f"."kind"`)
	var out []BuildName
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "t" ON "t"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "t"."variant_id"`).
		ColumnExpr(`DISTINCT "t"."id" AS "target_id", "s"."name" AS "stream", "va"."name" AS "variant"`).
		Where(`"s"."product_id" = ?`, productID).
		Where(`"f"."place_identity" = ?`, placeIdentity).
		Where(kinds, kindArgs...).
		OrderExpr(`"s"."name" ASC, "va"."name" ASC`).
		Scan(ctx, &out); err != nil {
		return nil, fmt.Errorf("read the builds the lead was seen in: %w", err)
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

// disclosing is what disclosing the leads at these places in a product with
// their flaw discloses.
func disclosing(ctx context.Context, db bun.IDB, productID int64, places []string) (Disclosure, error) {
	var out Disclosure
	claims := `SELECT "dc"."claim_id" FROM "decision" AS "dc"
		JOIN "vulnerability" AS "rv" ON "rv"."id" = "dc"."vulnerability_id"
		WHERE "dc"."product_id" = ? AND "dc"."place_identity" IN (?) AND "rv"."kind" = ?`
	if err := db.NewSelect().
		TableExpr(`(SELECT "cr"."written_by" AS "person_id" FROM "claim_revision" AS "cr"
			WHERE "cr"."claim_id" IN (`+claims+`)
			UNION ALL SELECT "cm"."written_by" AS "person_id" FROM "claim_comment" AS "cm"
			WHERE "cm"."claim_id" IN (`+claims+`)) AS "w"`,
			productID, bun.List(places), string(kind.Rule), productID, bun.List(places), string(kind.Rule)).
		ColumnExpr(`"w"."person_id", COUNT(*) AS "writings"`).
		GroupExpr(`"w"."person_id"`).
		OrderExpr(`"w"."person_id" ASC`).
		Scan(ctx, &out.Authors); err != nil {
		return out, fmt.Errorf("read who wrote about the lead: %w", err)
	}

	config, err := sourcelink.NewStore(db).Config(ctx, productID)
	if err != nil {
		return out, err
	}
	kinds, kindArgs := kind.Leads.Where(`"f"."kind"`)
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
			Where(`"f"."place_identity" IN (?)`, bun.List(places)).
			Where(kinds, kindArgs...)
	}
	for _, q := range []*bun.SelectQuery{from("analysis_result", "ar", "message_text"),
		from("analysis_location", "al", "message_text")} {
		var some []spoken
		if err := q.Scan(ctx, &some); err != nil {
			return out, fmt.Errorf("read what the lead names: %w", err)
		}
		said = append(said, some...)
	}
	paths := map[string]bool{}
	for _, s := range said {
		if s.Path != "" && !paths[s.Path] {
			paths[s.Path] = true
			out.Paths = append(out.Paths, s.Path)
		}
		if s.Message != "" {
			out.Messages++
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
	return out, nil
}

// Handing is a hand-off of one lead: the flaw to record and whether the lead
// moves into its case.
type Handing struct {
	ProductID     int64
	PlaceIdentity string
	// Flaw is the flaw as the recorded-flaw path takes it, with the builds
	// a person confirmed and the component they chose.
	Flaw finding.Entering
	Move bool
}

// Recorded is a flaw recorded from a lead: the identifier it was filed under,
// the component carrying it, and how many builds and places it opened at.
type Recorded struct {
	Identifier string
	Component  string
	Builds     int
	Places     int
}

// HandOff records a confirmed lead as a flaw here, through the path every
// recorded flaw takes, and links it and every lead its confirming claim
// covers to the flaw in the same transaction. The component chosen is learned
// for the lead's prefix, and the leads move into the case where the person
// asked.
func HandOff(ctx context.Context, db bun.IDB, subject access.Subject, in Handing) (*Recorded, error) {
	if err := MayHandOff(subject, in.ProductID); err != nil {
		return nil, err
	}
	in.Flaw.Disclosed = false
	in.Flaw.Told = finding.Told{FoundHere: true}
	in.Flaw.FromReport = ""
	in.Flaw.Version = ""
	in.Flaw.Then = func(ctx context.Context, tx bun.IDB, vulnerabilityID int64, now time.Time) error {
		// Read again here: whether the lead still stands confirmed and
		// unhanded is a fact a retry asks again.
		l, err := newestLead(ctx, tx, subject, in.ProductID, in.PlaceIdentity)
		if err != nil {
			return err
		}
		// The claims standing at the lead, with the stamps they hold, read
		// before whether one confirms it. Restamped once it does, so a
		// revision or withdrawal of the confirmation committing beside this
		// matches nothing, or makes this match nothing, and is asked again.
		standing, err := claimsAt(ctx, tx, in.ProductID, l.ID)
		if err != nil {
			return err
		}
		if err := finding.LeadEnded(ctx, tx, in.ProductID, in.PlaceIdentity, now); err != nil {
			return err
		}
		if handed, err := finding.HandoffAt(ctx, tx, in.ProductID, in.PlaceIdentity); err != nil {
			return err
		} else if handed != nil {
			return ErrHandedOff
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
		// Every lead the confirming claim covers is the one flaw, and is
		// linked to it: a lead of the group left behind holds a claim
		// nothing may change and no flaw.
		together, err := togetherAt(ctx, tx, in.ProductID, in.PlaceIdentity)
		if err != nil {
			return err
		}
		rows := make([]*finding.Handoff, 0, len(together))
		for _, place := range together {
			row := &finding.Handoff{
				ProductID: in.ProductID, PlaceIdentity: place, VulnerabilityID: vulnerabilityID,
				Visibility: access.Internal, HandedBy: subject.ID, HandedAt: now,
			}
			if _, err := tx.NewInsert().Model(row).Exec(ctx); err != nil {
				if database.IsDuplicate(err) {
					return ErrHandedOff
				}
				return fmt.Errorf("link the lead to its flaw: %w", err)
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
		if in.Move {
			for _, row := range rows {
				if err := moveIn(ctx, tx, subject, row, now); err != nil {
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
	return &Recorded{Identifier: identifier, Component: component, Builds: len(builds), Places: len(rows)}, nil
}

// Answerable refuses a claim about a lead the subject no longer reads in
// full, or one handed off as a flaw, which is judged instead. Asked inside the
// transaction writing the claim.
func Answerable(ctx context.Context, tx bun.IDB, subject access.Subject, productID int64, lead *finding.Finding) error {
	reach := finding.LeadReach(subject, productID)
	read, err := tx.NewSelect().TableExpr(`"finding" AS "f"`).
		Where(`"f"."id" = ?`, lead.ID).
		Where(reach.Full, reach.FullArgs...).
		Exists(ctx)
	if err != nil {
		return fmt.Errorf("read whether lead %d may be judged: %w", lead.ID, err)
	}
	if !read {
		return finding.ErrNoOpenFinding
	}
	handed, err := finding.HandoffAt(ctx, tx, productID, lead.PlaceIdentity)
	if err != nil {
		return err
	}
	if handed != nil {
		return ErrHandedOff
	}
	return finding.LeadEnded(ctx, tx, productID, lead.PlaceIdentity, time.Now().UTC())
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
		// Two hand-offs under one new prefix at once: the second deleted
		// nothing, and its retry replaces the first's.
		if database.IsDuplicate(err) {
			return database.ErrGoAgain
		}
		return fmt.Errorf("record what the prefix was confirmed as: %w", err)
	}
	return nil
}

// Move moves a kept lead into its flaw's case while the flaw is undisclosed,
// and every lead handed off as the flaw with it.
func Move(ctx context.Context, db bun.IDB, subject access.Subject, productID int64, placeIdentity string,
	now time.Time) error {

	if err := MayHandOff(subject, productID); err != nil {
		return err
	}
	return database.Within(ctx, db, func(ctx context.Context, tx bun.IDB) error {
		h, err := handedFor(ctx, tx, subject, productID, placeIdentity)
		if err != nil {
			return err
		}
		switch {
		case h.Disclosed():
			return ErrFlawDisclosed
		case h.Moved():
			return ErrAlreadyMoved
		}
		with, err := handedWith(ctx, tx, h)
		if err != nil {
			return err
		}
		at := now.UTC().Truncate(time.Microsecond)
		for i := range with {
			if with[i].Moved() || with[i].Disclosed() {
				continue
			}
			if err := moveIn(ctx, tx, subject, &with[i], at); err != nil {
				return err
			}
		}
		return nil
	})
}

// Unmove takes a moved lead back out of its flaw's case while the flaw is
// undisclosed, and every lead handed off as the flaw with it: each is
// internal again, and the claims about it with it.
func Unmove(ctx context.Context, db bun.IDB, subject access.Subject, productID int64, placeIdentity string) error {
	if err := MayHandOff(subject, productID); err != nil {
		return err
	}
	return database.Within(ctx, db, func(ctx context.Context, tx bun.IDB) error {
		h, err := handedFor(ctx, tx, subject, productID, placeIdentity)
		if err != nil {
			return err
		}
		switch {
		case h.Disclosed():
			return ErrFlawDisclosed
		case !h.Moved():
			return ErrNotMoved
		}
		with, err := handedWith(ctx, tx, h)
		if err != nil {
			return err
		}
		for i := range with {
			if !with[i].Moved() || with[i].Disclosed() {
				continue
			}
			if err := moveOut(ctx, tx, subject, &with[i]); err != nil {
				return err
			}
		}
		return nil
	})
}

// moveOut takes a moved lead back out of its flaw's case: its findings and
// the claims about it are internal again, and the undo is recorded as the
// access change it is.
func moveOut(ctx context.Context, tx bun.IDB, subject access.Subject, h *finding.Handoff) error {
	if err := finding.SetLeadVisibility(ctx, tx, h.ProductID, []string{h.PlaceIdentity},
		access.Private, access.Internal); err != nil {
		return err
	}
	if err := updateAsRead(ctx, tx.NewUpdate().Model((*finding.Handoff)(nil)).
		Set(`"visibility" = ?`, access.Internal).
		Set(`"moved_by" = NULL`).Set(`"moved_at" = NULL`), h); err != nil {
		return err
	}
	return recordMove(ctx, tx, subject, h, false)
}

// moveIn moves a handed-off lead into its flaw's case: its findings and the
// claims about it go private with the flaw, and the move is recorded as the
// access change it is.
func moveIn(ctx context.Context, tx bun.IDB, subject access.Subject, h *finding.Handoff, now time.Time) error {
	if err := finding.SetLeadVisibility(ctx, tx, h.ProductID, []string{h.PlaceIdentity},
		access.Internal, access.Private); err != nil {
		return err
	}
	by := subject.ID
	if err := updateAsRead(ctx, tx.NewUpdate().Model((*finding.Handoff)(nil)).
		Set(`"visibility" = ?`, access.Private).
		Set(`"moved_by" = ?`, by).Set(`"moved_at" = ?`, now), h); err != nil {
		return err
	}
	h.Visibility, h.MovedBy, h.MovedAt = access.Private, &by, &now
	return recordMove(ctx, tx, subject, h, true)
}

// updateAsRead runs an update of one hand-off matched on what the transaction
// read of it: a move, an undo, a disclosure or a run landing since is a lost
// race, which the retry reads again.
func updateAsRead(ctx context.Context, q *bun.UpdateQuery, h *finding.Handoff) error {
	result, err := h.AsRead(q).Exec(ctx)
	if err != nil {
		return fmt.Errorf("move the lead: %w", err)
	}
	if n, err := database.Affected(result); err != nil {
		return fmt.Errorf("move the lead: %w", err)
	} else if n != 1 {
		return fmt.Errorf("move the lead: %w", database.ErrGoAgain)
	}
	return nil
}

// handedFor is the hand-off of a lead the subject reads in full, for a move or
// an undo.
func handedFor(ctx context.Context, tx bun.IDB, subject access.Subject, productID int64,
	placeIdentity string) (*finding.Handoff, error) {

	if _, err := newestLead(ctx, tx, subject, productID, placeIdentity); err != nil {
		return nil, err
	}
	h, err := finding.HandoffAt(ctx, tx, productID, placeIdentity)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, ErrNotHandedOff
	}
	return h, nil
}

// recordMove writes a move or its undo in the administration trail.
func recordMove(ctx context.Context, tx bun.IDB, subject access.Subject, h *finding.Handoff, moved bool) error {
	name, err := LeadName(ctx, tx, h)
	if err != nil {
		return err
	}
	was, became := "kept", "moved into the case"
	if !moved {
		was, became = became, was
	}
	return recordAccess(ctx, tx, subject, name, &was, &became)
}

// LeadName is what the trail calls a handed-off lead: its product, its flaw
// and its analyzer's rule.
func LeadName(ctx context.Context, db bun.IDB, h *finding.Handoff) (string, error) {
	var names struct {
		Product string `bun:"product"`
		Flaw    string `bun:"flaw"`
		Rule    string `bun:"rule"`
	}
	kinds, kindArgs := kind.Leads.Where(`"f"."kind"`)
	if err := db.NewSelect().TableExpr(`"product" AS "p"`).
		Join(`JOIN "vulnerability" AS "fv" ON "fv"."id" = ?`, h.VulnerabilityID).
		ColumnExpr(`"p"."name" AS "product", "fv"."identifier" AS "flaw"`).
		ColumnExpr(`(SELECT MAX("vu"."identifier") FROM "finding" AS "f"
			JOIN "vulnerability" AS "vu" ON "vu"."id" = "f"."vulnerability_id"
			JOIN "target" AS "t" ON "t"."id" = "f"."target_id"
			JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"
			WHERE "s"."product_id" = "p"."id" AND "f"."place_identity" = ? AND `+kinds+`) AS "rule"`,
			append([]any{h.PlaceIdentity}, kindArgs...)...).
		Where(`"p"."id" = ?`, h.ProductID).
		Scan(ctx, &names); err != nil {
		return "", fmt.Errorf("read what to call the lead: %w", err)
	}
	return names.Product + " · " + names.Flaw + " · " + names.Rule, nil
}

// recordAccess writes one change to who reads a handed-off lead in the
// administration trail, in the transaction that makes it.
func recordAccess(ctx context.Context, tx bun.IDB, subject access.Subject, name string, was, became *string) error {
	return trail.NewStore(tx).Record(ctx, subject, trail.Case, name, was, became)
}
