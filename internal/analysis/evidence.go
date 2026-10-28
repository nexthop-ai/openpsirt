// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
)

// Evidence is what the newest run that saw a code finding said about it, with each
// place linked into the source it was analyzed at.
type Evidence struct {
	At      Located
	Steps   []Located
	Related []Located
	// LastSeen is when the build the newest run that saw the code finding was made,
	// and NotSeen when the build of the first run after it that did not see
	// it was, nil while every run since has seen it.
	LastSeen time.Time
	NotSeen  *time.Time
	// NotSeenRun is the first run after it that did not see the code finding, zero
	// while every run since has seen it, and FixedIn the run whose build a
	// person stated fixed it in, nil until somebody did.
	NotSeenRun int64
	FixedIn    *RunAt
	// LastCommit and NotSeenCommit are the commits the code finding's own repository
	// was at in those two builds, empty where the run named none.
	LastCommit    string
	NotSeenCommit string
	// Compare is the address comparing the code finding's repository between those
	// two builds, and Unchanged whether both name the same commit for it and
	// neither patched it.
	Compare   string
	Unchanged bool
	// Rule is the analyzer's rule, as the issue it is filed under names it.
	Rule string
	// State is where the code finding stands.
	State State
	// Kin is the other code findings on the build that are the same flaw, or
	// possibly are.
	Kin []Kin
	// ThirdParty says the code finding is under a path the newest run that saw it
	// declared as third-party code.
	ThirdParty bool
	// Component and Version are the component the code finding is placed on,
	// and OnBuild says that component is the build itself.
	Component string
	Version   string
	OnBuild   bool
}

// placedOn selects the component a code finding "f" is placed on, joined as
// "co": its name, its version, and 1 where it is a root of the build, which is
// where a result in no inventory repository is placed. It takes true.
const placedOn = `"co"."name" AS "component", "co"."version" AS "component_version", ` +
	`CASE WHEN EXISTS (SELECT 1 FROM "graph_node" AS "gn" WHERE "gn"."build_id" = "f"."build_id" ` +
	`AND "gn"."component_id" = "f"."component_id" AND "gn"."is_root" = ?) THEN 1 ELSE 0 END AS "on_build"`

// RunAt is one run, by the build it analyzed: when it was made and the
// commit at the top of its checkout, empty where the run stated none.
type RunAt struct {
	ID      int64
	BuiltAt time.Time
	Commit  string
}

// Located is one place a run named for a code finding.
type Located struct {
	Path                   string
	StartLine, StartColumn int
	EndLine, EndColumn     int
	Function               string
	Message                string
	Depth                  *int
	Snippet                string
	SnippetLine            int
	Link                   sourcelink.Link
}

// EvidenceOf is the evidence for one code finding, answered where the subject may
// read the code finding and as no code finding otherwise. The product's repository settings
// say where each place links to.
func EvidenceOf(ctx context.Context, db bun.IDB, subject access.Subject, codeFinding *finding.Finding, productID int64) (Evidence, error) {
	reach := finding.CodeFindingReach(subject, productID)
	read, err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Where(`"f"."id" = ?`, codeFinding.ID).
		Where(reach.Full, reach.FullArgs...).
		Exists(ctx)
	switch {
	case err != nil:
		return Evidence{}, fmt.Errorf("read whether code finding %d may be read: %w", codeFinding.ID, err)
	case !read:
		return Evidence{}, finding.ErrNoOpenFinding
	}
	var said result
	err = db.NewSelect().Model(&said).Where(`"ar"."finding_id" = ?`, codeFinding.ID).Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Evidence{}, finding.ErrNoOpenFinding
	case err != nil:
		return Evidence{}, fmt.Errorf("read what the run said about code finding %d: %w", codeFinding.ID, err)
	}
	var occurrences []location
	if err := db.NewSelect().Model(&occurrences).Where(`"al"."finding_id" = ?`, codeFinding.ID).
		OrderExpr(`"al"."ordinal" ASC`).Scan(ctx); err != nil {
		return Evidence{}, fmt.Errorf("read the places code finding %d names: %w", codeFinding.ID, err)
	}
	var seen series.Sighting
	if err := db.NewSelect().Model(&seen).Where(`"si"."finding_id" = ?`, codeFinding.ID).
		OrderExpr(`"si"."id" DESC`).Limit(1).Scan(ctx); err != nil {
		return Evidence{}, fmt.Errorf("read when code finding %d was seen: %w", codeFinding.ID, err)
	}
	config, err := sourcelink.NewStore(db).Config(ctx, productID)
	if err != nil {
		return Evidence{}, err
	}
	store := series.NewStore(db)
	last, modules, err := runAndModules(ctx, store, seen.LastRunID)
	if err != nil {
		return Evidence{}, err
	}
	link := modulesOfRun(modules)
	out := Evidence{
		At: Located{
			Path: said.Path, StartLine: atLeast(said.StartLine), StartColumn: atLeast(said.StartColumn),
			EndLine: atLeast(said.EndLine), EndColumn: atLeast(said.EndColumn),
			Function: said.Enclosing, Message: said.MessageText,
			Snippet: said.Snippet, SnippetLine: atLeast(said.SnippetLine),
			Link: config.File(link, said.Path, atLeast(said.StartLine), atLeast(said.EndLine)),
		},
		LastSeen:   last.BuiltAt,
		LastCommit: sourcelink.CommitOf(link, last.SourceCommit, said.Path),
		ThirdParty: declaredThirdParty(last, said.Path) != "",
	}
	for _, p := range occurrences {
		one := Located{
			Path: p.Path, StartLine: atLeast(p.StartLine), StartColumn: atLeast(p.StartColumn),
			EndLine: atLeast(p.EndLine), EndColumn: atLeast(p.EndColumn),
			Message: p.MessageText, Depth: p.Depth,
			Snippet: p.Snippet, SnippetLine: atLeast(p.SnippetLine),
		}
		if p.Path == "" {
			one.Link = sourcelink.Link{Unlinked: sourcelink.NoRepository}
		} else {
			one.Link = config.File(link, p.Path, one.StartLine, one.EndLine)
		}
		if p.Part == partStep {
			out.Steps = append(out.Steps, one)
		} else {
			out.Related = append(out.Related, one)
		}
	}
	state, stateArgs := stateOf(productID)
	var onBuild int
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "vulnerability" AS "vu" ON "vu"."id" = "f"."vulnerability_id"`).
		Join(`JOIN "component" AS "co" ON "co"."id" = "f"."component_id"`).
		ColumnExpr(state+` AS "state"`, stateArgs...).
		ColumnExpr(`"vu"."identifier" AS "rule"`).
		ColumnExpr(placedOn, true).
		Where(`"f"."id" = ?`, codeFinding.ID).Limit(1).
		Scan(ctx, &out.State, &out.Rule, &out.Component, &out.Version, &onBuild); err != nil {
		return Evidence{}, fmt.Errorf("read where code finding %d stands: %w", codeFinding.ID, err)
	}
	out.OnBuild = onBuild == 1
	if out.Kin, err = KinOf(ctx, db, subject, productID, codeFinding.ID); err != nil {
		return Evidence{}, err
	}
	if seen.AbsentRunID != nil {
		absent, after, err := runAndModules(ctx, store, *seen.AbsentRunID)
		if err != nil {
			return Evidence{}, err
		}
		out.NotSeen, out.NotSeenRun = &absent.BuiltAt, absent.ID
		out.NotSeenCommit = sourcelink.CommitOf(modulesOfRun(after), absent.SourceCommit, said.Path)
		out.Compare, out.Unchanged = config.Compare(link, modulesOfRun(after), said.Path)
	}
	if seen.FixedRunID != nil {
		fixed, err := store.ByID(ctx, *seen.FixedRunID)
		if err != nil {
			return Evidence{}, err
		}
		out.FixedIn = &RunAt{ID: fixed.ID, BuiltAt: fixed.BuiltAt, Commit: fixed.SourceCommit}
	}
	return out, nil
}

// runAndModules is a run and the repositories its checkout held.
func runAndModules(ctx context.Context, store *series.Store, runID int64) (*series.Run, []series.Module, error) {
	run, err := store.ByID(ctx, runID)
	if err != nil {
		return nil, nil, err
	}
	modules, err := store.ModulesOf(ctx, runID)
	if err != nil {
		return nil, nil, err
	}
	return run, modules, nil
}

// modulesOfRun is a run's repositories as links read them.
func modulesOfRun(modules []series.Module) []sourcelink.Module {
	out := make([]sourcelink.Module, len(modules))
	for i, m := range modules {
		out[i] = sourcelink.Module{Path: m.Path, Remote: m.Remote, Revision: m.Revision, Changed: m.Changed}
	}
	return out
}

// atLeast is a stored line or column, zero where none was stated.
func atLeast(n *int) int {
	if n == nil {
		return 0
	}
	return *n
}
