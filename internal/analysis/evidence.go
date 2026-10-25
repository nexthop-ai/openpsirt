// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
)

// Evidence is what the newest run that saw a lead said about it, with each
// place linked into the source it was analyzed at.
type Evidence struct {
	At      Located
	Steps   []Located
	Related []Located
	// LastSeen is when the build the newest run that saw the lead was made,
	// and NotSeen when the build of the first run after it that did not see
	// it was, nil while every run since has seen it.
	LastSeen time.Time
	NotSeen  *time.Time
	// Compare is the address comparing the lead's repository between those
	// two builds, and Unchanged whether both name the same commit for it and
	// neither patched it.
	Compare   string
	Unchanged bool
	// State is where the lead stands.
	State State
	// Kin is the other leads on the build that are the same flaw, or
	// possibly are.
	Kin []Kin
}

// Located is one place a run named for a lead.
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

// EvidenceOf is the evidence for one lead, answered where the subject may
// read the lead and as no lead otherwise. The product's repository settings
// say where each place links to.
func EvidenceOf(ctx context.Context, db bun.IDB, subject access.Subject, lead *finding.Finding, productID int64) (Evidence, error) {
	visible, err := access.Readable(subject, productID)
	if err != nil || !slices.Contains(visible, lead.Visibility) {
		return Evidence{}, finding.ErrNoOpenFinding
	}
	var said result
	err = db.NewSelect().Model(&said).Where(`"ar"."finding_id" = ?`, lead.ID).Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Evidence{}, finding.ErrNoOpenFinding
	case err != nil:
		return Evidence{}, fmt.Errorf("read what the run said about lead %d: %w", lead.ID, err)
	}
	var places []location
	if err := db.NewSelect().Model(&places).Where(`"al"."finding_id" = ?`, lead.ID).
		OrderExpr(`"al"."ordinal" ASC`).Scan(ctx); err != nil {
		return Evidence{}, fmt.Errorf("read the places lead %d names: %w", lead.ID, err)
	}
	var seen series.Sighting
	if err := db.NewSelect().Model(&seen).Where(`"si"."finding_id" = ?`, lead.ID).
		OrderExpr(`"si"."id" DESC`).Limit(1).Scan(ctx); err != nil {
		return Evidence{}, fmt.Errorf("read when lead %d was seen: %w", lead.ID, err)
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
		LastSeen: last.BuiltAt,
	}
	for _, p := range places {
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
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		ColumnExpr(state, stateArgs...).
		Where(`"f"."id" = ?`, lead.ID).Limit(1).Scan(ctx, &out.State); err != nil {
		return Evidence{}, fmt.Errorf("read where lead %d stands: %w", lead.ID, err)
	}
	if out.Kin, err = KinOf(ctx, db, subject, productID, lead.ID); err != nil {
		return Evidence{}, err
	}
	if seen.AbsentRunID != nil {
		absent, after, err := runAndModules(ctx, store, *seen.AbsentRunID)
		if err != nil {
			return Evidence{}, err
		}
		out.NotSeen = &absent.BuiltAt
		out.Compare, out.Unchanged = config.Compare(link, modulesOfRun(after), said.Path)
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
