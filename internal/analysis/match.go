// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/sarif"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

// result is what the newest run that saw a finding said about it.
type result struct {
	bun.BaseModel `bun:"table:analysis_result,alias:ar"`

	ID                int64  `bun:"id,pk,autoincrement"`
	FindingID         int64  `bun:"finding_id,notnull"`
	Path              string `bun:"path,notnull"`
	StartLine         *int   `bun:"start_line"`
	StartColumn       *int   `bun:"start_column"`
	EndLine           *int   `bun:"end_line"`
	EndColumn         *int   `bun:"end_column"`
	Enclosing         string `bun:"enclosing,nullzero"`
	CallChain         string `bun:"call_chain,nullzero"`
	MessageText       string `bun:"message_text,notnull"`
	Fingerprint       string `bun:"fingerprint,nullzero"`
	FingerprintScheme string `bun:"fingerprint_scheme,nullzero"`
	MatchKey          string `bun:"match_key,notnull"`
	FunctionKey       string `bun:"function_key,nullzero"`
	LineKey           string `bun:"line_key,notnull"`
	MatchedOn         string `bun:"matched_on,nullzero"`
	Level             string `bun:"level,nullzero"`
	Snippet           string `bun:"snippet,nullzero"`
	SnippetLine       *int   `bun:"snippet_line"`
	LastPath          string `bun:"last_path,notnull"`
	LastPathIdentity  string `bun:"last_path_identity,notnull"`
	LastLine          *int   `bun:"last_line"`
}

// lastOf is the last place a result names: the last step of the analyzer's
// path, the last related location in the result's own file, or the result's
// own location. Two analyzers reporting one flaw disagree about where it
// starts and agree about where it bites: cppcheck names the check first and
// the dereference last, and the others name the dereference.
func lastOf(k Keyed) (string, int) {
	if n := len(k.Steps); n > 0 && k.Steps[n-1].Path != "" {
		return k.Steps[n-1].Path, k.Steps[n-1].StartLine
	}
	for i := len(k.Related) - 1; i >= 0; i-- {
		if k.Related[i].Path == k.Path {
			return k.Path, k.Related[i].StartLine
		}
	}
	return k.Path, k.StartLine
}

// pathIdentity is the digest a path is indexed by.
func pathIdentity(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:])
}

// location is another place a result names: a step on the analyzer's path,
// or a related location.
type location struct {
	bun.BaseModel `bun:"table:analysis_location,alias:al"`

	ID          int64  `bun:"id,pk,autoincrement"`
	FindingID   int64  `bun:"finding_id,notnull"`
	Ordinal     int    `bun:"ordinal,notnull"`
	Part        string `bun:"part,notnull"`
	Path        string `bun:"path,nullzero"`
	StartLine   *int   `bun:"start_line"`
	StartColumn *int   `bun:"start_column"`
	EndLine     *int   `bun:"end_line"`
	EndColumn   *int   `bun:"end_column"`
	MessageText string `bun:"message_text,nullzero"`
	Depth       *int   `bun:"depth"`
	Snippet     string `bun:"snippet,nullzero"`
	SnippetLine *int   `bun:"snippet_line"`
}

// The parts a location plays.
const (
	partStep    = "step"
	partRelated = "related"
)

// match pairs a run's results with the findings its series holds open on
// the build, one to one, layer by layer (pair). It reports the pairs, the
// results nothing matched, the open findings the run did not see, and how
// many of the pairs had been missed by an earlier run.
func match(ctx context.Context, db bun.IDB, open []series.Sighting, keyed []Keyed) (
	map[int64]Keyed, []Keyed, []int64, int, error) {

	absent := make(map[int64]bool, len(open))
	ids := make([]int64, 0, len(open))
	for _, s := range open {
		ids = append(ids, s.FindingID)
		absent[s.FindingID] = s.AbsentRunID != nil
	}
	candidates, err := candidatesOf(ctx, db, ids, absent)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("read what the series holds open: %w", err)
	}
	matched := map[int64]Keyed{}
	paired := make([]bool, len(keyed))
	for _, p := range pair(candidates, keyed) {
		k := keyed[p.result]
		k.On = p.on
		matched[candidates[p.candidate].findingID] = k
		paired[p.result] = true
	}
	var fresh []Keyed
	for i, k := range keyed {
		if !paired[i] {
			fresh = append(fresh, k)
		}
	}
	var missed []int64
	returned := 0
	for _, s := range open {
		_, seen := matched[s.FindingID]
		switch {
		case seen && s.AbsentRunID != nil:
			returned++
		case !seen && s.AbsentRunID == nil:
			missed = append(missed, s.FindingID)
		}
	}
	return matched, fresh, missed, returned, nil
}

// candidatesOf is these findings as their newest sightings described them,
// in the order of their identifiers.
func candidatesOf(ctx context.Context, db bun.IDB, ids []int64, absent map[int64]bool) ([]candidate, error) {
	var out []candidate
	err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		var rows []result
		if err := db.NewSelect().Model(&rows).
			Column("finding_id", "match_key", "function_key", "line_key", "start_line").
			Where(`"ar"."finding_id" IN (?)`, bun.List(batch)).Scan(ctx); err != nil {
			return err
		}
		for _, r := range rows {
			c := candidate{
				findingID: r.FindingID, key: r.MatchKey, functionKey: r.FunctionKey,
				lineKey: r.LineKey, absent: absent[r.FindingID],
			}
			if r.StartLine != nil {
				c.line = *r.StartLine
			}
			out = append(out, c)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].findingID < out[j].findingID })
	return out, err
}

// open records each result new to this build as a finding, with what the run
// said about it. A result the series holds elsewhere takes that lead's place,
// so a decision on it reaches this build too; any other opens at a place its
// series and key name. It returns the findings, and those in the baseline
// because a lead they were carried from is.
func (a *Applier) open(ctx context.Context, db bun.IDB, run *series.Run, productID, seriesID int64, fresh []Keyed,
	rules map[string]int64, from map[int]carried, components map[string]int64, root int64) (
	[]int64, []int64, error) {

	if len(fresh) == 0 {
		return nil, nil, nil
	}
	now := a.now().Truncate(time.Microsecond)
	places := freshPlaces(seriesID, fresh, from)
	for i := range fresh {
		if c, ok := from[i]; ok {
			fresh[i].On = c.on
		}
	}
	// A lead handed off and moved into its case opens where it is, so the
	// next run's sighting is not a new internal lead.
	handed, err := handedVisibility(ctx, db, productID, places)
	if err != nil {
		return nil, nil, err
	}
	rows := make([]finding.Finding, len(fresh))
	for i, k := range fresh {
		component := root
		if id, ok := components[k.Remote]; ok {
			component = id
		}
		visibility := OpensAt
		if v, ok := handed[places[i]]; ok {
			visibility = v
		}
		rows[i] = finding.Finding{
			TargetID: run.TargetID, Kind: kind.Analysis, VulnerabilityID: rules[k.Rule],
			Visibility: visibility, ComponentID: component, PlaceIdentity: places[i],
			OpenedAt: now,
		}
	}
	if err := database.InBatches(ctx, db, rows); err != nil {
		return nil, nil, fmt.Errorf("record what the run found: %w", err)
	}
	ids := make([]int64, len(rows))
	var baseline []int64
	said := map[int64]Keyed{}
	for i := range rows {
		ids[i] = rows[i].ID
		said[rows[i].ID] = fresh[i]
		if from[i].baseline {
			baseline = append(baseline, rows[i].ID)
		}
	}
	if err := write(ctx, db, said, false); err != nil {
		return nil, nil, err
	}
	return ids, baseline, nil
}

// freshPlaces is the place each result new to this build opens at: the lead's
// it was carried from, or the one its series and key name.
func freshPlaces(seriesID int64, fresh []Keyed, from map[int]carried) []string {
	places := make([]string, len(fresh))
	for i, k := range fresh {
		places[i] = identity(seriesID, k.Key)
		if c, ok := from[i]; ok {
			places[i] = c.place
		}
	}
	return places
}

// describeAgain records what this run said about the findings it saw again,
// replacing what the run before it said.
func describeAgain(ctx context.Context, db bun.IDB, matched map[int64]Keyed) error {
	return write(ctx, db, matched, true)
}

// write records what a run said about each finding. Where replace is set,
// what an earlier run said is removed first.
func write(ctx context.Context, db bun.IDB, said map[int64]Keyed, replace bool) error {
	if len(said) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(said))
	for id := range said {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if replace {
		if err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
			if _, err := db.NewDelete().Model((*location)(nil)).
				Where(`"finding_id" IN (?)`, bun.List(batch)).Exec(ctx); err != nil {
				return err
			}
			_, err := db.NewDelete().Model((*result)(nil)).
				Where(`"finding_id" IN (?)`, bun.List(batch)).Exec(ctx)
			return err
		}); err != nil {
			return fmt.Errorf("let go of what the last run said: %w", err)
		}
	}
	results := make([]result, 0, len(ids))
	var locations []location
	for _, id := range ids {
		k := said[id]
		lastPath, lastLine := lastOf(k)
		results = append(results, result{
			FindingID: id, Path: k.Path,
			StartLine: stated(k.StartLine), StartColumn: stated(k.StartColumn),
			EndLine: stated(k.EndLine), EndColumn: stated(k.EndColumn),
			Enclosing: k.Function, CallChain: k.Chain, MessageText: k.Message,
			Fingerprint: k.Print, FingerprintScheme: k.Scheme, MatchKey: k.Key,
			FunctionKey: k.FunctionKey, LineKey: k.LineKey, MatchedOn: k.On, Level: k.Level,
			Snippet: k.Snippet, SnippetLine: stated(k.SnippetLine),
			LastPath: lastPath, LastPathIdentity: pathIdentity(lastPath), LastLine: stated(lastLine),
		})
		ordinal := 0
		for _, steps := range []struct {
			part  string
			steps []sarif.PlacedStep
		}{{partStep, k.Steps}, {partRelated, k.Related}} {
			for _, s := range steps.steps {
				locations = append(locations, location{
					FindingID: id, Ordinal: ordinal, Part: steps.part, Path: s.Path,
					StartLine: stated(s.StartLine), StartColumn: stated(s.Column),
					MessageText: s.Message, Depth: s.Depth,
					Snippet: s.Snippet, SnippetLine: stated(s.SnippetLine),
				})
				ordinal++
			}
		}
	}
	if err := database.InBatchesUnkeyed(ctx, db, results); err != nil {
		return fmt.Errorf("record what the run said: %w", err)
	}
	if err := database.InBatchesUnkeyed(ctx, db, locations); err != nil {
		return fmt.Errorf("record the places the run named: %w", err)
	}
	return nil
}

// stated is a line or column as stored: absent where the document stated
// none.
func stated(n int) *int {
	if n <= 0 {
		return nil
	}
	return &n
}

// handedVisibility is the visibility each handed-off lead among these places
// holds in a product.
func handedVisibility(ctx context.Context, db bun.IDB, productID int64, places []string) (
	map[string]access.Visibility, error) {

	out := map[string]access.Visibility{}
	for start := 0; start < len(places); start += database.BatchSize {
		batch := places[start:min(start+database.BatchSize, len(places))]
		var rows []finding.Handoff
		if err := db.NewSelect().Model(&rows).
			Column("lh.place_identity", "lh.visibility").
			Where(`"lh"."product_id" = ?`, productID).
			Where(`"lh"."place_identity" IN (?)`, bun.List(batch)).
			Scan(ctx); err != nil {
			return nil, fmt.Errorf("read which of the leads were handed off: %w", err)
		}
		for _, r := range rows {
			out[r.PlaceIdentity] = r.Visibility
		}
	}
	return out, nil
}
