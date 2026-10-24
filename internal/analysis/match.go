// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bun"

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
	Level             string `bun:"level,nullzero"`
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
}

// The parts a location plays.
const (
	partStep    = "step"
	partRelated = "related"
)

// match pairs a run's results with the findings its series holds open on
// the build, one to one, on the exact key. It reports the pairs, the results
// nothing matched, the open findings the run did not see, and how many of the
// pairs had been missed by an earlier run.
func match(ctx context.Context, db bun.IDB, open []series.Sighting, keyed []Keyed) (
	map[int64]Keyed, []Keyed, []int64, int, error) {

	ids := make([]int64, 0, len(open))
	for _, s := range open {
		ids = append(ids, s.FindingID)
	}
	byKey := map[string][]int64{}
	if err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		var rows []result
		if err := db.NewSelect().Model(&rows).Column("finding_id", "match_key").
			Where(`"ar"."finding_id" IN (?)`, bun.List(batch)).Scan(ctx); err != nil {
			return err
		}
		for _, r := range rows {
			byKey[r.MatchKey] = append(byKey[r.MatchKey], r.FindingID)
		}
		return nil
	}); err != nil {
		return nil, nil, nil, 0, fmt.Errorf("read what the series holds open: %w", err)
	}
	for k := range byKey {
		sort.Slice(byKey[k], func(i, j int) bool { return byKey[k][i] < byKey[k][j] })
	}

	matched := map[int64]Keyed{}
	var fresh []Keyed
	for _, k := range keyed {
		if held := byKey[k.Key]; len(held) > 0 {
			matched[held[0]] = k
			byKey[k.Key] = held[1:]
			continue
		}
		fresh = append(fresh, k)
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

// baselined is the results new to this build that a lead in the series'
// baseline already reports on another build. Such a lead is the same result,
// and is in the baseline too.
func baselined(ctx context.Context, db bun.IDB, seriesID int64, fresh []Keyed) (map[string]bool, error) {
	keys := make([]string, 0, len(fresh))
	seen := map[string]bool{}
	for _, k := range fresh {
		if !seen[k.Key] {
			seen[k.Key] = true
			keys = append(keys, k.Key)
		}
	}
	out := map[string]bool{}
	where, args := kind.In(`"f"."kind"`, []kind.Kind{kind.Analysis})
	for start := 0; start < len(keys); start += database.BatchSize {
		end := min(start+database.BatchSize, len(keys))
		var found []string
		if err := db.NewSelect().
			TableExpr(`"analysis_result" AS "ar"`).
			Join(`JOIN "finding" AS "f" ON "f"."id" = "ar"."finding_id"`).
			Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
			ColumnExpr(`"ar"."match_key"`).
			Where(`"si"."series_id" = ?`, seriesID).
			Where(`"si"."baseline" = ?`, true).
			Where(`"ar"."match_key" IN (?)`, bun.List(keys[start:end])).
			Where(where, args...).
			Scan(ctx, &found); err != nil {
			return nil, fmt.Errorf("read which of these results the baseline holds: %w", err)
		}
		for _, k := range found {
			out[k] = true
		}
	}
	return out, nil
}

// open records each result new to this build as a finding, with what the run
// said about it, at the place its series and key name: one result is one
// place on every build of the series, so a decision on it reaches each. It
// returns the findings, and those the baseline already holds elsewhere.
func (a *Applier) open(ctx context.Context, db bun.IDB, run *series.Run, seriesID int64, fresh []Keyed,
	rules map[string]int64, inBaseline map[string]bool, components map[string]int64, root int64) (
	[]int64, []int64, error) {

	if len(fresh) == 0 {
		return nil, nil, nil
	}
	now := a.now().Truncate(time.Microsecond)
	rows := make([]finding.Finding, len(fresh))
	for i, k := range fresh {
		place := identity(seriesID, k.Key)
		component := root
		if id, ok := components[k.Remote]; ok {
			component = id
		}
		rows[i] = finding.Finding{
			TargetID: run.TargetID, Kind: opensAs.kind, VulnerabilityID: rules[k.Rule],
			Visibility: opensAs.visibility, ComponentID: component, PlaceIdentity: place,
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
		if inBaseline[fresh[i].Key] {
			baseline = append(baseline, rows[i].ID)
		}
	}
	if err := write(ctx, db, said, false); err != nil {
		return nil, nil, err
	}
	return ids, baseline, nil
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
		results = append(results, result{
			FindingID: id, Path: k.Path,
			StartLine: stated(k.StartLine), StartColumn: stated(k.StartColumn),
			EndLine: stated(k.EndLine), EndColumn: stated(k.EndColumn),
			Enclosing: k.Function, CallChain: k.Chain, MessageText: k.Message,
			Fingerprint: k.Print, FingerprintScheme: k.Scheme, MatchKey: k.Key, Level: k.Level,
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

// normalizedRemote is a repository's address as host, owner and name, in
// lower case, with no scheme, credential, revision or suffix: the form a
// remote and a package identifier are compared in.
func normalizedRemote(remote string) string {
	s := strings.ToLower(strings.TrimSpace(remote))
	s, _, _ = strings.Cut(s, "#")
	s, _, _ = strings.Cut(s, "?")
	s = strings.TrimPrefix(s, "git+")
	if _, rest, found := strings.Cut(s, "://"); found {
		s = rest
	} else if at := strings.Index(s, "@"); at >= 0 && strings.Contains(s[at:], ":") {
		// The form an SSH remote is written in: user@host:owner/name.
		s = strings.Replace(s[at+1:], ":", "/", 1)
	}
	host, path, _ := strings.Cut(s, "/")
	if at := strings.LastIndex(host, "@"); at >= 0 {
		host = host[at+1:]
	}
	host, _, _ = strings.Cut(host, ":")
	// A revision follows the path, as a version-control address in a package
	// identifier writes it.
	path, _, _ = strings.Cut(path, "@")
	path = strings.TrimSuffix(strings.TrimSuffix(path, "/"), ".git")
	if host == "" || path == "" {
		return ""
	}
	return host + "/" + path
}
