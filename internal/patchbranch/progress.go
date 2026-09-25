// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/outward"
)

// State is where one repository stands.
type State string

const (
	// Waiting is a repository with commits never looked up and no visit
	// under way.
	Waiting State = "waiting"
	// Working is a repository a visit has begun and not finished.
	Working State = "working"
	// Failed is a repository whose last visit stopped on an error.
	Failed State = "failed"
	// Done is a repository whose last visit finished with every commit
	// looked up.
	Done State = "done"
	// Refused is a repository on a host an administrator excluded. Nothing
	// is fetched from it.
	Refused State = "excluded"
)

// Step is what a visit under way is doing.
type Step string

const (
	// Fetching is a visit bringing the copy up to date and writing its
	// index, before the first commit is looked up.
	Fetching Step = "fetching"
	// LookingUp is a visit asking the copy about the commits due.
	LookingUp Step = "looking-up"
)

// RepositoryProgress is how far one repository's commits have been looked up.
type RepositoryProgress struct {
	URL   string
	Host  string
	State State
	// Position is where the repository stands in the order the pass takes
	// repositories with commits due, from one. Zero is a repository with
	// nothing due, or one the pass is not taking.
	Position int
	// Step is what a visit under way is doing, and VisitLooked how many
	// commits it has looked up so far. Both are empty outside a visit.
	Step        Step
	VisitLooked int
	// Due is how many commits are due a look now, and Worst the severity of
	// the most urgent of them.
	Due   int
	Worst string
	// Commits is how many commits patch links name in it, Looked how many
	// of those have been looked up, and Found how many of those its copy held.
	Commits int
	Looked  int
	Found   int
	// FetchedAt is when a visit last began, ReachedAt when one last finished,
	// and RetryAt when a failed repository is next taken.
	FetchedAt *time.Time
	ReachedAt *time.Time
	RetryAt   *time.Time
	Reason    string
	// HeldBytes is the size of the copy when the last visit finished.
	HeldBytes *int64
}

// Totals is the whole of the work.
type Totals struct {
	// Links is how many patch links reports carry, and Commits how many of
	// them name a commit in a repository this can fetch.
	Links   int
	Commits int
	Looked  int
	Found   int
	// HeldBytes is what every copy took when its last visit finished,
	// together. A copy removed to make room is not counted.
	HeldBytes int64
}

// Progress answers where every repository stands, in working order: the visit
// under way, then the repositories with commits due in the order the pass takes
// them, then those that failed, those on an excluded host, and those done.
//
// The order is the pass's own, from the same plan. A copy counts as held where
// the last visit recorded a size for it, because the report is answered by any
// replica and only the one working can see its disk.
func Progress(ctx context.Context, db bun.IDB, excluded outward.Excluded) ([]RepositoryProgress, Totals, error) {
	now := time.Now()
	commits, links, err := linked(ctx, db)
	if err != nil {
		return nil, Totals{}, err
	}
	var repositories []repositoryRow
	if err := db.NewSelect().Model(&repositories).Scan(ctx); err != nil {
		return nil, Totals{}, fmt.Errorf("read the repositories patch links point into: %w", err)
	}
	var rows []commitRow
	if err := db.NewSelect().Model(&rows).
		Column("repository_id", "commit_hash", "looked_at", "found").Scan(ctx); err != nil {
		return nil, Totals{}, fmt.Errorf("read the commits patch links name: %w", err)
	}
	type key struct {
		repository int64
		hash       string
	}
	recorded := map[key]commitRow{}
	for _, row := range rows {
		recorded[key{row.RepositoryID, row.Hash}] = row
	}
	byURL := map[string]*RepositoryProgress{}
	idOf := map[string]int64{}
	var held int64
	for _, repository := range repositories {
		one := &RepositoryProgress{
			URL: repository.URL, Host: repository.Host,
			FetchedAt: repository.FetchedAt, ReachedAt: repository.ReachedAt,
			HeldBytes: repository.HeldBytes,
		}
		if repository.Failed != nil {
			one.Reason = *repository.Failed
		}
		if repository.HeldBytes != nil {
			held += *repository.HeldBytes
		}
		byURL[repository.URL] = one
		idOf[repository.URL] = repository.ID
	}
	totals := Totals{Links: links, HeldBytes: held}
	for commit := range commits {
		one := byURL[commit.Repository]
		if one == nil {
			// Named by a link since the pass last ran. Counted as waiting
			// under a repository with no row yet.
			one = &RepositoryProgress{URL: commit.Repository, Host: commit.Host()}
			byURL[commit.Repository] = one
		}
		one.Commits++
		totals.Commits++
		row, ok := recorded[key{idOf[commit.Repository], commit.Hash}]
		if !ok || row.LookedAt == nil {
			continue
		}
		one.Looked++
		totals.Looked++
		if row.Found {
			one.Found++
			totals.Found++
		}
		if one.FetchedAt != nil && !row.LookedAt.Before(*one.FetchedAt) {
			one.VisitLooked++
		}
	}

	ordered, err := plan(ctx, db, commits, excluded, now, func(repository repositoryRow) bool {
		return repository.HeldBytes != nil
	})
	if err != nil {
		return nil, Totals{}, err
	}
	for i, each := range ordered {
		one := byURL[each.repository.URL]
		if one == nil {
			continue
		}
		one.Position = i + 1
		one.Due = len(each.due)
		worst := each.worst
		if each.never == 0 {
			worst = each.stale
		}
		one.Worst = severityOf(worst)
	}

	out := make([]RepositoryProgress, 0, len(byURL))
	for _, one := range byURL {
		if one.Commits == 0 {
			continue
		}
		one.State = stateOf(*one, excluded)
		switch one.State {
		case Working:
			one.Step = Fetching
			if one.VisitLooked > 0 {
				one.Step = LookingUp
			}
		case Failed:
			if one.FetchedAt != nil {
				retry := one.FetchedAt.Add(RetryAfter).UTC()
				one.RetryAt = &retry
			}
		}
		if one.State != Working {
			one.VisitLooked = 0
		}
		out = append(out, *one)
	}
	sort.SliceStable(out, func(i, j int) bool { return workingBefore(out[i], out[j]) })
	return out, totals, nil
}

// workingBefore orders the report: the visit under way, then the plan, then
// what the plan does not hold, each group in the order most useful to read.
func workingBefore(a, b RepositoryProgress) bool {
	if ga, gb := group(a), group(b); ga != gb {
		return ga < gb
	}
	switch {
	case a.Position != b.Position:
		return a.Position < b.Position
	case a.State == Done && b.State == Done && a.ReachedAt != nil && b.ReachedAt != nil &&
		!a.ReachedAt.Equal(*b.ReachedAt):
		return a.ReachedAt.After(*b.ReachedAt)
	case a.Commits-a.Looked != b.Commits-b.Looked:
		return a.Commits-a.Looked > b.Commits-b.Looked
	}
	return a.URL < b.URL
}

// group is which part of the report a repository is listed in.
func group(one RepositoryProgress) int {
	switch {
	case one.State == Working:
		return 0
	case one.Position > 0:
		return 1
	case one.State == Waiting:
		return 2
	case one.State == Failed:
		return 3
	case one.State == Refused:
		return 4
	default:
		return 5
	}
}

// severityOf is the severity word an urgency was ranked from, or nothing for
// an issue nobody rated.
func severityOf(how urgency) string {
	bands := finding.Bands()
	if how.rank < 1 || how.rank > len(bands) {
		return ""
	}
	return bands[len(bands)-how.rank]
}

// stateOf reads where a repository stands from what its row records.
func stateOf(one RepositoryProgress, excluded outward.Excluded) State {
	switch {
	case excluded.Host(one.Host):
		return Refused
	case one.Reason != "":
		return Failed
	case one.FetchedAt != nil && (one.ReachedAt == nil || one.ReachedAt.Before(*one.FetchedAt)):
		return Working
	case one.ReachedAt != nil && one.Looked == one.Commits:
		return Done
	default:
		return Waiting
	}
}
