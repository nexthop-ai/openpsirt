// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

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

// RepositoryProgress is how far one repository's commits have been looked up.
type RepositoryProgress struct {
	URL   string
	Host  string
	State State
	// Commits is how many commits patch links name in it, Looked how many
	// of those have been looked up, and Found how many of those its copy held.
	Commits int
	Looked  int
	Found   int
	// FetchedAt is when a visit last began, ReachedAt when one last finished.
	FetchedAt *time.Time
	ReachedAt *time.Time
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

// Progress answers where every repository stands, most work left first.
func Progress(ctx context.Context, db bun.IDB, excluded outward.Excluded) ([]RepositoryProgress, Totals, error) {
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
		if ok && row.LookedAt != nil {
			one.Looked++
			totals.Looked++
			if row.Found {
				one.Found++
				totals.Found++
			}
		}
	}
	out := make([]RepositoryProgress, 0, len(byURL))
	for _, one := range byURL {
		if one.Commits == 0 {
			continue
		}
		one.State = stateOf(*one, excluded)
		out = append(out, *one)
	}
	sort.Slice(out, func(i, j int) bool {
		left, right := out[i].Commits-out[i].Looked, out[j].Commits-out[j].Looked
		if left != right {
			return left > right
		}
		return out[i].URL < out[j].URL
	})
	return out, totals, nil
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
