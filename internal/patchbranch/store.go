package patchbranch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// repositoryRow is a repository patch links point into.
type repositoryRow struct {
	bun.BaseModel `bun:"table:patch_repository,alias:pr"`

	ID          int64      `bun:"id,pk,autoincrement"`
	URL         string     `bun:"url,notnull"`
	URLIdentity string     `bun:"url_identity,notnull"`
	Host        string     `bun:"host,notnull"`
	FetchedAt   *time.Time `bun:"fetched_at"`
	ReachedAt   *time.Time `bun:"reached_at"`
	Failed      *string    `bun:"failed"`
	HeldBytes   *int64     `bun:"held_bytes"`
	CreatedAt   time.Time  `bun:"created_at,notnull"`
}

// commitRow is a commit a patch link names.
type commitRow struct {
	bun.BaseModel `bun:"table:patch_commit,alias:pc"`

	ID           int64      `bun:"id,pk,autoincrement"`
	RepositoryID int64      `bun:"repository_id,notnull"`
	Hash         string     `bun:"commit_hash,notnull"`
	LookedAt     *time.Time `bun:"looked_at"`
	Found        bool       `bun:"found,notnull"`
	BranchCount  int        `bun:"branch_count,notnull"`
	CreatedAt    time.Time  `bun:"created_at,notnull"`
}

// branchRow is one branch a commit was found on.
type branchRow struct {
	bun.BaseModel `bun:"table:patch_commit_branch,alias:pcb"`

	ID       int64  `bun:"id,pk,autoincrement"`
	CommitID int64  `bun:"commit_id,notnull"`
	Branch   string `bun:"branch,notnull"`
}

// MostBranches is how many branch names are kept for one commit.
//
// A commit early in a long-lived repository is on every branch cut since, and
// the kernel's stable tree has 116. The count is kept whole; the names past
// this are not, because a label listing a hundred branches is not read.
const MostBranches = 100

// MostReason bounds what is kept of why a visit failed. The text carries a
// host's own words, which nothing bounds.
const MostReason = 1000

// identity is the digest a repository is keyed on.
func identity(repository string) string {
	sum := sha256.Sum256([]byte(repository))
	return hex.EncodeToString(sum[:])
}

// urgency is how soon a commit is worth looking up: the worst rating among the
// issues whose records link to it, and the score behind that rating.
type urgency struct {
	rank  int
	score int
}

func (u urgency) above(other urgency) bool {
	if u.rank != other.rank {
		return u.rank > other.rank
	}
	return u.score > other.score
}

// linkedRow is one patch link, with the rating of the issue that carries it.
type linkedRow struct {
	URL      string `bun:"url"`
	Severity string `bun:"severity"`
	Score    *int   `bun:"score_centi"`
}

// linked reads every commit patch links name, with how urgent each is.
//
// Worked out as the pass runs rather than stored, because it moves whenever an
// issue is rated again and nothing here needs it between passes.
func linked(ctx context.Context, db bun.IDB) (map[Commit]urgency, int, error) {
	var rows []linkedRow
	err := db.NewSelect().
		TableExpr(`"vulnerability_reference" AS "vr"`).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "vr"."vulnerability_id"`).
		ColumnExpr(`"vr"."url" AS "url"`).
		ColumnExpr(`"v"."severity" AS "severity"`).
		ColumnExpr(`"v"."score_centi" AS "score_centi"`).
		Where(`"vr"."kind" = ?`, finding.Patch).
		Scan(ctx, &rows)
	if err != nil {
		return nil, 0, fmt.Errorf("read the patch links reports carry: %w", err)
	}
	out := map[Commit]urgency{}
	for _, row := range rows {
		commit, ok := Parse(row.URL)
		if !ok {
			continue
		}
		this := urgency{rank: finding.Ranks(row.Severity)}
		if row.Score != nil {
			this.score = *row.Score
		}
		if held, seen := out[commit]; !seen || this.above(held) {
			out[commit] = this
		}
	}
	return out, len(rows), nil
}

// intern makes a row for every repository and commit not yet recorded.
//
// Rows are made and never removed. A commit no report links to any more is
// still a fact about its repository, and it is asked about only while it is
// due, which the pass narrows to what is still linked.
func intern(ctx context.Context, db bun.IDB, commits map[Commit]urgency, now time.Time) error {
	repositories := map[string]string{}
	for commit := range commits {
		repositories[identity(commit.Repository)] = commit.Repository
	}
	var known []repositoryRow
	if err := db.NewSelect().Model(&known).Column("id", "url_identity").Scan(ctx); err != nil {
		return fmt.Errorf("read the repositories already recorded: %w", err)
	}
	have := map[string]int64{}
	for _, row := range known {
		have[row.URLIdentity] = row.ID
	}
	var fresh []repositoryRow
	for key, repository := range repositories {
		if _, ok := have[key]; ok {
			continue
		}
		fresh = append(fresh, repositoryRow{
			URL: repository, URLIdentity: key,
			Host:      bound.HeadRunes(Commit{Repository: repository}.Host(), database.NameWidth),
			CreatedAt: now,
		})
	}
	if len(fresh) > 0 {
		sort.Slice(fresh, func(i, j int) bool { return fresh[i].URL < fresh[j].URL })
		if err := database.InBatchesKeeping(ctx, db, fresh); err != nil {
			return fmt.Errorf("record the repositories patch links point into: %w", err)
		}
		known = nil
		if err := db.NewSelect().Model(&known).Column("id", "url_identity").Scan(ctx); err != nil {
			return fmt.Errorf("read the repositories back: %w", err)
		}
		for _, row := range known {
			have[row.URLIdentity] = row.ID
		}
	}

	var recorded []commitRow
	if err := db.NewSelect().Model(&recorded).Column("repository_id", "commit_hash").Scan(ctx); err != nil {
		return fmt.Errorf("read the commits already recorded: %w", err)
	}
	type key struct {
		repository int64
		hash       string
	}
	seen := map[key]bool{}
	for _, row := range recorded {
		seen[key{row.RepositoryID, row.Hash}] = true
	}
	var missing []commitRow
	for commit := range commits {
		id, ok := have[identity(commit.Repository)]
		if !ok || seen[key{id, commit.Hash}] {
			continue
		}
		missing = append(missing, commitRow{RepositoryID: id, Hash: commit.Hash, CreatedAt: now})
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Slice(missing, func(i, j int) bool {
		if missing[i].RepositoryID != missing[j].RepositoryID {
			return missing[i].RepositoryID < missing[j].RepositoryID
		}
		return missing[i].Hash < missing[j].Hash
	})
	if err := database.InBatchesKeeping(ctx, db, missing); err != nil {
		return fmt.Errorf("record the commits patch links name: %w", err)
	}
	return nil
}

// Label is what is known about the branches a patch link's commit is on.
type Label struct {
	// Found says the repository's copy held the commit when it was last
	// asked. False with Looked true is a commit no branch holds.
	Found  bool
	Looked bool
	// Branches is the branches that held it, in version order, at most
	// MostBranches of them.
	Branches []string
	// Count is how many branches held it, which may be more than are named.
	Count int
}

// Labels answers what is known about each of the links given, keyed on the
// link. A link naming no commit, or one not yet looked up, is absent.
func Labels(ctx context.Context, db bun.IDB, links []string) (map[string]Label, error) {
	parsed := map[string]Commit{}
	identities := map[string]bool{}
	for _, link := range links {
		if commit, ok := Parse(link); ok {
			parsed[link] = commit
			identities[identity(commit.Repository)] = true
		}
	}
	if len(parsed) == 0 {
		return nil, nil
	}
	var repositories []repositoryRow
	if err := db.NewSelect().Model(&repositories).Column("id", "url_identity").
		Where(`"url_identity" IN (?)`, bun.List(keys(identities))).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the repositories these links point into: %w", err)
	}
	if len(repositories) == 0 {
		return nil, nil
	}
	repositoryOf := map[string]int64{}
	var ids []int64
	for _, row := range repositories {
		repositoryOf[row.URLIdentity] = row.ID
		ids = append(ids, row.ID)
	}
	hashes := map[string]bool{}
	for _, commit := range parsed {
		hashes[commit.Hash] = true
	}
	var commits []commitRow
	if err := db.NewSelect().Model(&commits).
		Where(`"repository_id" IN (?)`, bun.List(ids)).
		Where(`"commit_hash" IN (?)`, bun.List(keys(hashes))).
		Where(`"looked_at" IS NOT NULL`).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the commits these links name: %w", err)
	}
	type key struct {
		repository int64
		hash       string
	}
	byKey := map[key]commitRow{}
	var looked []int64
	for _, row := range commits {
		byKey[key{row.RepositoryID, row.Hash}] = row
		looked = append(looked, row.ID)
	}
	names := map[int64][]string{}
	if len(looked) > 0 {
		var branches []branchRow
		if err := db.NewSelect().Model(&branches).
			Where(`"commit_id" IN (?)`, bun.List(looked)).Scan(ctx); err != nil {
			return nil, fmt.Errorf("read the branches these commits are on: %w", err)
		}
		for _, row := range branches {
			names[row.CommitID] = append(names[row.CommitID], row.Branch)
		}
	}
	out := map[string]Label{}
	for link, commit := range parsed {
		row, ok := byKey[key{repositoryOf[identity(commit.Repository)], commit.Hash}]
		if !ok {
			continue
		}
		branches := names[row.ID]
		sort.Slice(branches, func(i, j int) bool { return versionLess(branches[i], branches[j]) })
		out[link] = Label{Found: row.Found, Looked: true, Branches: branches, Count: row.BranchCount}
	}
	return out, nil
}

// keys is a set's members, sorted so a statement built from them reads the
// same twice.
func keys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// versionLess orders branch names the way a person reads them: runs of digits
// by value, so linux-6.12.y comes after linux-6.6.y.
func versionLess(a, b string) bool {
	for a != "" && b != "" {
		ia, ib := digitsAt(a), digitsAt(b)
		switch {
		case ia > 0 && ib > 0:
			na, nb := strings.TrimLeft(a[:ia], "0"), strings.TrimLeft(b[:ib], "0")
			if len(na) != len(nb) {
				return len(na) < len(nb)
			}
			if na != nb {
				return na < nb
			}
			a, b = a[ia:], b[ib:]
		case a[0] != b[0]:
			return a[0] < b[0]
		default:
			a, b = a[1:], b[1:]
		}
	}
	return len(a) < len(b)
}

// digitsAt is how many digits a string starts with.
func digitsAt(s string) int {
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	return n
}
