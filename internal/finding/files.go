// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// filesPerStatement is how many issues one statement rewrites the files of.
// Each takes two bound values in the CASE and one in the list.
const filesPerStatement = 300

// ProgramFiles reads the files each issue's CVE record lists, as last
// recorded, one path per entry in byte order. An issue whose record lists none
// is absent.
func ProgramFiles(ctx context.Context, db bun.IDB, issues []int64) (map[int64][]string, error) {
	out := map[int64][]string{}
	for start := 0; start < len(issues); start += database.BatchSize {
		end := min(start+database.BatchSize, len(issues))
		var rows []struct {
			ID    int64   `bun:"id"`
			Files *string `bun:"program_files"`
		}
		if err := db.NewSelect().Table("vulnerability").
			Column("id", "program_files").
			Where(`"id" IN (?)`, bun.List(issues[start:end])).
			Where(`"program_files" IS NOT NULL`).
			Scan(ctx, &rows); err != nil {
			return nil, fmt.Errorf("read the files issues are in: %w", err)
		}
		for _, row := range rows {
			if files := filesOf(row.Files); len(files) > 0 {
				out[row.ID] = files
			}
		}
	}
	return out, nil
}

// filesOf is a stored list of files read back.
func filesOf(stored *string) []string {
	if stored == nil || *stored == "" {
		return nil
	}
	return strings.Split(*stored, "\n")
}

// JoinFiles is a list of files in the form it is stored in: one a line, in
// byte order, each once.
func JoinFiles(files []string) string {
	sorted := append([]string(nil), files...)
	sort.Strings(sorted)
	kept := sorted[:0]
	for i, file := range sorted {
		if file == "" || (i > 0 && file == sorted[i-1]) {
			continue
		}
		kept = append(kept, file)
	}
	return strings.Join(kept, "\n")
}

// recordFiles writes the files each issue's CVE record lists, where the run
// read the records and they differ from what is held.
//
// The record is the authority on its own list, so what the run read replaces
// what is held, and a record that lists none any more empties it. A run that
// read no records says nothing about any issue's files and leaves them.
func recordFiles(ctx context.Context, tx bun.IDB, vulnerabilities map[string]int64, reported []Reported) error {
	wanted := map[int64]string{}
	for _, r := range reported {
		if !r.RecordRead {
			continue
		}
		id, known := vulnerabilities[normalize(r.Issue.Identifier)]
		if !known {
			continue
		}
		joined := JoinFiles(r.RecordFiles)
		if held, seen := wanted[id]; seen && held != joined {
			// Two names of one issue whose records list different files: every
			// file either names is one the issue may be in.
			joined = JoinFiles(append(strings.Split(held, "\n"), r.RecordFiles...))
		}
		wanted[id] = joined
	}
	if len(wanted) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(wanted))
	for id := range wanted {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	held, err := ProgramFiles(ctx, tx, ids)
	if err != nil {
		return err
	}
	var moving []int64
	for _, id := range ids {
		if wanted[id] != strings.Join(held[id], "\n") {
			moving = append(moving, id)
		}
	}
	for start := 0; start < len(moving); start += filesPerStatement {
		end := min(start+filesPerStatement, len(moving))
		cases := make([]any, 0, 2*(end-start))
		for _, id := range moving[start:end] {
			cases = append(cases, id, absentIfEmpty(wanted[id]))
		}
		if _, err := tx.NewUpdate().Table("vulnerability").
			Set(`"program_files" = CASE "id"`+strings.Repeat(" WHEN ? THEN ?", end-start)+` END`, cases...).
			Where(`"id" IN (?)`, bun.List(moving[start:end])).
			Exec(ctx); err != nil {
			return fmt.Errorf("record the files issues are in: %w", err)
		}
	}
	return nil
}
