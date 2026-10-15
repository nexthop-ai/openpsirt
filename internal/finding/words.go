// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// Words is the reasoning a claim gives for itself, stored once.
//
// A statement naming five thousand components is five thousand claim rows,
// one per subject, and every one of them gives the same reasoning. Each row
// points here, so the prose is written once however many components it
// names, and two documents giving the same reasoning share it.
type Words struct {
	bun.BaseModel `bun:"table:statement_text,alias:stw"`

	ID     int64  `bun:"id,pk,autoincrement"`
	Digest string `bun:"words_digest,notnull"`
	Words  string `bun:"words,notnull"`
}

// MostWords bounds the reasoning kept for one statement, in bytes: the bound
// a markdown field typed here is held to.
const MostWords = markdown.MaxBytes

// WordsOf is reasoning as it is kept: valid UTF-8, without NUL, and cut to
// MostWords on a character boundary. The query builder makes the same two
// repairs on the way to the engine, so they are made here first: the words
// keyed and compared are then the words stored.
//
// Cut rather than refused. The reasoning is somebody else's, and one
// over-long explanation is no reason to refuse the scan or the document that
// carried it.
func WordsOf(said string) string {
	kept := strings.ReplaceAll(strings.ToValidUTF8(said, "�"), "\x00", "")
	return bound.Head(kept, MostWords)
}

// wordsDigest is what one stored copy of the reasoning is found by.
func wordsDigest(words string) string {
	sum := sha256.Sum256([]byte(words))
	return hex.EncodeToString(sum[:])
}

// WordsJoin joins the stored reasoning a row points at, under the alias
// "stw". Every reader of a claim's reasoning reads it through this join, in
// this package and outside it.
func WordsJoin(alias string) string {
	return `LEFT JOIN "statement_text" AS "stw" ON "stw"."id" = "` + alias + `"."statement_id"`
}

// WordsColumn is the reasoning a row points at, read through WordsJoin, and
// the empty string where it gave none.
const WordsColumn = `COALESCE("stw"."words", '')`

// internWords is the stored copy of each of the reasoning given, writing the
// ones not yet held.
//
// The empty string is no reasoning and has no copy. Run inside the caller's
// transaction, so the claims and the reasoning they point at are written
// together. Two writers storing the same new reasoning at once collide on the
// digest, and the one that loses is asked to go again: its retry finds the
// copy the other wrote.
func internWords(ctx context.Context, tx bun.IDB, said []string) (map[string]int64, error) {
	byDigest := map[string]string{}
	for _, words := range said {
		if words != "" {
			byDigest[wordsDigest(words)] = words
		}
	}
	held := make(map[string]int64, len(byDigest))
	if len(byDigest) == 0 {
		return held, nil
	}
	digests := make([]string, 0, len(byDigest))
	for digest := range byDigest {
		digests = append(digests, digest)
	}
	for from := 0; from < len(digests); from += database.BatchSize {
		var rows []Words
		if err := tx.NewSelect().Model(&rows).Column("id", "words_digest").
			Where(`"stw"."words_digest" IN (?)`, bun.List(digests[from:min(from+database.BatchSize, len(digests))])).
			Scan(ctx); err != nil {
			return nil, fmt.Errorf("read the reasoning already held: %w", err)
		}
		for _, row := range rows {
			held[byDigest[row.Digest]] = row.ID
		}
	}
	var missing []Words
	for digest, words := range byDigest {
		if _, ok := held[words]; !ok {
			missing = append(missing, Words{Digest: digest, Words: words})
		}
	}
	if len(missing) == 0 {
		return held, nil
	}
	if err := database.InBatches(ctx, tx, missing); err != nil {
		if database.IsDuplicate(err) {
			return nil, fmt.Errorf("record the reasoning given: %w", database.ErrGoAgain)
		}
		return nil, fmt.Errorf("record the reasoning given: %w", err)
	}
	for _, row := range missing {
		held[row.Words] = row.ID
	}
	return held, nil
}

// wordsID is the stored copy a row points at, and nil for no reasoning.
func wordsID(held map[string]int64, words string) *int64 {
	id, ok := held[words]
	if !ok {
		return nil
	}
	return &id
}
