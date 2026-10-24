// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package series

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// chunkSize is how much of a document one row holds: far inside the smallest
// statement size any engine allows by default, the bound the inventory
// documents are stored under.
const chunkSize = 512 << 10

// Document is what a run is held as until it is applied, stored in parts.
type Document struct {
	bun.BaseModel `bun:"table:series_document,alias:sd"`

	ID          int64      `bun:"id,pk,autoincrement"`
	RunID       int64      `bun:"run_id,notnull"`
	Ordinal     int        `bun:"ordinal,notnull"`
	ContentHash string     `bun:"content_hash,notnull"`
	SizeBytes   int64      `bun:"size_bytes,notnull"`
	CreatedAt   time.Time  `bun:"created_at,notnull"`
	DiscardedAt *time.Time `bun:"discarded_at"`
}

type chunk struct {
	bun.BaseModel `bun:"table:series_document_chunk,alias:sdc"`

	ID         int64  `bun:"id,pk,autoincrement"`
	DocumentID int64  `bun:"document_id,notnull"`
	Seq        int    `bun:"seq,notnull"`
	Body       []byte `bun:"body,notnull"`
}

// Write stores one document of a run, reading it as a stream. The hash is
// over the bytes stored.
func (s *Store) Write(ctx context.Context, runID int64, ordinal int, r io.Reader) (*Document, error) {
	doc := &Document{RunID: runID, Ordinal: ordinal, CreatedAt: s.now().Truncate(time.Microsecond)}
	if _, err := s.db.NewInsert().Model(doc).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record a document: %w", err)
	}
	digest := sha256.New()
	buf := make([]byte, chunkSize)
	for seq := 0; ; seq++ {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			digest.Write(buf[:n])
			doc.SizeBytes += int64(n)
			row := &chunk{DocumentID: doc.ID, Seq: seq, Body: buf[:n]}
			if _, err := s.db.NewInsert().Model(row).Exec(ctx); err != nil {
				return nil, fmt.Errorf("store part %d of a document: %w", seq, err)
			}
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read a document: %w", err)
		}
	}
	doc.ContentHash = hex.EncodeToString(digest.Sum(nil))
	if _, err := s.db.NewUpdate().Model(doc).Column("content_hash", "size_bytes").WherePK().Exec(ctx); err != nil {
		return nil, fmt.Errorf("record a document's size and hash: %w", err)
	}
	return doc, nil
}

// Documents is a run's documents still held whole, in the order they were
// written.
func (s *Store) Documents(ctx context.Context, runID int64) ([]Document, error) {
	var docs []Document
	err := s.db.NewSelect().Model(&docs).
		Where(`"sd"."run_id" = ?`, runID).
		Where(`"sd"."discarded_at" IS NULL`).
		OrderExpr(`"sd"."ordinal" ASC`).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the documents of run %d: %w", runID, err)
	}
	return docs, nil
}

// Open reads a document back, one part at a time.
func (s *Store) Open(ctx context.Context, doc *Document) io.Reader {
	return &chunks{ctx: ctx, db: s.db, documentID: doc.ID}
}

type chunks struct {
	ctx        context.Context
	db         bun.IDB
	documentID int64
	next       int
	held       []byte
	done       bool
}

func (c *chunks) Read(p []byte) (int, error) {
	for len(c.held) == 0 {
		if c.done {
			return 0, io.EOF
		}
		var row chunk
		err := c.db.NewSelect().Model(&row).
			Where(`"document_id" = ?`, c.documentID).
			Where(`"seq" = ?`, c.next).
			Limit(1).Scan(c.ctx)
		switch {
		case database.IsNoRows(err):
			c.done = true
			return 0, io.EOF
		case err != nil:
			return 0, fmt.Errorf("read part %d of a document: %w", c.next, err)
		}
		c.held = row.Body
		c.next++
	}
	n := copy(p, c.held)
	c.held = c.held[n:]
	return n, nil
}

// Discard lets a run's documents go once the run ends. The rows
// recording what arrived stay; the bytes do not. It joins the caller's
// transaction, so the run's ending and the bytes going are one act.
func (s *Store) Discard(ctx context.Context, runID int64) error {
	var ids []int64
	if err := s.db.NewSelect().Model((*Document)(nil)).Column("id").
		Where(`"run_id" = ?`, runID).
		Where(`"discarded_at" IS NULL`).
		Scan(ctx, &ids); err != nil {
		return fmt.Errorf("read which documents of run %d are held: %w", runID, err)
	}
	if len(ids) == 0 {
		return nil
	}
	if err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		_, err := s.db.NewDelete().Model((*chunk)(nil)).
			Where(`"document_id" IN (?)`, bun.List(batch)).Exec(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("let go of the documents of run %d: %w", runID, err)
	}
	if _, err := s.db.NewUpdate().Model((*Document)(nil)).
		Set(`"discarded_at" = ?`, s.now().Truncate(time.Microsecond)).
		Where(`"run_id" = ?`, runID).
		Where(`"discarded_at" IS NULL`).Exec(ctx); err != nil {
		return fmt.Errorf("record that the documents of run %d were let go: %w", runID, err)
	}
	return nil
}
