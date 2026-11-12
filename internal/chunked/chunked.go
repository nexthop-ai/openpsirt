// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package chunked stores a document as bounded parts and reads it back as a
// stream. The document rows are the caller's; this holds only their parts.
package chunked

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Table is a table holding documents' parts. Only the values declared here
// exist, because a table name cannot be bound as a parameter.
type Table string

const (
	// ScanParts holds the parts of what a build sent.
	ScanParts Table = "scan_document_chunk"
	// SeriesParts holds the parts of a run held until it is applied.
	SeriesParts Table = "series_document_chunk"
)

// PartSize is how much of a document one row holds.
//
// Two engines cap how large a single statement may be, the cap is server
// configuration rather than anything a client can discover, and the lowest
// default in circulation is sixteen megabytes. A bounded row stays far inside
// every default and lets a document be read as a stream rather than held
// whole.
const PartSize = 512 << 10

// ErrReleased ends a document's stream when the document was let go while it
// was read.
//
// A fault rather than a refusal, and not the unexpected end of file a JSON
// decoder reports for a file ending inside a value: the bytes that arrived
// were whole, and stating it as a truncated file blames whoever sent them.
var ErrReleased = errors.New("the document was let go while it was read")

// part is one bounded piece of a document, in whichever table holds it.
type part struct {
	bun.BaseModel `bun:"alias:p"`

	ID         int64  `bun:"id,pk,autoincrement"`
	DocumentID int64  `bun:"document_id,notnull"`
	Seq        int    `bun:"seq,notnull"`
	Body       []byte `bun:"body,notnull"`
}

// Write stores a document's parts, reading it as a stream, and returns its
// size and the hash of the bytes stored.
func Write(ctx context.Context, db bun.IDB, table Table, documentID int64,
	r io.Reader) (size int64, hash string, err error) {

	digest := sha256.New()
	buf := make([]byte, PartSize)
	for seq := 0; ; seq++ {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			body := buf[:n]
			digest.Write(body)
			size += int64(n)
			row := &part{DocumentID: documentID, Seq: seq, Body: body}
			if _, err := db.NewInsert().Model(row).
				ModelTableExpr("?", bun.Ident(string(table))).Exec(ctx); err != nil {
				return 0, "", fmt.Errorf("store part %d of a document: %w", seq, err)
			}
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return 0, "", fmt.Errorf("read a document: %w", err)
		}
	}
	return size, hex.EncodeToString(digest.Sum(nil)), nil
}

// Open reads a document of size bytes back as a stream.
//
// Its parts are read one at a time and not in one snapshot, so a document let
// go while it is read runs out of parts before its size. That ends the stream
// with ErrReleased: ended cleanly, a reader takes the bytes it got for the
// whole document.
func Open(ctx context.Context, db bun.IDB, table Table, documentID, size int64) io.Reader {
	return &reader{ctx: ctx, db: db, table: table, documentID: documentID, size: size}
}

// Delete removes every part of these documents.
func Delete(ctx context.Context, db bun.IDB, table Table, documentIDs []int64) error {
	return database.IDsInBatches(ctx, documentIDs, func(ctx context.Context, batch []int64) error {
		_, err := db.NewDelete().Model((*part)(nil)).
			ModelTableExpr("?", bun.Ident(string(table))).
			Where(`"document_id" IN (?)`, bun.List(batch)).Exec(ctx)
		return err
	})
}

// reader walks a document's parts in order.
type reader struct {
	ctx        context.Context
	db         bun.IDB
	table      Table
	documentID int64
	// size is how many bytes the document holds, and read how many have been
	// handed over.
	size int64
	read int64
	next int
	held []byte
	done bool
	err  error
}

func (c *reader) Read(p []byte) (int, error) {
	for len(c.held) == 0 {
		if c.err != nil {
			return 0, c.err
		}
		if c.done {
			return 0, io.EOF
		}
		var row part
		err := c.db.NewSelect().Model(&row).
			ModelTableExpr(`? AS "p"`, bun.Ident(string(c.table))).
			Where(`"document_id" = ?`, c.documentID).
			Where(`"seq" = ?`, c.next).
			Limit(1).Scan(c.ctx)
		switch {
		case database.IsNoRows(err) && c.read < c.size:
			// Its parts ran out before its size: let go while it was read.
			c.err = ErrReleased
			return 0, c.err
		case database.IsNoRows(err):
			c.done = true
			return 0, io.EOF
		case err != nil:
			c.err = fmt.Errorf("read part %d of a document: %w", c.next, err)
			return 0, c.err
		}
		c.held = row.Body
		c.next++
	}
	n := copy(p, c.held)
	c.held = c.held[n:]
	c.read += int64(n)
	return n, nil
}
