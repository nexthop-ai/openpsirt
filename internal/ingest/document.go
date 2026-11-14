// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/chunked"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// Kind says what a document a build sent is.
type Kind string

const (
	// InventoryKind is what the build shipped: components and the edges
	// between them.
	InventoryKind Kind = "inventory"
	// SuppressionsKind is what the build has already argued does not apply to
	// it, usually because it carries a patch.
	SuppressionsKind Kind = "suppressions"
)

// Kinds is every kind of document a build sends.
func Kinds() []Kind { return []Kind{InventoryKind, SuppressionsKind} }

// Document is one of the files a build sent, as we hold it.
type Document struct {
	bun.BaseModel `bun:"table:scan_document,alias:sd"`

	ID     int64 `bun:"id,pk,autoincrement"`
	ScanID int64 `bun:"scan_id,notnull"`
	Kind   Kind  `bun:"kind,notnull"`
	// Ordinal separates several documents of one kind. A build's suppressions
	// arrive as a directory rather than a file, so there is rarely one.
	Ordinal int `bun:"ordinal,notnull"`
	// ContentHash is over the bytes as received, which is what makes a
	// re-upload recognizable without reading it again. It outlives the
	// bytes: a nightly scan's contents are let go once they have been
	// read, and the hash is the whole reason the row stays behind.
	ContentHash string    `bun:"content_hash,notnull"`
	SizeBytes   int64     `bun:"size_bytes,notnull"`
	CreatedAt   time.Time `bun:"created_at,notnull"`
	// DiscardedAt says the contents are gone and when they went. Nil is a
	// document still held whole.
	DiscardedAt *time.Time `bun:"discarded_at"`
}

// Documents holds what a build sent, from arrival until it has been read.
type Documents struct {
	db  bun.IDB
	now func() time.Time
}

// NewDocuments returns a store over db.
//
// It takes the narrower handle deliberately: writing a document has to be able
// to join the transaction that records the scan, since a scan whose documents
// did not land is a scan nothing can ever read.
func NewDocuments(db bun.IDB) *Documents {
	return &Documents{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// Write stores a document, reading it as a stream.
//
// The content hash is computed here rather than taken from the caller: a hash
// somebody else calculated says nothing about the bytes that actually arrived.
func (d *Documents) Write(ctx context.Context, scanID int64, kind Kind, ordinal int, r io.Reader) (*Document, error) {
	doc := &Document{
		ScanID: scanID, Kind: kind, Ordinal: ordinal,
		CreatedAt: asStored(d.now()),
	}
	if _, err := d.db.NewInsert().Model(doc).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record document: %w", err)
	}

	size, hash, err := chunked.Write(ctx, d.db, chunked.ScanParts, doc.ID, r)
	if err != nil {
		return nil, err
	}
	doc.SizeBytes, doc.ContentHash = size, hash
	if _, err := d.db.NewUpdate().Model(doc).
		Column("content_hash", "size_bytes").WherePK().Exec(ctx); err != nil {
		return nil, fmt.Errorf("record document size and hash: %w", err)
	}
	return doc, nil
}

// List returns the documents of a scan that are still held whole, in the order
// they were sent.
//
// A document whose contents have been let go is not one of these. It is still
// a record of what arrived — Sent answers that — but it is not something
// anything can read, and a caller looking for an inventory to parse wants the
// question answered rather than a row that will hand it nothing.
func (d *Documents) List(ctx context.Context, scanID int64) ([]Document, error) {
	var docs []Document
	err := d.db.NewSelect().Model(&docs).
		Where(`"scan_id" = ?`, scanID).
		Where(`"discarded_at" IS NULL`).
		Order("kind", "ordinal").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("list documents: %w", err)
	}
	return docs, nil
}

// Sent returns everything a scan arrived with, held or not.
//
// The record rather than the contents: what kind of document it was, how large
// it was, the hash of the bytes that arrived, and whether they are still here.
// It outlives them deliberately — a build asked to send a file again can be
// told whether what it sends is what was read, and a scan whose contents have
// been let go still says what it was made of instead of looking like one that
// arrived with nothing.
func (d *Documents) Sent(ctx context.Context, scanIDs []int64) (map[int64][]Document, error) {
	sent := map[int64][]Document{}
	if len(scanIDs) == 0 {
		return sent, nil
	}
	var docs []Document
	err := database.IDsInBatches(ctx, scanIDs, func(ctx context.Context, batch []int64) error {
		var page []Document
		if err := d.db.NewSelect().Model(&page).
			Where(`"scan_id" IN (?)`, bun.List(batch)).
			Order("scan_id", "kind", "ordinal").
			Scan(ctx); err != nil {
			return err
		}
		docs = append(docs, page...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read what these scans arrived with: %w", err)
	}
	for _, doc := range docs {
		sent[doc.ScanID] = append(sent[doc.ScanID], doc)
	}
	return sent, nil
}

// Open reads a document back as a stream.
//
// A document is tens of megabytes and there is no reason to hold one in memory
// to hand it to a reader that only ever moves forwards.
//
// A document let go while it is read ends with chunked.ErrReleased.
func (d *Documents) Open(ctx context.Context, doc *Document) io.Reader {
	return chunked.Open(ctx, d.db, chunked.ScanParts, doc.ID, doc.SizeBytes)
}

// Discard lets go of a scan's contents, keeping the record of what arrived.
//
// A nightly build's documents are superseded the next night, so keeping them
// costs storage that grows with the calendar. What a tagged release sent is
// kept, because re-scanning it years from now needs both what it contained and
// what the build had already argued about its own patches — so this is called
// for one and not the other.
//
// The rows describing the documents stay either way, marked as let go. They
// are a few hundred bytes against tens of megabytes, and they carry the hash
// of what arrived — which is what retaining a tagged release keeps them for: a re-parse means asking the build to send the file again, and
// without the hash there is nothing to check the second copy against.
func (d *Documents) Discard(ctx context.Context, scanID int64) error {
	db, ok := database.Handle(d.db)
	if !ok {
		return fmt.Errorf("this store is already inside a transaction")
	}
	// Removing the bytes and recording that they are gone are one act, so
	// they are one transaction. Written apart, a failure between them
	// leaves rows saying the document is still held with nothing behind
	// them — and the listing filters on exactly that mark, so a reader is
	// offered a document that answers with nothing rather than with the
	// 410 that says what happened to it.
	return database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		// Read inside, because a retry runs against a database that
		// has moved and this is what the delete is aimed at.
		held, err := deleteChunks(ctx, tx, scanID, true,
			"read which documents are held", "discard document content")
		if err != nil || !held {
			return err
		}
		if _, err := tx.NewUpdate().Model((*Document)(nil)).
			Set(`"discarded_at" = ?`, asStored(d.now())).
			Where(`"scan_id" = ?`, scanID).
			Where(`"discarded_at" IS NULL`).Exec(ctx); err != nil {
			return fmt.Errorf("record that the contents were let go: %w", err)
		}
		return nil
	})
}

// heldBefore returns the scans of a build older than scanID whose documents
// are still held.
func (d *Documents) heldBefore(ctx context.Context, buildID, scanID int64) ([]int64, error) {
	var ids []int64
	if err := d.db.NewSelect().
		TableExpr(`"scan_document" AS "sd"`).
		ColumnExpr(`DISTINCT "sd"."scan_id"`).
		Join(`JOIN "scan" AS "sc" ON "sc"."id" = "sd"."scan_id"`).
		Where(`"sc"."build_id" = ?`, buildID).
		Where(`"sd"."scan_id" < ?`, scanID).
		Where(`"sd"."discarded_at" IS NULL`).
		Scan(ctx, &ids); err != nil {
		return nil, fmt.Errorf("read which older scans still hold documents: %w", err)
	}
	return ids, nil
}

// sameInventory says whether the inventory a scan arrived with hashed to this.
//
// The record of what a document was outlives its contents, so it answers for a
// scan whose bytes have been let go as well as for one still held whole.
func (d *Documents) sameInventory(ctx context.Context, scanID int64, hash string) (bool, error) {
	if hash == "" {
		return false, nil
	}
	held, err := d.db.NewSelect().Model((*Document)(nil)).
		Where(`"scan_id" = ?`, scanID).
		Where(`"kind" = ?`, InventoryKind).
		Where(`"content_hash" = ?`, hash).
		Count(ctx)
	if err != nil {
		return false, fmt.Errorf("read what the inventory already held hashed to: %w", err)
	}
	return held > 0, nil
}

// Remove deletes the documents of a scan, contents and record together.
//
// For a submission taken again after the attempt to read it failed. What
// identifies a submission is all of it, so the bytes arriving now are the
// bytes already stored against that scan — replaced rather than added to,
// because a second copy of an inventory is one a reader would read twice and
// count twice.
//
// It runs in whatever handle it was given, a transaction included: the rows
// going and the rows replacing them are one act, and a failure between them
// would leave a scan with nothing to read.
func (d *Documents) Remove(ctx context.Context, scanID int64) error {
	held, err := deleteChunks(ctx, d.db, scanID, false,
		"read which documents this scan has", "remove document content")
	if err != nil || !held {
		return err
	}
	if _, err := d.db.NewDelete().Model((*Document)(nil)).
		Where(`"scan_id" = ?`, scanID).Exec(ctx); err != nil {
		return fmt.Errorf("remove what this scan arrived with: %w", err)
	}
	return nil
}

// deleteChunks removes the contents of a scan's documents, every one or only
// the ones still held, and reports whether there were any. reading and
// removing name the two steps in an error.
func deleteChunks(ctx context.Context, db bun.IDB, scanID int64, heldOnly bool,
	reading, removing string) (bool, error) {

	var ids []int64
	q := db.NewSelect().Model((*Document)(nil)).
		Column("id").
		Where(`"scan_id" = ?`, scanID)
	if heldOnly {
		q = q.Where(`"discarded_at" IS NULL`)
	}
	if err := q.Scan(ctx, &ids); err != nil {
		return false, fmt.Errorf("%s: %w", reading, err)
	}
	if len(ids) == 0 {
		return false, nil
	}
	if err := chunked.Delete(ctx, db, chunked.ScanParts, ids); err != nil {
		return false, fmt.Errorf("%s: %w", removing, err)
	}
	return true, nil
}

// Held returns one document of one scan, for reading its contents back.
//
// Addressed through the scan it belongs to, not by its own identifier
// alone: whoever authorized the scan has authorized this, and a document
// identifier that resolved on its own would be a second way in that has to
// remember the same rule.
//
// A document whose contents have been let go answers as one that is gone
// rather than as one that does not exist, because those are different facts: a
// nightly build's contents are released once they have been read, and the
// record of what arrived stays behind on purpose.
func (d *Documents) Held(ctx context.Context, scanID, documentID int64) (*Document, error) {
	doc := new(Document)
	err := d.db.NewSelect().Model(doc).
		Where(`"id" = ?`, documentID).
		Where(`"scan_id" = ?`, scanID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoDocument
	}
	if err != nil {
		return nil, fmt.Errorf("read that document: %w", err)
	}
	if doc.DiscardedAt != nil {
		return nil, ErrLetGo
	}
	return doc, nil
}

// ErrNoDocument is no such document of that scan, and ErrLetGo is one whose
// contents were released after they were read.
var (
	ErrNoDocument = errors.New("no such document")
	ErrLetGo      = refusal.New("the contents of that document were let go")
)
