package ingest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
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

// chunkSize is how much of a document one row holds.
//
// Two engines cap how large a single statement may be, the cap is server
// configuration rather than anything a client can discover, and the lowest
// default in circulation is sixteen megabytes. A bounded row stays far inside
// every default and lets a document be read as a stream rather than held
// whole.
const chunkSize = 512 << 10

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

// chunk is a bounded piece of a document.
type chunk struct {
	bun.BaseModel `bun:"table:scan_document_chunk,alias:sdc"`

	ID         int64  `bun:"id,pk,autoincrement"`
	DocumentID int64  `bun:"document_id,notnull"`
	Seq        int    `bun:"seq,notnull"`
	Body       []byte `bun:"body,notnull"`
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
		CreatedAt: d.now().UTC().Truncate(time.Microsecond),
	}
	if _, err := d.db.NewInsert().Model(doc).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record document: %w", err)
	}

	digest := sha256.New()
	buf := make([]byte, chunkSize)
	for seq := 0; ; seq++ {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			body := buf[:n]
			digest.Write(body)
			doc.SizeBytes += int64(n)
			row := &chunk{DocumentID: doc.ID, Seq: seq, Body: body}
			if _, err := d.db.NewInsert().Model(row).Exec(ctx); err != nil {
				return nil, fmt.Errorf("store part %d of document: %w", seq, err)
			}
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read document: %w", err)
		}
	}

	doc.ContentHash = hex.EncodeToString(digest.Sum(nil))
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
		Where("scan_id = ?", scanID).
		Where("discarded_at IS NULL").
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
			Where("scan_id IN (?)", bun.List(batch)).
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
func (d *Documents) Open(ctx context.Context, documentID int64) io.Reader {
	return &chunkReader{ctx: ctx, db: d.db, documentID: documentID}
}

// Discard lets go of a scan's contents, keeping the record of what arrived.
//
// What a nightly build sent is superseded the next night, so keeping it costs
// storage that grows with the calendar. What a tagged release sent is kept,
// because re-scanning it years from now needs both what it contained and what
// the build had already argued about its own patches — so this is called for
// one and not the other.
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
		var ids []int64
		if err := tx.NewSelect().Model((*Document)(nil)).
			Column("id").
			Where("scan_id = ?", scanID).
			Where("discarded_at IS NULL").
			Scan(ctx, &ids); err != nil {
			return fmt.Errorf("read which documents are held: %w", err)
		}
		if len(ids) == 0 {
			return nil
		}
		if err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
			_, err := tx.NewDelete().Model((*chunk)(nil)).
				Where("document_id IN (?)", bun.List(batch)).Exec(ctx)
			return err
		}); err != nil {
			return fmt.Errorf("discard document content: %w", err)
		}
		if _, err := tx.NewUpdate().Model((*Document)(nil)).
			Set("discarded_at = ?", d.now().UTC()).
			Where("scan_id = ?", scanID).
			Where("discarded_at IS NULL").Exec(ctx); err != nil {
			return fmt.Errorf("record that the contents were let go: %w", err)
		}
		return nil
	})
}

// chunkReader walks a document's rows in order.
type chunkReader struct {
	ctx        context.Context
	db         bun.IDB
	documentID int64
	next       int
	held       []byte
	done       bool
	err        error
}

func (c *chunkReader) Read(p []byte) (int, error) {
	for len(c.held) == 0 {
		if c.err != nil {
			return 0, c.err
		}
		if c.done {
			return 0, io.EOF
		}
		var row chunk
		err := c.db.NewSelect().Model(&row).
			Where("document_id = ?", c.documentID).
			Where("seq = ?", c.next).
			Limit(1).Scan(c.ctx)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			c.done = true
			return 0, io.EOF
		case err != nil:
			c.err = fmt.Errorf("read part %d of document: %w", c.next, err)
			return 0, c.err
		}
		c.held = row.Body
		c.next++
	}
	n := copy(p, c.held)
	c.held = c.held[n:]
	return n, nil
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
		Where("scan_id = ?", scanID).
		Where("kind = ?", InventoryKind).
		Where("content_hash = ?", hash).
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
	var ids []int64
	if err := d.db.NewSelect().Model((*Document)(nil)).
		Column("id").
		Where("scan_id = ?", scanID).
		Scan(ctx, &ids); err != nil {
		return fmt.Errorf("read which documents this scan has: %w", err)
	}
	if len(ids) == 0 {
		return nil
	}
	if err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		_, err := d.db.NewDelete().Model((*chunk)(nil)).
			Where("document_id IN (?)", bun.List(batch)).Exec(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("remove document content: %w", err)
	}
	if _, err := d.db.NewDelete().Model((*Document)(nil)).
		Where("scan_id = ?", scanID).Exec(ctx); err != nil {
		return fmt.Errorf("remove what this scan arrived with: %w", err)
	}
	return nil
}

// Held returns one document of one scan, for reading its contents back.
//
// **Addressed through the scan it belongs to**, not by its own identifier
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
		Where("id = ?", documentID).
		Where("scan_id = ?", scanID).
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
	ErrLetGo      = errors.New("the contents of that document were let go")
)
