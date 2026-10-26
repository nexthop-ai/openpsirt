// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/typedname"
)

// What became of a VEX document or a supplier advisory that arrived.
const (
	// UploadTaken is a document whose statements were recorded.
	UploadTaken = "completed"
	// UploadTurnedAway is a document refused, with what the sender was told.
	UploadTurnedAway = "refused"
)

// mostUploadReason bounds what a refusal records of what the sender was told.
const mostUploadReason = 2000

// Arrival is how a document came to be recorded: uploaded by the subject
// recording it, or fetched by a supplier advisory feed.
type Arrival struct {
	// FeedID is the supplier whose feed fetched it, and zero for an upload.
	FeedID int64
}

// Upload is one VEX document or supplier advisory that arrived for a product,
// taken or turned away.
type Upload struct {
	bun.BaseModel `bun:"table:document_upload,alias:du"`

	ID        int64  `bun:"id,pk,autoincrement"`
	ProductID int64  `bun:"product_id,notnull"`
	Source    string `bun:"source,notnull"`
	// Publisher is normalized as a statement's is. Publisher and Identifier
	// are empty where the upload was refused before either was read.
	Publisher  string `bun:"publisher,notnull"`
	Identifier string `bun:"document_id,notnull"`
	// Document is the file name a client gave, or the address a feed fetched
	// it from.
	Document string  `bun:"document,notnull"`
	Digest   *string `bun:"digest"`
	// Credential is who uploaded it, as a scan's sender is spelled, and
	// FeedID the supplier whose feed fetched it. One of the two is set.
	Credential *string   `bun:"credential"`
	FeedID     *int64    `bun:"advisory_source_id"`
	ReceivedAt time.Time `bun:"received_at,notnull"`
	Status     string    `bun:"status,notnull"`
	Reason     *string   `bun:"reason"`
	// Recorded is how many statements it left standing and Superseded how
	// many earlier ones it set aside, as it was taken.
	Recorded   int `bun:"recorded,notnull"`
	Superseded int `bun:"superseded,notnull"`

	// Feed is the supplier's name, where a feed fetched it.
	Feed string `bun:"feed,scanonly"`
	// Newest is one where this is the newest upload taken under its
	// document's key.
	Newest int `bun:"newest,scanonly"`
}

// Current reports whether what this upload said is what stands now: it was
// taken, and no upload of the same document has been taken since.
func (u Upload) Current() bool { return u.Newest == 1 }

// arrived records that a document was taken, in the transaction that recorded
// its statements. A document a feed fetched that left no statement and set
// none aside is about nothing this product ships, and is not recorded: a
// distribution lists tens of thousands of those.
func (s *Store) arrived(ctx context.Context, tx bun.IDB, by access.Subject, productID int64,
	from Supplied, recorded, superseded int) error {

	if from.Arrived == nil || (from.Source != FromVex && from.Source != FromAdvisory) {
		return nil
	}
	if from.Arrived.FeedID != 0 && recorded == 0 && superseded == 0 {
		return nil
	}
	row := uploadOf(by, productID, from, s.now())
	row.Status, row.Recorded, row.Superseded = UploadTaken, recorded, superseded
	if _, err := tx.NewInsert().Model(&row).Exec(ctx); err != nil {
		return fmt.Errorf("record the upload: %w", err)
	}
	return nil
}

// TurnedAway records that a VEX document or a supplier advisory was refused,
// with what the sender was told. The publisher, the name and the digest are
// whatever was read of the document before it was refused.
//
// The subject is who was turned away, not a narrowing: this writes one row
// about one document and reads nothing back. It is recorded as the sender of
// an upload.
//
// A note about something that already failed. The caller logs what comes back
// and answers the sender either way.
func (s *Store) TurnedAway(ctx context.Context, by access.Subject, productID int64,
	from Supplied, reason string) error {

	if from.Arrived == nil || (from.Source != FromVex && from.Source != FromAdvisory) {
		return fmt.Errorf("record a refused upload: a document of kind %q, arriving no way this records",
			from.Source)
	}
	// Bounded to the columns, since what is refused is often what was too
	// long to take. Cut where a character starts, for the engines that check
	// the encoding.
	from.Publisher = bound.HeadRunes(from.Publisher, database.NameWidth)
	from.Identifier = bound.HeadRunes(from.Identifier, database.NameWidth)
	row := uploadOf(by, productID, from, s.now())
	said := bound.Head(reason, mostUploadReason)
	row.Status, row.Reason = UploadTurnedAway, &said
	if _, err := s.db.NewInsert().Model(&row).Exec(ctx); err != nil {
		return fmt.Errorf("record a refused upload: %w", err)
	}
	return nil
}

// uploadOf is the record of a document arriving, as far as it is known.
func uploadOf(by access.Subject, productID int64, from Supplied, now time.Time) Upload {
	row := Upload{
		ProductID: productID, Source: from.Source,
		Publisher:  typedname.Matching(from.Publisher),
		Identifier: strings.TrimSpace(from.Identifier),
		Document:   from.Document,
		ReceivedAt: now.UTC().Truncate(time.Microsecond),
	}
	if from.Digest != "" {
		digest := from.Digest
		row.Digest = &digest
	}
	if from.Arrived.FeedID != 0 {
		feed := from.Arrived.FeedID
		row.FeedID = &feed
	} else if sender := access.Sender(by); sender != "" {
		row.Credential = &sender
	}
	return row
}

// Uploads is the VEX documents or supplier advisories that arrived for one
// product, taken and turned away, the newest first, with how many there are.
//
// Read by a person who may know the product exists, which is who reads the
// product's uploads. A pipeline key sends inventories rather than these, and
// reads nothing about them.
func (s *Store) Uploads(ctx context.Context, subject access.Subject, productID int64,
	source string, limit, offset int) ([]Upload, int, error) {

	if !subject.Unnarrowed() && (subject.Kind != access.Person || !subject.Sees(productID)) {
		return nil, 0, access.Denied(fmt.Sprintf("read the documents uploaded to product %d", productID))
	}
	limit = database.AList.Of(limit)
	total, err := s.db.NewSelect().Model((*Upload)(nil)).
		Where(`"du"."product_id" = ?`, productID).
		Where(`"du"."source" = ?`, source).
		Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count the documents uploaded: %w", err)
	}

	var held []Upload
	err = s.db.NewSelect().Model(&held).
		ColumnExpr(`"du".*`).
		ColumnExpr(`"sp"."display_name" AS "feed"`).
		// Taken, and nothing taken under the same key since. The key is the
		// one a later upload replaces statements on.
		ColumnExpr(`CASE WHEN "du"."status" = ? AND NOT EXISTS (
			SELECT 1 FROM "document_upload" AS "newer"
			WHERE "newer"."product_id" = "du"."product_id"
				AND "newer"."source" = "du"."source"
				AND "newer"."publisher" = "du"."publisher"
				AND "newer"."document_id" = "du"."document_id"
				AND "newer"."status" = ?
				AND ("newer"."received_at" > "du"."received_at"
					OR ("newer"."received_at" = "du"."received_at" AND "newer"."id" > "du"."id"))
			) THEN 1 ELSE 0 END AS "newest"`, UploadTaken, UploadTaken).
		Join(`LEFT JOIN "advisory_source" AS "sp" ON "sp"."id" = "du"."advisory_source_id"`).
		Where(`"du"."product_id" = ?`, productID).
		Where(`"du"."source" = ?`, source).
		OrderExpr(`"du"."received_at" DESC, "du"."id" DESC`).
		Limit(int64(limit)).Offset(int64(offset)).
		Scan(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("read the documents uploaded: %w", err)
	}
	for i := range held {
		held[i].ReceivedAt = held[i].ReceivedAt.UTC()
	}
	return held, int(total), nil
}
