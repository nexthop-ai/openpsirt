// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
)

// ErrMayNotPublish says the subject may read this build and may not say a
// document about it went out.
//
// A denial rather than the answer a build nobody declared gets: whoever
// reaches it has just been handed the build by name, so telling them it is not
// there contradicts the read they performed. It is a denial of its own rather
// than the one a reader gets, because the two refuse different callers and the
// route turns one into a 404 and the other into a 403.
var ErrMayNotPublish = fmt.Errorf(
	"%w: recording that a document went out asks for the triage role on this product",
	access.ErrDenied)

// Issuance is one time the document for a build went out.
//
// A fact about a moment rather than a derived value. What was published on a
// date cannot be worked out again once a claim is withdrawn, a decision is
// revised or a scan closes a finding, so if the act is not written down when
// it happens it is gone.
//
// It is also what the document's version counts. A document assembled from
// what stands now holds no history of its own, so without a record of what
// went out every generation is the first revision of something — which is what
// a reader keeping documents by their identifier has no way to order.
type Issuance struct {
	bun.BaseModel `bun:"table:vex_issuance,alias:vi"`

	ID int64 `bun:"id,pk,autoincrement"`
	// TargetID is the build the document was about, which is what its
	// identifier names.
	TargetID int64 `bun:"target_id,notnull"`
	// Ordinal is which issuance this is, counting from one, and the version
	// the document kept beside it states.
	Ordinal int `bun:"ordinal,notnull"`
	// Digest is what the document said, hashed. It is what makes "is what is
	// published still what we would generate" a question with a yes or no.
	Digest string `bun:"digest,notnull"`
	// Document is what went out, as the bytes handed to whoever recorded it.
	//
	// Written in the transaction that takes the ordinal, so the version the
	// document states is the one it is recorded under. A document generated
	// before the write carries whatever the count said then, and a second
	// issuance committing in between leaves an operator holding a document
	// numbered one behind its record.
	Document string    `bun:"document,notnull"`
	IssuedBy int64     `bun:"issued_by,notnull"`
	IssuedAt time.Time `bun:"issued_at,notnull"`
}

// Issued records that the document for a build went out, and returns what was
// recorded, the document itself included.
//
// The document handed back is the one to send. It carries the version it is
// recorded under, which a document generated before recording does not
// promise: somebody else recording in between moves the count.
//
// The digest is taken from the document as it is now, generated inside this
// call rather than supplied by the caller. A caller-supplied digest is a
// digest of whatever they say, and the question this exists to answer only
// means something if both sides come from here.
//
// The public document, never the preview. Asking for the undisclosed ones
// builds something for a reader inside this deployment to look at, and
// recording that as having gone out would say the deployment published work
// nobody has announced.
//
// Recording asks for the triage role on the product rather than the right to
// read it. The document is this deployment's word to a customer, and the
// second pair of eyes on each statement it carries was taken when the claim
// was approved.
func (s *Store) Issued(ctx context.Context, subject access.Subject, who publisher.Named,
	product, stream, variant string) (*Issuance, error) {

	if !who.Stated() {
		return nil, errNoPublisher
	}
	named, target, err := s.locate(ctx, subject, product, stream, variant)
	if err != nil {
		return nil, err
	}
	if !subject.Triages(access.Public, named.ProductID) {
		return nil, ErrMayNotPublish
	}
	doc, err := s.document(ctx, who, named, target,
		[]access.Visibility{access.Public})
	if err != nil {
		return nil, err
	}
	digest, err := settledDigest(doc)
	if err != nil {
		return nil, err
	}
	if s.generated != nil {
		s.generated()
	}

	var recorded *Issuance
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		// Read here, like the ordinal below and for the same reason. Taken
		// before the transaction, a retry carries the moment the first
		// attempt started: two people recording an issuance for one build at
		// once leaves the loser retrying and landing the later ordinal with
		// the earlier moment, so what went out reads as having gone out
		// before the revision it follows.
		issuedAt := s.now().UTC().Truncate(time.Microsecond)
		// Built inside, because an insert writes the generated identifier
		// back into the model and the ordinal below is read from the
		// database. A retry of a rolled-back attempt would re-insert a model
		// carrying both of that attempt's answers.
		recorded = &Issuance{
			TargetID: target.ID, Digest: digest,
			IssuedBy: subject.ID, IssuedAt: issuedAt,
		}
		// Scanned into a value rather than read through a cursor: a cursor
		// left open while the insert runs is two statements interleaved on one
		// connection, which one engine tolerates and another refuses.
		var highest int
		if err := tx.NewSelect().Model((*Issuance)(nil)).
			ColumnExpr("COALESCE(MAX(ordinal), 0)").
			Where("target_id = ?", target.ID).
			Scan(ctx, &highest); err != nil {
			return err
		}
		recorded.Ordinal = highest + 1
		// The bytes that go out, numbered and dated inside the write. What
		// the digest covers was settled above; the version and the moment
		// are what this transaction decides.
		went := *doc
		went.Version, went.Timestamp = recorded.Ordinal, issuedAt
		body, err := json.Marshal(went)
		if err != nil {
			return fmt.Errorf("write down what went out: %w", err)
		}
		recorded.Document = string(body)
		// The number is read and used here, and two people recording at the
		// same moment still read the same one — what stops them sharing it is
		// the unique constraint, whose answer is an error. Said as a lost
		// race, the helper re-runs the whole closure and the second reads the
		// number the first wrote; reported as it arrives, it is a fault
		// nobody can act on.
		if _, err := tx.NewInsert().Model(recorded).Exec(ctx); err != nil {
			if database.IsDuplicate(err) {
				return database.ErrGoAgain
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("record that it went out: %w", err)
	}
	return recorded, nil
}

// Went is one issuance as a reader of the record gets it.
//
// The person is named rather than numbered. A record of an act that says only
// that somebody did it answers half the question, and the row is the whole of
// what this act leaves behind — there is no trail entry beside it.
type Went struct {
	Ordinal  int       `bun:"ordinal"`
	Digest   string    `bun:"digest"`
	IssuedBy string    `bun:"issued_by"`
	IssuedAt time.Time `bun:"issued_at"`
}

// Issuances is what has gone out for one build, oldest first.
//
// Readable without generating a document, and without a publisher configured:
// it names no author and assembles nothing. Somebody deciding whether to
// publish a revision is asking before they generate anything, and the digest
// beside each entry is what answers whether the last one still describes what
// this would produce.
//
// Narrowed the way the document is: a build in a product this reader may not
// see is one they are told does not exist, and a row saying a document about
// it went out is as much a disclosure as the document.
func (s *Store) Issuances(ctx context.Context, subject access.Subject,
	product, stream, variant string) ([]Went, error) {

	_, target, err := s.locate(ctx, subject, product, stream, variant)
	if err != nil {
		return nil, err
	}
	var rows []Went
	err = s.db.NewSelect().
		TableExpr(`"vex_issuance" AS "vi"`).
		Join(`JOIN "person" AS "pe" ON pe.id = vi.issued_by`).
		ColumnExpr(`vi.ordinal AS "ordinal"`).
		ColumnExpr(`vi.digest AS "digest"`).
		ColumnExpr(`pe.identity AS "issued_by"`).
		ColumnExpr(`vi.issued_at AS "issued_at"`).
		Where("vi.target_id = ?", target.ID).
		OrderExpr("vi.ordinal ASC").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what has gone out: %w", err)
	}
	return rows, nil
}

// Changed reports whether what the public document for a build says now
// differs from what last went out, or nil where that has no answer.
//
// Nil where nothing has gone out, since there is nothing to differ from, and
// where no publisher is configured, since nothing can be generated to compare.
// The comparison is between settled digests, so a document regenerated with
// nothing but its moment and its version moved reads as unchanged.
func (s *Store) Changed(ctx context.Context, subject access.Subject, who publisher.Named,
	product, stream, variant string) (*bool, error) {

	if !who.Stated() {
		return nil, nil
	}
	named, target, err := s.locate(ctx, subject, product, stream, variant)
	if err != nil {
		return nil, err
	}
	var last string
	err = s.db.NewSelect().Model((*Issuance)(nil)).
		Column("digest").
		Where("target_id = ?", target.ID).
		OrderExpr("ordinal DESC").
		Limit(1).
		Scan(ctx, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read what last went out: %w", err)
	}
	doc, err := s.document(ctx, who, named, target, []access.Visibility{access.Public})
	if err != nil {
		return nil, err
	}
	now, err := settledDigest(doc)
	if err != nil {
		return nil, err
	}
	changed := now != last
	return &changed, nil
}

// Sent is the document that went out as one revision, as the bytes that went
// out.
//
// Narrowed the way the record of issuances is, because the bytes are what the
// row describes.
func (s *Store) Sent(ctx context.Context, subject access.Subject,
	product, stream, variant string, ordinal int) (string, error) {

	_, target, err := s.locate(ctx, subject, product, stream, variant)
	if err != nil {
		return "", err
	}
	var body string
	err = s.db.NewSelect().Model((*Issuance)(nil)).
		Column("document").
		Where("target_id = ?", target.ID).
		Where("ordinal = ?", ordinal).
		Limit(1).
		Scan(ctx, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNoSuchRevision
	}
	if err != nil {
		return "", fmt.Errorf("read what went out: %w", err)
	}
	return body, nil
}

// ErrNoSuchRevision says no document went out as that revision.
var ErrNoSuchRevision = errors.New("no document went out as that revision")

// revision is which revision the document for this build is, counting from
// one.
//
// One past what has gone out. A document nobody has published is the first;
// the next one generated after an issuance is the second, and says so before
// it goes out, because the bytes an operator sends have to carry the number
// they will be known by.
func (s *Store) revision(ctx context.Context, targetID int64) (int, error) {
	var highest int
	err := s.db.NewSelect().Model((*Issuance)(nil)).
		ColumnExpr("COALESCE(MAX(ordinal), 0)").
		Where("target_id = ?", targetID).
		Scan(ctx, &highest)
	if err != nil {
		return 0, fmt.Errorf("read which revision this is: %w", err)
	}
	return highest + 1, nil
}

// settledDigest is what the document says, hashed.
//
// The settled digest, which is one of the two hashes a published document has
// and the one taken here. It answers "is what is published still what we would
// generate", so everything that moves for a reason other than the content is
// left out of it: the moment it was generated, the build of OpenPSIRT that
// generated it, and the revision number, which moves *because* the document
// went out rather than because it says something different.
//
// The other hash is over the delivered bytes, volatile fields included, and
// answers whether the file a reader fetched arrived intact. The two are not
// interchangeable and neither is a duplicate of the other.
//
// The identifier is inside it. It names the build the document is about, which
// is as much a part of what the document says as any statement in it.
func settledDigest(doc *Statements) (string, error) {
	settled := *doc
	settled.Timestamp = time.Time{}
	settled.Tooling = ""
	settled.Version = 0
	body, err := json.Marshal(settled)
	if err != nil {
		return "", fmt.Errorf("hash what went out: %w", err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

// AnyIssuedForVariant reports whether a document has gone out for any build of
// one variant.
//
// What a rename is refused on. A document is identified by the build it is
// about — the publisher's namespace, then the product, the release and the
// variant — and that identifier is inside the digest of what went out. A
// reader tells a revision of a document they hold from a second document by
// whether the identifier matches, so moving the name after publication does
// not revise the document: it mints a different one, and leaves the one people
// have looking abandoned.
//
// The record cannot carry the correction either. An issuance is stored against
// the build and the revision number, and never against the name, so a rename
// would leave every row reading as a revision of a document that never went
// out under that name.
//
// Asked of the variant rather than of one build, because a variant is built on
// every release and any one of them having gone out is enough.
//
// A function over the handle it is given rather than a method, so that it runs
// inside the transaction that acts on the answer. A store here holds a pool
// because it opens transactions of its own, and asking this outside the
// rename's transaction answers for a database the rename no longer writes to:
// a document issued between the two would be published under a name this had
// already said nothing was published under.
func AnyIssuedForVariant(ctx context.Context, db bun.IDB, variantID int64) (bool, error) {
	return anyIssuedWhere(ctx, db, "tg.variant_id = ?", variantID, "variant")
}

// AnyIssuedForStream reports whether a document has gone out for any variant of
// one release.
//
// The release is inside the same identifier the variant is, for the same
// reasons AnyIssuedForVariant gives.
func AnyIssuedForStream(ctx context.Context, db bun.IDB, streamID int64) (bool, error) {
	return anyIssuedWhere(ctx, db, "tg.stream_id = ?", streamID, "release")
}

// AnyIssuedForProduct reports whether a document has gone out for any build of
// one product.
func AnyIssuedForProduct(ctx context.Context, db bun.IDB, productID int64) (bool, error) {
	return anyIssuedWhere(ctx, db,
		`"tg"."stream_id" IN (SELECT "id" FROM "stream" WHERE "product_id" = ?)`,
		productID, "product")
}

func anyIssuedWhere(ctx context.Context, db bun.IDB, where string, id int64, what string) (bool, error) {
	issued, err := db.NewSelect().Model((*Issuance)(nil)).
		Join(`JOIN "target" AS "tg" ON tg.id = vi.target_id`).
		Where(where, id).
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether anything has gone out for this %s: %w", what, err)
	}
	return issued, nil
}
