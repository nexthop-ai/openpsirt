// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// Store reads and writes attachments, and owns the bytes as well as the rows.
//
// Both together, deliberately: an attachment is a row that describes a file,
// and a caller able to write one without the other could leave a reference to
// bytes that never arrived, or bytes nothing will ever reach.
type Store struct {
	db    *bun.DB
	files Storage
	now   func() time.Time
	// logger is where this package says what it destroyed, and which bytes it
	// could not: the collection pass, and an upload whose record failed. Nil
	// where a caller has not said, and then the process's default logger.
	logger *slog.Logger
	// afterPage runs between the collection pass reading its page and acting
	// on it, so a test can put there what a comment saving its text does. The
	// window is the whole of what the pass's guard is for, and waiting for it
	// to happen by itself is a test that passes by not racing.
	afterPage func()
	// beforeRecord runs inside an upload's transaction, after the room is
	// checked and before the row is written, so a test can hold two uploads
	// in the window a concurrent writer would otherwise slip through.
	beforeRecord func()
	// recorded replaces the error an upload's transaction answered, so a test
	// can report a failure for a transaction that committed, as a driver does
	// when the caller goes away during the commit.
	recorded func(error) error
}

// NewStore returns a store over db, keeping bytes in files.
//
// A nil Storage is the ordinary case for a deployment that configured none:
// attachments are off and everything else works.
func NewStore(db *bun.DB, files Storage) *Store {
	return &Store{db: db, files: files, now: func() time.Time { return time.Now().UTC() }}
}

// Reporting gives a store somewhere to say what it removed and what it could
// not.
//
// The collection pass destroys somebody's data and keeps no record of what it
// destroyed, and an upload whose record failed leaves bytes no row names.
// What either logs is what an orphan can be found by.
func (s *Store) Reporting(logger *slog.Logger) *Store {
	s.logger = logger
	return s
}

// log is where the store says what it could not remove: its own logger, or
// the process's default, because an unremoved key is the only way to find the
// bytes and has to reach somebody.
func (s *Store) log() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return slog.Default()
}

// Configured reports whether this deployment can hold files at all.
func (s *Store) Configured() bool { return s.files != nil }

// ErrNotConfigured is what every path answers where no store is configured.
var ErrNotConfigured = fmt.Errorf("this deployment holds no attachments")

// ErrTooLarge, ErrNoRoom and ErrGone are the three refusals a caller has to
// tell apart: one file is too big, the deployment is full, and the bytes were
// taken back out on purpose.
var (
	ErrTooLarge = fmt.Errorf("that file is larger than this deployment accepts")
	ErrNoRoom   = fmt.Errorf("this deployment has no room for more attachments")
	ErrGone     = fmt.Errorf("that attachment was removed")
)

// visibilitiesOf is how disclosed an issue is in one product: the
// visibilities a reader has to hold to reach what hangs off it.
//
// The most careful rows govern. An issue with one undisclosed finding
// against it is undisclosed here, whatever else is open beside it — the same
// rule that decides what may be said about a group outside the application.
// Each visibility other than public is its own grant and neither answers for
// the other, so an issue holding private and security testing rows asks for both.
// Only an issue with nothing but disclosed rows asks for public. Asked at the
// moment of the request rather than copied onto the attachment, so an embargo
// ending carries the file with the words.
//
// The issue's presence here at all is the second answer. Without it, "no
// undisclosed findings" and "no findings" are the same answer, and any reader
// of any product could confirm a guessed identifier one request at a time.
func visibilitiesOf(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64) (
	[]access.Visibility, bool, error) {

	var held []string
	kinds, kindArgs := kind.Triage.Where(`"f"."kind"`)
	err := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		ColumnExpr(`DISTINCT "f"."visibility"`).
		Where(`"st"."product_id" = ?`, productID).
		Where(finding.HeldAs(`"f"."vulnerability_id"`), vulnerabilityID).
		Where(kinds, kindArgs...).
		Scan(ctx, &held)
	if err != nil {
		return nil, false, fmt.Errorf("read how disclosed an issue is: %w", err)
	}
	var withheld []access.Visibility
	for _, each := range held {
		if v := access.AsVisibility(each); v != access.Public {
			withheld = append(withheld, v)
		}
	}
	if len(withheld) > 0 {
		return withheld, true, nil
	}
	return []access.Visibility{access.Public}, len(held) > 0, nil
}

// mayReach reports whether a subject may read this issue's text, which is
// exactly the question of whether they may read what the text refers to.
func mayReach(ctx context.Context, db bun.IDB, subject access.Subject,
	productID, vulnerabilityID int64) error {

	if subject.Kind != access.Person {
		return access.Denied("reach an attachment without being a person")
	}
	required, here, err := visibilitiesOf(ctx, db, productID, vulnerabilityID)
	if err != nil {
		return err
	}
	if !here {
		// An issue this product does not have. Answered as a refusal rather
		// than as a visibility question, because there is nothing here to be
		// visible: a name filed against some other product would otherwise
		// confirm itself against this one.
		return access.Denied(fmt.Sprintf("reach attachments in product %d", productID))
	}
	// The case grant is asked here too. Somebody brought into one issue
	// may read what hangs off it, and asking only the product-wide
	// question made the grant one that granted nothing on the files that
	// are usually the evidence.
	if !holdsAll(access.VisibleOn(subject, productID, vulnerabilityID), required) {
		// The same answer as an issue that is not there. Telling
		// somebody that a file exists but is not theirs is telling
		// them the issue exists .
		return access.Denied(fmt.Sprintf("reach attachments in product %d", productID))
	}
	return nil
}

// mayAttach reports whether a subject may put a file against this issue.
//
// Attaching is triage work, not reading. It was authorized with the read
// test above, so a role granting nothing but the ability to read disclosed
// findings on one product could write files into the deployment's store — and
// what that costs is not the reader's, it is every other upload in every
// product once the quota is gone.
//
// A collaborator brought onto the case may still attach. Evidence is usually
// the reason somebody is brought in, and a grant that cannot carry it is one
// that grants nothing where it matters.
func mayAttach(ctx context.Context, db bun.IDB, subject access.Subject,
	productID, vulnerabilityID int64) error {

	if err := mayReach(ctx, db, subject, productID, vulnerabilityID); err != nil {
		return err
	}
	if subject.OnCaseToAct(productID, vulnerabilityID) {
		return nil
	}
	required, _, err := visibilitiesOf(ctx, db, productID, vulnerabilityID)
	if err != nil {
		return err
	}
	for _, visibility := range required {
		if !subject.Triages(visibility, productID) {
			// The same words reaching it refuses with, for the same reason.
			return access.Denied(fmt.Sprintf("attach a file in product %d", productID))
		}
	}
	return nil
}

// MayAttach refuses what Upload refuses about who is asking: a deployment that
// configured no store, and a subject who may not attach to what the file would
// hang off. Asked by a route before anything is carried.
func (s *Store) MayAttach(ctx context.Context, subject access.Subject, at Against) error {
	if !s.Configured() {
		return ErrNotConfigured
	}
	return mayAttachTo(ctx, s.db, subject, at)
}

// mayAttachTo is mayAttach asked of whichever of the two a file hangs off.
func mayAttachTo(ctx context.Context, db bun.IDB, subject access.Subject,
	at Against) error {

	if err := at.named(); err != nil {
		return err
	}
	if issue := at.Issue(); issue != nil {
		return mayAttach(ctx, db, subject, at.ProductID, *issue)
	}
	// Writing to a report asks for the right to work reports, which reading
	// one does not grant. The report has to be here first, for the reason a
	// read asks it first.
	if err := mayReachReport(ctx, db, subject, at.ProductID, *at.Report()); err != nil {
		return err
	}
	if !subject.Triages(access.Private, at.ProductID) {
		return access.Denied(fmt.Sprintf("reach attachments in product %d", at.ProductID))
	}
	return nil
}

// mayReachReport reports whether a subject may read what arrived with one
// report.
//
// The right to read work nobody has announced in that product, whether or
// not the report has been judged. A file that arrived with a claim is what a
// stranger sent and nobody has reviewed it, so judging the claim to be a
// disclosed issue must not publish it to everybody who reads that product —
// a file meant to be read there is attached to the issue, which is an act
// somebody takes.
//
// The same rule the report itself takes, so the record and what arrived with
// it have one answer rather than two. Attaching one asks for more, and is
// checked where a file is attached.
//
// A file on an issue follows the issue instead, including an embargo ending.
// The two differ because what they hang off differs: one is our own record of
// a flaw, the other is what somebody outside sent us.
//
// The product is the one the request named, and a report filed against
// another product answers as one that is not here. Told apart, the pair of
// answers says which products hold claims.
func mayReachReport(ctx context.Context, db bun.IDB, subject access.Subject,
	productID, reportID int64) error {

	if subject.Kind != access.Person {
		return access.Denied("reach an attachment without being a person")
	}
	// The report has to be in the product the request named before anything
	// is said about who may read it.
	var here int
	err := db.NewSelect().
		TableExpr(`"flaw_report" AS "fr"`).
		ColumnExpr("COUNT(*)").
		Where(`"fr"."id" = ?`, reportID).
		Where(`"fr"."product_id" = ?`, productID).
		Scan(ctx, &here)
	if err != nil {
		return fmt.Errorf("read what a report is about: %w", err)
	}
	// The same answer for a report that is not here and one this subject may
	// not read, for the reason an issue's files give the same answer twice:
	// telling somebody a file exists but is not theirs tells them the claim
	// exists.
	if here == 0 || !subject.Reads(access.Private, productID) {
		return access.Denied(fmt.Sprintf("reach attachments in product %d", productID))
	}
	return nil
}

// Upload stores a file against an issue or a report and records it.
//
// The bytes are streamed rather than held (the file-size limit bounds one
// file; holding each would mean every upload happening at once is resident at
// once), and hashed on the way through so that a redaction can say later what
// it removed.
//
// `held` says nothing is going to point at this from text. A file attached
// while somebody is composing a justification is pointed at by words that are
// not saved yet, so it waits, and the sweep collects it if they abandon the
// form. A file the thing itself holds — evidence on an issue, a test case
// that proves the flaw, whatever arrived with a report — is pointed at the
// moment it arrives, and waiting for text that will never be written would
// mean the sweep took it a day later.
func (s *Store) Upload(ctx context.Context, subject access.Subject,
	at Against, filename string, body io.Reader, size int64,
	maxSize, quota, share int64, held bool) (*Attachment, error) {

	if err := s.MayAttach(ctx, subject, at); err != nil {
		return nil, err
	}
	if size <= 0 {
		return nil, fmt.Errorf("an attachment has to have something in it")
	}
	if maxSize > 0 && size > maxSize {
		return nil, ErrTooLarge
	}
	// Asked before anything is carried, so an upload that cannot be kept is
	// refused rather than transferred and then thrown away.
	if err := roomIn(ctx, s.db, size, quota); err != nil {
		return nil, err
	}
	if err := shareLeft(ctx, s.db, subject.ID, size, share); err != nil {
		return nil, err
	}
	if quota > 0 || share > 0 {
		if err := queue.EnsureTurn(ctx, s.db, uploadLock); err != nil {
			return nil, err
		}
	}

	token, err := mintToken()
	if err != nil {
		return nil, err
	}
	key := keyFor(token)

	// The type is decided from the bytes and never from what the uploader
	// called it, which means reading the head before the rest goes to the
	// store — and then putting it back in front, so the store still
	// receives the whole file.
	head := make([]byte, 512)
	read, err := io.ReadFull(body, head)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("read what was uploaded: %w", err)
	}
	head = head[:read]
	contentType := TypeOf(head)

	digest := sha256.New()
	whole := io.MultiReader(strings.NewReader(string(head)), body)
	// A body that is not the declared size is the store's to refuse, and
	// both do (Storage.Put).
	if err := s.files.Put(ctx, key, io.TeeReader(whole, digest), size, contentType); err != nil {
		return nil, err
	}

	var row *Attachment
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		now := s.now().Truncate(time.Microsecond)
		// Built inside, because an insert writes the generated identifier back
		// into the model. A retry of a rolled-back attempt would re-insert a
		// model already carrying the key that attempt was given.
		row = &Attachment{
			Token: token, ProductID: at.ProductID,
			VulnerabilityID: at.Issue(), FlawReportID: at.Report(),
			Filename: SafeName(filename), ContentType: contentType, SizeBytes: size,
			Digest: hex.EncodeToString(digest.Sum(nil)), ObjectKey: key,
			UploadedBy: subject.ID, UploadedAt: now,
		}
		if held {
			row.AttachedAt = &now
		}
		// Asked again inside the transaction, because the first answer
		// was read before the bytes were carried and the deployment
		// may have filled up while they were. Behind the lock, because a
		// total read beside another upload's transaction does not hold that
		// upload's file.
		if quota > 0 || share > 0 {
			if err := queue.TakeTurn(ctx, tx, uploadLock); err != nil {
				return err
			}
		}
		if err := roomIn(ctx, tx, size, quota); err != nil {
			return err
		}
		if err := shareLeft(ctx, tx, subject.ID, size, share); err != nil {
			return err
		}
		if s.beforeRecord != nil {
			s.beforeRecord()
		}
		_, err := tx.NewInsert().Model(row).Exec(ctx)
		return err
	})
	if s.recorded != nil {
		err = s.recorded(err)
	}
	if err != nil {
		if s.unrecorded(ctx, token, key) {
			// The commit landed: the upload is done, and answering it failed
			// would have the caller send a second copy.
			return row, nil
		}
		return nil, fmt.Errorf("record an attachment: %w", err)
	}
	return row, nil
}

// unrecorded removes the bytes of an upload whose transaction failed.
//
// The row is what the sweep can see, so a failure leaves bytes nothing knows
// about. The bytes are removed at once, because no record is left for a sweep
// to find them by, and where that removal fails too, the key is logged,
// because it is then the only thing that can find them. On a context of its
// own, because the request's is often why the record failed: a client that
// went away.
//
// A failure answered during the commit does not say the commit failed, so the
// row is looked for first: bytes a committed row names stay with their row,
// and the answer says the row was found.
func (s *Store) unrecorded(ctx context.Context, token, key string) bool {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupWait)
	defer cancel()
	held, err := s.db.NewSelect().Model((*Attachment)(nil)).Where(`"token" = ?`, token).Count(cleanup)
	if err != nil {
		s.log().ErrorContext(ctx, "an upload that may not have been recorded left bytes behind",
			"key", key, "error", err)
		return false
	}
	if held > 0 {
		return true
	}
	if removed := s.files.Delete(cleanup, key); removed != nil {
		s.log().ErrorContext(ctx, "an upload that could not be recorded left bytes behind",
			"key", key, "error", removed)
	}
	return false
}

// uploadLock names the turn an upload's transaction takes before it reads how
// much is stored. The room is a sum over rows, and a sum read beside another
// upload's uncommitted insert does not include it.
const uploadLock = "attachment uploads"

// cleanupWait bounds a removal that runs on a context of its own so that it
// finishes past a stop or a caller going away: an upload's bytes whose record
// failed, the collection pass's claim and its bytes, and a redacted file's
// bytes. One still running when the shutdown grace ends fails the exit, which
// is true, and cutting it short would leave bytes nothing names.
const cleanupWait = 30 * time.Second

// roomIn refuses an upload the deployment has no space for.
//
// Takes the handle rather than reading the store's own, so that the question
// can be asked again inside the transaction that writes.
func roomIn(ctx context.Context, db bun.IDB, size, quota int64) error {
	if quota <= 0 {
		return nil
	}
	held, err := heldBytes(ctx, db, 0)
	if err != nil {
		return fmt.Errorf("read how much is stored: %w", err)
	}
	if held+size > quota {
		return ErrNoRoom
	}
	return nil
}

// shareLeft refuses an upload that would take one person past their part of
// the store.
//
// The deployment-wide ceiling is one person's to reach on their own, and what
// reaching it costs is everybody else's next upload — a triager's evidence on
// an active embargo in another product answering "no room" because somebody
// filled it. Asked with the same handle roomIn takes, for the same reason.
func shareLeft(ctx context.Context, db bun.IDB, personID, size, share int64) error {
	if share <= 0 || personID == 0 {
		return nil
	}
	held, err := heldBytes(ctx, db, personID)
	if err != nil {
		return fmt.Errorf("read how much they are holding: %w", err)
	}
	if held+size > share {
		return ErrNoRoom
	}
	return nil
}

// heldBytes is how many bytes the store holds that nobody redacted: every
// upload, or one person's where personID is not zero.
func heldBytes(ctx context.Context, db bun.IDB, personID int64) (int64, error) {
	var held int64
	q := db.NewSelect().
		TableExpr(`"attachment" AS "at"`).
		ColumnExpr(`COALESCE(SUM("at"."size_bytes"), 0)`).
		Where(`"at"."redacted_at" IS NULL`)
	if personID != 0 {
		q = q.Where(`"at"."uploaded_by" = ?`, personID)
	}
	err := q.Scan(ctx, &held)
	return held, err
}

// holdsAll reports whether every visibility wanted is among these.
func holdsAll(visible []access.Visibility, wanted []access.Visibility) bool {
	for _, want := range wanted {
		found := false
		for _, each := range visible {
			if each == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
