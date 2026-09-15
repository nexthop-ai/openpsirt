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
	// logger is where the one destructive pass in this package says what it
	// destroyed and what it could not. Nil where a caller has not said, which
	// every caller but the sweep is.
	logger *slog.Logger
	// afterPage runs between the collection pass reading its page and acting
	// on it, so a test can put there what a comment saving its text does. The
	// window is the whole of what the pass's guard is for, and waiting for it
	// to happen by itself is a test that passes by not racing.
	afterPage func()
}

// NewStore returns a store over db, keeping bytes in files.
//
// A nil Storage is the ordinary case for a deployment that configured none:
// attachments are off and everything else works.
func NewStore(db *bun.DB, files Storage) *Store {
	return &Store{db: db, files: files, now: func() time.Time { return time.Now().UTC() }}
}

// Reporting gives a store somewhere to say what a collection pass did.
//
// The pass is the only writer here that destroys somebody's data and the only
// one that kept no record of what it destroyed — a count, with no key, no
// filename and no issue. What it names is what an orphan can be found by.
func (s *Store) Reporting(logger *slog.Logger) *Store {
	s.logger = logger
	return s
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

// visibilityOf is how disclosed an issue is in one product.
//
// **The most careful row governs.** An issue with one undisclosed finding
// against it is undisclosed here, whatever else is open beside it — the same
// rule that decides what may be said about a group outside the application
// . Asked at the moment of the request rather than copied onto the
// attachment, so an embargo ending carries the file with the words.
func visibilityOf(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64) (access.Visibility, bool, error) {
	var counted struct {
		Here    int `bun:"here"`
		Private int `bun:"undisclosed"`
	}
	err := db.NewSelect().
		TableExpr(`finding AS "f"`).
		Join(`JOIN target AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN stream AS "st" ON st.id = tg.stream_id`).
		ColumnExpr(`COUNT(*) AS "here"`).
		// Counted rather than summed over a CASE. That shape comes back as a
		// decimal on two of the four engines and the cast that fixes it is
		// spelled per engine, which is why the rule says to write two counts
		// — and this was the second copy of a shape recorded as removed.
		ColumnExpr(`COUNT(CASE WHEN f.visibility = ? THEN 1 END) AS "undisclosed"`,
			access.Private).
		Where("st.product_id = ?", productID).
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Scan(ctx, &counted)
	if err != nil {
		return access.Private, false, fmt.Errorf("read how disclosed an issue is: %w", err)
	}
	// Whether the issue is here at all, answered separately from how disclosed
	// it is. Without it, "no undisclosed findings" and "no findings" were the
	// same answer — so an issue that is not in this product read as public
	// here and any reader of any product could confirm, one request at a time,
	// that a name exists somewhere in the deployment. That turns the random
	// draw an entered identifier is minted from into a space somebody can
	// check a guess against.
	if counted.Private > 0 {
		return access.Private, true, nil
	}
	return access.Public, counted.Here > 0, nil
}

// mayReach reports whether a subject may read this issue's text, which is
// exactly the question of whether they may read what the text refers to.
func mayReach(ctx context.Context, db bun.IDB, subject access.Subject,
	productID, vulnerabilityID int64) error {

	if subject.Kind != access.Person {
		return access.Denied("reach an attachment without being a person")
	}
	visibility, here, err := visibilityOf(ctx, db, productID, vulnerabilityID)
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
	if !holds(access.VisibleOn(subject, productID, vulnerabilityID), visibility) {
		// The same answer as an issue that is not there. Telling
		// somebody that a file exists but is not theirs is telling
		// them the issue exists .
		return access.Denied(fmt.Sprintf("reach attachments in product %d", productID))
	}
	return nil
}

// mayAttach reports whether a subject may put a file against this issue.
//
// **Attaching is triage work, not reading.** It was authorized with the read
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
	if subject.OnCase(productID, vulnerabilityID) {
		return nil
	}
	visibility, _, err := visibilityOf(ctx, db, productID, vulnerabilityID)
	if err != nil {
		return err
	}
	if !subject.Triages(visibility, productID) {
		// The same words reaching it refuses with, for the same reason.
		return access.Denied(fmt.Sprintf("attach a file in product %d", productID))
	}
	return nil
}

// Upload stores a file against an issue and records it.
//
// The bytes are streamed rather than held (the file-size limit bounds one
// file; holding each would mean every upload happening at once is resident at
// once), and hashed on the way through so that a redaction can say later what
// it removed.
//
// **`hangsOffTheIssue` says nothing is going to point at this from text.** A
// file attached while somebody is composing a justification is pointed at by
// words that are not saved yet, so it waits, and the sweep collects it if they
// abandon the form. A file attached to the issue itself — evidence, a
// test case that proves the flaw — is pointed at by the issue the moment it
// arrives, and waiting for text that will never be written would mean the
// sweep took it a day later.
func (s *Store) Upload(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64, filename string, body io.Reader, size int64,
	maxSize, quota, share int64, hangsOffTheIssue bool) (*Attachment, error) {

	if !s.Configured() {
		return nil, ErrNotConfigured
	}
	if err := mayAttach(ctx, s.db, subject, productID, vulnerabilityID); err != nil {
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
	counted := &counting{}
	if err := s.files.Put(ctx, key, io.TeeReader(io.TeeReader(whole, digest), counted),
		size, contentType); err != nil {
		return nil, err
	}
	if counted.n != size {
		if removed := s.files.Delete(ctx, key); removed != nil && s.logger != nil {
			s.logger.ErrorContext(ctx, "a short upload left bytes behind",
				"key", key, "error", removed)
		}
		return nil, fmt.Errorf("%d bytes arrived of the %d declared", counted.n, size)
	}

	now := s.now().Truncate(time.Microsecond)
	var row *Attachment
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		// Built inside, because an insert writes the generated identifier back
		// into the model. A retry of a rolled-back attempt would re-insert a
		// model already carrying the key that attempt was given.
		row = &Attachment{
			Token: token, ProductID: productID, VulnerabilityID: vulnerabilityID,
			Filename: SafeName(filename), ContentType: contentType, SizeBytes: size,
			Digest: hex.EncodeToString(digest.Sum(nil)), ObjectKey: key,
			UploadedBy: subject.ID, UploadedAt: now,
		}
		if hangsOffTheIssue {
			row.AttachedAt = &now
		}
		// Asked again inside the transaction, because the first answer
		// was read before the bytes were carried and the deployment
		// may have filled up while they were.
		if err := roomIn(ctx, tx, size, quota); err != nil {
			return err
		}
		if err := shareLeft(ctx, tx, subject.ID, size, share); err != nil {
			return err
		}
		_, err := tx.NewInsert().Model(row).Exec(ctx)
		return err
	})
	if err != nil {
		// The row is what the sweep can see, so a failure here leaves bytes
		// nothing knows about. Removed now rather than left for a reaper that
		// has no record to work from — and where that removal fails too, the
		// key is said out loud, because it is then the only thing that can
		// find them.
		if removed := s.files.Delete(ctx, key); removed != nil && s.logger != nil {
			s.logger.ErrorContext(ctx, "an upload that could not be recorded left bytes behind",
				"key", key, "error", removed)
		}
		return nil, fmt.Errorf("record an attachment: %w", err)
	}
	return row, nil
}

// counting counts what passed through it, so that a declared size that does
// not match what arrived is caught rather than trusted.
type counting struct{ n int64 }

func (c *counting) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// roomIn refuses an upload the deployment has no space for.
//
// Takes the handle rather than reading the store's own, so that the question
// can be asked again inside the transaction that writes.
func roomIn(ctx context.Context, db bun.IDB, size, quota int64) error {
	if quota <= 0 {
		return nil
	}
	var held int64
	if err := db.NewSelect().
		TableExpr(`attachment AS "at"`).
		ColumnExpr("COALESCE(SUM(at.size_bytes), 0)").
		Where("at.redacted_at IS NULL").
		Scan(ctx, &held); err != nil {
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
	var held int64
	if err := db.NewSelect().
		TableExpr(`attachment AS "at"`).
		ColumnExpr("COALESCE(SUM(at.size_bytes), 0)").
		Where("at.redacted_at IS NULL").
		Where("at.uploaded_by = ?", personID).
		Scan(ctx, &held); err != nil {
		return fmt.Errorf("read how much they are holding: %w", err)
	}
	if held+size > share {
		return ErrNoRoom
	}
	return nil
}

// holds reports whether one of these visibilities is the one wanted.
func holds(visible []access.Visibility, want access.Visibility) bool {
	for _, each := range visible {
		if each == want {
			return true
		}
	}
	return false
}
