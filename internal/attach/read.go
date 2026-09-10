package attach

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Find returns one attachment, if the asker may read the issue it hangs off.
//
// **Authorized before anything about the file is said back**. The row
// is read first because the issue it belongs to is not knowable otherwise, and
// nothing about it — that it exists, what it is called, that it was redacted —
// reaches the caller until they have been let in. A token nobody minted and a
// token on an issue somebody may not see answer identically.
func (s *Store) Find(ctx context.Context, subject access.Subject, token string) (*Attachment, error) {
	if !s.Configured() {
		return nil, ErrNotConfigured
	}
	row := new(Attachment)
	err := s.db.NewSelect().Model(row).Where("token = ?", strings.TrimSpace(token)).Scan(ctx)
	if database.IsNoRows(err) {
		return nil, access.Denied("reach an attachment")
	}
	if err != nil {
		return nil, fmt.Errorf("read an attachment: %w", err)
	}
	if err := mayReach(ctx, s.db, subject, row.ProductID, row.VulnerabilityID); err != nil {
		if errors.Is(err, access.ErrDenied) {
			// **The same words as a token nobody minted**, and deliberately
			// not the ones mayReach produces: those name the product, which a
			// token does not. Told apart, the two answers turn a reference
			// somebody guessed into a way to ask which products exist and
			// which of them hold undisclosed work.
			return nil, access.Denied("reach an attachment")
		}
		return nil, err
	}
	return row, nil
}

// Fetch says how one attachment should be served.
//
// Either an address to send the browser to, or a reader to serve from here —
// and which it is comes from inline images served here: an image displayed in
// the page is carried by the application, because a page here may load images
// from this origin and no other, and everything else is redirected.
//
// A store with no signing authority of its own answers with no address, and
// then everything is served from here. That is the local backend, and it is
// why the two cases are one decision rather than a configuration flag.
func (s *Store) Fetch(ctx context.Context, subject access.Subject, token string,
	ttl time.Duration) (*Attachment, string, io.ReadCloser, error) {

	row, err := s.Find(ctx, subject, token)
	if err != nil {
		return nil, "", nil, err
	}
	if row.Redacted() {
		return row, "", nil, ErrGone
	}
	if !row.Inline() {
		address, err := s.files.URLFor(ctx, row.ObjectKey, ttl, Disposition(row), row.ContentType)
		if err != nil {
			return nil, "", nil, err
		}
		if address != "" {
			return row, address, nil, nil
		}
	}
	body, err := s.files.Open(ctx, row.ObjectKey)
	if err != nil {
		return nil, "", nil, err
	}
	return row, "", body, nil
}

// ForIssue is what hangs off one issue, newest first.
func (s *Store) ForIssue(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64) ([]Attachment, error) {

	if !s.Configured() {
		return nil, nil
	}
	if err := mayReach(ctx, s.db, subject, productID, vulnerabilityID); err != nil {
		return nil, err
	}
	var rows []Attachment
	if err := s.db.NewSelect().Model(&rows).
		Where("product_id = ?", productID).
		Where("vulnerability_id = ?", vulnerabilityID).
		Where("attached_at IS NOT NULL").
		Order("uploaded_at DESC", "id DESC").
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what hangs off an issue: %w", err)
	}
	return rows, nil
}

// Attached records that saved text now refers to these attachments.
//
// Set once and never cleared. Text is append-only, so a reference that existed
// goes on existing in the revision that made it, and an attachment that has
// ever been referred to is never a candidate for the sweep again.
//
// **Silent about tokens it does not recognize.** The text has already been
// accepted by then, and a reference to nothing is a broken link in a document
// rather than a reason to refuse somebody's justification.
func Attached(ctx context.Context, db bun.IDB, tokens []string, now time.Time) error {
	if len(tokens) == 0 {
		return nil
	}
	if _, err := db.NewUpdate().Model((*Attachment)(nil)).
		Set("attached_at = ?", now.UTC().Truncate(time.Microsecond)).
		Where("token IN (?)", bun.List(tokens)).
		Where("attached_at IS NULL").
		Exec(ctx); err != nil {
		return fmt.Errorf("record that an attachment is referred to: %w", err)
	}
	return nil
}

// Redact takes a file back out, leaving the record and the reference.
//
// **An administrator's act, and only theirs.** It is the answer to somebody
// having attached a credential, which is a thing that will happen — so it
// exists, it is recorded, and it is not something whoever uploaded the file
// can do quietly.
//
// The bytes go and the row stays. Text that pointed at the file says what
// happened rather than pointing at nothing, which is the whole difference
// between a redaction and a hole in the record.
func (s *Store) Redact(ctx context.Context, subject access.Subject, token, reason string) error {
	if !s.Configured() {
		return ErrNotConfigured
	}
	if !subject.Admin {
		return access.Denied("redact an attachment")
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("say why the file is being removed")
	}
	row := new(Attachment)
	err := s.db.NewSelect().Model(row).Where("token = ?", strings.TrimSpace(token)).Scan(ctx)
	if database.IsNoRows(err) {
		return access.Denied("reach an attachment")
	}
	if err != nil {
		return fmt.Errorf("read an attachment: %w", err)
	}
	if row.Redacted() {
		return ErrGone
	}

	now := s.now().Truncate(time.Microsecond)
	// The row is marked before the bytes go. The other order leaves a file
	// removed with nothing saying so, which reads as a store that lost it.
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		res, err := tx.NewUpdate().Model((*Attachment)(nil)).
			Set("redacted_at = ?", now).
			Set("redacted_by = ?", subject.ID).
			Set("redacted_reason = ?", reason).
			Where("token = ?", row.Token).
			Where("redacted_at IS NULL").
			Exec(ctx)
		if err != nil {
			return err
		}
		// Somebody else redacting it first is the outcome asked for, not a
		// conflict to report.
		if n, err := res.RowsAffected(); err == nil && n == 0 {
			return ErrGone
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.files.Delete(ctx, row.ObjectKey)
}

// Sweep removes uploads nothing ever referred to.
//
// Somebody drags a file in and closes the tab, and what is left is bytes no
// text will ever reach and nobody knows to remove. Bounded by age rather than
// run immediately, because an upload is unattached for as long as it takes to
// write the justification it belongs to.
//
// Returns how many went, which is what a log line says.
func (s *Store) Sweep(ctx context.Context, olderThan time.Duration) (int, error) {
	if !s.Configured() {
		return 0, nil
	}
	before := s.now().Add(-olderThan).Truncate(time.Microsecond)
	var stale []Attachment
	if err := s.db.NewSelect().Model(&stale).
		Where("attached_at IS NULL").
		Where("redacted_at IS NULL").
		Where("uploaded_at < ?", before).
		Limit(500).
		Scan(ctx); err != nil {
		return 0, fmt.Errorf("read what nothing refers to: %w", err)
	}

	gone := 0
	for i := range stale {
		row := &stale[i]
		// The file first here, and the row after. This is the opposite order
		// from a redaction and for the opposite reason: nothing refers to
		// these, so a file removed with its row still present is collected
		// again on the next pass, where a row removed first would leave bytes
		// nothing can ever find.
		if err := s.files.Delete(ctx, row.ObjectKey); err != nil {
			return gone, err
		}
		if _, err := s.db.NewDelete().Model((*Attachment)(nil)).
			Where("id = ?", row.ID).
			Where("attached_at IS NULL").
			Exec(ctx); err != nil {
			return gone, fmt.Errorf("remove an attachment nothing refers to: %w", err)
		}
		gone++
	}
	return gone, nil
}

// Issue resolves the product and issue an attachment path names, authorizing
// the product before the identifier is looked up.
//
// Resolving first and refusing after would make the refusal informative: an
// identifier nobody has filed and one filed on a product this person cannot
// see would come back differently, which turns a lookup into a directory.
func (s *Store) Issue(ctx context.Context, subject access.Subject,
	product, identifier string) (productID, vulnerabilityID int64, err error) {

	named, err := catalog.NewStore(s.db).ProductByName(ctx, product)
	if err != nil || subject.Kind != access.Person || !subject.Sees(named.ID) {
		return 0, 0, ErrNoSuchIssue
	}
	var issue int64
	err = s.db.NewSelect().
		TableExpr("vulnerability AS v").
		ColumnExpr("v.id").
		// Against the folded column rather than a function of the
		// identifier, which is what the column is for: both sides are
		// folded the same way on the way in, so this is an equality an
		// index can be used for.
		Where("v.identifier_folded = ?", strings.ToLower(strings.TrimSpace(identifier))).
		Scan(ctx, &issue)
	if database.IsNoRows(err) {
		return 0, 0, ErrNoSuchIssue
	}
	if err != nil {
		return 0, 0, fmt.Errorf("look up an issue: %w", err)
	}
	// That the issue exists says nothing until it is known to be *here*: an
	// identifier filed against another product would otherwise confirm itself
	// against this one.
	if err := mayReach(ctx, s.db, subject, named.ID, issue); err != nil {
		return 0, 0, ErrNoSuchIssue
	}
	return named.ID, issue, nil
}

// ErrNoSuchIssue is the one answer for an issue that is not here, one nobody
// may see, and a product that is neither.
var ErrNoSuchIssue = fmt.Errorf("no issue here goes by that name")
