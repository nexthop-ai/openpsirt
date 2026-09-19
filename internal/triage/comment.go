package triage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// Comment is discussion on a decision.
//
// Not the reasoning. The obvious mistake is treating all text on a finding as
// one thing, and the two behave differently on purpose: revising the reasoning
// takes back the approval standing on it, and a comment never disturbs
// anything. Annotating an approved decision months later — "re-checked, still
// true" — is ordinary, and an approval that fell over each time somebody added
// a note would teach people not to add notes.
type Comment struct {
	bun.BaseModel `bun:"table:claim_comment,alias:dc"`

	ID        int64     `bun:"id,pk,autoincrement"`
	ClaimID   int64     `bun:"claim_id,notnull"`
	Body      string    `bun:"body,notnull"`
	WrittenBy int64     `bun:"written_by,notnull"`
	WrittenAt time.Time `bun:"written_at,notnull"`
	// EditedAt marks that the author changed it. What it said before is kept
	// too: a comment is part of the record that goes public at
	// disclosure, and a record whose earlier text is unrecoverable is readable
	// rather than checkable — which is the property the whole append-only
	// history exists for.
	EditedAt *time.Time `bun:"edited_at"`
}

// WasSaid is what a comment said before it was changed.
//
// The previous text, written when it is replaced, rather than every version
// including the current one: the comment row holds what it says now, and this
// holds what it stopped saying, which is the part nothing else keeps.
type WasSaid struct {
	bun.BaseModel `bun:"table:claim_comment_revision,alias:dcr"`

	ID         int64     `bun:"id,pk,autoincrement"`
	CommentID  int64     `bun:"comment_id,notnull"`
	Ordinal    int       `bun:"ordinal,notnull"`
	Body       string    `bun:"body,notnull"`
	ReplacedAt time.Time `bun:"replaced_at,notnull"`
}

// Say adds a comment to a claim.
//
// Allowed at any point, including long after an approval, and it disturbs
// nothing. On the claim rather than on a row of it, because the conversation
// is about the argument: a note on one place of forty-four is one nobody else
// reading the claim would see.
func (s *Store) Say(ctx context.Context, subject access.Subject, claimID int64, body string) (*Comment, error) {
	if _, _, err := s.claimRows(ctx, subject, claimID, mayTakePart); err != nil {
		return nil, err
	}
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("a comment has to say something")
	}
	if err := markdown.Check(body); err != nil {
		return nil, err
	}

	comment := &Comment{
		ClaimID: claimID, Body: body,
		WrittenBy: subject.ID, WrittenAt: s.now().Truncate(time.Microsecond),
	}
	// Both writes or neither. Attaching is what makes a file listable and
	// keeps it from the sweep, so a comment stored without it points at
	// something already gone from the issue's file list.
	if err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		if _, err := tx.NewInsert().Model(comment).Exec(ctx); err != nil {
			return fmt.Errorf("record a comment: %w", err)
		}
		return noting(ctx, tx, body, comment.WrittenAt)
	}); err != nil {
		return nil, err
	}
	return comment, nil
}

// Reword changes a comment, which only its author may do.
//
// Overwritten rather than revised, and marked as edited. Nobody else may
// change somebody's words — an edit that could be made by another person is
// not a correction, it is a forgery with a timestamp.
//
// The asker's reach to the claim is settled before anything about the
// comment is said back. The row is read first, because the claim it hangs off
// is not knowable otherwise, but no answer turns on what was in it until the
// asker has been let in: refusing on authorship first told anybody holding
// triage anywhere that a comment with this identifier exists, one request at a
// time, including on findings nobody has disclosed. A comment that is not there
// and one on a claim this person may not reach answer identically.
//
// It answers with the claim the comment hangs off, because whoever edited it
// may have named somebody the first version did not, and telling them needs to
// know what the text is about.
func (s *Store) Reword(ctx context.Context, subject access.Subject, commentID int64,
	body string) (int64, error) {
	comment := new(Comment)
	if err := s.db.NewSelect().Model(comment).
		Where("id = ?", commentID).Scan(ctx); err != nil {
		// The bare sentinel, not a wrapped one. The identifier in the message
		// is the difference a caller counts: "change comment 10000: not
		// authorized" against "not authorized" separates the two answers this
		// is written to make identical.
		return 0, ErrNotTheirs
	}
	if _, _, err := s.claimRows(ctx, subject, comment.ClaimID, mayTakePart); err != nil {
		return 0, err
	}
	if comment.WrittenBy != subject.ID {
		return 0, fmt.Errorf("only the person who wrote a comment may change it")
	}
	if strings.TrimSpace(body) == "" {
		return 0, fmt.Errorf("a comment has to say something")
	}
	if err := markdown.Check(body); err != nil {
		return 0, err
	}

	edited := s.now().Truncate(time.Microsecond)
	// The earlier wording, kept, and both writes together. Written apart,
	// an edit that succeeded and a history write that did not would leave
	// the record saying a comment was changed and nothing saying from what
	// — which is worse than the state this replaces, because it looks like
	// a history and is not.
	if err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		// The ordinal is read inside the transaction, so two edits at once
		// cannot be handed the same number: the unique index refuses the
		// second, and the loser retries against a database that has moved.
		var highest int
		if err := tx.NewSelect().Model((*WasSaid)(nil)).
			ColumnExpr("COALESCE(MAX(ordinal), 0)").
			Where("comment_id = ?", commentID).Scan(ctx, &highest); err != nil {
			return err
		}
		// And what it says now, read here rather than carried in from
		// the lookup above. The row this writes is the record of what
		// the comment said before this edit, so a retry that used the
		// text read before the first attempt would record it as the
		// previous version while an edit that landed in between became
		// one nothing kept. A history that is wrong in a way nothing
		// reports is worse than the state it replaced, because it
		// looks like a history.
		var was string
		if err := tx.NewSelect().Model((*Comment)(nil)).
			Column("body").Where("id = ?", commentID).Scan(ctx, &was); err != nil {
			return err
		}
		if _, err := tx.NewInsert().Model(&WasSaid{
			CommentID: commentID, Ordinal: highest + 1,
			Body: was, ReplacedAt: edited,
		}).Exec(ctx); err != nil {
			return fmt.Errorf("keep what it said before: %w", err)
		}
		if _, err := tx.NewUpdate().Model((*Comment)(nil)).
			Set("body = ?", body).
			Set("edited_at = ?", edited).
			Where("id = ?", commentID).Exec(ctx); err != nil {
			return fmt.Errorf("change a comment: %w", err)
		}
		// An edit can add a reference the first version did not have, and it
		// is attached in the same transaction as the text that refers to it:
		// written afterwards and failing, the comment points at a file the
		// issue's list no longer offers and the sweep deletes. It can also
		// take one away, and that does not un-attach the file: the revision
		// that referred to it is still on record.
		return noting(ctx, tx, body, edited)
	}); err != nil {
		return 0, err
	}
	return comment.ClaimID, nil
}

// Discussion returns what has been said about a claim, oldest first.
func (s *Store) Discussion(ctx context.Context, subject access.Subject, claimID int64) ([]Comment, error) {
	if _, _, err := s.claimRows(ctx, subject, claimID, readable); err != nil {
		return nil, err
	}
	var comments []Comment
	if err := s.db.NewSelect().Model(&comments).
		Where("claim_id = ?", claimID).
		Order("id ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the discussion: %w", err)
	}
	return comments, nil
}

// noting records that saved text refers to attachments.
//
// Called wherever text is stored, and only after it is stored: an upload
// becomes attached when something points at it, and something points at it
// once the words containing the reference are on record. Until then it is an
// upload somebody may yet abandon, which is what the sweep collects.
//
// Silent about references it cannot match. The text has already been
// accepted, and a reference to nothing is a broken link in a document rather
// than a reason to refuse somebody's justification after the fact.
func noting(ctx context.Context, db bun.IDB, body string, now time.Time) error {
	return attach.Attached(ctx, db, markdown.References(body), now)
}

// Earlier is what a comment said before, oldest first.
//
// Narrowed by the claim it belongs to rather than by the comment: who may read
// a comment is who may read what it is about, and asking the question about the
// comment alone would be a second rule to keep in step.
func (s *Store) Earlier(ctx context.Context, subject access.Subject,
	commentID int64) ([]WasSaid, error) {

	comment := new(Comment)
	if err := s.db.NewSelect().Model(comment).
		Where("id = ?", commentID).Scan(ctx); err != nil {
		return nil, ErrNotTheirs
	}
	if _, _, err := s.claimRows(ctx, subject, comment.ClaimID, readable); err != nil {
		return nil, err
	}
	var rows []WasSaid
	if err := s.db.NewSelect().Model(&rows).
		Where("comment_id = ?", commentID).Order("ordinal").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what it said before: %w", err)
	}
	return rows, nil
}
