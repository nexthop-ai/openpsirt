// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
)

// Issuance is one time an advisory went out.
//
// A fact about a moment rather than a derived value: what was published on a
// date cannot be worked out again once the record it was generated from has
// moved on — a release is added, a decision is revised, a fix lands. If it is
// not written down when it happens it is gone.
type Issuance struct {
	bun.BaseModel `bun:"table:advisory_issuance,alias:ai"`

	ID int64 `bun:"id,pk,autoincrement"`
	// AdvisoryID is what this is an issuance of. Keyed on the advisory, which
	// is what makes a revision of a document covering two issues one record
	// rather than two.
	AdvisoryID int64 `bun:"advisory_id,notnull"`
	// Ordinal is which issuance this is, counting from one. It is what the
	// document's version says, and a validator checks that a revised document
	// carries a higher one than the last.
	Ordinal int `bun:"ordinal,notnull"`
	// EditionID is the edition that went out, which is a fact about a
	// moment. The advisory moves on and what was published does not, so a
	// record of what went out in March asked of the advisory today answers
	// with June's title.
	EditionID int64 `bun:"edition_id,notnull"`
	// Document is what went out, as the bytes that went out.
	//
	// Kept because it cannot be worked out again. A release is added, a
	// decision is revised, a fix lands, and the document generated from the
	// record today is a different document — so a directory of published
	// advisories that regenerated them would move a file whose own date says
	// it has not moved.
	//
	// Every issuance written here has one. One v0.1.0 recorded has none,
	// because it kept the digest and not the bytes, and no read here selects
	// this column from those.
	Document string `bun:"document,notnull"`
	// Digest is the part of those bytes that says what the document states,
	// hashed. It answers "is what is published still what we generate" where
	// the document answers "what was published", and both are written from
	// one document in one statement.
	Digest   string    `bun:"digest,notnull"`
	Summary  string    `bun:"summary"`
	IssuedBy int64     `bun:"issued_by,notnull"`
	IssuedAt time.Time `bun:"issued_at,notnull"`
}

// Issued records that an advisory went out, and returns what was recorded.
//
// The digest is taken from the document as it is now, generated inside
// this call rather than supplied by the caller. A caller-supplied digest is a
// digest of whatever they say — and the question this exists to answer is
// whether what is published is still what we would generate, which only means
// something if both sides come from here.
//
// The ordinal is read and used in one transaction, and the unique constraint
// is what refuses two people the same number — a refusal this reports as a
// lost race, so the second attempt reads the number the first wrote.
func (s *Store) Issued(ctx context.Context, subject access.Subject, who publisher.Named,
	identifier, summary string) (*Issuance, error) {

	// The submission policy, before the summary is stored. It is typed prose
	// that goes into the published revision history, so what is in the column
	// has to be known to have passed what was in force when it arrived.
	summary = strings.TrimSpace(summary)
	if err := markdown.Check(summary); err != nil {
		return nil, err
	}

	// One resolution, which the document was built from. Asked again it was
	// more round trips for an answer already in hand — and what the advisory
	// covers changing in between would key the issuance on a document that was
	// never hashed.
	doc, row, err := s.forAdvisory(ctx, subject, who, identifier)
	if err != nil {
		return nil, err
	}
	// Recording that it went out publishes it to the directory and fixes what
	// each release was fixed from, which is a statement about every product it
	// covers, so it takes the role every other change to the advisory does.
	if err := s.mayWrite(ctx, subject, row, "record that an advisory went out"); err != nil {
		return nil, err
	}
	// A second person has agreed to what it says, checked here because this
	// is the act of the document leaving. Generating one is reading;
	// recording that it went out is the publication.
	//
	// The text is the company speaking, and an advisory that went out on one
	// person's word is the control this deployment applies to a dismissal of
	// a single finding not being applied to the document a customer acts on.
	//
	// Whether the flaws behind it are public is a separate question and is
	// not asked here. An advisory about an embargoed flaw sent to a
	// coordinating body is the case coordinated disclosure is made of, and
	// what keeps it safe is the distribution label the document carries —
	// RED while anything it covers is held back, whatever its editorial
	// state says.
	digest, err := settledDigest(doc)
	if err != nil {
		return nil, err
	}

	var recorded *Issuance
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		// Read here, like the ordinal below and for the same reason. Taken
		// before the transaction, a retry carries the moment the first
		// attempt started: two people issuing one advisory at once leaves the
		// loser retrying and landing the later ordinal with the earlier
		// moment, and every document generated after that lists a revision
		// history whose dates run backwards — which a validator compares.
		issuedAt := s.now().UTC().Truncate(time.Microsecond)
		// Built inside, because an insert writes the generated identifier back
		// into the model and the ordinal below is read from the database. A
		// retry of a rolled-back attempt would re-insert a model carrying both
		// of that attempt's answers.
		// The agreement is read here rather than before the transaction
		// opened. A retitle or a withdrawal committing in between would
		// otherwise leave an issuance recorded with nothing standing, which
		// is the control this exists for.
		//
		// The edition is compared as well as counted: the document above was
		// hashed against the edition this advisory pointed at, and one that
		// moved since means the digest describes a document that is no
		// longer what would be generated.
		var at Advisory
		if err := tx.NewSelect().Model(&at).
			Where("id = ?", row.ID).Limit(1).Scan(ctx); err != nil {
			return err
		}
		if at.EditionID == nil || row.EditionID == nil || *at.EditionID != *row.EditionID {
			return ErrNotAgreed
		}
		var standing int
		if err := tx.NewSelect().Model((*Approval)(nil)).
			ColumnExpr("COUNT(*)").
			Where("edition_id = ?", *at.EditionID).
			Where("withdrawn_at IS NULL").
			Scan(ctx, &standing); err != nil {
			return err
		}
		if standing == 0 {
			return ErrNotAgreed
		}
		recorded = &Issuance{
			AdvisoryID: row.ID, EditionID: *at.EditionID,
			Digest: digest, Summary: summary,
			IssuedBy: subject.ID, IssuedAt: issuedAt,
		}
		// What has gone out already, read here rather than carried in from
		// the document above. The document was assembled outside this
		// transaction, so a second writer that committed in between left its
		// count of issuances one behind — and that count is the version the
		// document states and the history it lists. Read here they agree with
		// the record under any order the two writers arrive in.
		//
		// Scanned into values rather than read through a cursor: a cursor
		// left open while the insert runs is two statements interleaved on one
		// connection, which one engine tolerates and another refuses.
		var gone []Issuance
		if err := tx.NewSelect().Model(&gone).
			Column("ordinal", "issued_at", "summary").
			Where("advisory_id = ?", row.ID).
			OrderExpr("ordinal ASC").
			Scan(ctx); err != nil {
			return err
		}
		recorded.Ordinal = 1
		if len(gone) > 0 {
			recorded.Ordinal = gone[len(gone)-1].Ordinal + 1
		}
		// The bytes that go out, which are the only copy of this moment. What
		// would be generated tomorrow is a different document, so a reader
		// handed the regenerated one would be handed something nobody
		// published.
		body, err := json.Marshal(issuedDocument(doc, gone, recorded.Ordinal, issuedAt, summary))
		if err != nil {
			return fmt.Errorf("write down what went out: %w", err)
		}
		recorded.Document = string(body)
		// The first issuance freezes the moment the document dates itself
		// from, and no later one touches it. An affected-row count means rows
		// matched, so the clause is what decides it rather than the count:
		// two writers reaching here together both find it unset, and the
		// second writes the same value the first did.
		if _, err := tx.NewUpdate().Model((*Advisory)(nil)).
			Set("released_from = ?", doc.Document.Tracking.InitialReleaseDate).
			Where("id = ?", row.ID).
			Where("released_from IS NULL").
			Exec(ctx); err != nil {
			return err
		}
		if s.beforeWrite != nil {
			if err := s.beforeWrite(); err != nil {
				return err
			}
		}
		// Two people recording at the same moment read the same number, and
		// what stops them sharing it is the unique constraint, whose answer
		// is an error. Said as a lost race, the helper re-runs the whole
		// closure and the second reads the number the first wrote; reported
		// as it arrives, it is a fault nobody can act on.
		if _, err := tx.NewInsert().Model(recorded).Exec(ctx); err != nil {
			if database.IsDuplicate(err) {
				return database.ErrGoAgain
			}
			return err
		}
		return nil
	})
	if errors.Is(err, ErrNotAgreed) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("record that it went out: %w", err)
	}
	return recorded, nil
}

// settledDigest is what the document says, hashed.
//
// The settled digest, which is one of the two hashes a published document has
// and the one taken here. It answers "is this revision still what we would
// generate", so everything that moves for a reason other than what the
// document says is left out of it: the current release date and the
// generator's date change every time the document is asked for, and the
// version and the revision history move because the document went out rather
// than because it says something different. What is left is the title, the
// notes, the product tree and the vulnerabilities — the part a reader acts on,
// and the part that must not have quietly moved.
//
// The status follows the agreement rather than the words. Taking an agreement
// back moves a published document to interim with nothing a reader acts on
// having changed, and giving it again moves it back, so a digest carrying it
// would report a difference in substance where there is none.
//
// The other hash is over the delivered bytes, volatile fields included, and
// answers whether the file a reader fetched arrived intact. The two are not
// interchangeable and neither is a duplicate of the other.
func settledDigest(doc *Document) (string, error) {
	settled := *doc
	// Where the document is published is left out with them. It is a
	// property of where the file sits rather than of what the document says,
	// so a deployment that starts writing a directory would otherwise report
	// every issuance it already had as differing from what would be
	// generated now — which reads as "re-issue all of them" and is not what
	// the record is asking.
	settled.Document.References = without(doc.Document.References, "self")
	settled.Document.Tracking.CurrentReleaseDate = time.Time{}
	settled.Document.Tracking.Generator = nil
	settled.Document.Tracking.Version = ""
	settled.Document.Tracking.Status = ""
	settled.Document.Tracking.RevisionHistory = nil
	body, err := json.Marshal(settled)
	if err != nil {
		return "", fmt.Errorf("hash what went out: %w", err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

// without is the references less the ones of a category.
//
// A copy, because the document it came from is the one being generated and a
// digest may not edit it.
func without(references []Reference, category string) []Reference {
	out := make([]Reference, 0, len(references))
	for _, one := range references {
		if one.Category != category {
			out = append(out, one)
		}
	}
	return out
}

// Issuances is what has gone out for one advisory, oldest first.
//
// Readable without generating a document. Every issuance is already in the
// document's own revision history, which is right for a reader of the document
// — but it made "has this gone out, and is what is published still what we
// would generate" a question you had to build a CSAF document to answer.
// Somebody deciding whether to publish a revision is asking before they
// generate anything.
//
// Narrowed the way the document is: an advisory covering a product this reader
// may not see is one they are told does not exist, and a count of its
// issuances is as much a disclosure as the document.
func (s *Store) Issuances(ctx context.Context, subject access.Subject,
	identifier string) ([]Issuance, error) {

	row, err := s.byName(ctx, subject, identifier)
	if err != nil {
		return nil, err
	}
	return s.issuances(ctx, subject, row)
}

// Changed reports whether what an advisory's document says now differs from
// what last went out, or nil where that has no answer.
//
// Nil where nothing has gone out, and where no publisher is configured, the
// advisory covers nothing, or this reader may not generate it, since then
// there is no document to compare. The
// comparison is between settled digests, so a document whose dates, version
// and status moved and nothing else reads as unchanged.
func (s *Store) Changed(ctx context.Context, subject access.Subject, who publisher.Named,
	identifier string) (*bool, error) {

	if !who.Stated() {
		return nil, nil
	}
	row, err := s.byName(ctx, subject, identifier)
	if err != nil {
		return nil, err
	}
	gone, err := s.issuances(ctx, subject, row)
	if err != nil || len(gone) == 0 {
		return nil, err
	}
	// Generated as this reader, which a reader who may see the advisory
	// cannot always do: an undisclosed flaw it covers is one they may not
	// read. That is no answer to this question rather than a refusal of the
	// advisory they asked for.
	doc, _, err := s.forAdvisory(ctx, subject, who, identifier)
	switch {
	case errors.Is(err, ErrNothingToSay), errors.Is(err, ErrNoSuchIssue),
		errors.Is(err, ErrNotOurs):
		return nil, nil
	case err != nil:
		return nil, err
	}
	now, err := settledDigest(doc)
	if err != nil {
		return nil, err
	}
	changed := now != gone[len(gone)-1].Digest
	return &changed, nil
}

// issuances is what has gone out for one advisory, oldest first.
//
// Oldest first because it becomes the revision history, which a document
// states in the order it happened.
//
// It takes the advisory rather than its identifier for the reason the read of
// what it covers does: the clearance is the argument, and the only things that
// answer with one have narrowed or just minted it.
//
// Where anything has gone out, the reader must also read what every issuance
// named, which is the narrowing the report of what went out applies. Reading
// an advisory by name asks only of what it covers now, and each issuance carries a summary written about what it covered then —
// which the list of issuances and the document's revision history both show.
// A reader who fails it is told the advisory does not exist, since answering
// "nothing went out" would be a false statement they could act on.
func (s *Store) issuances(ctx context.Context, subject access.Subject,
	row *Advisory) ([]Issuance, error) {

	var rows []Issuance
	err := s.db.NewSelect().Model(&rows).
		// Without the documents. This answers the revision history and the
		// list of what went out, neither of which reads one, and a document
		// is the largest column here by a wide margin.
		ExcludeColumn("document").
		Where("advisory_id = ?", row.ID).
		OrderExpr("ai.ordinal ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read what has gone out: %w", err)
	}
	if len(rows) == 0 {
		return rows, nil
	}
	// Every issuance, each at what it named, or none of them.
	readable, err := narrowed(s.db.NewSelect().
		TableExpr(`"advisory_issuance" AS "ai"`).
		Join(`JOIN "advisory" AS "ad" ON ad.id = ai.advisory_id`).
		Where("ai.advisory_id = ?", row.ID), subject).Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("check what advisory %q has named: %w", row.Identifier, err)
	}
	if readable != len(rows) {
		return nil, ErrNoSuchAdvisory
	}
	return rows, nil
}

// issuedDocument is the document as it goes out.
//
// A copy rather than the document in hand. The transaction this is called in
// may run again, and a retry has to find what it was given as it was.
//
// Everything volatile is dated at the moment it left. The document was
// assembled a little earlier, and a file whose date says when it was generated
// is one a reader re-fetches because the bytes moved while the advisory did
// not.
//
// The history is rebuilt from what has gone out rather than taken from the
// document, for the reason the ordinal is read inside the transaction: the
// assembled one lists what had gone out when it was assembled, and an issuance
// that committed in between leaves a number missing from the middle of it,
// which a validator reports.
func issuedDocument(doc *Document, gone []Issuance, ordinal int,
	at time.Time, summary string) *Document {

	out := *doc
	version := strconv.Itoa(ordinal + 1)
	out.Document.Tracking.Version = version
	out.Document.Tracking.CurrentReleaseDate = at
	if doc.Document.Tracking.Generator != nil {
		generator := *doc.Document.Tracking.Generator
		generator.Date = at
		out.Document.Tracking.Generator = &generator
	}
	out.Document.Tracking.RevisionHistory = append(
		history(doc.Document.Tracking.InitialReleaseDate, gone),
		Revision{Number: version, Date: at, Summary: summaryOrIssued(summary)})
	return &out
}

// history is what has gone out, as the document lists it.
//
// The first entry is the flaw being recorded here, which is what the document
// dates itself from, and one entry per issuance after it. A revision is
// numbered one past its ordinal because the recording is the first.
func history(opened time.Time, gone []Issuance) []Revision {
	out := make([]Revision, 0, len(gone)+2)
	out = append(out, Revision{Number: "1", Date: opened, Summary: "Recorded in OpenPSIRT"})
	for _, one := range gone {
		out = append(out, Revision{
			Number: strconv.Itoa(one.Ordinal + 1), Date: one.IssuedAt.UTC(),
			Summary: summaryOrIssued(one.Summary),
		})
	}
	return out
}

// summaryOrIssued is what a revision says about itself. A history whose every
// entry reads the same is one nobody reads, and one entry with nothing at all
// is an entry a validator refuses.
func summaryOrIssued(summary string) string {
	if summary == "" {
		return "Issued"
	}
	return summary
}

func revisions(opened time.Time, gone []Issuance, now time.Time) []Revision {
	out := history(opened, gone)
	// The document in hand, named as what it is. Only where something has
	// gone out before: a document nobody has published is not a revision of
	// anything, and its newest entry is the flaw being recorded, which is
	// what it describes.
	//
	// It is also the one case where counting the version separately agrees
	// with the history by accident, which is why the disagreement shows only
	// once an advisory has been issued.
	if len(gone) > 0 {
		out = append(out, Revision{
			Number: strconv.Itoa(len(gone) + 2), Date: now,
			Summary: "Generated, not yet issued",
		})
	}
	return out
}
