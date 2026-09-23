package advisory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
)

// ErrNoPrefix says no prefix is configured to mint an identifier from.
//
// A configuration gap rather than a bad request, the way a missing publisher
// is: whoever is asking cannot fix it, and an operator can.
var ErrNoPrefix = errors.New(
	"no advisory identifier prefix is configured: set OPENPSIRT_ADVISORY_PREFIX")

// ErrNoSuchAdvisory says there is no advisory by that name that this reader
// may see.
//
// One answer for an advisory that does not exist and one that covers an issue
// the reader may not see. Told apart, the pair says what exists.
var ErrNoSuchAdvisory = errors.New("there is no advisory by that name")

// ErrAlreadyCovered says the advisory already names that issue in that
// product.
var ErrAlreadyCovered = errors.New("this advisory already covers that issue in that product")

// ErrNothingToSay says the advisory covers no issue.
var ErrNothingToSay = errors.New("an advisory with no issues states nothing")

// Advisory is a document this deployment writes, under a name it minted.
//
// Keyed on itself rather than on a product and an issue. The standard carries
// vulnerabilities as an array and means the tracking identifier to be the
// publisher's own name for the document, so a key made of one product and one
// issue cannot express a document about two and hands out somebody else's name
// for one of them.
type Advisory struct {
	bun.BaseModel `bun:"table:advisory,alias:ad"`

	ID int64 `bun:"id,pk,autoincrement"`
	// Identifier is the name a reader cites this by, and Folded is the same
	// name as uniqueness and lookup ask it. A name people type is matched
	// without regard to capitals, and the engines fold differently, so the
	// folded value is stored rather than the comparison asked to fold.
	Identifier string `bun:"identifier,notnull"`
	Folded     string `bun:"identifier_folded,notnull"`
	// Year and Number are what the identifier was minted from. Minting asks
	// for the highest number in the current year, which taking apart the
	// identifier would make a string operation four engines spell differently.
	Year   int `bun:"minted_year,notnull"`
	Number int `bun:"mint_number,notnull"`
	// EditionID is what the advisory says as it stands. An approval points
	// at one edition rather than at the advisory, so this moving is exactly
	// what withdraws an approval.
	EditionID *int64 `bun:"edition_id"`
	// ReleasedFrom is the moment the document dates itself from, written
	// when it first goes out and never again.
	//
	// Until then it is worked out from the flaws the advisory covers, which
	// is the earliest moment this deployment knew about any of them. Left to
	// move, naming an older flaw after publication would change what a
	// published document says its first release was — and the year folder a
	// reader already found it in is that date's year.
	ReleasedFrom *time.Time `bun:"released_from"`
	// Title is what somebody called it, read from that edition rather than
	// stored here. Absent until anybody says otherwise, and the document
	// falls back to naming the issues it covers.
	Title    string    `bun:"title,scanonly"`
	MintedAt time.Time `bun:"minted_at,notnull"`
	MintedBy int64     `bun:"minted_by,notnull"`
}

// Cover is one issue an advisory covers, in one product.
//
// The pair rather than the issue alone: an issue in two products is two
// entries, because the releases that carry it differ and a status is stated
// about releases.
type Cover struct {
	bun.BaseModel `bun:"table:advisory_issue,alias:ac"`

	ID              int64     `bun:"id,pk,autoincrement"`
	AdvisoryID      int64     `bun:"advisory_id,notnull"`
	ProductID       int64     `bun:"product_id,notnull"`
	VulnerabilityID int64     `bun:"vulnerability_id,notnull"`
	AddedAt         time.Time `bun:"added_at,notnull"`
	AddedBy         int64     `bun:"added_by,notnull"`
	// RemovedAt says it is off the advisory, and RemovedBy who took it off.
	// The row stays rather than being deleted, because who removed an issue
	// from an advisory is a question a deleted row does not answer.
	RemovedAt *time.Time `bun:"removed_at"`
	RemovedBy *int64     `bun:"removed_by"`
}

// Covered is one issue an advisory covers, by the names a reader knows them
// by.
type Covered struct {
	Product     string
	ProductName string
	ProductID   int64
	Issue       string
	IssueID     int64
	Summary     string
	AddedAt     time.Time
}

// Mint starts an advisory and gives it a name.
//
// The name is minted rather than taken from the caller. It is what a reader
// cites the document by and what a revision of it keeps, so a deployment that
// let one be chosen would have two advisories under one name the first time
// anybody typed carelessly.
func (s *Store) Mint(ctx context.Context, subject access.Subject, who publisher.Named,
	title string) (*Advisory, error) {

	if subject.Kind != access.Person || subject.ID == 0 {
		return nil, access.Denied("start an advisory")
	}
	// Whoever may record a flaw in a product may write an advisory about one.
	// An advisory names no product until an issue is added, so this is the
	// only gate there is at this point — and one that let anybody who can read
	// start one would fill the list with names nobody meant to mint.
	if !subject.HoldsAnywhere(access.PublicTriage, access.PrivateTriage) {
		return nil, access.Denied("start an advisory")
	}
	if !who.Mints() {
		return nil, ErrNoPrefix
	}
	title = strings.TrimSpace(title)
	// The same submission policy a justification goes through. It is our own
	// prose and it reaches the published document's title.
	if err := markdown.Check(title); err != nil {
		return nil, err
	}

	minted := s.now().UTC().Truncate(time.Microsecond)
	var made *Advisory
	err := database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		// Built inside, because the insert writes the generated identifier
		// back into the model and the number below is read from the database.
		// A retry would otherwise re-insert a model carrying the rolled-back
		// attempt's answers.
		year := minted.Year()
		var highest int
		if err := tx.NewSelect().Model((*Advisory)(nil)).
			ColumnExpr("COALESCE(MAX(mint_number), 0)").
			Where("minted_year = ?", year).
			Scan(ctx, &highest); err != nil {
			return err
		}
		made = &Advisory{
			Identifier: fmt.Sprintf("%s-%d-%04d", who.Prefix, year, highest+1),
			Year:       year, Number: highest + 1,
			MintedAt: minted, MintedBy: subject.ID,
		}
		made.Folded = fold(made.Identifier)
		if _, err := tx.NewInsert().Model(made).Exec(ctx); err != nil {
			return err
		}
		// The first edition, so that an advisory always has words somebody
		// can be asked to agree to. Without it the title would sit nowhere
		// until the first edit, and an approval would have no edition to
		// name.
		edition, err := openEdition(ctx, tx, made.ID, subject.ID, title, minted)
		if err != nil {
			return err
		}
		made.EditionID = &edition.ID
		made.Title = title
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("start an advisory: %w", err)
	}
	return made, nil
}

// byName reads the advisory under that name, refusing one this reader may not
// see the whole of.
//
// Every issue, not one of them. An advisory spanning two products is a
// document about both, and a reader who may see one of them would otherwise
// hold a document that silently leaves the other out — which reads as a
// complete statement about a product it says nothing about.
func (s *Store) byName(ctx context.Context, subject access.Subject,
	identifier string) (*Advisory, error) {

	if subject.Kind != access.Person {
		return nil, ErrNoSuchAdvisory
	}
	var row Advisory
	err := s.db.NewSelect().Model(&row).
		ColumnExpr(`"ad".*`).
		ColumnExpr(`COALESCE("ae"."title", '') AS "title"`).
		Join(`LEFT JOIN "advisory_edition" AS "ae" ON "ae"."id" = "ad"."edition_id"`).
		Where("identifier_folded = ?", fold(identifier)).
		Limit(1).Scan(ctx)
	if err != nil {
		return nil, database.FromRead(err, ErrNoSuchAdvisory,
			fmt.Sprintf("look up advisory %q", identifier))
	}
	var held struct {
		Live   int `bun:"live"`
		Beyond int `bun:"beyond"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"advisory_issue" AS "ac"`).
		ColumnExpr(`COUNT(*) AS "live"`).
		ColumnExpr(`SUM(CASE WHEN ac.product_id IN (?) THEN 0 ELSE 1 END) AS "beyond"`,
			bun.List(seen(subject))).
		Where("ac.advisory_id = ?", row.ID).
		Where("ac.removed_at IS NULL").
		Scan(ctx, &held); err != nil {
		return nil, fmt.Errorf("check what advisory %q covers: %w", identifier, err)
	}
	if held.Beyond > 0 {
		return nil, ErrNoSuchAdvisory
	}
	// An advisory covering nothing is its minter's alone. Covering nothing it
	// satisfies every narrowing there is, and its title is prose somebody
	// typed that goes on to be the document's — so between minting it and
	// naming the first flaw on it, "Remote code execution in the recovery
	// console" would be readable by anybody signed in. The same holds for one
	// whose issues were all taken off.
	if held.Live == 0 && row.MintedBy != subject.ID {
		return nil, ErrNoSuchAdvisory
	}
	return &row, nil
}

// seen is the products this subject may read findings in, as a list a
// statement can bind.
//
// A person holding every product is answered with nothing, which a binder
// renders as a null — and a product identifier is never in a list of one null,
// so a clause asking for the covers outside what they hold finds none. A
// person holding no product is given a sentinel no identifier takes, because
// a statement asking for a list needs something to bind and an empty one is
// not it.
func seen(subject access.Subject) []int64 {
	products, all := subject.Products()
	if all {
		return nil
	}
	if len(products) == 0 {
		return []int64{0}
	}
	return products
}

// fold is an identifier as uniqueness and lookup ask it.
//
// Lower-cased and bounded, which is what the folded column beside an issue's
// identifier holds — so one spelling answers for an advisory's own name and
// for the issue names a narrowed list compares against. A name people type is
// matched without regard to capitals; the stored value is normalized rather
// than the comparison asked to fold, because the four engines default to
// different collations and a normalized value compares the same under any of
// them.
func fold(identifier string) string {
	return bound.HeadRunes(strings.ToLower(strings.TrimSpace(identifier)), database.NameWidth)
}

// Add names an issue in a product as covered by the advisory.
//
// The issue is resolved through the same read the document is built from, so
// one a scanner reported against a third-party component is refused here
// rather than when the document is generated. The refusal then names the issue
// somebody chose, at the moment they chose it.
func (s *Store) Add(ctx context.Context, subject access.Subject,
	advisory, product, identifier string) (*Covered, error) {

	row, err := s.byName(ctx, subject, advisory)
	if err != nil {
		return nil, err
	}
	// Naming a flaw opens an edition and takes back every agreement standing
	// on the advisory, which is a change to what it says about every product
	// it covers. Asked before the product in the request is resolved,
	// because a refusal here is about the advisory rather than about a name.
	if err := s.mayWrite(ctx, subject, row, "name a flaw on an advisory"); err != nil {
		return nil, err
	}
	named, err := catalog.NewStore(s.db).ProductByName(ctx, product)
	if err != nil {
		return nil, err
	}
	// Authorized before the identifier is resolved, so a name nobody holds
	// and a name somebody holds come back the same way.
	//
	// And the triage role on this product as well as on the ones it already
	// covers. Naming a flaw is what puts it into a document published about
	// that product, so somebody who triages one product and only reads
	// another would otherwise publish about the second.
	if !triages(subject, named.ID) {
		return nil, ErrNoSuchIssue
	}
	issue, _, err := s.ours(ctx, subject, named.ID, identifier)
	if err != nil {
		return nil, err
	}

	added := s.now().UTC().Truncate(time.Microsecond)
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		// Asked inside the transaction, because the unique constraint is what
		// actually decides it and a count read outside describes a database
		// that has moved. The count is what turns the constraint into a
		// refusal a caller can act on.
		var held Cover
		err := tx.NewSelect().Model(&held).
			Where("advisory_id = ?", row.ID).
			Where("product_id = ?", named.ID).
			Where("vulnerability_id = ?", issue.ID).
			Limit(1).Scan(ctx)
		switch {
		case err != nil && !database.IsNoRows(err):
			return err
		case err == nil && held.RemovedAt == nil:
			return ErrAlreadyCovered
		case err == nil:
			// Taken off before and put back. The row is revived rather than a
			// second one written, which is what keeps the pair unique — and
			// it reads as what it is: on the advisory again, put there by
			// whoever did that.
			if _, err = tx.NewUpdate().Model((*Cover)(nil)).
				Set("removed_at = NULL").Set("removed_by = NULL").
				Set("added_at = ?", added).Set("added_by = ?", subject.ID).
				Where("id = ?", held.ID).Exec(ctx); err != nil {
				return err
			}
			return reopen(ctx, tx, row, subject.ID, added)
		}
		_, err = tx.NewInsert().Model(&Cover{
			AdvisoryID: row.ID, ProductID: named.ID, VulnerabilityID: issue.ID,
			AddedAt: added, AddedBy: subject.ID,
		}).Exec(ctx)
		// The count above turns the constraint into a refusal a caller can
		// act on, and the constraint is what actually decides it: two writers
		// arriving together both read nothing and both insert, and the loser
		// would otherwise carry the raw constraint up as a fault.
		if database.IsDuplicate(err) {
			return ErrAlreadyCovered
		}
		if err != nil {
			return err
		}
		return reopen(ctx, tx, row, subject.ID, added)
	})
	if errors.Is(err, ErrAlreadyCovered) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("add an issue to an advisory: %w", err)
	}
	shown := named.DisplayName
	if shown == "" {
		shown = named.Name
	}
	return &Covered{
		Product: named.Name, ProductName: shown, ProductID: named.ID,
		Issue: issue.Identifier, IssueID: issue.ID,
		Summary: summaryOf(issue, identifier), AddedAt: added,
	}, nil
}

// Drop takes an issue in a product back off the advisory.
//
// An advisory is written before it goes out and what it covers is somebody's
// judgment, so what was added by hand comes off by hand. Nothing here asks
// whether it has been issued: an issuance records what went out at a moment,
// and editing the advisory afterwards is how the next revision differs from
// the last.
func (s *Store) Drop(ctx context.Context, subject access.Subject,
	advisory, product, identifier string) error {

	row, err := s.byName(ctx, subject, advisory)
	if err != nil {
		return err
	}
	// The same rule adding one asks for, and for the same reason: taking a
	// flaw off opens an edition and takes back every agreement standing on
	// the advisory.
	if err := s.mayWrite(ctx, subject, row, "take a flaw off an advisory"); err != nil {
		return err
	}
	named, err := catalog.NewStore(s.db).ProductByName(ctx, product)
	if err != nil {
		return err
	}
	// Taking a flaw back off a document about a product is as much a
	// statement about that product as putting it on was.
	if !triages(subject, named.ID) {
		return ErrNoSuchIssue
	}
	issue, _, err := s.ours(ctx, subject, named.ID, identifier)
	if err != nil {
		return err
	}
	removed := s.now().UTC().Truncate(time.Microsecond)
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		res, err := tx.NewUpdate().Model((*Cover)(nil)).
			Set("removed_at = ?", removed).
			Set("removed_by = ?", subject.ID).
			Where("advisory_id = ?", row.ID).
			Where("product_id = ?", named.ID).
			Where("vulnerability_id = ?", issue.ID).
			Where("removed_at IS NULL").
			Exec(ctx)
		if err != nil {
			return err
		}
		// An affected-row count means rows matched. Nothing matched is an
		// issue the advisory did not cover, which is the caller's to fix
		// rather than a quiet success — and the edition below must not open
		// for a change that did not happen.
		if n, err := res.RowsAffected(); err == nil && n == 0 {
			return ErrNoSuchIssue
		}
		return reopen(ctx, tx, row, subject.ID, removed)
	})
	if errors.Is(err, ErrNoSuchIssue) {
		return err
	}
	if err != nil {
		return fmt.Errorf("take an issue off an advisory: %w", err)
	}
	return nil
}

// reopen opens an edition for a change that left the title alone.
//
// Naming a flaw on an advisory and taking one back off both change what the
// document says, so both take back every agreement standing on what it said
// before — an approver read a document covering three flaws, and a fourth
// added under their agreement is one nobody read.
func reopen(ctx context.Context, tx bun.Tx, row *Advisory, who int64, now time.Time) error {
	title, err := carryTitle(ctx, tx, row.ID)
	if err != nil {
		return err
	}
	_, err = openEdition(ctx, tx, row.ID, who, title, now)
	return err
}

// Covers is what the advisory covers, in the order it was assembled.
func (s *Store) Covers(ctx context.Context, subject access.Subject,
	advisory string) (*Advisory, []Covered, error) {

	row, err := s.byName(ctx, subject, advisory)
	if err != nil {
		return nil, nil, err
	}
	held, err := s.covers(ctx, row)
	if err != nil {
		return nil, nil, err
	}
	return row, held, nil
}

// covers is the same read without the narrowing, for a caller that has already
// done it.
//
// byName refuses an advisory covering anything this reader may not see, so a
// caller that went through it is reading rows it has already been cleared for.
// Narrowing again here would be a second spelling of one rule, and two
// spellings disagree.
//
// It takes the advisory rather than its identifier so that the clearance is
// the argument: the only things that answer with one are byName, which
// narrows, and Mint, which just made it and covers nothing. A caller holding
// an identifier cannot reach this without going through one of them.
func (s *Store) covers(ctx context.Context, row *Advisory) ([]Covered, error) {
	var rows []Covered
	err := s.db.NewSelect().
		TableExpr(`"advisory_issue" AS "ac"`).
		Join(`JOIN "product" AS "pd" ON pd.id = ac.product_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = ac.vulnerability_id`).
		ColumnExpr(`pd.name AS "product"`).
		ColumnExpr(`COALESCE(NULLIF(pd.display_name, ''), pd.name) AS "product_name"`).
		ColumnExpr(`pd.id AS "product_id"`).
		ColumnExpr(`v.identifier AS "issue"`).
		ColumnExpr(`v.id AS "issue_id"`).
		ColumnExpr(`COALESCE(v.description, '') AS "summary"`).
		ColumnExpr(`ac.added_at AS "added_at"`).
		Where("ac.advisory_id = ?", row.ID).
		Where("ac.removed_at IS NULL").
		// The order it was assembled in, which is the order somebody chose.
		// Left to the engine, two documents generated from the same facts are
		// different bytes.
		OrderExpr("ac.added_at ASC, ac.id ASC").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what an advisory covers: %w", err)
	}
	return rows, nil
}

// Listed is one advisory as a list of them reads it.
type Listed struct {
	Identifier string
	Title      string
	// Issues is how many it covers and Products how many products those sit
	// in. Both, because one issue in three products and three issues in one
	// are different documents and a single count reads the same for each.
	Issues   int
	Products int
	// Issuances is how many times it has gone out. More than none is the
	// thing somebody scanning the list is looking for.
	Issuances int
	// Agreed is how many people have agreed to what it says as it stands.
	// None is what a document that may not go out looks like.
	Agreed   int
	MintedAt time.Time
}

// Status is where the document is in its life, in the standard's words.
func (l Listed) Status() string { return statusOf(l.Issuances > 0, l.Agreed > 0) }

// Covering narrows a list to the advisories that say something about one
// issue, one product, or both.
type Covering struct {
	Product       string
	Vulnerability string
}

// List is the advisories this reader may see, newest first.
//
// Narrowed the way the document is: an advisory covering a product the reader
// may not see is one they are not shown. An advisory covering nothing yet is
// shown to everybody who may start one, because it discloses nothing — it is a
// name somebody minted and has not filled in.
func (s *Store) List(ctx context.Context, subject access.Subject, over Covering,
	limit, offset int) ([]Listed, int, error) {

	if subject.Kind != access.Person {
		return nil, 0, access.Denied("read advisories")
	}
	limit = database.AList.Of(limit)
	if offset < 0 {
		offset = 0
	}
	// The narrowing, as one clause both statements use. An advisory is out
	// where it covers anything outside what this reader may see, which is the
	// same rule reading one by name applies — spelled twice, the list and the
	// document would disagree about what exists.
	q := s.db.NewSelect().
		TableExpr(`"advisory" AS "ad"`).
		Where(`NOT EXISTS (SELECT 1 FROM "advisory_issue" AS "ac"
			WHERE ac.advisory_id = ad.id AND ac.removed_at IS NULL
			  AND ac.product_id NOT IN (?))`, bun.List(seen(subject))).
		// And one covering nothing is its minter's alone, for the reason
		// reading one by name applies: covering nothing it satisfies every
		// narrowing, and its title is prose somebody typed.
		Where(`(ad.minted_by = ? OR EXISTS (SELECT 1 FROM "advisory_issue" AS "al"
			WHERE al.advisory_id = ad.id AND al.removed_at IS NULL))`, subject.ID)

	// Narrowed to what covers one issue, where a caller asked. A screen about
	// one flaw is asking which advisories already say something about it,
	// which is the question somebody has before they start another.
	if over.Vulnerability != "" {
		q = q.Where(`EXISTS (SELECT 1 FROM "advisory_issue" AS "ac2"
			JOIN "vulnerability" AS "v2" ON v2.id = ac2.vulnerability_id
			WHERE ac2.advisory_id = ad.id AND ac2.removed_at IS NULL
			  AND v2.identifier_folded = ?)`, fold(over.Vulnerability))
	}
	if over.Product != "" {
		q = q.Where(`EXISTS (SELECT 1 FROM "advisory_issue" AS "ac3"
			JOIN "product" AS "pd3" ON pd3.id = ac3.product_id
			WHERE ac3.advisory_id = ad.id AND ac3.removed_at IS NULL
			  AND pd3.name = ?)`, fold(over.Product))
	}

	total, err := q.Clone().Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count the advisories: %w", err)
	}

	var rows []Listed
	err = q.
		ColumnExpr(`ad.identifier AS "identifier"`).
		ColumnExpr(`COALESCE((SELECT ae2.title FROM "advisory_edition" AS "ae2"
			WHERE ae2.id = ad.edition_id), '') AS "title"`).
		ColumnExpr(`(SELECT COUNT(*) FROM "advisory_approval" AS "aa2"
			WHERE aa2.edition_id = ad.edition_id AND aa2.withdrawn_at IS NULL) AS "agreed"`).
		ColumnExpr(`ad.minted_at AS "minted_at"`).
		ColumnExpr(`(SELECT COUNT(*) FROM "advisory_issue" AS "ai2"
			WHERE ai2.advisory_id = ad.id AND ai2.removed_at IS NULL) AS "issues"`).
		ColumnExpr(`(SELECT COUNT(DISTINCT ai3.product_id) FROM "advisory_issue" AS "ai3"
			WHERE ai3.advisory_id = ad.id AND ai3.removed_at IS NULL) AS "products"`).
		ColumnExpr(`(SELECT COUNT(*) FROM "advisory_issuance" AS "ai4"
			WHERE ai4.advisory_id = ad.id) AS "issuances"`).
		// Newest first, and the identifier to break a tie: two minted in one
		// microsecond would otherwise come back in whichever order the engine
		// chose, and a page of them would not be stable between reads.
		OrderExpr("ad.minted_at DESC, ad.identifier DESC").
		Limit(limit).Offset(offset).
		Scan(ctx, &rows)
	if err != nil {
		return nil, 0, fmt.Errorf("read the advisories: %w", err)
	}
	return rows, total, nil
}

// triages reports whether this subject may decide things about one product.
//
// The role on that product rather than anywhere. Starting an advisory asks for
// the role somewhere, because an advisory names no product until an issue is
// added to it; naming one is the act that picks the product, and from there
// the ordinary per-product rule applies.
func triages(subject access.Subject, productID int64) bool {
	return subject.Holds(access.PublicTriage, productID) ||
		subject.Holds(access.PrivateTriage, productID)
}

// Nameable is one flaw recorded in a product, as a list of what an advisory
// may name reads it.
type Nameable struct {
	Identifier string `bun:"identifier"`
	Summary    string `bun:"summary"`
	// Open is how many of its findings in the product are still open. None
	// means it is fixed wherever it was found, which is the ordinary state of
	// a flaw an advisory is written about.
	Open int `bun:"still_open"`
}

// mostNameable bounds the list of flaws a product offers an advisory. A flaw
// recorded here is recorded by hand, one at a time.
const mostNameable = 500

// Nameable is every flaw recorded here in one product that this subject may
// name on an advisory, open or fixed.
//
// Fixed ones included, because an advisory is usually written after the fix
// lands. The same rows naming one accepts: recorded by a person, at a
// visibility this subject may see, in a product they triage. Somebody who does
// not triage the product is answered as though it were not declared.
func (s *Store) Nameable(ctx context.Context, subject access.Subject,
	product string) ([]Nameable, error) {

	named, err := catalog.NewStore(s.db).ProductByName(ctx, product)
	if err != nil {
		return nil, err
	}
	if !triages(subject, named.ID) {
		return nil, catalog.ErrNotFound
	}
	grouped := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "t" ON t.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = t.stream_id`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`SUM(CASE WHEN f.closed_at IS NULL THEN 1 ELSE 0 END) AS "still_open"`).
		Where("st.product_id = ?", named.ID).
		Where("f.kind = ?", finding.Entered).
		Where("f.visibility IN (?)", bun.List(access.Visible(subject, named.ID))).
		GroupExpr("f.vulnerability_id")
	var rows []Nameable
	err = s.db.NewSelect().
		TableExpr(`(?) AS "recorded_flaw"`, grouped).
		Join(`JOIN "vulnerability" AS "vu" ON vu.id = recorded_flaw.vulnerability_id`).
		ColumnExpr(`vu.identifier AS "identifier"`).
		ColumnExpr(`COALESCE(vu.description, '') AS "summary"`).
		ColumnExpr(`recorded_flaw.still_open AS "still_open"`).
		OrderExpr("vu.identifier ASC").
		Limit(mostNameable).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read the flaws recorded in that product: %w", err)
	}
	return rows, nil
}
