// Package catalog holds what a scan can be filed against: the products, the
// branches and tags within them, and the variants each of those is built as.
//
// Everything here is declared before it can be targeted. A scan naming
// something undeclared is rejected, because a mistyped stream name would
// otherwise create one that looks entirely real — its own findings, its own
// counts, its own place in every report — while the real one appears to have
// stopped being scanned.
package catalog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Kind distinguishes a moving line of development from a frozen point.
type Kind string

const (
	// Branch moves: it is rebuilt, and its current state changes.
	Branch Kind = "branch"
	// Tag never moves. It was built once and is what someone received.
	Tag Kind = "tag"
)

// Valid reports whether k is a kind we recognize.
func (k Kind) Valid() bool { return k == Branch || k == Tag }

// ErrNotFound is returned when something named has not been declared.
var ErrNotFound = errors.New("not declared")

// ErrExists is returned when a declaration would duplicate one already made.
var ErrExists = errors.New("already declared")

// missingOr says which of the two a failed read was: a row that is not there,
// or a read that could not be made.
//
// One spelling, because the two answers differ by a status code at every
// caller and the distinction was made by hand at each of them — where it was
// made at all. A reader that wraps every failure alike hands a caller "that
// does not exist" for a database it could not reach, and a caller that trusts
// it says so to whoever asked.
//
// absent names the thing, in the words a reader sees: "product 12", "target 4".
// reading names the act, for the line an operator gets: "look up product 12".
func missingOr(err error, absent, reading string) error {
	return database.FromRead(err, fmt.Errorf("%s: %w", absent, ErrNotFound), reading)
}

// Product is a thing that gets shipped.
type Product struct {
	bun.BaseModel `bun:"table:product,alias:p"`

	ID          int64      `bun:"id,pk,autoincrement"`
	Name        string     `bun:"name,notnull"`
	DisplayName string     `bun:"display_name,notnull"`
	EOLOn       *time.Time `bun:"eol_on"`
	// TriageFloor is what this product considers worth triaging, where it
	// has an opinion of its own. Empty means the deployment's line applies
	// — stating the default instead would stop this product following it
	// when the default changed.
	TriageFloor *string   `bun:"triage_floor"`
	CreatedAt   time.Time `bun:"created_at,notnull"`
}

// Stream is a branch or a tag of a product.
//
// Both live here because they differ in one respect only — a branch moves and
// a tag does not — and share everything else.
type Stream struct {
	bun.BaseModel `bun:"table:stream,alias:s"`

	ID          int64  `bun:"id,pk,autoincrement"`
	ProductID   int64  `bun:"product_id,notnull"`
	Name        string `bun:"name,notnull"`
	DisplayName string `bun:"display_name,notnull"`
	Kind        Kind   `bun:"kind,notnull"`
	// ParentID is the branch a tag was cut from, where that is known. It is
	// what lets a branch be compared against its last release.
	ParentID *int64     `bun:"parent_id"`
	EOLOn    *time.Time `bun:"eol_on"`
	// ReleasedOn is when a tag actually went out, which is not when it was
	// declared here: a release recorded months after it shipped orders wrongly
	// against the others by its declaration, and the chart of what each
	// release shipped with labels its points with dates. Null where nobody has
	// said, and then the first scan of it stands in — something was built on
	// that day.
	ReleasedOn *time.Time `bun:"released_on"`
	CreatedAt  time.Time  `bun:"created_at,notnull"`
}

// Variant is one of the ways a stream is built — a chip variant, an operating
// system, an architecture.
//
// It belongs to the product rather than to any one release, so one introduced in a
// later release does not appear to have existed in earlier ones.
type Variant struct {
	bun.BaseModel `bun:"table:variant,alias:v"`

	ID          int64  `bun:"id,pk,autoincrement"`
	ProductID   int64  `bun:"product_id,notnull"`
	Name        string `bun:"name,notnull"`
	DisplayName string `bun:"display_name,notnull"`
	// CustomerFacing says whether this ships to customers or exists only
	// internally. It feeds ranking: a critical in a test-only artifact matters
	// less than a medium in something a customer runs.
	CustomerFacing bool      `bun:"customer_facing,notnull"`
	CreatedAt      time.Time `bun:"created_at,notnull"`
	// RetiredAt is when this was taken out of use, or absent while it is in
	// use. A retired variant is offered nowhere and accepts no scan, and
	// everything already filed against it still resolves by name.
	RetiredAt *time.Time `bun:"retired_at"`
}

// Retired reports whether this variant has been taken out of use.
func (v Variant) Retired() bool { return v.RetiredAt != nil }

// Store reads and writes the catalog.
type Store struct{ db bun.IDB }

// NewStore returns a store over db.
func NewStore(db bun.IDB) *Store { return &Store{db: db} }

// Within runs do inside one transaction, with this store rebuilt over it.
//
// For an act that is more than one statement: a handler doing two of these in
// a row leaves the first standing when the second fails, and a caller already
// inside a transaction joins it rather than opening a second.
func (s *Store) Within(ctx context.Context, do func(context.Context, *Store) error) error {
	return database.Within(ctx, s.db, func(ctx context.Context, db bun.IDB) error {
		return do(ctx, NewStore(db))
	})
}

// maxNameLength matches the column width, which is bounded so a unique index
// on it stays inside every engine's key-length limit.
const maxNameLength = 191

// validName rejects what would be confusing or unusable as an identifier.
func validName(what, name string) error {
	trimmed := strings.TrimSpace(name)
	switch {
	case trimmed == "":
		return fmt.Errorf("%s name is empty", what)
	case trimmed != name:
		return fmt.Errorf("%s name %q has leading or trailing spaces", what, name)
	case len(name) > maxNameLength:
		return fmt.Errorf("%s name is %d characters; the limit is %d", what, len(name), maxNameLength)
	}
	// A name travels into places that are not this database: a path, a header,
	// the filename on an export somebody downloads. A control character or a
	// quote is unusable in all three — a quote ends a quoted header field
	// early and a carriage return ends the header — and none of them is
	// anything somebody meant to type. The export writes its own safe filename
	// as well, because a name declared before this check is still in here.
	for _, r := range name {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			return fmt.Errorf("%s name %q contains a character that cannot travel "+
				"in a path or a header", what, name)
		}
	}
	return nil
}

// DeclareProduct records a product so scans may be filed against it.
func (s *Store) DeclareProduct(ctx context.Context, name, displayName string) (*Product, error) {
	if err := validName("product", name); err != nil {
		return nil, err
	}
	// Trimmed and checked the way the name is, which the two siblings get for
	// free by deriving it from the name. Stored as typed it was the one
	// catalog field nothing looked at — a display name is what a screen puts
	// in front of somebody and what a report is titled with.
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		displayName = name
	}
	if err := validName("product display", displayName); err != nil {
		return nil, err
	}
	if _, err := s.ProductByName(ctx, name); err == nil {
		return nil, fmt.Errorf("product %q: %w", name, ErrExists)
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	p := &Product{Name: matching(name), DisplayName: displayName, CreatedAt: now()}
	if _, err := s.db.NewInsert().Model(p).Exec(ctx); err != nil {
		return nil, fmt.Errorf("declare product %q: %w", name, err)
	}
	return p, nil
}

// EndOfLife is when support for something ends, and where that date was
// stated.
//
// A date rather than a flag: a date answers "what goes out of support next
// quarter", which is a real planning question, and it takes effect on its own
// rather than waiting for somebody to remember. It is how lifecycle policies
// are actually published.
type EndOfLife struct {
	// On is the date, or absent where nothing has said one.
	On *time.Time
	// FromStream says the release stated this rather than inheriting the
	// product's. Carried so a screen can say whose decision it is looking at.
	FromStream bool
}

// Past reports whether the date has passed, as of when.
//
// Absent is not past. A release nobody has dated is supported until somebody
// says otherwise, which is the only reading that does not switch things off by
// default.
func (e EndOfLife) Past(at time.Time) bool {
	return e.On != nil && !at.Before(*e.On)
}

// SetProductEndOfLife records when a product goes out of support, or clears
// it.
//
// Reversible, because extended support happens and the alternative is
// recreating a product to undo a date.
func (s *Store) SetProductEndOfLife(ctx context.Context, productID int64, on *time.Time) error {
	return s.setEndOfLife(ctx, (*Product)(nil), productID, on, "product")
}

// SetStreamEndOfLife records when one release goes out of support, or clears
// it so the release follows its product again.
//
// Cleared rather than set to the product's date, for the reason a product's
// triage line is cleared rather than copied: a release holding the product's
// current date would stop following it the next time the product moved, and
// nobody would see that happen.
func (s *Store) SetStreamEndOfLife(ctx context.Context, streamID int64, on *time.Time) error {
	return s.setEndOfLife(ctx, (*Stream)(nil), streamID, on, "release")
}

// SetReleasedOn records when a release actually went out, or clears it.
//
// Settable after the fact, because that is when it is usually known. A tag
// is declared here so scans can be filed against it, which happens whenever
// somebody gets to it — before the release, months after, or as part of
// backfilling a year. Ordering releases by when they were declared here makes
// a chart of what each shipped with read as an accident of administration.
//
// A date rather than a moment: a release goes out on a day, and the hour a
// deployment happens to be asked is not part of the answer.
func (s *Store) SetReleasedOn(ctx context.Context, streamID int64, on *time.Time) error {
	q := s.db.NewUpdate().Model((*Stream)(nil)).Where("id = ?", streamID)
	if on == nil {
		q = q.Set("released_on = NULL")
	} else {
		q = q.Set("released_on = ?", on.UTC().Truncate(24*time.Hour))
	}
	res, err := q.Exec(ctx)
	if err != nil {
		return fmt.Errorf("record when this release went out: %w", err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return fmt.Errorf("record when this release went out: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("release %d: %w", streamID, ErrNotFound)
	}
	return nil
}

// FillInParent records which branch a tag was cut from, where nothing has been
// said yet.
//
// Filling in, never changing. A pipeline that does not know
// declares the tag without a parent, and release readiness then reports that
// nothing has ever been released from the branch — which is indistinguishable
// from a branch that has genuinely shipped nothing. Saying it late is the same
// act arriving late, because nothing had been said for it to contradict.
//
// Naming a *different* branch is refused, and so is clearing one: a tag is one
// frozen point and it came from wherever it came from. Somebody who recorded
// the wrong one has recorded a fact wrongly, and that is a correction to make
// deliberately rather than by typing over it.
//
// A parent is a branch and nothing is its own parent. Both are refused rather
// than stored: a cycle here is a comparison that never returns, and a tag
// under a tag is a line that does not exist.
func (s *Store) FillInParent(ctx context.Context, streamID, parent int64) error {
	if parent == streamID {
		return fmt.Errorf("a release cannot be cut from itself")
	}
	var kind Kind
	if err := s.db.NewSelect().Model((*Stream)(nil)).Column("kind").
		Where("id = ?", parent).Scan(ctx, &kind); err != nil {
		return missingOr(err, fmt.Sprintf("release %d", parent),
			fmt.Sprintf("look up what release %d is", parent))
	}
	if kind != Branch {
		return fmt.Errorf("a release is cut from a branch, and that is a %s", kind)
	}
	// Only where nothing stands, asked in the write rather than before it: a
	// check and a write that are two statements are two moments, and what is
	// being protected here is that a stated parent never changes.
	res, err := s.db.NewUpdate().Model((*Stream)(nil)).
		Set("parent_id = ?", parent).
		Where("id = ?", streamID).
		Where("parent_id IS NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("record what this release was cut from: %w", err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return fmt.Errorf("record what this release was cut from: %w", err)
	}
	if n == 0 {
		var stood *int64
		if err := s.db.NewSelect().Model((*Stream)(nil)).Column("parent_id").
			Where("id = ?", streamID).Scan(ctx, &stood); err != nil {
			return missingOr(err, fmt.Sprintf("release %d", streamID),
				fmt.Sprintf("read what release %d was cut from", streamID))
		}
		if stood != nil && *stood == parent {
			return nil
		}
		return fmt.Errorf("this release already says what it was cut from, and a release " +
			"came from wherever it came from")
	}
	return nil
}

func (s *Store) setEndOfLife(ctx context.Context, model any, id int64, on *time.Time, what string) error {
	q := s.db.NewUpdate().Model(model).Where("id = ?", id)
	if on == nil {
		q = q.Set("eol_on = NULL")
	} else {
		// Stored as a date rather than a moment. Support ends on a day, and
		// keeping a time of day would make "past" depend on the hour a
		// deployment happened to be asked.
		q = q.Set("eol_on = ?", on.UTC().Truncate(24*time.Hour))
	}
	res, err := q.Exec(ctx)
	if err != nil {
		return fmt.Errorf("record when this %s goes out of support: %w", what, err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return fmt.Errorf("record when this %s goes out of support: %w", what, err)
	}
	if n == 0 {
		return fmt.Errorf("%s %d: %w", what, id, ErrNotFound)
	}
	return nil
}

// EndOfLifeFor reads the date in force for one release.
//
// The release's own where it has stated one, the product's otherwise. A
// release with no date of its own inherits rather than copying, so it keeps
// following the product when the product's policy moves.
func (s *Store) EndOfLifeFor(ctx context.Context, streamID int64) (EndOfLife, error) {
	return s.endOfLife(ctx, "s.id = ?", streamID, "release", streamID)
}

// EndOfLifeForTarget reads the date in force for the release one build belongs
// to.
//
// A build is of a release, and support ends for the release rather than for
// one of the ways it is built: shipping two chip variants of a version does
// not make one of them supported for longer than the other.
func (s *Store) EndOfLifeForTarget(ctx context.Context, targetID int64) (EndOfLife, error) {
	return s.endOfLife(ctx,
		`s.id IN (SELECT tg.stream_id FROM "target" AS "tg" WHERE tg.id = ?)`, targetID,
		"build", targetID)
}

func (s *Store) endOfLife(ctx context.Context, where string, arg any, what string, id int64) (EndOfLife, error) {
	var stated struct {
		Stream  *time.Time `bun:"stream_eol"`
		Product *time.Time `bun:"product_eol"`
	}
	err := s.db.NewSelect().
		TableExpr(`"stream" AS "s"`).
		Join(`JOIN "product" AS "p" ON p.id = s.product_id`).
		ColumnExpr(`s.eol_on AS "stream_eol"`).
		ColumnExpr(`p.eol_on AS "product_eol"`).
		Where(where, arg).
		Scan(ctx, &stated)
	if err != nil {
		if database.IsNoRows(err) {
			return EndOfLife{}, fmt.Errorf("%s %d: %w", what, id, ErrNotFound)
		}
		return EndOfLife{}, fmt.Errorf("read when this %s goes out of support: %w", what, err)
	}
	if stated.Stream != nil {
		return EndOfLife{On: stated.Stream, FromStream: true}, nil
	}
	return EndOfLife{On: stated.Product}, nil
}

// TargetMoves reports whether a build's release can change.
//
// A branch moves: it is rebuilt, and its current state changes. A tag never
// does — it was built once and is what somebody received. Everything that turns
// on "can this still be fixed" asks here rather than reading the kind for
// itself, so the two cannot come to disagree.
func (s *Store) TargetMoves(ctx context.Context, targetID int64) (bool, error) {
	var kind string
	err := s.db.NewSelect().
		TableExpr(`"stream" AS "s"`).
		ColumnExpr("s.kind").
		Where(`s.id IN (SELECT tg.stream_id FROM "target" AS "tg" WHERE tg.id = ?)`, targetID).
		Scan(ctx, &kind)
	if err != nil {
		if database.IsNoRows(err) {
			return false, fmt.Errorf("build %d: %w", targetID, ErrNotFound)
		}
		return false, fmt.Errorf("read whether that release moves: %w", err)
	}
	return Kind(kind) == Branch, nil
}

// TagStreams is which releases were built once and cannot change.
//
// The counterpart of StreamsPastEndOfLife, and used the same way: a sweep takes
// the deadline off everything on one of them, because a deadline on a release
// nothing will ever land in was unmeetable the moment it was written.
func (s *Store) TagStreams(ctx context.Context) ([]int64, error) {
	var ids []int64
	if err := s.db.NewSelect().
		TableExpr(`"stream" AS "s"`).
		ColumnExpr("s.id").
		Where("s.kind = ?", Tag).Scan(ctx, &ids); err != nil {
		return nil, fmt.Errorf("read which releases were built once: %w", err)
	}
	return ids, nil
}

// StreamsPastEndOfLife is which releases have gone out of support by a date.
//
// The date comparison is spelled here and nowhere else. What "past end of
// life" means decides three separate things — whether a finding carries a
// deadline, whether a build going quiet is a fault, and what a screen says —
// and this project's bugs have all come from letting one fact into two rules.
func (s *Store) StreamsPastEndOfLife(ctx context.Context, at time.Time) ([]int64, error) {
	return s.streamsEndingBy(ctx, at)
}

// StreamsEndingBy is which releases will have gone out of support by a date.
//
// The same question asked of a day that has not arrived. Nothing warns
// before a release crosses: the day it does, the deadline comes off every
// open finding on it, and a pile of work leaves every overdue count at once
// with nobody having decided anything. Asking ahead is what makes that a date
// somebody can plan for rather than a figure that moves overnight.
func (s *Store) StreamsEndingBy(ctx context.Context, by time.Time) ([]int64, error) {
	return s.streamsEndingBy(ctx, by)
}

// streamsEndingBy is the predicate both of those ask, spelled once: a release
// answering to its own date where it states one and to its product's
// otherwise.
func (s *Store) streamsEndingBy(ctx context.Context, at time.Time) ([]int64, error) {
	day := at.UTC().Truncate(24 * time.Hour)
	var past []int64
	err := s.db.NewSelect().
		TableExpr(`"stream" AS "s"`).
		Join(`JOIN "product" AS "p" ON p.id = s.product_id`).
		ColumnExpr("s.id").
		// The release's own date where it has one, the product's otherwise —
		// the same precedence a single read applies, written as a condition
		// rather than fetched and compared, so a deployment with thousands of
		// releases is one statement.
		Where(`(s.eol_on IS NOT NULL AND s.eol_on <= ?)
			OR (s.eol_on IS NULL AND p.eol_on IS NOT NULL AND p.eol_on <= ?)`, day, day).
		OrderExpr("s.id").
		Scan(ctx, &past)
	if err != nil {
		return nil, fmt.Errorf("read which releases are out of support: %w", err)
	}
	return past, nil
}

// Retired is a release that has gone out of support, with what it belongs to
// and which date put it there.
type Retired struct {
	StreamID  int64
	ProductID int64
	Product   string
	Stream    string
	Kind      Kind
	// EndedOn is the date support ended: the release's own where it stated
	// one, its product's otherwise.
	EndedOn time.Time
	// Inherited says the date came from the product rather than from this
	// release. Following a date and stating the same one are different
	// things, and only one of them survives the product changing its mind.
	Inherited bool
}

// OutOfSupport lists the releases somebody may see that have gone out of
// support.
//
// The releases themselves are asked of StreamsEndingBy rather than spelled
// again. The date comparison lives in exactly one place. A report that works
// it out for itself eventually describes a different set of releases from the
// one whose deadlines were stripped, and it is the report people believe.
//
// A release whose date has not arrived is included where `by` is later than
// `at`, so one call answers both what has ended and what is about to. Which of
// the two a row is, is the caller's to read off the date it carries.
func (s *Store) OutOfSupport(ctx context.Context, subject access.Subject,
	at, by time.Time) ([]Retired, error) {

	// A person's question. A pipeline key reads back what it sent, and which
	// releases a deployment has stopped supporting is not that.
	// Not merely empty: "here is nothing" and "you cannot ask" are
	// different statements, and this is the second. A person holding
	// nothing is the first, and is answered below.
	if subject.Kind != access.Person {
		return nil, access.Denied("read which releases are out of support")
	}
	products, all := subject.Products()
	if !all && len(products) == 0 {
		return nil, nil
	}
	if by.Before(at) {
		by = at
	}
	past, err := s.StreamsEndingBy(ctx, by)
	if err != nil {
		return nil, err
	}
	if len(past) == 0 {
		return nil, nil
	}

	out := make([]Retired, 0, len(past))
	err = database.IDsInBatches(ctx, past, func(ctx context.Context, batch []int64) error {
		var rows []struct {
			StreamID   int64      `bun:"stream_id"`
			ProductID  int64      `bun:"product_id"`
			Product    string     `bun:"product"`
			Stream     string     `bun:"stream"`
			Kind       Kind       `bun:"kind"`
			OwnEOL     *time.Time `bun:"own_eol"`
			ProductEOL *time.Time `bun:"product_eol"`
		}
		q := s.db.NewSelect().
			TableExpr(`"stream" AS "s"`).
			Join(`JOIN "product" AS "p" ON p.id = s.product_id`).
			ColumnExpr(`s.id AS "stream_id"`).
			ColumnExpr(`s.name AS "stream"`).
			ColumnExpr(`s.kind AS "kind"`).
			ColumnExpr(`s.eol_on AS "own_eol"`).
			ColumnExpr(`p.id AS "product_id"`).
			ColumnExpr(`p.name AS "product"`).
			ColumnExpr(`p.eol_on AS "product_eol"`).
			Where("s.id IN (?)", bun.List(batch)).
			OrderExpr("p.name, s.name")
		if !all {
			q = q.Where("s.product_id IN (?)", bun.List(products))
		}
		if err := q.Scan(ctx, &rows); err != nil {
			return fmt.Errorf("read the releases that are out of support: %w", err)
		}
		for _, row := range rows {
			ended := Retired{
				StreamID: row.StreamID, ProductID: row.ProductID,
				Product: row.Product, Stream: row.Stream, Kind: row.Kind,
			}
			switch {
			case row.OwnEOL != nil:
				ended.EndedOn = row.OwnEOL.UTC()
			case row.ProductEOL != nil:
				ended.EndedOn, ended.Inherited = row.ProductEOL.UTC(), true
			default:
				// The set came from the comparison above, so one of the two
				// dates is always there. Skipping rather than reporting a
				// zero date keeps a row that cannot happen from reading as a
				// release that ended in year one.
				continue
			}
			out = append(out, ended)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SetTriageFloor records what a product considers worth triaging, or clears it
// so the product follows the deployment again.
//
// Cleared rather than set to the deployment's current value. A product that
// copied the line the day somebody looked at it would stop following the
// deployment the next time the deployment changed its mind, and nobody would
// see that happen.
func (s *Store) SetTriageFloor(ctx context.Context, productID int64, word string) error {
	q := s.db.NewUpdate().Model((*Product)(nil)).Where("id = ?", productID)
	if word == "" {
		q = q.Set("triage_floor = NULL")
	} else {
		q = q.Set("triage_floor = ?", word)
	}
	res, err := q.Exec(ctx)
	if err != nil {
		return fmt.Errorf("record what this product triages: %w", err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return fmt.Errorf("record what this product triages: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("product %d: %w", productID, ErrNotFound)
	}
	return nil
}

// ProductByName finds a product, or reports that it was never declared.
func (s *Store) ProductByName(ctx context.Context, name string) (*Product, error) {
	p := new(Product)
	err := s.db.NewSelect().Model(p).Where("name = ?", matching(name)).Scan(ctx)
	if err != nil {
		if database.IsNoRows(err) {
			return nil, fmt.Errorf("product %q: %w", name, ErrNotFound)
		}
		return nil, fmt.Errorf("look up product %q: %w", name, err)
	}
	return p, nil
}

// DeclareStream records a branch or tag of a product.
func (s *Store) DeclareStream(ctx context.Context, productID int64, name string, kind Kind, parentID *int64) (*Stream, error) {
	if err := validName("stream", name); err != nil {
		return nil, err
	}
	if !kind.Valid() {
		return nil, fmt.Errorf("stream kind %q: want %q or %q", kind, Branch, Tag)
	}
	if _, err := s.StreamByName(ctx, productID, name); err == nil {
		return nil, fmt.Errorf("stream %q: %w", name, ErrExists)
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	st := &Stream{
		ProductID: productID, Name: matching(name), DisplayName: strings.TrimSpace(name),
		Kind: kind, ParentID: parentID, CreatedAt: now(),
	}
	if _, err := s.db.NewInsert().Model(st).Exec(ctx); err != nil {
		return nil, fmt.Errorf("declare stream %q: %w", name, err)
	}
	return st, nil
}

// StreamByName finds a stream within a product.
func (s *Store) StreamByName(ctx context.Context, productID int64, name string) (*Stream, error) {
	st := new(Stream)
	err := s.db.NewSelect().Model(st).
		Where("product_id = ?", productID).Where("name = ?", matching(name)).Scan(ctx)
	if err != nil {
		if database.IsNoRows(err) {
			return nil, fmt.Errorf("stream %q: %w", name, ErrNotFound)
		}
		return nil, fmt.Errorf("look up stream %q: %w", name, err)
	}
	return st, nil
}

// DeclareVariant records a way a product is built.
//
// Once per product, not once per release. A variant is a chip, an
// architecture, an operating system — a property of the product that does not
// change because a new release came out. Restating it per release is how one
// release ends up with a name spelled differently from the last, and three
// spellings are three sets of findings with nothing saying they belong
// together.
func (s *Store) DeclareVariant(ctx context.Context, productID int64, name string, customerFacing bool) (*Variant, error) {
	if err := validName("variant", name); err != nil {
		return nil, err
	}
	if _, err := s.VariantByName(ctx, productID, name); err == nil {
		return nil, fmt.Errorf("variant %q: %w", name, ErrExists)
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	v := &Variant{
		ProductID: productID, Name: matching(name), DisplayName: strings.TrimSpace(name),
		CustomerFacing: customerFacing, CreatedAt: now(),
	}
	if _, err := s.db.NewInsert().Model(v).Exec(ctx); err != nil {
		return nil, fmt.Errorf("declare variant %q: %w", name, err)
	}
	return v, nil
}

// VariantByName finds one of a product's variants.
func (s *Store) VariantByName(ctx context.Context, productID int64, name string) (*Variant, error) {
	v := new(Variant)
	err := s.db.NewSelect().Model(v).
		Where("product_id = ?", productID).Where("name = ?", matching(name)).Scan(ctx)
	if err != nil {
		if database.IsNoRows(err) {
			return nil, fmt.Errorf("variant %q: %w", name, ErrNotFound)
		}
		return nil, fmt.Errorf("look up variant %q: %w", name, err)
	}
	return v, nil
}

// Resolve turns the names a scan supplies into the target it is filed against.
//
// Every part must already be declared. The error names exactly which part is
// missing, because whoever sees the failed upload needs to know what to add
// rather than that something, somewhere, was wrong.
//
// The pair itself is not declared. Once the product, the release and the
// variant all exist, a scan saying this release was built as that variant is
// reporting a fact rather than naming something new, so the row is recorded on
// first use. It is also why a variant introduced later stays out of earlier
// releases: nothing ever filed a scan for it there.
func (s *Store) Resolve(ctx context.Context, product, stream, variant string) (*Target, error) {
	named, err := s.Locate(ctx, product, stream, variant)
	if err != nil {
		return nil, err
	}
	return s.TargetFor(ctx, named.StreamID, named.VariantID)
}

// Named is what an upload said it was for, resolved to rows but not yet
// recorded as a target.
//
// The three names are the stored ones rather than the ones that were typed. A
// name people type is matched without regard to capitals, so two callers
// naming one build spell it two ways, and anything a document is identified by
// has to be the same string both times.
type Named struct {
	ProductID int64
	StreamID  int64
	VariantID int64
	Product   string
	Stream    string
	Variant   string
	// VariantRetired says the variant named here is out of use. Carried
	// rather than refused inside the lookup, because resolving the names is
	// how a document already issued for it is still found and how its
	// findings are still read. Filing a scan is the one act that refuses.
	VariantRetired bool
}

// LocateVisible is Locate for one sender, reporting anything they may not file
// against as not declared.
//
// The same answer as a name nobody ever declared, deliberately. A key holds one
// product; without this, presenting it and guessing at names elsewhere would
// return a different error for a name that exists — which turns a stolen build
// credential into a reader of the whole shipping catalog.
func (s *Store) LocateVisible(ctx context.Context, subject access.Subject, product, stream, variant string) (*Named, error) {
	p, err := s.ProductByName(ctx, product)
	if err != nil {
		return nil, err
	}
	// Somebody brought into a case here may resolve the build's names, and
	// nothing more: what they were told about names a product, so refusing
	// to resolve it would refuse them the one thing they were granted
	// while telling them nothing they did not already know. Every read
	// past this still asks about the issue.
	if !subject.Sees(p.ID) && len(subject.Cases(p.ID)) == 0 {
		return nil, fmt.Errorf("product %q: %w", product, ErrNotFound)
	}
	return s.Locate(ctx, product, stream, variant)
}

// Locate turns the names an upload states into the things they refer to,
// without recording anything.
//
// Separate from Resolve so that whether the sender is allowed to file against
// this can be decided before the pair is written down. Recording first and
// checking afterwards leaves a row created by a request that was refused.
func (s *Store) Locate(ctx context.Context, product, stream, variant string) (*Named, error) {
	p, err := s.ProductByName(ctx, product)
	if err != nil {
		return nil, err
	}
	st, err := s.StreamByName(ctx, p.ID, stream)
	if err != nil {
		return nil, fmt.Errorf("product %q: %w", product, err)
	}
	v, err := s.VariantByName(ctx, p.ID, variant)
	if err != nil {
		return nil, fmt.Errorf("product %q: %w", product, err)
	}
	return &Named{
		ProductID: p.ID, StreamID: st.ID, VariantID: v.ID,
		Product: p.Name, Stream: st.Name, Variant: v.Name,
		VariantRetired: v.Retired(),
	}, nil
}

// TargetFor returns the row for a release built as a variant, recording it the
// first time.
func (s *Store) TargetFor(ctx context.Context, streamID, variantID int64) (*Target, error) {
	target := new(Target)
	err := s.db.NewSelect().Model(target).
		Where("stream_id = ?", streamID).Where("variant_id = ?", variantID).Scan(ctx)
	if err == nil {
		return target, nil
	}
	if !database.IsNoRows(err) {
		return nil, fmt.Errorf("look up what a scan is filed against: %w", err)
	}

	target = &Target{StreamID: streamID, VariantID: variantID, CreatedAt: now()}
	if _, err := s.db.NewInsert().Model(target).Exec(ctx); err != nil {
		if database.IsDuplicate(err) {
			// Two pipelines filed the first scan for this pair at once. The
			// row the other one wrote is the row: the read above and this
			// write are two statements, so both found nothing and both
			// inserted, and the unique index refused whichever arrived
			// second. Nothing here is the loser's to report.
			return s.ExistingTarget(ctx, streamID, variantID)
		}
		return nil, fmt.Errorf("record that this release is built as this variant: %w", err)
	}
	return target, nil
}

func now() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// matching is how a name people type is compared.
//
// Lower case and trimmed. These names get typed by hand into build scripts, so
// "sonic" reaching a product declared as "SONiC" is the same typo problem that
// declaring-before-use exists to catch — and refusing it teaches somebody the
// product is not declared when it plainly is.
//
// Normalizing the stored value rather than comparing case-insensitively is
// what makes every engine agree without any of them being asked to: a
// lower-case value compares the same under any collation, and the unique
// constraint means the same thing everywhere.
//
// The spelling somebody typed is kept beside it and is what gets shown back.
func matching(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// Target is one release built as one variant. It is what a scan is filed
// against, and what everything downstream points at, so a single identifier
// runs from a scan through to a finding.
type Target struct {
	bun.BaseModel `bun:"table:target,alias:tg"`

	ID        int64     `bun:"id,pk,autoincrement"`
	StreamID  int64     `bun:"stream_id,notnull"`
	VariantID int64     `bun:"variant_id,notnull"`
	CreatedAt time.Time `bun:"created_at,notnull"`
	// LastScanID is which scan last wrote here, and taking it is how two
	// workers applying two scans of one target are kept apart.
	LastScanID *int64 `bun:"last_scan_id"`
	// LastRunID is the same thing for the pass that records what a scanner
	// found. It is a separate write over the same target, so it needs its own
	// hold on the row.
	LastRunID *int64 `bun:"last_run_id"`
}

// Placement is a target with everything above it named: what it is of, whether
// that line moves, and what to call the thing a scan is about when the scan
// does not name it.
type Placement struct {
	Product string
	Stream  string
	Kind    Kind
	Variant string
	// Moves says whether the line this was filed against is one that advances.
	// A branch is superseded by the next build; a tag never is, so what it
	// shipped has to be answerable years later.
	Moves bool
}

// Describe reads back what a target is.
func (s *Store) Describe(ctx context.Context, targetID int64) (*Placement, error) {
	var t Target
	if err := s.db.NewSelect().Model(&t).Where("id = ?", targetID).Scan(ctx); err != nil {
		return nil, missingOr(err, fmt.Sprintf("target %d", targetID),
			fmt.Sprintf("look up target %d", targetID))
	}
	var v Variant
	if err := s.db.NewSelect().Model(&v).Where("id = ?", t.VariantID).Scan(ctx); err != nil {
		return nil, missingOr(err, fmt.Sprintf("variant %d", t.VariantID),
			fmt.Sprintf("look up the variant target %d is built as", targetID))
	}
	var st Stream
	if err := s.db.NewSelect().Model(&st).Where("id = ?", t.StreamID).Scan(ctx); err != nil {
		return nil, missingOr(err, fmt.Sprintf("stream %d", t.StreamID),
			fmt.Sprintf("look up the release target %d belongs to", targetID))
	}
	var p Product
	if err := s.db.NewSelect().Model(&p).Where("id = ?", st.ProductID).Scan(ctx); err != nil {
		return nil, missingOr(err, fmt.Sprintf("product %d", st.ProductID),
			fmt.Sprintf("look up the product release %d belongs to", st.ID))
	}
	return &Placement{
		Product: p.DisplayName, Stream: st.DisplayName, Kind: st.Kind, Variant: v.DisplayName,
		Moves: st.Kind == Branch,
	}, nil
}

// ProductByID finds a product by its row.
//
// Used where something already holds an identifier and needs the name to show:
// a credential says which product it may send for, and an operator reading the
// list wants the name they declared rather than a number.
func (s *Store) ProductByID(ctx context.Context, id int64) (*Product, error) {
	p := new(Product)
	if err := s.db.NewSelect().Model(p).Where("id = ?", id).Scan(ctx); err != nil {
		return nil, missingOr(err, fmt.Sprintf("product %d", id),
			fmt.Sprintf("look up product %d", id))
	}
	return p, nil
}

// StreamByID names a branch or tag already known by identifier.
//
// Beside ProductByID because a credential and a target both carry identifiers
// and a screen showing either has to say the name somebody typed.
func (s *Store) StreamByID(ctx context.Context, id int64) (*Stream, error) {
	row := new(Stream)
	if err := s.db.NewSelect().Model(row).Where("id = ?", id).Scan(ctx); err != nil {
		return nil, missingOr(err, fmt.Sprintf("stream %d", id),
			fmt.Sprintf("look up stream %d", id))
	}
	return row, nil
}

// VariantByID names a variant already known by identifier.
func (s *Store) VariantByID(ctx context.Context, id int64) (*Variant, error) {
	row := new(Variant)
	if err := s.db.NewSelect().Model(row).Where("id = ?", id).Scan(ctx); err != nil {
		return nil, missingOr(err, fmt.Sprintf("variant %d", id),
			fmt.Sprintf("look up variant %d", id))
	}
	return row, nil
}

// ExistingTarget finds a release built as a variant, without recording one.
//
// Reading is not filing. Asking what is open against a build that has never
// been scanned should not create the record that says it was.
func (s *Store) ExistingTarget(ctx context.Context, streamID, variantID int64) (*Target, error) {
	target := new(Target)
	err := s.db.NewSelect().Model(target).
		Where("stream_id = ?", streamID).Where("variant_id = ?", variantID).Scan(ctx)
	if err != nil {
		if database.IsNoRows(err) {
			return nil, fmt.Errorf("nothing has been filed against this build: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("look up what is filed against this build: %w", err)
	}
	return target, nil
}

// ProductsCalled is the name each of these products goes by, as an address
// takes it.
//
// Beside ProductNames, which answers the display name. The two are different
// questions, and a caller wanting one and handed the other gets a word that
// does not resolve.
//
// Batched for the reason ProductNames is, and stated there.
func (s *Store) ProductsCalled(ctx context.Context, ids []int64) (map[int64]string, error) {
	called := map[int64]string{}
	if len(ids) == 0 {
		return called, nil
	}
	var products []Product
	if err := s.db.NewSelect().Model(&products).
		Column("id", "name").
		Where("id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what these products are called: %w", err)
	}
	for _, product := range products {
		called[product.ID] = product.Name
	}
	return called, nil
}

// ProductNames resolves products to their display names, for showing which
// product a row is about.
//
// Batched for the same reason people are: the lists that need it are long, and
// a query per row is how a page of fifty becomes fifty-one round trips.
func (s *Store) ProductNames(ctx context.Context, ids []int64) (map[int64]string, error) {
	names := map[int64]string{}
	if len(ids) == 0 {
		return names, nil
	}
	var products []Product
	if err := s.db.NewSelect().Model(&products).
		Column("id", "display_name").
		Where("id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read which products these are: %w", err)
	}
	for _, product := range products {
		names[product.ID] = product.DisplayName
	}
	return names, nil
}
