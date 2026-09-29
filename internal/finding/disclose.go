// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/rating"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Embargoed is one finding nobody has announced, and when that ends.
type Embargoed struct {
	Vulnerability string `bun:"vulnerability"`
	Summary       string `bun:"summary"`
	Component     string `bun:"component"`
	Product       string `bun:"product"`
	ProductName   string `bun:"product_name"`
	Stream        string `bun:"stream"`
	StreamName    string `bun:"stream_name"`
	Variant       string `bun:"variant"`
	VariantName   string `bun:"variant_name"`
	Severity      string `bun:"severity"`
	// DiscloseAt is when the embargo ends. Reaching it discloses nothing:
	// it is a date to answer, not a trigger.
	DiscloseAt time.Time `bun:"disclose_at"`
	AssignedTo *int64    `bun:"assigned_to"`
	// Places is how many findings this covers.
	Places int `bun:"places"`
}

// Passed says the date has arrived and nothing has been decided about it.
func (e Embargoed) Passed(now time.Time) bool { return !e.DiscloseAt.After(now) }

// DisclosingPage reports what is approaching disclosure, and what is past it,
// soonest first, from a position in the list, with how many there are in all.
//
// Before the date, not on it. The date arriving is the last
// moment to act on it rather than the first useful warning, and a list that
// only ever showed what was already overdue would be a list of decisions
// somebody has already failed to make.
//
// Nothing here discloses anything. Reaching the date escalates: the row
// appears, and the people who can act on it are told. Publishing embargoed
// detail because a timer expired is the wrong default — if the fix is not
// ready, disclosing anyway is a decision a person makes.
//
// Narrowed like everything else, and more consequentially: this is a list of
// findings nobody has announced, so somebody who may not read undisclosed work
// in a product sees none of that product's. What that costs them is a shorter
// list; what the alternative costs is the disclosure the whole split exists to
// prevent.
//
// Paged because a ceiling with no offset means what is past it cannot be read
// through the API at all — not slowly, not at all — and the total because a
// caller holding a full page cannot otherwise tell a clipped page from the
// whole list.
func (s *Store) DisclosingPage(ctx context.Context, subject access.Subject, scope Scope,
	within time.Duration, limit, offset int) ([]Embargoed, int, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are
	// different statements, and this is the second. A person holding
	// nothing is the first, and is answered below.
	if subject.Kind != access.Person {
		return nil, 0, access.Denied("read what is being disclosed")
	}
	products, all := subject.Products()
	if !all && len(products) == 0 {
		return nil, 0, nil
	}
	limit = database.InBulk.Of(limit)
	if within <= 0 {
		within = 30 * 24 * time.Hour
	}

	// Only what this person may see undisclosed work about. A product where
	// they hold public access alone contributes nothing, because every row
	// here is undisclosed by definition — and a count would say as much as a
	// row.
	private := make([]int64, 0, len(products))
	if all {
		private = nil
	} else {
		for _, id := range products {
			if subject.Reads(access.Private, id) {
				private = append(private, id)
			}
		}
		if len(private) == 0 {
			return nil, 0, nil
		}
	}

	query := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "variant" AS "va" ON va.id = tg.variant_id`).
		Join(`JOIN "product" AS "p" ON p.id = st.product_id`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		Join(rating.For(rating.OnStream)).
		ColumnExpr(`v.identifier AS "vulnerability"`).
		ColumnExpr(`v.description AS "summary"`).
		ColumnExpr(rating.EffectiveExpr+` AS "severity"`).
		ColumnExpr(`c.name AS "component"`).
		Apply(catalog.BuildNames("p", "st", "va")).
		ColumnExpr(`MIN(f.disclose_at) AS "disclose_at"`).
		// Whoever is dealing with it, and nobody where the places disagree.
		// A minimum named one of them: a partly assigned embargo read as one
		// person's, which is a list of what is coming that names the wrong
		// person to ask. The same reconciliation the deadline list does, in
		// the statement rather than after it.
		ColumnExpr(`CASE WHEN COUNT(f.assigned_to) = COUNT(*)
			AND MIN(f.assigned_to) = MAX(f.assigned_to)
			THEN MIN(f.assigned_to) END AS "assigned_to"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		Where("f.visibility = ?", access.Private).
		Where("f.closed_at IS NULL").
		Where("f.disclose_at IS NOT NULL").
		Where("f.disclose_at <= ?", s.now().UTC().Add(within)).
		GroupExpr("v.identifier, v.description, " + rating.EffectiveExpr +
			", c.name, p.name, p.display_name, st.name, st.display_name, va.name, va.display_name").
		OrderExpr("disclose_at, v.identifier")
	if len(private) > 0 {
		query = query.Where("st.product_id IN (?)", bun.List(private))
	}
	query = scope.Narrow(query)

	// Counted over the grouping rather than the rows: a row here is an issue
	// at a component however many places it sits at, and counting the places
	// would say a number the list cannot show.
	total, err := s.db.NewSelect().
		TableExpr(`(?) AS "approaching"`, query).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count what is approaching disclosure: %w", err)
	}

	var rows []Embargoed
	if err := query.Limit(limit).Offset(offset).Scan(ctx, &rows); err != nil {
		return nil, 0, fmt.Errorf("read what is approaching disclosure: %w", err)
	}
	return rows, total, nil
}

// Act is which way a disclosure date was moved, and what that movement means.
//
// Stored rather than read off the two dates. "We extended it because the fix
// slipped" and "we shortened it because it leaked" are different events, and a
// reader working out which from the sign of a date change is reading an
// inference where the record should hold a fact.
type Act string

const (
	// Extension is the embargo ending later than it was going to.
	Extension Act = "extension"
	// Shortening is the embargo ending sooner, which is what a coordinator or
	// a peer vendor pulling a date in asks for.
	Shortening Act = "shortening"
	// Disclosure is the embargo ending today, and the issue becoming public
	// in the product. The last movement an embargo has.
	Disclosure Act = "disclosure"
	// Duplicated is a claim from outside ruled a duplicate of a flaw recorded
	// here, starting the embargo's end or bringing it earlier. Nobody chose
	// the date: it is when the claim arrived plus the disclosure window.
	Duplicated Act = "duplicate"
	// Unduplicated is that ruling withdrawn, and the end put back where the
	// movements still standing leave it.
	Unduplicated Act = "duplicate-undone"
)

// Acts are all of them, in the order a person meets them.
func Acts() []Act {
	return []Act{Extension, Shortening, Disclosure, Duplicated, Unduplicated}
}

// ruled reports whether a ruling recorded this movement rather than a person
// asking for it.
func (a Act) ruled() bool { return a == Duplicated || a == Unduplicated }

// moves reports whether this act is the one that moves a date from was to
// until. A movement of no distance is neither.
func (a Act) moves(was, until time.Time) bool {
	switch a {
	case Extension:
		return until.After(was)
	case Shortening, Duplicated:
		return until.Before(was)
	case Disclosure:
		// Disclosing moves no date a person typed. It ends the embargo
		// whichever side of its date today is.
		return true
	}
	return false
}

// Movement is one time somebody moved the end of an embargo.
type Movement struct {
	bun.BaseModel `bun:"table:disclosure_movement,alias:dx"`

	ID              int64 `bun:"id,pk,autoincrement"`
	VulnerabilityID int64 `bun:"vulnerability_id,notnull"`
	ProductID       int64 `bun:"product_id,notnull"`
	// Act is which movement this is, recorded as its own thing.
	Act Act `bun:"act,notnull"`
	// Was and Until are where the embargo ended before and where it is asked
	// to end. Both kept: "extended by three weeks" is not answerable from the
	// new date alone once a second movement follows it. Only a movement a
	// ruling recorded holds a nil: an embargo it started had no end before,
	// and one its withdrawal put back may have none after.
	Was     *time.Time `bun:"was"`
	Until   *time.Time `bun:"until"`
	Reason  string     `bun:"reason,notnull"`
	AskedBy int64      `bun:"asked_by,notnull"`
	AskedAt time.Time  `bun:"asked_at,notnull"`
	// NeedsApproval says a second person had to agree, recorded rather than
	// recomputed: the threshold is a setting and it moves.
	NeedsApproval bool       `bun:"needs_approval,notnull"`
	ApprovedBy    *int64     `bun:"approved_by"`
	ApprovedAt    *time.Time `bun:"approved_at"`
	// RulingID is the ruling that recorded this movement, and FlawReportID
	// the claim whose arrival the date counts from. Nil on a movement a
	// person asked for.
	RulingID     *int64 `bun:"ruling_id"`
	FlawReportID *int64 `bun:"flaw_report_id"`

	// Report is that claim's reference, filled in for a reader who may read
	// the product's reports.
	Report string `bun:"-"`
}

// InForce says this movement is the one the date follows.
func (m Movement) InForce() bool { return !m.NeedsApproval || m.ApprovedAt != nil }

// Distance is how far this moved the date, whichever way it moved it.
//
// A magnitude, because what the threshold is measured against is how far an
// embargo's end has been carried from where it was agreed to sit. A date
// pulled in three weeks and pushed back three weeks is six weeks of movement,
// not none.
//
// A ruling bringing an existing date earlier is a shortening and carries its
// distance. A ruling starting a flaw's first date carries none, having no date
// to move, and a withdrawal putting a ruling's date back carries none either:
// it undoes a movement rather than making one.
func (m Movement) Distance() time.Duration {
	if m.Act == Unduplicated || m.Was == nil || m.Until == nil {
		return 0
	}
	if span := m.Until.Sub(*m.Was); span > 0 {
		return span
	}
	return m.Was.Sub(*m.Until)
}

// ErrNotEmbargoed says there is no embargo here to move.
var ErrNotEmbargoed = refusal.New("nothing undisclosed here has a date to move")

// ErrAlreadyAgreed says somebody has already agreed to this movement.
//
// A sentinel rather than a bare error, because a second approver arriving is
// an ordinary race — two people were sent the same queue entry — and it is a
// conflict rather than something going wrong. Left as a plain error it reached
// the caller as a 500, which reads as a defect in the tool and sends somebody
// to the logs to find out that nothing was broken.
var ErrAlreadyAgreed = refusal.New("that movement has already been agreed to")

// ErrNotLater says an extension would not move the date later.
var ErrNotLater = refusal.New("an extension moves a date later")

// Unreasoned is a movement asked for with no reason. The caller's to fix.
type Unreasoned struct{ Said string }

func (u Unreasoned) Error() string { return u.Said }

// Refused marks it as a sentence for the caller, who left the reason out.
func (u Unreasoned) Refused() {}

// ErrNotEarlier says bringing a date forward would not move it earlier.
var ErrNotEarlier = refusal.New("bringing a disclosure date forward moves it earlier")

// wrongWay is the refusal for an act asked to move a date the way it does not.
func wrongWay(act Act) error {
	if act == Shortening || act == Duplicated {
		return ErrNotEarlier
	}
	return ErrNotLater
}

// Extend asks to move the end of an embargo later, and reports whether it took
// effect or is waiting for somebody to agree.
//
// The unilateral case: the fix slipped, so the embargo runs longer.
func (s *Store) Extend(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64, until time.Time, reason string) (*Movement, error) {

	return s.move(ctx, subject, Extension, productID, vulnerabilityID, until, reason)
}

// BringForward asks to end an embargo sooner, and reports whether it took
// effect or is waiting for somebody to agree.
//
// The coordinated case: a coordinator or a peer vendor is publishing on a date
// of their own, or the detail has leaked, and holding to the old date
// discloses nothing to anybody except the people relying on us.
//
// Its own act rather than an extension with a negative sign. What a reader
// needs off the record is which of the two happened, and inferring it from the
// sign of a date change is an inference where there should be a fact.
func (s *Store) BringForward(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64, until time.Time, reason string) (*Movement, error) {

	return s.move(ctx, subject, Shortening, productID, vulnerabilityID, until, reason)
}

// move records one movement of an embargo's end, and applies it where it needs
// nobody else.
//
// A reason is required, always, however short the movement. One with no
// reason is the record saying somebody moved it and nothing else, which is the
// state the whole table exists to prevent.
//
// Past a threshold it needs a second person. Both acts are measured the same
// way and against the same setting: not against this request alone but against
// everything this embargo has already been moved by, because measured per
// request the exception swallows the rule three weeks at a time.
//
// A movement that needs agreement does not move the date until it has it.
// A proposal waiting for a second person changes nothing about the finding it
// is about, which is already true of a decision waiting for one; an embargo
// that quietly ran on while somebody thought about it would be the movement
// taking effect on one person's say-so with a queue entry as decoration.
func (s *Store) move(ctx context.Context, subject access.Subject, act Act,
	productID, vulnerabilityID int64, until time.Time, reason string) (*Movement, error) {

	if act != Extension && act != Shortening {
		return nil, refusal.Errorf("a disclosure date is moved later or brought forward")
	}
	if !subject.Triages(access.Private, productID) {
		return nil, access.Denied(
			fmt.Sprintf("move a disclosure date in product %d", productID))
	}
	if subject.ID == 0 {
		return nil, access.Denied("move a disclosure date without being anybody")
	}
	if strings.TrimSpace(reason) == "" {
		return nil, Unreasoned{Said: "say why the embargo is being moved"}
	}
	// The submission policy, run before the text is stored. This row is
	// append-only and is read back into a disclosure record.
	if err := markdown.Check(reason); err != nil {
		return nil, err
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	until = until.UTC().Truncate(time.Microsecond)

	var out *Movement
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		// Where it ends now, read inside the transaction: a retry re-runs
		// this against a database another movement may have moved.
		was, err := endsAt(ctx, tx, productID, vulnerabilityID)
		if err != nil {
			return err
		}
		// The act has to be the one that moves the date the way it is being
		// asked to move. An act taken as whichever way the dates happen to
		// point would record a typed date as a decision somebody made.
		if !act.moves(was, until) {
			return wrongWay(act)
		}

		threshold, err := setting.NewStore(tx).Duration(ctx,
			setting.MovementThreshold, setting.DefaultMovementThreshold)
		if err != nil {
			return err
		}
		already, err := movedBy(ctx, tx, productID, vulnerabilityID)
		if err != nil {
			return err
		}
		asked := &Movement{
			VulnerabilityID: vulnerabilityID, ProductID: productID,
			Act: act, Was: &was, Until: &until, Reason: reason,
			AskedBy: subject.ID, AskedAt: now,
		}
		asked.NeedsApproval = threshold <= 0 || already+asked.Distance() >= threshold
		out = asked
		// ApprovedAt is unset on every path to here, so nothing clears it.
		if _, err := tx.NewInsert().Model(out).Exec(ctx); err != nil {
			return fmt.Errorf("record the movement: %w", err)
		}
		if out.NeedsApproval {
			// Written, and the date left where it was. What is on record is
			// that somebody asked; what is in force is still the old date.
			return nil
		}
		return moveTo(ctx, tx, productID, vulnerabilityID, until, now)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// endsAt reads where an embargo ends now.
//
// Read again by whoever is about to move it, rather than carried from when the
// movement was asked for. A request sits in the queue while other movements
// take effect, so the date it was measured against is not the date it would
// move.
func endsAt(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64) (time.Time, error) {
	var was time.Time
	err := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr("MAX(f.disclose_at)").
		Where("st.product_id = ?", productID).
		Where(HeldAs("f.vulnerability_id"), vulnerabilityID).
		Where("f.visibility = ?", access.Private).
		Where("f.closed_at IS NULL").
		Where("f.disclose_at IS NOT NULL").
		Scan(ctx, &was)
	if database.IsNoRows(err) || (err == nil && was.IsZero()) {
		return time.Time{}, ErrNotEmbargoed
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("read where the embargo ends: %w", err)
	}
	return was, nil
}

// AgreeToMovement records a second person agreeing, and moves the date.
//
// The person who asked may not be the one who agrees. That is the control the
// threshold exists to reach, and a movement somebody approved for themselves
// is the same as one nobody approved.
//
// It answers the movement agreed to, which says which act took effect.
func (s *Store) AgreeToMovement(ctx context.Context, subject access.Subject, id int64) (*Movement, error) {
	if subject.ID == 0 {
		return nil, access.Denied("agree to a disclosure movement without being anybody")
	}
	now := s.now().UTC().Truncate(time.Microsecond)

	var agreed *Movement
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		asked := new(Movement)
		agreed = asked
		if err := tx.NewSelect().Model(asked).Where("id = ?", id).Scan(ctx); err != nil {
			// A movement somebody may not reach and one that is
			// not there answer alike, so guessing identifiers says
			// nothing.
			return ErrNotEmbargoed
		}
		if !subject.Triages(access.Private, asked.ProductID) {
			return ErrNotEmbargoed
		}
		if asked.AskedBy == subject.ID {
			return ErrSamePerson
		}
		if asked.ApprovedAt != nil {
			return ErrAlreadyAgreed
		}
		// One that needed nobody already moved the date when it was asked
		// for. Agreeing to it would write its old date over whatever has
		// happened since, and there is no agreement to record: the record
		// says it needed none. That includes every movement a ruling
		// recorded.
		if !asked.NeedsApproval || asked.Until == nil {
			return ErrAlreadyAgreed
		}

		if asked.Act == Disclosure {
			// Nothing to re-measure: disclosing ends the embargo wherever
			// its date has moved to since. What has to still hold is that
			// something here is undisclosed.
			if _, err := undisclosedHere(ctx, tx, asked.ProductID, asked.VulnerabilityID); err != nil {
				return err
			}
			if err := agree(ctx, tx, id, subject.ID, now); err != nil {
				return err
			}
			return makePublic(ctx, tx, asked.ProductID, asked.VulnerabilityID, now)
		}

		// A ruling's shortening stands only while the ruling does. Withdrawn,
		// there is no claim left for the date to count from.
		if asked.Act == Duplicated {
			if err := rulingStands(ctx, tx, asked.RulingID); err != nil {
				return err
			}
		}

		// Where the embargo ends now, rather than where it ended when this
		// was asked for. A request waits in the queue while other movements
		// take effect, so the date it was measured against is not the date it
		// would move — and an extension agreed to after a later one already
		// landed would carry the date backwards, which is the act recorded as
		// doing the one thing it never does.
		was, err := endsAt(ctx, tx, asked.ProductID, asked.VulnerabilityID)
		if err != nil {
			return err
		}
		if !asked.Act.moves(was, *asked.Until) {
			return wrongWay(asked.Act)
		}

		if err := agree(ctx, tx, id, subject.ID, now); err != nil {
			return err
		}
		if asked.Act == Duplicated {
			return dateFlaw(ctx, tx, asked.ProductID, asked.VulnerabilityID, asked.Until, true, now)
		}
		return moveTo(ctx, tx, asked.ProductID, asked.VulnerabilityID, *asked.Until, now)
	})
	if err != nil {
		return nil, err
	}
	return agreed, nil
}

// agree records one person agreeing to one movement.
//
// The count is read, because the WHERE below is what decides the outcome.
// Discarded, a second person agreeing at the same moment as the first matched
// nothing and was told they had agreed — the clause was there, the guard it
// carries was not reported, and the two-person rule reported two agreements
// where the record holds one.
func agree(ctx context.Context, tx bun.IDB, id, personID int64, now time.Time) error {
	res, err := tx.NewUpdate().Model((*Movement)(nil)).
		Set("approved_by = ?", personID).
		Set("approved_at = ?", now).
		Where("id = ?", id).
		Where("approved_at IS NULL").Exec(ctx)
	if err != nil {
		return fmt.Errorf("record the agreement: %w", err)
	}
	switch agreed, err := database.Affected(res); {
	case err != nil:
		return fmt.Errorf("read whether the agreement was recorded: %w", err)
	case agreed == 0:
		// Somebody agreed between the read and this write. Reported as what
		// it is rather than as a second agreement: the record holds one, and
		// the date moved once.
		return ErrAlreadyAgreed
	}
	return nil
}

// Movements lists every time this embargo was moved, oldest first.
//
// Kept in full and never overwritten. One movement is a judgment and six is a
// policy nobody wrote down, and the difference is invisible if each replaces
// the last.
//
// Public once the issue is disclosed in the product: the history of the
// embargo is part of the record that disclosing opens (REQ-40). Until then
// only somebody reading undisclosed work there may read it.
func (s *Store) Movements(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64) ([]Movement, error) {

	if !subject.Reads(access.Private, productID) {
		denied := access.Denied(fmt.Sprintf("read undisclosed work in product %d", productID))
		if !subject.Reads(access.Public, productID) {
			return nil, denied
		}
		switch _, err := undisclosedHere(ctx, s.db, productID, vulnerabilityID); {
		case errors.Is(err, ErrDisclosed):
		case err == nil, errors.Is(err, ErrNotEmbargoed):
			return nil, denied
		default:
			return nil, err
		}
	}
	var rows []Movement
	if err := s.db.NewSelect().Model(&rows).
		Where("product_id = ?", productID).
		Where(FiledUnder("vulnerability_id"), vulnerabilityID).
		Order("asked_at", "id").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read how this embargo has been moved: %w", err)
	}
	// The ruling, the claim it counted from and the ruling's reasoning are
	// read by somebody who may read the product's reports, under the rule
	// every report is read under. The history being public says nothing about
	// whether what a stranger sent, or what was said about it, is.
	if mayReadReports(subject, productID) != nil {
		for i := range rows {
			if rows[i].Act.ruled() {
				rows[i].Reason = ""
			}
			rows[i].RulingID, rows[i].FlawReportID = nil, nil
		}
		return rows, nil
	}
	var reports []int64
	for _, row := range rows {
		if row.FlawReportID != nil {
			reports = append(reports, *row.FlawReportID)
		}
	}
	if len(reports) == 0 {
		return rows, nil
	}
	var named []struct {
		ID        int64  `bun:"id"`
		Reference string `bun:"reference"`
	}
	if err := s.db.NewSelect().Model((*FlawReport)(nil)).
		Column("fr.id", "fr.reference").
		Where("fr.id IN (?)", bun.List(reports)).
		Scan(ctx, &named); err != nil {
		return nil, fmt.Errorf("read which claims this embargo counts from: %w", err)
	}
	references := make(map[int64]string, len(named))
	for _, row := range named {
		references[row.ID] = row.Reference
	}
	for i := range rows {
		if rows[i].FlawReportID != nil {
			rows[i].Report = references[*rows[i].FlawReportID]
		}
	}
	return rows, nil
}

// movedBy is how far this embargo has already been carried, counting only what
// took effect.
//
// A request nobody agreed to moved nothing, so it does not count toward the
// threshold — otherwise asking for a long extension and being refused would
// push every later request over the line for something that never happened.
//
// Both acts count, and each by its magnitude. The threshold asks how far an
// embargo's end has travelled from where it was first set, and an embargo
// pulled in and pushed back repeatedly is one whose date nobody can rely on,
// whichever way the last move went.
func movedBy(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64) (time.Duration, error) {
	var rows []Movement
	err := db.NewSelect().Model(&rows).
		Where("product_id = ?", productID).
		Where(FiledUnder("vulnerability_id"), vulnerabilityID).
		Scan(ctx)
	if err != nil {
		return 0, fmt.Errorf("read how far this has already been moved: %w", err)
	}
	total := time.Duration(0)
	for _, row := range rows {
		if !row.InForce() {
			continue
		}
		total += row.Distance()
	}
	return total, nil
}

// moveTo writes the new end of an embargo across everything it covers.
func moveTo(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64,
	until, now time.Time) error {

	_, err := db.NewUpdate().Model((*Finding)(nil)).
		Set("disclose_at = ?", until).
		Set("last_changed_at = ?", now).
		Where(HeldAs("vulnerability_id"), vulnerabilityID).
		Where("visibility = ?", access.Private).
		Where("closed_at IS NULL").
		Where(inThisProduct, productID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("move the disclosure date: %w", err)
	}
	return nil
}

// Waiting is a movement of a disclosure date nobody has agreed to yet, with
// the issue and product it is about.
//
// A movement over the threshold needs a second person, and there has to be
// somewhere to be that second person: read on the finding it belongs to and
// nowhere else, the only way to find one is to already know it exists. That is
// the same failure the review queue exists to prevent, in the one place where
// the thing being agreed to is how long something stays hidden.
type Waiting struct {
	Movement
	Product       string
	Vulnerability string
}

// PendingPage lists movements of a disclosure date waiting for a second person,
// across every product the subject may read undisclosed work in, from a
// position in the list, with how many there are in all.
//
// Narrowed in the query rather than afterwards. The list is itself a
// disclosure: a row says an issue exists, is embargoed, and is being kept
// hidden longer — which is exactly what a visibility narrowing keeps out of
// every count somebody may not see.
//
// Their own requests are included. They cannot agree to one and the
// endpoint refuses it, but a proposer looking for what is holding a case up
// should not have their own request hidden from them — which is the opposite
// of the review queue's rule, where the entry is work the reader might do.
// Here it is a state of the case rather than a task, so it is shown and said
// to be theirs.
//
// Paged because a ceiling with no offset means what is past it cannot be read
// through the API at all, and the total because a screen was printing the
// length of its own page as the number of requests waiting.
func (s *Store) PendingPage(ctx context.Context, subject access.Subject,
	limit, offset int) ([]Waiting, int, error) {

	limit = database.AList.Of(limit)
	// Not merely empty: "here is nothing" and "you cannot ask" are different
	// statements, and this is the second.
	if subject.Kind != access.Person {
		return nil, 0, access.Denied("read which embargoes are pending")
	}
	products, all := subject.Products()
	var readable []int64
	for _, id := range products {
		if subject.Reads(access.Private, id) {
			readable = append(readable, id)
		}
	}
	if subject.Kind != access.Person || (!all && len(readable) == 0) {
		return nil, 0, nil
	}

	var rows []struct {
		Movement      `bun:",extend"`
		Product       string `bun:"product"`
		Vulnerability string `bun:"vulnerability"`
	}
	query := s.db.NewSelect().
		Model((*Movement)(nil)).
		ColumnExpr("dx.*").
		Join(`JOIN "product" AS "p" ON p.id = dx.product_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = dx.vulnerability_id`).
		ColumnExpr(`p.name AS "product"`).
		ColumnExpr(`v.identifier AS "vulnerability"`).
		Where("dx.needs_approval = ?", true).
		Where("dx.approved_at IS NULL").
		// Only while something here is still undisclosed. A request left
		// waiting when the issue was disclosed can no longer be agreed to,
		// and a queue entry nobody can act on is noise on the one list whose
		// point is that everything on it is a question.
		Where(`EXISTS (SELECT 1 FROM "finding" AS "fu"
			JOIN "target" AS "tu" ON tu.id = fu.target_id
			JOIN "stream" AS "su" ON su.id = tu.stream_id
			WHERE `+SameIssue("fu.vulnerability_id", "dx.vulnerability_id")+`
			AND su.product_id = dx.product_id
			AND fu.visibility = ?)`, access.Private).
		// Nor one a withdrawn ruling asked for, which can no longer be agreed
		// to.
		Where(`NOT EXISTS (SELECT 1 FROM "report_ruling" AS "rw"
			WHERE rw.id = dx.ruling_id AND rw.withdrawn_at IS NOT NULL)`).
		OrderExpr("dx.asked_at DESC")
	if !all {
		query = query.Where("dx.product_id IN (?)", bun.List(readable))
	}
	total, err := s.db.NewSelect().TableExpr(`(?) AS "waiting"`, query).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count which embargoes are waiting to be moved: %w", err)
	}
	if err := query.Limit(limit).Offset(offset).Scan(ctx, &rows); err != nil {
		return nil, 0, fmt.Errorf("read which embargoes are waiting to be moved: %w", err)
	}
	out := make([]Waiting, 0, len(rows))
	for _, row := range rows {
		out = append(out, Waiting{
			Movement: row.Movement, Product: row.Product,
			Vulnerability: row.Vulnerability,
		})
	}
	return out, total, nil
}
