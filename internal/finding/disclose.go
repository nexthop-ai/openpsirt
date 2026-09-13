package finding

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Embargoed is one finding nobody has announced, and when that ends.
type Embargoed struct {
	Vulnerability string `bun:"vulnerability"`
	Summary       string `bun:"summary"`
	Component     string `bun:"component"`
	Product       string `bun:"product"`
	Stream        string `bun:"stream"`
	Variant       string `bun:"variant"`
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

// Disclosing reports what is approaching disclosure, and what is past it,
// soonest first.
//
// **Before the date, not on it**. The date arriving is the last
// moment to act on it rather than the first useful warning, and a list that
// only ever showed what was already overdue would be a list of decisions
// somebody has already failed to make.
//
// **Nothing here discloses anything.** Reaching the date escalates: the row
// appears, and the people who can act on it are told. Publishing embargoed
// detail because a timer expired is the wrong default — if the fix is not
// ready, disclosing anyway is a decision a person makes.
//
// Narrowed like everything else, and more consequentially: this is a list of
// findings nobody has announced, so somebody who may not read undisclosed work
// in a product sees none of that product's. What that costs them is a shorter
// list; what the alternative costs is the disclosure the whole split exists to
// prevent.
func (s *Store) Disclosing(ctx context.Context, subject access.Subject, scope Scope,
	within time.Duration, limit int) ([]Embargoed, error) {

	products, all := subject.Products()
	if subject.Kind != access.Person || (!all && len(products) == 0) {
		return nil, nil
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
			return nil, nil
		}
	}

	query := s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN target AS tg ON tg.id = f.target_id").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		Join("JOIN variant AS va ON va.id = tg.variant_id").
		Join("JOIN product AS p ON p.id = st.product_id").
		Join("JOIN component AS c ON c.id = f.component_id").
		Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
		Join(RatedFor("st.product_id")).
		ColumnExpr("v.identifier AS vulnerability").
		ColumnExpr("v.description AS summary").
		ColumnExpr(EffectiveSeverityExpr+" AS severity").
		ColumnExpr("c.name AS component").
		ColumnExpr("p.display_name AS product").
		ColumnExpr("st.display_name AS stream").
		ColumnExpr("va.display_name AS variant").
		ColumnExpr("MIN(f.disclose_at) AS disclose_at").
		ColumnExpr("MIN(f.assigned_to) AS assigned_to").
		ColumnExpr("COUNT(*) AS places").
		Where("f.visibility = ?", access.Private).
		Where("f.closed_at IS NULL").
		Where("f.disclose_at IS NOT NULL").
		Where("f.disclose_at <= ?", s.now().UTC().Add(within)).
		GroupExpr("v.identifier, v.description, " + EffectiveSeverityExpr +
			", c.name, p.display_name, st.display_name, va.display_name").
		OrderExpr("disclose_at, v.identifier").
		Limit(limit)
	if len(private) > 0 {
		query = query.Where("st.product_id IN (?)", bun.List(private))
	}
	query = scope.Narrow(query)

	var rows []Embargoed
	if err := query.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what is approaching disclosure: %w", err)
	}
	return rows, nil
}

// Extension is one time somebody moved the end of an embargo.
type Extension struct {
	bun.BaseModel `bun:"table:disclosure_extension,alias:dx"`

	ID              int64 `bun:"id,pk,autoincrement"`
	VulnerabilityID int64 `bun:"vulnerability_id,notnull"`
	ProductID       int64 `bun:"product_id,notnull"`
	// Was and Until are where the embargo ended before and where it is asked
	// to end. Both kept: "extended by three weeks" is not answerable from the
	// new date alone once a second extension follows it.
	Was     time.Time `bun:"was,notnull"`
	Until   time.Time `bun:"until,notnull"`
	Reason  string    `bun:"reason,notnull"`
	AskedBy int64     `bun:"asked_by,notnull"`
	AskedAt time.Time `bun:"asked_at,notnull"`
	// NeedsApproval says a second person had to agree, recorded rather than
	// recomputed: the threshold is a setting and it moves.
	NeedsApproval bool       `bun:"needs_approval,notnull"`
	ApprovedBy    *int64     `bun:"approved_by"`
	ApprovedAt    *time.Time `bun:"approved_at"`
}

// InForce says this extension is the one the date follows.
func (e Extension) InForce() bool { return !e.NeedsApproval || e.ApprovedAt != nil }

// ErrNotEmbargoed says there is no embargo here to move.
var ErrNotEmbargoed = errors.New("nothing undisclosed here has a date to move")

// ErrAlreadyAgreed says somebody has already agreed to this extension.
//
// A sentinel rather than a bare error, because a second approver arriving is
// an ordinary race — two people were sent the same queue entry — and it is a
// conflict rather than something going wrong. Left as a plain error it reached
// the caller as a 500, which reads as a defect in the tool and sends somebody
// to the logs to find out that nothing was broken.
var ErrAlreadyAgreed = errors.New("that extension has already been agreed to")

// ErrBackwards says an extension would bring a date forward.
var ErrBackwards = errors.New("an extension moves a date later, not earlier")

// Extend asks to move the end of an embargo, and reports whether it took
// effect or is waiting for somebody to agree.
//
// **A reason is required, always**, however short the extension. One with no
// reason is the record saying somebody moved it and nothing else, which is the
// state the whole table exists to prevent.
//
// **Past a threshold it needs a second person**, and it is the same
// act a deferral is — keeping risk hidden for longer — so it is measured the
// same way: against everything this embargo has *already* been moved by, not
// against this request alone. Measured per request the exception swallows the
// rule three weeks at a time.
//
// **An extension that needs agreement does not move the date until it has it.**
// A proposal waiting for a second person changes nothing about the finding it
// is about, which is already true of a decision waiting for one; an embargo
// that quietly ran on while somebody thought about it would be the extension
// taking effect on one person's say-so with a queue entry as decoration.
func (s *Store) Extend(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64, until time.Time, reason string) (*Extension, error) {

	if !subject.Triages(access.Private, productID) {
		return nil, access.Denied(
			fmt.Sprintf("move a disclosure date in product %d", productID))
	}
	if subject.ID == 0 {
		return nil, access.Denied("move a disclosure date without being anybody")
	}
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("say why the embargo is being extended")
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	until = until.UTC().Truncate(time.Microsecond)

	var out *Extension
	err := database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		// Where it ends now, read inside the transaction: a retry
		// re-runs this against a database another extension may have
		// moved.
		var was time.Time
		err := tx.NewSelect().
			TableExpr("finding AS f").
			Join("JOIN target AS tg ON tg.id = f.target_id").
			Join("JOIN stream AS st ON st.id = tg.stream_id").
			ColumnExpr("MAX(f.disclose_at)").
			Where("st.product_id = ?", productID).
			Where("f.vulnerability_id = ?", vulnerabilityID).
			Where("f.visibility = ?", access.Private).
			Where("f.closed_at IS NULL").
			Where("f.disclose_at IS NOT NULL").
			Scan(ctx, &was)
		if database.IsNoRows(err) || (err == nil && was.IsZero()) {
			return ErrNotEmbargoed
		}
		if err != nil {
			return fmt.Errorf("read where the embargo ends: %w", err)
		}
		if !until.After(was) {
			return ErrBackwards
		}

		threshold, err := setting.NewStore(tx).Duration(ctx,
			setting.ExtensionThreshold, setting.DefaultExtensionThreshold)
		if err != nil {
			return err
		}
		already, err := movedBy(ctx, tx, productID, vulnerabilityID)
		if err != nil {
			return err
		}
		needs := threshold <= 0 || already+until.Sub(was) >= threshold

		out = &Extension{
			VulnerabilityID: vulnerabilityID, ProductID: productID,
			Was: was, Until: until, Reason: reason,
			AskedBy: subject.ID, AskedAt: now, NeedsApproval: needs,
		}
		if !needs {
			out.ApprovedAt = nil
		}
		if _, err := tx.NewInsert().Model(out).Exec(ctx); err != nil {
			return fmt.Errorf("record the extension: %w", err)
		}
		if needs {
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

// AgreeToExtension records a second person agreeing, and moves the date.
//
// The person who asked may not be the one who agrees. That is the control the
// threshold exists to reach, and an extension somebody approved for themselves
// is the same as one nobody approved.
func (s *Store) AgreeToExtension(ctx context.Context, subject access.Subject, id int64) error {
	if subject.ID == 0 {
		return access.Denied("agree to an extension without being anybody")
	}
	now := s.now().UTC().Truncate(time.Microsecond)

	return database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		asked := new(Extension)
		if err := tx.NewSelect().Model(asked).Where("id = ?", id).Scan(ctx); err != nil {
			// An extension somebody may not reach and one that is
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

		if _, err := tx.NewUpdate().Model((*Extension)(nil)).
			Set("approved_by = ?", subject.ID).
			Set("approved_at = ?", now).
			Where("id = ?", id).
			Where("approved_at IS NULL").Exec(ctx); err != nil {
			return fmt.Errorf("record the agreement: %w", err)
		}
		return moveTo(ctx, tx, asked.ProductID, asked.VulnerabilityID, asked.Until, now)
	})
}

// Extensions lists every time this embargo was moved, oldest first.
//
// Kept in full and never overwritten. One extension is a judgment and six is a
// policy nobody wrote down, and the difference is invisible if each replaces
// the last.
func (s *Store) Extensions(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64) ([]Extension, error) {

	if !subject.Reads(access.Private, productID) {
		return nil, access.Denied(fmt.Sprintf("read undisclosed work in product %d", productID))
	}
	var rows []Extension
	if err := s.db.NewSelect().Model(&rows).
		Where("product_id = ?", productID).
		Where("vulnerability_id = ?", vulnerabilityID).
		Order("asked_at", "id").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read how this embargo has been moved: %w", err)
	}
	return rows, nil
}

// movedBy is how much this embargo has already been moved by, counting only
// what took effect.
//
// A request nobody agreed to moved nothing, so it does not count toward the
// threshold — otherwise asking for a long extension and being refused would
// push every later request over the line for something that never happened.
func movedBy(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64) (time.Duration, error) {
	var rows []Extension
	err := db.NewSelect().Model(&rows).
		Where("product_id = ?", productID).
		Where("vulnerability_id = ?", vulnerabilityID).
		Scan(ctx)
	if err != nil {
		return 0, fmt.Errorf("read how far this has already been moved: %w", err)
	}
	total := time.Duration(0)
	for _, row := range rows {
		if !row.InForce() {
			continue
		}
		if span := row.Until.Sub(row.Was); span > 0 {
			total += span
		}
	}
	return total, nil
}

// moveTo writes the new end of an embargo across everything it covers.
func moveTo(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64,
	until, now time.Time) error {

	_, err := db.NewUpdate().Model((*Finding)(nil)).
		Set("disclose_at = ?", until).
		Set("last_changed_at = ?", now).
		Where("vulnerability_id = ?", vulnerabilityID).
		Where("visibility = ?", access.Private).
		Where("closed_at IS NULL").
		Where(`target_id IN (SELECT tg.id FROM "target" AS tg
			JOIN "stream" AS st ON st.id = tg.stream_id
			WHERE st.product_id = ?)`, productID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("move the disclosure date: %w", err)
	}
	return nil
}

// Waiting is an extension request nobody has agreed to yet, with the issue and
// product it is about.
//
// An extension over the threshold needs a second person, and until now there
// was nowhere to be that second person: the request could be read on the
// finding it belongs to and nowhere else, so the only way to find one was to
// already know it existed. That is the same failure the review queue exists to
// prevent, in the one place where the thing being agreed to is how long
// something stays hidden.
type Waiting struct {
	Extension
	Product       string
	Vulnerability string
	AskedByName   string
}

// Pending lists extension requests waiting for a second person, across every
// product the subject may read undisclosed work in.
//
// **Narrowed in the query rather than afterwards.** The list is itself a
// disclosure: a row says an issue exists, is embargoed, and is being kept
// hidden longer — which is the shape of thing a disclosure date escalating keeps out of every count
// somebody may not see.
//
// **Their own requests are included.** They cannot agree to one and the
// endpoint refuses it, but a proposer looking for what is holding a case up
// should not have their own request hidden from them — which is the opposite
// of the review queue's rule, where the entry is work the reader might do.
// Here it is a state of the case rather than a task, so it is shown and said
// to be theirs.
func (s *Store) Pending(ctx context.Context, subject access.Subject,
	limit int) ([]Waiting, error) {

	limit = database.AList.Of(limit)
	products, all := subject.Products()
	var readable []int64
	for _, id := range products {
		if subject.Reads(access.Private, id) {
			readable = append(readable, id)
		}
	}
	if subject.Kind != access.Person || (!all && len(readable) == 0) {
		return nil, nil
	}

	var rows []struct {
		Extension     `bun:",extend"`
		Product       string `bun:"product"`
		Vulnerability string `bun:"vulnerability"`
		AskedByName   string `bun:"asked_by_name"`
	}
	query := s.db.NewSelect().
		Model((*Extension)(nil)).
		ColumnExpr("dx.*").
		Join(`JOIN "product" AS p ON p.id = dx.product_id`).
		Join(`JOIN "vulnerability" AS v ON v.id = dx.vulnerability_id`).
		Join(`LEFT JOIN "person" AS ps ON ps.id = dx.asked_by`).
		ColumnExpr("p.name AS product").
		ColumnExpr("v.identifier AS vulnerability").
		ColumnExpr(`COALESCE(NULLIF(ps.display_name, ''), ps.identity, '') AS asked_by_name`).
		Where("dx.needs_approval = ?", true).
		Where("dx.approved_at IS NULL").
		OrderExpr("dx.asked_at DESC").
		Limit(limit)
	if !all {
		query = query.Where("dx.product_id IN (?)", bun.List(readable))
	}
	if err := query.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read which embargoes are waiting to be moved: %w", err)
	}
	out := make([]Waiting, 0, len(rows))
	for _, row := range rows {
		out = append(out, Waiting{
			Extension: row.Extension, Product: row.Product,
			Vulnerability: row.Vulnerability, AskedByName: row.AskedByName,
		})
	}
	return out, nil
}
