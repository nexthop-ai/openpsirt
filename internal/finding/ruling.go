package finding

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Disposition is what a report was judged to be.
type Disposition string

const (
	// Accepted is a claim that turned out to be an issue here. It is written
	// by pointing the report at that issue, never by a ruling.
	Accepted Disposition = "accepted"
	// Duplicate is a claim about an issue that is already open here. The
	// work exists elsewhere, so nothing is hidden and nobody else agrees.
	Duplicate Disposition = "duplicate"
	// NotReproducible is a claim nobody could make happen.
	NotReproducible Disposition = "not-reproducible"
	// OutOfScope is a claim about something this product does not answer
	// for.
	OutOfScope Disposition = "out-of-scope"
	// Rejected is a claim that is not a flaw.
	Rejected Disposition = "rejected"
)

// Rulable reports whether a ruling may carry this disposition.
func (d Disposition) Rulable() bool {
	switch d {
	case Duplicate, NotReproducible, OutOfScope, Rejected:
		return true
	}
	return false
}

// NeedsSecondPerson reports whether somebody other than the proposer has to
// agree before the disposition takes effect.
//
// Rejecting a claim and declaring it out of scope set it aside with nothing
// left anywhere to work on, which is hiding risk in the sense REQ-24 means.
func (d Disposition) NeedsSecondPerson() bool { return d == OutOfScope || d == Rejected }

// ReportRuling is one act of saying what one or more claims are, where the
// answer is not an issue here.
type ReportRuling struct {
	bun.BaseModel `bun:"table:report_ruling,alias:rr"`

	ID          int64       `bun:"id,pk,autoincrement"`
	ProductID   int64       `bun:"product_id,notnull"`
	Disposition Disposition `bun:"disposition,notnull"`
	// Reasoning is never edited. An approval is of these words.
	Reasoning   string     `bun:"reasoning"`
	DuplicateOf *int64     `bun:"duplicate_of"`
	ProposedBy  int64      `bun:"proposed_by,notnull"`
	ProposedAt  time.Time  `bun:"proposed_at,notnull"`
	ApprovedBy  *int64     `bun:"approved_by"`
	ApprovedAt  *time.Time `bun:"approved_at"`
	SettledAt   *time.Time `bun:"settled_at"`
	WithdrawnBy *int64     `bun:"withdrawn_by"`
	WithdrawnAt *time.Time `bun:"withdrawn_at"`

	// Product is the name of the product it was made in.
	Product string `bun:"product,scanonly"`

	// References are the reports it covers, by the names they are reached
	// by. Read from the permanent record of what it covered, so a withdrawn
	// ruling still says what it was about.
	References []string `bun:"-"`
}

// Waiting reports whether it is waiting for a second person.
func (r *ReportRuling) Waiting() bool { return r.SettledAt == nil && r.WithdrawnAt == nil }

// InForce reports whether it is what its reports currently are.
func (r *ReportRuling) InForce() bool { return r.SettledAt != nil && r.WithdrawnAt == nil }

// reportRuled is the permanent record of which reports one ruling covered.
type reportRuled struct {
	bun.BaseModel `bun:"table:report_ruled,alias:rd"`

	RulingID     int64 `bun:"ruling_id,pk"`
	FlawReportID int64 `bun:"flaw_report_id,pk"`
}

// Ruled is a ruling as somebody submits it.
type Ruled struct {
	// References name the reports it covers. Naming one twice covers it once.
	References  []string
	Disposition Disposition
	Reasoning   string
	// DuplicateOf is the open issue a duplicate points at, already resolved
	// against what the proposer may be told of. Zero on every other
	// disposition.
	DuplicateOf int64
}

// The ways proposing, approving or withdrawing a ruling is refused.
var (
	ErrNotRulable = errors.New("a ruling says a report is a duplicate, not reproducible, " +
		"out of scope or rejected; one accepted as an issue is pointed at that issue")
	ErrNoReports   = errors.New("name the reports this rules on")
	ErrNoReasoning = errors.New("say why — a ruling nobody explained cannot be reviewed " +
		"or answered")
	ErrNoDuplicateTarget = errors.New("name the open issue it duplicates")
	ErrNotADuplicate     = errors.New("only a duplicate names an issue")
	// ErrDuplicateOfClosed is a duplicate of work that is no longer open. It
	// would bury the report, because nothing is left to work on.
	ErrDuplicateOfClosed = errors.New("that issue is closed, dismissed or suppressed at " +
		"every place here, so a duplicate of it leaves nothing to work on; reject it " +
		"instead, which a second person agrees to")
	ErrTooManyReports = errors.New("that would rule on more reports than one action may")
	ErrNoSuchRuling   = errors.New("no ruling here goes by that number")
	ErrOwnRuling      = errors.New("the person who proposed a ruling may not approve it")
	ErrNotWaiting     = errors.New("that ruling is not waiting for anybody")
	ErrWithdrawn      = errors.New("that ruling has already been withdrawn")
)

// NotHere is a ruling naming references this product does not hold, or holds
// where the proposer may not read them. It is ErrNoSuchReport, carrying which.
type NotHere struct {
	References []string
}

func (e *NotHere) Error() string {
	return ErrNoSuchReport.Error() + ": " + strings.Join(e.References, ", ")
}

// Is makes it ErrNoSuchReport to errors.Is.
func (e *NotHere) Is(target error) bool { return target == ErrNoSuchReport }

// Rule proposes a ruling on one or more reports.
//
// A disposition nobody else has to agree to takes effect at once. One that
// does waits, and its reports are held by it: nobody can accept them as an
// issue or rule on them again until it is approved or withdrawn.
//
// Bounded by the setting that bounds every bulk judgment, counted in reports
// written rather than names given.
func (s *Store) Rule(ctx context.Context, subject access.Subject, productID int64,
	in Ruled) (*ReportRuling, error) {

	if err := mayHandle(subject, productID); err != nil {
		return nil, err
	}
	if !in.Disposition.Rulable() {
		return nil, ErrNotRulable
	}
	reasoning := strings.TrimSpace(in.Reasoning)
	// A duplicate's reason is the issue it names. Every other disposition
	// sets a claim aside, and a reviewer or a reporter asking why is owed a
	// sentence.
	if reasoning == "" && in.Disposition != Duplicate {
		return nil, ErrNoReasoning
	}
	if reasoning != "" {
		if err := markdown.Check(reasoning); err != nil {
			return nil, err
		}
	}
	switch {
	case in.Disposition == Duplicate && in.DuplicateOf == 0:
		return nil, ErrNoDuplicateTarget
	case in.Disposition != Duplicate && in.DuplicateOf != 0:
		return nil, ErrNotADuplicate
	}
	named := distinctReferences(in.References)
	if len(named) == 0 {
		return nil, ErrNoReports
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	var ruling *ReportRuling
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		cap, err := setting.NewStore(tx).Count(ctx,
			setting.TogetherCap, setting.DefaultTogetherCap)
		if err != nil {
			return fmt.Errorf("read how much one action may write: %w", err)
		}
		// Each name resolves to at most one report, so more distinct names
		// than the cap is more reports than the cap or a name that is not
		// here — refused either way, and before a list of that length is
		// sent to the engine.
		if len(named) > cap {
			return fmt.Errorf("%w: it names %d and one action here writes %d",
				ErrTooManyReports, len(named), cap)
		}
		if in.Disposition == Duplicate {
			if err := openHere(ctx, tx, subject, productID, in.DuplicateOf); err != nil {
				return err
			}
		}

		var found []struct {
			ID        int64  `bun:"id"`
			Reference string `bun:"reference"`
		}
		if err := tx.NewSelect().Model((*FlawReport)(nil)).
			Column("fr.id", "fr.reference").
			Where("fr.product_id = ?", productID).
			Where("fr.reference IN (?)", bun.List(named)).
			Scan(ctx, &found); err != nil {
			return fmt.Errorf("read the reports named: %w", err)
		}
		ids := make([]int64, 0, len(found))
		here := map[string]bool{}
		for _, row := range found {
			ids = append(ids, row.ID)
			here[row.Reference] = true
		}
		// One answer for a name nobody minted and one in another product,
		// as reading a report gives. The caller typed every name, so saying
		// which stopped it tells them nothing they did not send.
		if len(ids) != len(named) {
			var missing []string
			for _, each := range named {
				if !here[each] {
					missing = append(missing, each)
				}
			}
			return &NotHere{References: missing}
		}

		// Built inside, because an insert writes the generated identifier
		// back into the model and a retry would re-insert a model already
		// carrying the rolled-back attempt's key.
		ruling = &ReportRuling{
			ProductID: productID, Disposition: in.Disposition, Reasoning: reasoning,
			ProposedBy: subject.ID, ProposedAt: now,
		}
		if in.DuplicateOf != 0 {
			target := in.DuplicateOf
			ruling.DuplicateOf = &target
		}
		if !in.Disposition.NeedsSecondPerson() {
			ruling.SettledAt = &now
		}
		if _, err := tx.NewInsert().Model(ruling).Exec(ctx); err != nil {
			return fmt.Errorf("record a ruling: %w", err)
		}

		update := tx.NewUpdate().Model((*FlawReport)(nil)).
			Set("ruling_id = ?", ruling.ID).
			Where("id IN (?)", bun.List(ids)).
			// Whether each is still unanswered is asked here, in the write,
			// so two people ruling at once cannot both succeed.
			Where("ruling_id IS NULL").
			Where("vulnerability_id IS NULL")
		if ruling.SettledAt != nil {
			update = update.Set("evaluated_at = ?", now).Set("evaluated_by = ?", subject.ID)
		}
		res, err := update.Exec(ctx)
		if err != nil {
			return fmt.Errorf("rule on those reports: %w", err)
		}
		changed, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("rule on those reports: %w", err)
		}
		if changed != int64(len(ids)) {
			var held []string
			if err := tx.NewSelect().Model((*FlawReport)(nil)).
				Column("fr.reference").
				Where("fr.id IN (?)", bun.List(ids)).
				Where("fr.ruling_id IS NULL OR fr.ruling_id <> ?", ruling.ID).
				OrderExpr("fr.reference").
				Scan(ctx, &held); err != nil {
				return fmt.Errorf("read which reports are already answered: %w", err)
			}
			return fmt.Errorf("%w: %s", ErrAlreadyJudged, strings.Join(held, ", "))
		}

		covered := make([]reportRuled, 0, len(ids))
		for _, id := range ids {
			covered = append(covered, reportRuled{RulingID: ruling.ID, FlawReportID: id})
		}
		if _, err := tx.NewInsert().Model(&covered).Exec(ctx); err != nil {
			return fmt.Errorf("record which reports a ruling covers: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Read back rather than returned as built, so it carries what the other
	// acts' answers carry: the product's name and the reports as stored.
	return s.RulingBy(ctx, subject, productID, ruling.ID)
}

// openHere refuses a duplicate target that is not an open issue this subject
// may be told of in this product.
//
// An issue that is not here and one the subject may not be told of answer
// alike, so the ruling cannot be used to ask which identifiers are open. One
// told of and closed everywhere here is the rule the answer is about.
func openHere(ctx context.Context, tx bun.IDB, subject access.Subject,
	productID, vulnerabilityID int64) error {

	told, err := MayBeToldOfWithin(ctx, tx, subject, productID, vulnerabilityID)
	if err != nil {
		return err
	}
	if !told {
		return ErrNoSuchIssueHere
	}
	// Open is work somebody still has in front of them: not closed, not
	// argued away by the build, and not dismissed by a decision in force at
	// that place. A dismissal and a suppression leave the row open and close
	// the question, so a duplicate of one sends the new claim somewhere
	// nobody is looking. A deferral or a promised upgrade leaves work that
	// comes back, so those count as open.
	standing, held := InForce()
	open, err := tx.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		ColumnExpr("f.id").
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where("st.product_id = ?", productID).
		Where("f.closed_at IS NULL").
		Where("f.suppressed_by IS NULL").
		Where(`NOT EXISTS (SELECT 1 FROM "decision" AS "de"
			JOIN "claim" AS "cl" ON cl.id = de.claim_id
			WHERE de.product_id = st.product_id
			  AND de.vulnerability_id = f.vulnerability_id
			  AND de.place_identity = f.place_identity
			  AND de.live_key IS NOT NULL
			  AND `+KeyMatches+`
			  AND `+standing+`
			  AND cl.outcome IN (?))`, append(held, bun.List(Dismissing))...).
		Exists(ctx)
	if err != nil {
		return fmt.Errorf("read whether that issue is open here: %w", err)
	}
	if !open {
		return ErrDuplicateOfClosed
	}
	return nil
}

// Dismissing is the outcomes that close the question at a place: it does not
// apply, the match is wrong, it will not be fixed, the fix is already here.
// The triage package owns the outcomes and a test there holds this list to
// its own.
var Dismissing = []string{"not-applicable", Mismatched, "wont-fix", "already-fixed"}

// distinctReferences folds and de-duplicates the names given, in a stable
// order.
func distinctReferences(typed []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(typed))
	for _, each := range typed {
		folded := foldReference(each)
		if folded == "" || seen[folded] {
			continue
		}
		seen[folded] = true
		out = append(out, folded)
	}
	sort.Strings(out)
	return out
}

// ApproveRuling records a second person agreeing to a waiting ruling, which
// is when it takes effect.
//
// The proposer may never approve, with no override — the rule a decision
// takes, for the same reason.
func (s *Store) ApproveRuling(ctx context.Context, subject access.Subject,
	productID, rulingID int64) (*ReportRuling, error) {

	// Somebody who may not read the product's reports is told there is no
	// such ruling, the answer a number nobody minted gets. Somebody who reads
	// them and may not agree is refused in words: they can list the ruling,
	// and "no such ruling" would contradict the read they just made.
	if err := mayReadReports(subject, productID); err != nil {
		return nil, ErrNoSuchRuling
	}
	if err := mayApproveRuling(subject, productID); err != nil {
		return nil, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		ruling, err := rulingIn(ctx, tx, productID, rulingID)
		if err != nil {
			return err
		}
		// Who proposed it never changes, so it is safe to ask of the read.
		// Whether it is still waiting is asked in the write.
		if ruling.ProposedBy == subject.ID {
			return ErrOwnRuling
		}
		res, err := tx.NewUpdate().Model((*ReportRuling)(nil)).
			Set("approved_by = ?", subject.ID).
			Set("approved_at = ?", now).
			Set("settled_at = ?", now).
			Where("id = ?", rulingID).
			Where("settled_at IS NULL").
			Where("withdrawn_at IS NULL").
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("approve a ruling: %w", err)
		}
		changed, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("approve a ruling: %w", err)
		}
		if changed == 0 {
			return ErrNotWaiting
		}
		// Who judged each claim is who proposed the ruling, and when they
		// did. Written now, so that a report waiting on a second person does
		// not read as judged.
		if _, err := tx.NewUpdate().Model((*FlawReport)(nil)).
			Set("evaluated_at = ?", ruling.ProposedAt).
			Set("evaluated_by = ?", ruling.ProposedBy).
			Where("ruling_id = ?", rulingID).
			Exec(ctx); err != nil {
			return fmt.Errorf("record who judged those reports: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.RulingBy(ctx, subject, productID, rulingID)
}

// WithdrawRuling takes a ruling back, waiting or in force, and returns its
// reports to the inbox.
//
// Needs nobody else. Returning a claim to the inbox re-exposes it rather than
// hiding it, and the proposer sending their own back and an approver sending
// it back are the same act.
func (s *Store) WithdrawRuling(ctx context.Context, subject access.Subject,
	productID, rulingID int64) (*ReportRuling, error) {

	if err := mayHandle(subject, productID); err != nil {
		return nil, ErrNoSuchRuling
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		// Read for whether it is here at all. Whether it is still standing
		// is asked in the write, so two people withdrawing at once cannot
		// both succeed.
		if _, err := rulingIn(ctx, tx, productID, rulingID); err != nil {
			return err
		}
		res, err := tx.NewUpdate().Model((*ReportRuling)(nil)).
			Set("withdrawn_by = ?", subject.ID).
			Set("withdrawn_at = ?", now).
			Where("id = ?", rulingID).
			Where("withdrawn_at IS NULL").
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("withdraw a ruling: %w", err)
		}
		changed, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("withdraw a ruling: %w", err)
		}
		if changed == 0 {
			return ErrWithdrawn
		}
		if _, err := tx.NewUpdate().Model((*FlawReport)(nil)).
			Set("ruling_id = NULL").
			Set("evaluated_at = NULL").
			Set("evaluated_by = NULL").
			Where("ruling_id = ?", rulingID).
			Exec(ctx); err != nil {
			return fmt.Errorf("return those reports to the inbox: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.RulingBy(ctx, subject, productID, rulingID)
}

// rulingIn reads one ruling in one product.
func rulingIn(ctx context.Context, db bun.IDB, productID, rulingID int64) (*ReportRuling, error) {
	ruling := new(ReportRuling)
	err := named(db.NewSelect().Model(ruling)).
		Where("rr.id = ?", rulingID).
		Where("rr.product_id = ?", productID).
		Scan(ctx)
	switch {
	case database.IsNoRows(err):
		return nil, ErrNoSuchRuling
	case err != nil:
		return nil, fmt.Errorf("read a ruling: %w", err)
	}
	return ruling, nil
}

// RulingBy reads one ruling with the reports it covered.
//
// A number nobody issued, one in another product and one the subject may not
// read answer alike.
func (s *Store) RulingBy(ctx context.Context, subject access.Subject,
	productID, rulingID int64) (*ReportRuling, error) {

	if err := mayReadReports(subject, productID); err != nil {
		return nil, ErrNoSuchRuling
	}
	ruling, err := rulingIn(ctx, s.db, productID, rulingID)
	if err != nil {
		return nil, err
	}
	if err := coveredBy(ctx, s.db, []*ReportRuling{ruling}); err != nil {
		return nil, err
	}
	return ruling, nil
}

// named selects a ruling with the name of its product.
func named(q *bun.SelectQuery) *bun.SelectQuery {
	return q.ColumnExpr("rr.*").
		ColumnExpr(`p.name AS "product"`).
		Join(`JOIN "product" AS "p" ON p.id = rr.product_id`)
}

// RulingsIn is one product's rulings, newest first, with how many there are.
// Waiting narrows to those waiting for a second person.
func (s *Store) RulingsIn(ctx context.Context, subject access.Subject, productID int64,
	waiting bool, limit, offset int) ([]ReportRuling, int, error) {

	if err := mayReadReports(subject, productID); err != nil {
		return nil, 0, err
	}
	return s.RulingsAcross(ctx, subject, RulingsAsked{
		ProductIDs: []int64{productID}, Waiting: waiting, Limit: limit, Offset: offset,
	})
}

// RulingsAsked narrows a list of rulings across products.
type RulingsAsked struct {
	// ProductIDs keeps these products. Empty is every product.
	ProductIDs []int64
	// Waiting keeps those waiting for a second person.
	Waiting bool
	// Since and Until keep those proposed in a period, Until exclusive.
	Since, Until *time.Time
	Limit        int
	Offset       int
}

// RulingsAcross is the rulings in every product this subject may work reports
// in, newest first, with how many there are.
//
// A product somebody may not work reports in contributes nothing, not even to
// the count: a ruling says what a stranger's claim is, and reading it reads
// the claim.
func (s *Store) RulingsAcross(ctx context.Context, subject access.Subject,
	asked RulingsAsked) ([]ReportRuling, int, error) {

	products := reportProducts(subject, asked.ProductIDs)
	if len(products) == 0 {
		return []ReportRuling{}, 0, nil
	}
	var rows []ReportRuling
	q := named(s.db.NewSelect().Model(&rows)).
		Where("rr.product_id IN (?)", bun.List(products))
	if asked.Waiting {
		q = q.Where("rr.settled_at IS NULL").Where("rr.withdrawn_at IS NULL")
	}
	if asked.Since != nil {
		q = q.Where("rr.proposed_at >= ?", *asked.Since)
	}
	if asked.Until != nil {
		q = q.Where("rr.proposed_at < ?", *asked.Until)
	}
	total, err := q.Order("rr.proposed_at DESC", "rr.id DESC").
		Limit(asked.Limit).Offset(asked.Offset).
		ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("read the rulings on reports: %w", err)
	}
	page := make([]*ReportRuling, 0, len(rows))
	for i := range rows {
		page = append(page, &rows[i])
	}
	if err := coveredBy(ctx, s.db, page); err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}

// reportProducts is the products this subject may read reports in, kept to
// those asked for where any were.
func reportProducts(subject access.Subject, asked []int64) []int64 {

	// The products read from, which include every product the subject reads
	// undisclosed work in. An estate-wide role is one grant per product by the
	// time it is asked here, and the one subject that reads every product
	// unnarrowed holds no role and reads no undisclosed work by it.
	candidates, _ := subject.Products()
	if len(asked) > 0 {
		candidates = asked
	}
	out := make([]int64, 0, len(candidates))
	for _, id := range candidates {
		if subject.Reads(access.Private, id) {
			out = append(out, id)
		}
	}
	return out
}

// coveredBy fills in the references each ruling covered, in one read.
func coveredBy(ctx context.Context, db bun.IDB, rulings []*ReportRuling) error {
	if len(rulings) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(rulings))
	for _, r := range rulings {
		ids = append(ids, r.ID)
	}
	var rows []struct {
		RulingID  int64  `bun:"ruling_id"`
		Reference string `bun:"reference"`
	}
	if err := db.NewSelect().
		TableExpr(`"report_ruled" AS "rd"`).
		Join(`JOIN "flaw_report" AS "fr" ON fr.id = rd.flaw_report_id`).
		ColumnExpr(`rd.ruling_id AS "ruling_id"`).
		ColumnExpr(`fr.reference AS "reference"`).
		Where("rd.ruling_id IN (?)", bun.List(ids)).
		OrderExpr("fr.reference").
		Scan(ctx, &rows); err != nil {
		return fmt.Errorf("read which reports a ruling covers: %w", err)
	}
	byID := map[int64]*ReportRuling{}
	for _, r := range rulings {
		r.References = []string{}
		byID[r.ID] = r
	}
	for _, row := range rows {
		byID[row.RulingID].References = append(byID[row.RulingID].References, row.Reference)
	}
	return nil
}

// RulingsOf reads the live ruling of each report that has one, keyed by the
// ruling's identifier.
//
// The reports were read under their own authorization, and a ruling is read
// by the same people in the same product, so nothing narrows again here.
func (s *Store) RulingsOf(ctx context.Context, reports []FlawReport) (map[int64]ReportRuling, error) {
	ids := make([]int64, 0, len(reports))
	for _, r := range reports {
		if r.RulingID != nil {
			ids = append(ids, *r.RulingID)
		}
	}
	out := map[int64]ReportRuling{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []ReportRuling
	if err := s.db.NewSelect().Model(&rows).
		Where("rr.id IN (?)", bun.List(ids)).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what those reports were ruled: %w", err)
	}
	for _, row := range rows {
		out[row.ID] = row
	}
	return out, nil
}

// DuplicatesOf is every report in this product ruled a duplicate of one
// issue.
//
// Joined through the report's live pointer, which a withdrawal clears, and a
// duplicate takes effect when it is made — so every row the join reaches is
// in force without asking.
//
// A duplicate carries what arrived with it — a screenshot that makes the
// issue clearer — so the issue is where somebody triaging it finds it. Read
// under the rule every report is read under, which is the right to triage
// undisclosed work in the product: the issue being readable says nothing
// about whether what a stranger sent is.
func (s *Store) DuplicatesOf(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64) ([]FlawReport, error) {

	if err := mayReadReports(subject, productID); err != nil {
		return nil, err
	}
	var rows []FlawReport
	if err := s.db.NewSelect().Model(&rows).
		Join(`JOIN "report_ruling" AS "rr" ON rr.id = fr.ruling_id`).
		Where("fr.product_id = ?", productID).
		Where("rr.disposition = ?", Duplicate).
		Where("rr.duplicate_of = ?", vulnerabilityID).
		Order("fr.recorded_at DESC", "fr.id DESC").
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the duplicates of an issue: %w", err)
	}
	return rows, nil
}
