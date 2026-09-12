// Package saved is a narrowing of a list that somebody kept, and the claim it
// prepares.
//
// **Not access.** It lived there because a saved filter hangs off a person,
// which is the wrong reason: `access` decides who may do what, and a personal
// narrowing is neither a grant nor a check. What it cost was that the triage
// vocabulary — an outcome, a justification, reasoning, how long a deferral —
// was defined a second time inside the package about permissions, which is the
// last place somebody looks for it.
package saved

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Filter is a narrowing of a list that somebody kept.
//
// Personal, and nothing is shared: no ownership, no permissions, and no
// arguing about whose filter is authoritative — which is also what lets
// somebody keep one that is half-formed.
type Filter struct {
	bun.BaseModel `bun:"table:saved_filter,alias:sf"`

	ID       int64 `bun:"id,pk,autoincrement"`
	PersonID int64 `bun:"person_id,notnull"`
	// ProductID is whose list it narrows. A filter's query names branches and
	// variants, which belong to one product and usually exist in no other, so
	// a filter offered everywhere is offered where it matches nothing.
	ProductID int64 `bun:"product_id,notnull"`
	// Name is what is matched, stored normalized, and DisplayName is the
	// spelling they used, which is what is shown back.
	Name        string `bun:"name,notnull"`
	DisplayName string `bun:"display_name"`
	// Query is the list's own query string, without a leading "?". Kept as
	// text rather than as a column per filter: the filters belong to the list
	// and they move, and a second place deciding what one means is a second
	// place to be wrong.
	Query     string    `bun:"query,notnull"`
	CreatedAt time.Time `bun:"created_at,notnull"`

	// Outcome, Justification, Reasoning and DeferDays are what this filter
	// prepares, all absent on an ordinary saved filter — which is most of
	// them. **A rule prepares a claim; a person proposes it**: what is
	// kept here is offered prefilled, and a named person submits it as
	// their own for a second person to approve.
	//
	// The wider form — a rule proposing its own pending claim — was argued
	// for and refused: it leaves the approver as the only human judgment
	// on the claim, which is what making the claim the approver's unit was
	// meant to prevent, and it puts a configuration file where a name
	// belongs in the record.
	Outcome       string `bun:"outcome"`
	Justification string `bun:"justification"`
	Reasoning     string `bun:"reasoning"`
	// DeferDays is how long a deferral it prepares, from whenever somebody
	// submits it. A date would be wrong the week after it was saved: what a
	// rule means is "put this off for a quarter", not "until 3 March".
	DeferDays int `bun:"defer_days"`
}

// Prepares reports whether this filter carries a claim to prefill.
func (f Filter) Prepares() bool { return strings.TrimSpace(f.Outcome) != "" }

// Called is the spelling to show, which is the one they typed where there is
// one.
func (f Filter) Called() string {
	if f.DisplayName != "" {
		return f.DisplayName
	}
	return f.Name
}

// Store keeps and reads what people have saved.
type Store struct {
	db  bun.IDB
	now func() time.Time
}

// NewStore returns a store over db.
func NewStore(db bun.IDB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// ErrNoSuchFilter is returned when somebody has kept no filter by that name.
var ErrNoSuchFilter = errors.New("you have kept no filter by that name")

// SaveFilterPreparing keeps a narrowing under a name, replacing one of the
// same name, along with what the filter prepares.
//
// Replacing rather than refusing: the act is "let this be what I mean by
// overdue kernel", and answering "you already have one of those" makes
// somebody delete before they can correct.
//
// **The reasoning is required where an outcome is.** What is being saved is
// what somebody will put their name to, and a prefill with an empty argument
// is a button that proposes a dismissal saying nothing. The person who submits
// it owns it, which is the whole of why the narrow form was chosen.
//
// **A deferral carries how long it defers for, never a date.** The date is
// worked out from the length whenever somebody submits it, so a rule saved in
// March means "put this off for a quarter" rather than "until 3 March".
func (s *Store) SaveFilterPreparing(ctx context.Context, personID, productID int64,
	name, query string, prepares Filter) (*Filter, error) {

	matched := strings.ToLower(strings.TrimSpace(name))
	if matched == "" {
		return nil, fmt.Errorf("a saved filter needs a name")
	}
	prepares.Outcome = strings.TrimSpace(prepares.Outcome)
	prepares.Justification = strings.TrimSpace(prepares.Justification)
	prepares.Reasoning = strings.TrimSpace(prepares.Reasoning)
	if prepares.Prepares() && prepares.Reasoning == "" {
		return nil, fmt.Errorf("a filter that prepares a claim has to carry the reasoning " +
			"somebody will be proposing, because they are the one putting their name to it")
	}
	// The length is required where the outcome is a deferral, and dropped
	// where it is not. The form works the date out from the length whenever
	// somebody submits it, so a deferral prepared without one opens with the
	// outcome chosen and no date, which cannot be submitted; a length beside
	// any other outcome is a number nothing reads.
	if prepares.Outcome == string(triage.Deferred) && prepares.DeferDays <= 0 {
		return nil, fmt.Errorf("a filter that prepares a deferral has to carry how long it " +
			"defers for, because the date is worked out from it whenever somebody submits it")
	}
	if prepares.Outcome != string(triage.Deferred) {
		prepares.DeferDays = 0
	}
	if !prepares.Prepares() {
		// Nothing prepared is nothing carried. Keeping a justification or a
		// deferral beside no outcome would be a prefill that half-fires.
		prepares = Filter{}
	}
	kept := &Filter{
		PersonID: personID, ProductID: productID,
		Name: matched, DisplayName: strings.TrimSpace(name),
		Query:     strings.TrimPrefix(strings.TrimSpace(query), "?"),
		CreatedAt: s.now().Truncate(time.Microsecond),
		Outcome:   prepares.Outcome, Justification: prepares.Justification,
		Reasoning: prepares.Reasoning, DeferDays: prepares.DeferDays,
	}

	// An update then an insert, in one transaction, because there is no
	// portable spelling of an upsert and because what the insert writes
	// against has to be what the update just saw.
	write := func(ctx context.Context, db bun.IDB) error {
		res, err := db.NewUpdate().Model((*Filter)(nil)).
			Set("query = ?", kept.Query).
			Set("display_name = ?", kept.DisplayName).
			// What it prepares is replaced too, including with nothing: saving
			// over a name is deciding what that name means now, and a prefill
			// that survived being taken off would fire on a filter somebody
			// thought they had made ordinary.
			Set("outcome = ?", kept.Outcome).
			Set("justification = ?", kept.Justification).
			Set("reasoning = ?", kept.Reasoning).
			Set("defer_days = ?", kept.DeferDays).
			Where("person_id = ?", personID).Where("product_id = ?", productID).
			Where("name = ?", matched).
			Exec(ctx)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			return db.NewSelect().Model(kept).
				Where("person_id = ?", personID).Where("product_id = ?", productID).
				Where("name = ?", matched).
				Limit(1).Scan(ctx)
		}
		_, err = db.NewInsert().Model(kept).Exec(ctx)
		return err
	}
	db, ok := s.db.(*bun.DB)
	var err error
	if ok {
		err = database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
			return write(ctx, tx)
		})
	} else {
		err = write(ctx, s.db)
	}
	if err != nil {
		return nil, fmt.Errorf("keep that filter: %w", err)
	}
	return kept, nil
}

// SavedFilters lists what one person has kept for one product, by name.
//
// Narrowed by product as well as by person. A filter is a narrowing of one
// product's findings list and its query names branches and variants that
// usually exist in no other, so offering it elsewhere offers something that
// matches nothing and says nothing about why — and picking it replaces what is
// on screen with a narrowing built for somewhere else.
func (s *Store) SavedFilters(ctx context.Context, personID, productID int64) ([]Filter, error) {
	var kept []Filter
	if err := s.db.NewSelect().Model(&kept).
		Where("person_id = ?", personID).
		Where("product_id = ?", productID).
		Order("name").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what you have kept: %w", err)
	}
	return kept, nil
}

// ForgetFilter drops one of somebody's own.
//
// Narrowed by the person as well as by the name, so that an identifier is not
// a way to reach somebody else's — the filters are personal, and personal has
// to mean it at the query rather than only on the screen.
func (s *Store) ForgetFilter(ctx context.Context, personID, productID int64, name string) error {
	res, err := s.db.NewDelete().Model((*Filter)(nil)).
		Where("person_id = ?", personID).
		Where("product_id = ?", productID).
		Where("name = ?", strings.ToLower(strings.TrimSpace(name))).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("forget that filter: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoSuchFilter
	}
	return nil
}
