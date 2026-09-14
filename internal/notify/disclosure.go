package notify

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// The conditions about findings rather than about the tool.
//
// These three differ from the operational conditions beside them in every way
// that matters to the code: they go to a person rather than to whoever
// administers the deployment, the row they are about can be undisclosed, and
// each is narrowed by what its recipient may read. The sweep that runs them
// and the conditions about the tool's own health stay in watch.go.

// pastDisclosure is every embargo whose date has arrived with nothing decided,
// against the people who should hear about it.
//
// **Administrators, and whoever holds it**. Nobody else: every one of
// these is a finding nobody has announced, so the alert is a disclosure in its
// own right, and the person holding it is told only where they may read
// undisclosed work in that product — an assignment that outlived the role that
// allowed it would otherwise deliver the thing the role was withdrawn to stop.
//
// It is derived rather than remembered, so an embargo somebody extends leaves
// this list on the next sweep without anybody dismissing anything, and one
// that is disclosed leaves it because the finding stops being private.
func (w *Watch) pastDisclosure(ctx context.Context, admins []int64) (map[int64][]Holds, error) {
	return w.disclosureWithin(ctx, admins, 0)
}

// approachingDisclosure is every embargo whose date falls inside the lead time
// somebody set.
//
// **Before the date, not on it.** The date arriving is the last moment to act
// rather than the first useful warning, and an approver who touches disclosure
// a few times a year has no reason to open the screen that would have told
// them. In the application rather than by mail, because mail may not name an
// undisclosed issue.
func (w *Watch) approachingDisclosure(ctx context.Context, admins []int64) (map[int64][]Holds, error) {
	lead, err := setting.NewStore(w.db).Duration(ctx, setting.DisclosureLead,
		setting.DefaultDisclosureLead)
	if err != nil {
		return nil, fmt.Errorf("read how much warning to give: %w", err)
	}
	if lead <= 0 {
		lead = setting.DefaultDisclosureLead
	}
	return w.disclosureWithin(ctx, admins, lead)
}

// statementsRevised is every standing decision whose cited VEX statement has
// since been set aside.
//
// **The decision stands.** A publisher changing their mind does not withdraw
// somebody's judgment — a third party's claim never becomes ours — so this is
// a condition saying the ground moved under it, not an act on the decision.
//
// It clears the way every other condition here clears: when the decision stops
// standing, or when the statement it cites is current again. Nothing is
// dismissed, because nothing here is an event.
func (w *Watch) statementsRevised(ctx context.Context) (map[int64][]Holds, error) {
	var rows []struct {
		DecisionID      int64  `bun:"decision_id"`
		ProductID       int64  `bun:"product_id"`
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Product         string `bun:"product"`
		Vulnerability   string `bun:"vulnerability"`
		Publisher       string `bun:"publisher"`
		Visibility      string `bun:"visibility"`
	}
	err := w.db.NewSelect().
		TableExpr(`decision AS "de"`).
		Join(`JOIN vex_statement AS "ss" ON ss.id = de.from_statement_id`).
		Join(`JOIN product AS "p" ON p.id = de.product_id`).
		Join(`JOIN vulnerability AS "v" ON v.id = de.vulnerability_id`).
		ColumnExpr(`MIN(de.id) AS "decision_id"`).
		ColumnExpr(`de.product_id AS "product_id"`).
		ColumnExpr(`de.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`MIN(p.name) AS "product"`).
		ColumnExpr(`MIN(v.identifier) AS "vulnerability"`).
		ColumnExpr(`MIN(ss.publisher) AS "publisher"`).
		ColumnExpr(`MIN(de.visibility) AS "visibility"`).
		// Standing, because a decision nobody is relying on any more is not
		// one whose evidence moving matters.
		Where("de.live_key IS NOT NULL").
		Where("de.state = ?", triage.Approved).
		// And the statement it cited is no longer what that publisher says.
		Where("ss.superseded_at IS NOT NULL").
		GroupExpr("de.product_id, de.vulnerability_id, de.from_statement_id").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read where a publisher changed their mind: %w", err)
	}

	// Whoever may read it and act on it, which for a claim somebody approved
	// is whoever may triage that product.
	acts, err := w.whoActs(ctx)
	if err != nil {
		return nil, err
	}

	out := map[int64][]Holds{}
	told, err := w.beingTold(ctx, StatementRevised)
	if err != nil {
		return nil, err
	}
	for _, person := range told {
		out[person] = nil
	}
	for personID := range acts {
		if _, already := out[personID]; !already {
			out[personID] = nil
		}
	}

	for _, row := range rows {
		private := row.Visibility == string(access.Private)
		holds := Holds{
			About: identify(fmt.Sprintf("statement-revised %d %s %s",
				row.ProductID, row.Vulnerability, row.Publisher)),
			Body: fmt.Sprintf("%s has changed what they published about %s in %s, "+
				"and a standing decision was made after reading the old statement. "+
				"The decision stands; somebody should look.",
				row.Publisher, row.Vulnerability, row.Product),
			Link:            fmt.Sprintf("/decisions/%d", row.DecisionID),
			Private:         private,
			ProductID:       &row.ProductID,
			VulnerabilityID: &row.VulnerabilityID,
		}
		for personID, per := range acts {
			if !per[row.ProductID].triages(private) {
				continue
			}
			out[personID] = append(out[personID], holds)
		}
	}
	return out, nil
}

// disclosureWithin is every undisclosed finding whose date has arrived, or —
// where a lead time is given — is about to.
func (w *Watch) disclosureWithin(ctx context.Context, admins []int64,
	lead time.Duration) (map[int64][]Holds, error) {

	var rows []struct {
		Product         string    `bun:"product"`
		Stream          string    `bun:"stream"`
		Variant         string    `bun:"variant"`
		Component       string    `bun:"component"`
		Vulnerability   string    `bun:"vulnerability"`
		ProductID       int64     `bun:"product_id"`
		VulnerabilityID int64     `bun:"vulnerability_id"`
		DiscloseAt      time.Time `bun:"disclose_at"`
		AssignedTo      *int64    `bun:"assigned_to"`
	}
	err := findingsWith(w.db.NewSelect(), false).
		ColumnExpr(`MIN(f.disclose_at) AS "disclose_at"`).
		ColumnExpr(`MIN(f.assigned_to) AS "assigned_to"`).
		Where("f.visibility = ?", access.Private).
		Where("f.closed_at IS NULL").
		Where("f.disclose_at IS NOT NULL").
		Where("f.disclose_at <= ?", time.Now().UTC().Add(lead)).
		// Where a lead time is given this is the *coming* ones only: what has
		// already arrived is the other condition, and one row raising both
		// would be told twice about one thing.
		Where(func() string {
			if lead > 0 {
				return "f.disclose_at > ?"
			}
			return "f.disclose_at <= ?"
		}(), time.Now().UTC()).
		GroupExpr("p.name, st.name, va.name, c.name, v.identifier, st.product_id, v.id").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what is past its disclosure date: %w", err)
	}
	// Note there is no early return for an empty answer. Every administrator
	// has to be handed a list either way, empty included: Reconcile makes
	// somebody's open set exactly what it is given, so an embargo that was
	// extended clears the alert it opened only because the next sweep hands
	// the same person a list without it. Returning nothing at all would leave
	// every cleared condition standing.
	people, held, err := access.NewStore(w.db).People(ctx)
	if err != nil {
		return nil, fmt.Errorf("read who may hear about this: %w", err)
	}
	private := map[int64]map[int64]bool{}
	// Who a party is. The assignment column holds a party rather than a
	// person , and a notification goes to somebody, so the two are mapped
	// in one place rather than at each use.
	whose := make(map[int64]int64, len(people))
	for _, person := range people {
		reaches := map[int64]bool{}
		for _, grant := range held[person.ID] {
			if grant.Active && (grant.Role == access.PrivateRead || grant.Role == access.PrivateTriage) {
				reaches[grant.ProductID] = true
			}
		}
		private[person.ID] = reaches
		whose[person.PartyID] = person.ID
	}

	out := make(map[int64][]Holds, len(admins)+len(rows))
	for _, admin := range admins {
		out[admin] = nil
	}
	// And everybody who is currently being told one of these, whether or not
	// they should still hear about anything. Reconcile makes one person's open
	// set exactly what it is handed, so somebody who is never handed a list is
	// never reconciled — and their alert stands after the thing it was about
	// has been answered.
	//
	// This does not arise for the conditions that only ever go to
	// administrators, because that set does not move. It arises here because
	// who hears about an embargo includes whoever holds it, and work is handed
	// around: the person who held it yesterday would keep an alert about a
	// date that has since been moved, with nothing left to clear it.
	told, err := w.beingTold(ctx, DisclosureDue)
	if err != nil {
		return nil, err
	}
	for _, person := range told {
		if _, already := out[person]; !already {
			out[person] = nil
		}
	}
	for _, row := range rows {
		where := row.Product + " " + row.Stream + " " + row.Variant + " " + row.Vulnerability
		// Two conditions, two identities: an embargo that is coming and one
		// that has arrived clear differently, and a single alert would go on
		// saying "coming" after the date had passed.
		about, body := "disclosure "+where,
			row.Vulnerability+" in "+row.Product+" reached its disclosure date on "+
				row.DiscloseAt.Format(time.DateOnly)+" and nothing has been decided."
		if lead > 0 {
			about = "disclosure-near " + where
			body = row.Vulnerability + " in " + row.Product + " discloses on " +
				row.DiscloseAt.Format(time.DateOnly) +
				" and nothing has been decided. Extending it needs a second person, " +
				"and that takes time to arrange."
		}
		holds := Holds{
			About: identify(about),
			Body:  body,
			Link: "/products/" + url.PathEscape(row.Product) +
				"/streams/" + url.PathEscape(row.Stream) +
				"/variants/" + url.PathEscape(row.Variant) +
				"/findings/" + url.PathEscape(row.Vulnerability) +
				"/components/" + url.PathEscape(row.Component),
			// Every one of these is about a finding nobody has
			// announced — that is what an embargo is — so what
			// leaves this deployment about it is a link and
			// nothing else.
			Private:         true,
			ProductID:       &row.ProductID,
			VulnerabilityID: &row.VulnerabilityID,
		}
		for _, admin := range admins {
			out[admin] = append(out[admin], holds)
		}
		// And whoever holds it, where they may still read undisclosed work
		// here and are not already being told as an administrator.
		if row.AssignedTo == nil {
			continue
		}
		owner, isPerson := whose[*row.AssignedTo]
		if !isPerson {
			// A party that is not a person: a team's queue, which is nobody's
			// to be told about individually.
			continue
		}
		if _, already := out[owner]; already && contains(out[owner], holds.About) {
			continue
		}
		if !private[owner][row.ProductID] {
			continue
		}
		out[owner] = append(out[owner], holds)
	}
	return out, nil
}

// contains says a person is already being told about this one.
func contains(holding []Holds, about string) bool {
	for _, h := range holding {
		if h.About == about {
			return true
		}
	}
	return false
}
