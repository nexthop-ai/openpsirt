// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// The upstream version a decision is keyed on, as SQL, so that everything
// asking the question asks it the same way.
//
// The stated upstream version where there is one, and the component's own
// where there is not. Most packages are not forks and state no upstream at all
// — measured on a real image, 88% of them — so reading only the stated one
// leaves the version half of the key empty for almost everything, and a key
// that never changes is a decision that never lapses.
//
// Exported because a decision is written against these versions in one place
// and compared against them in another. Two spellings of the same expression
// is how a decision starts lapsing on one path and standing on the other.
const (
	ComponentUpstreamExpr = "COALESCE(NULLIF(c.upstream_version, ''), c.version, '')"
	ConsumerUpstreamExpr  = "COALESCE(NULLIF(uc.upstream_version, ''), uc.version, '')"
)

// Deciding carries everything a decision needs about where it is being
// made, read from the findings rather than from whoever is making it.
//
// A caller naming a place freely would be choosing which decisions apply
// where, and the versions are what expiry compares — so they come from the
// rows. What a person supplies is which finding they are looking at.
type Deciding struct {
	ProductID       int64
	VulnerabilityID int64
	PlaceIdentity   string
	Visibility      access.Visibility
	// The upstream versions, which are what a decision is keyed on. A shipped
	// version moves whenever something is rebuilt, and a rebuild is not
	// somebody's reasoning becoming wrong.
	ComponentUpstream string
	ConsumerUpstream  string
	// SeverityCenti is how bad this is judged to be now, recorded with the
	// claim so a later re-affirmation can ask whether it has risen since.
	SeverityCenti int
	// DueAt is this place's deadline, where it has one. Carried because a
	// promise to act is gated against the earliest deadline among what the
	// act covers, and that is a fact about the set being resolved rather
	// than one the caller can supply.
	DueAt *time.Time
	// FixedIn is the version the report says this was fixed in, where it says
	// one. Somebody deciding to defer should see whether there is anywhere to
	// go, and somebody claiming a whole component is unreachable should see
	// which of it is already fixable.
	FixedIn string
	// Summary, Exploited and LikelihoodPPM are what the issue is and how
	// likely it is to be used, for somebody judging many issues at once.
	// Deciding in bulk on less evidence than deciding singly is the wrong way
	// round: the bulk screen narrows *by* the description and showed neither
	// it, nor the exploited flag, nor the estimate.
	Summary       string
	Exploited     bool
	LikelihoodPPM int
	// ExploitedHere is this product's own standing record of being attacked
	// through the issue. A bulk act that sets such an issue aside is refused,
	// so the screen building one says which they are before it is sent.
	ExploitedHere bool
	// Consumer is what pulls the component in here, for naming the place to
	// somebody choosing which of them a judgment covers. Empty where that is
	// the product itself.
	Consumer string
	// distinctVersions is how many versions of this component sit at this
	// place. More than one means a decision cannot cover all of them.
	distinctVersions int
	// Places is how many findings this decision would cover. One judgment
	// about one issue in one component applies everywhere that pair sits, and
	// somebody deciding should know whether that is one place or sixty.
	Places int
	// OnTag says this sits in a release that was built once and cannot change.
	//
	// A tag is what somebody received. Nothing about it will be different
	// tomorrow, so an outcome that promises to act by a date is a promise
	// about a thing that cannot move — and a deadline on it is one that was
	// unmeetable the moment it was written.
	OnTag bool
}

// PlaceFor resolves what somebody is deciding about.
//
// Authorized here, not by the caller: reaching a finding is what makes it
// yours to argue about, so a place is only returned where the subject can see
// findings of that visibility on that product.
func (s *Store) PlaceFor(ctx context.Context, subject access.Subject, targetID int64, vulnerabilityID int64, placeIdentity string) (*Deciding, error) {
	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	// Asked about the issue rather than about the product, because
	// reaching a finding is what makes it yours to argue about — and a
	// collaborator was given exactly one issue to reach.
	if !access.SeesOn(subject, productID, vulnerabilityID) {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	visible := access.VisibleOn(subject, productID, vulnerabilityID)
	if len(visible) == 0 {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}

	var rows []placeRow
	err = placeColumns(s.db.NewSelect().TableExpr(`"finding" AS "f"`), productID).
		Where("f.target_id = ?", targetID).
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where("f.place_identity = ?", placeIdentity).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		OrderExpr("component_upstream, consumer_upstream").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what is open at that place: %w", err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no open finding is recorded there")
	}

	// A place is a pair of names, so one place can hold the same package at
	// two versions — a build shipping both is unusual and not impossible. The
	// rows are ordered so that which version a decision is keyed on is the
	// same on every engine and every run, rather than whichever the database
	// happened to return first.
	return &Deciding{
		ProductID: productID, VulnerabilityID: vulnerabilityID, PlaceIdentity: placeIdentity,
		Visibility:        access.AsVisibility(rows[0].Visibility),
		ComponentUpstream: rows[0].ComponentUpstream,
		ConsumerUpstream:  rows[0].ConsumerUpstream,
		SeverityCenti:     rows[0].score(),
		DueAt:             earliestDue(rows),
		OnTag:             rows[0].OnTag == 1,
		Places:            len(rows),
		distinctVersions:  distinctVersions(rows),
	}, nil
}

// earliestDue is the deadline a place is gated against: the earliest among the
// findings sitting there, and nil where none of them has one.
//
// The earliest rather than the first row's, for the reason one act covering a
// critical and a medium is gated by the critical — a place holding the same
// package under two consumers is one thing to decide about, and the strictest
// deadline among them is what the decision is measured against.
func earliestDue(rows []placeRow) *time.Time {
	var earliest *time.Time
	for _, row := range rows {
		if row.DueAt == nil {
			continue
		}
		if earliest == nil || row.DueAt.Before(*earliest) {
			at := *row.DueAt
			earliest = &at
		}
	}
	return earliest
}

// At names one place a decision was made about, for asking what is open there
// now.
type At struct {
	VulnerabilityID int64
	PlaceIdentity   string
}

// DeadlineAt is the earliest deadline among the open findings at these places,
// in these builds.
//
// The gate a promise already recorded is measured against, asked again rather
// than remembered: the deadline moves when the policy or the rating moves, so
// a promise being edited is gated against the deadline in force now and not
// the one in force when it was first made.
//
// Narrowed by what the subject may see, like every other read here, and taking
// a handle because the caller opens the transaction: resolved beforehand, a
// retry recomputes a gate from findings somebody closed in between.
func (s *Store) DeadlineAt(ctx context.Context, db bun.IDB, subject access.Subject,
	productID int64, targets []int64, places []At) (*time.Time, error) {

	if !subject.Sees(productID) {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	visible := access.Visible(subject, productID)
	if len(visible) == 0 {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	if len(targets) == 0 || len(places) == 0 {
		return nil, nil
	}

	// The pair of lists matches more combinations than were asked for, so what
	// was not asked for is dropped after the read. Naming each pair in the
	// statement would be one OR group per place, and a claim reaches as many
	// places as the issue sits at.
	issues := make([]int64, 0, len(places))
	identities := make([]string, 0, len(places))
	wanted := make(map[At]bool, len(places))
	for _, place := range places {
		if wanted[place] {
			continue
		}
		wanted[place] = true
		issues = append(issues, place.VulnerabilityID)
		identities = append(identities, place.PlaceIdentity)
	}

	var rows []struct {
		VulnerabilityID int64      `bun:"vulnerability_id"`
		PlaceIdentity   string     `bun:"place_identity"`
		DueAt           *time.Time `bun:"due_at"`
	}
	if err := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.place_identity AS "place_identity"`).
		ColumnExpr(`MIN(f.due_at) AS "due_at"`).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.vulnerability_id IN (?)", bun.List(issues)).
		Where("f.place_identity IN (?)", bun.List(identities)).
		Where("f.closed_at IS NULL").
		Where("f.due_at IS NOT NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr("f.vulnerability_id, f.place_identity").
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the deadline this covers: %w", err)
	}

	var earliest *time.Time
	for _, row := range rows {
		if row.DueAt == nil || !wanted[At{row.VulnerabilityID, row.PlaceIdentity}] {
			continue
		}
		if earliest == nil || row.DueAt.Before(*earliest) {
			at := *row.DueAt
			earliest = &at
		}
	}
	return earliest, nil
}

// score is how bad this place's issue is judged to be now, by the one rule for
// the number: the rating somebody made here where there is one, the published
// score where there is not, and the published word scored where there is
// neither.
func (r placeRow) score() int {
	return Rating{
		Published: r.Published, Assessed: r.Assessed, ScoreCenti: r.ScoreCenti,
	}.Score()
}

// placeRow is one open finding at the place being decided about.
type placeRow struct {
	Visibility        string     `bun:"visibility"`
	DueAt             *time.Time `bun:"due_at"`
	ComponentUpstream string     `bun:"component_upstream"`
	ConsumerUpstream  string     `bun:"consumer_upstream"`
	Published         string     `bun:"published_severity"`
	// Assessed is what this place's own product rates the issue, empty where
	// it rates it nothing. Another product's rating is not read here: the
	// judgment being made is this product's.
	Assessed   string `bun:"rated_here"`
	ScoreCenti int    `bun:"score_centi"`
	// OnTag as an integer rather than a boolean: the four engines spell a
	// boolean three ways, and a CASE returning 1 or 0 reads the same on all of
	// them.
	OnTag int `bun:"on_tag"`
}

// Versions reports how many distinct versions this place holds.
//
// One is the ordinary answer. More than one means a build ships the same
// package twice at different versions under the same consumer, and a single
// decision cannot honestly cover both — so whoever is deciding is told rather
// than being given a judgment about one version silently applied to another.
func (d Deciding) Versions() int { return d.distinctVersions }

// distinctVersions counts the version pairs a place holds.
func distinctVersions(rows []placeRow) int {
	seen := map[[2]string]bool{}
	for _, row := range rows {
		seen[[2]string{row.ComponentUpstream, row.ConsumerUpstream}] = true
	}
	return len(seen)
}

// InBundle is one component of a fix bundle, with the places the bundle
// reaches in it.
//
// Grouped by component and issue because that is the grain a decision and a
// fix target are both keyed on: a bundle spanning two binary packages of one
// source is two of these, and one act covers both.
type InBundle struct {
	VulnerabilityID int64
	ComponentID     int64
	TargetID        int64
	Places          []Deciding
}

// PlacesOnComponentWithin is everywhere a component is open, across a
// product's builds, read through a handle the caller chooses.
//
// The read half of planning an upgrade. Coverage is the component rather than
// a version pair, because an upgrade is a claim that moving the package
// answers what is open on it — and deciding that 3.5.2 also covers something
// fixed in 3.5.0 would need an ordering per ecosystem this does not have. A
// person claims it, and the next scan says which of it was true.
//
// Narrowed by what the subject may see, like every other read here. A place
// they cannot see is not one they can declare a bump for.
//
// It takes the handle because the caller opens the transaction itself and
// resolves the places it writes about from inside it: resolved beforehand, a
// retry can propose about a finding somebody closed in between.
func (s *Store) PlacesOnComponentWithin(ctx context.Context, db bun.IDB,
	subject access.Subject, productID int64, targets []int64,
	component string) ([]InBundle, error) {

	if !subject.Sees(productID) {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	visible := access.Visible(subject, productID)
	if len(visible) == 0 || len(targets) == 0 {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}

	var rows []struct {
		placeRow
		VulnerabilityID int64  `bun:"vulnerability_id"`
		ComponentID     int64  `bun:"component_id"`
		TargetID        int64  `bun:"target_id"`
		PlaceIdentity   string `bun:"place_identity"`
		Consumer        string `bun:"consumer"`
		FixedIn         string `bun:"fixed_in"`
	}
	query := placeColumns(db.NewSelect().TableExpr(`"finding" AS "f"`), productID).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		ColumnExpr(`f.target_id AS "target_id"`).
		ColumnExpr(`f.place_identity AS "place_identity"`).
		ColumnExpr(`COALESCE(uc.name, '') AS "consumer"`).
		ColumnExpr(`COALESCE(f.fixed_in, '') AS "fixed_in"`).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		// Everything open against the package, whatever version each
		// finding records as its fix. An upgrade is a claim that
		// moving the package answers what is open on it, and the next
		// scan is what decides whether it did — so this does not
		// filter on the fix version, which would need the ordering
		// nothing here has and would leave out everything fixed in an
		// earlier release of the same line.
		//
		// Matched on the fold, which is the reason the bundle view
		// existed: curl, libcurl4t64 and libcurl3t64 are one source package
		// bumping once, and keying on the binary name would make upgrading
		// them three acts that can disagree. Naming any of the three reaches
		// all of them, and the act says which it covered — while one source
		// shipped at two versions in one build stays two, which matching on
		// the source package's name alone could not do.
		Where(FoldedOn+` = (SELECT c2."fold_key" FROM "component" AS "c2"
				WHERE c2."name_folded" = ? LIMIT 1)`, graph.Folded(component)).
		OrderExpr("f.vulnerability_id, f.component_id, f.target_id, place_identity")
	err := query.Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read where that bump would reach: %w", err)
	}

	order := []string{}
	grouped := map[string]*InBundle{}
	seen := map[string]bool{}
	for _, row := range rows {
		at := fmt.Sprintf("%d\x00%d\x00%d", row.VulnerabilityID, row.ComponentID, row.TargetID)
		one, held := grouped[at]
		if !held {
			one = &InBundle{
				VulnerabilityID: row.VulnerabilityID, ComponentID: row.ComponentID,
				TargetID: row.TargetID,
			}
			grouped[at] = one
			order = append(order, at)
		}
		// One entry per place, however many rows a place has: a place with two
		// consumers is one thing to decide about, and counting it twice would
		// write two claims about the same code.
		if seen[at+"\x00"+row.PlaceIdentity] {
			continue
		}
		seen[at+"\x00"+row.PlaceIdentity] = true
		one.Places = append(one.Places, Deciding{
			ProductID: productID, VulnerabilityID: row.VulnerabilityID,
			PlaceIdentity:     row.PlaceIdentity,
			Visibility:        access.AsVisibility(row.Visibility),
			ComponentUpstream: row.ComponentUpstream,
			ConsumerUpstream:  row.ConsumerUpstream,
			SeverityCenti:     row.score(),
			DueAt:             row.DueAt,
			FixedIn:           row.FixedIn,
			Consumer:          row.Consumer,
			OnTag:             row.OnTag == 1,
			Places:            1,
		})
	}
	bundled := make([]InBundle, 0, len(order))
	for _, at := range order {
		bundled = append(bundled, *grouped[at])
	}
	return bundled, nil
}

// PlacesFor resolves every place one issue occupies in one component.
//
// This is what a judgment made on the finding covers: all of them by default,
// with a narrower set chosen deliberately. Deciding one place at a time was
// the only thing on offer, and a finding sitting at thirty places then meant
// thirty judgments — which is how somebody stops reading.
//
// Read in one statement and grouped here rather than asked per place. A place
// is a pair of names and the rows under one are ordered the same way PlaceFor
// orders them, so which version a decision is keyed on does not depend on what
// the database happened to return first.
func (s *Store) PlacesFor(ctx context.Context, subject access.Subject, targetID int64,
	vulnerabilityID, componentID int64) ([]Deciding, error) {

	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	// Asked about the issue, for the reason PlaceFor is.
	if !access.SeesOn(subject, productID, vulnerabilityID) {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	visible := access.VisibleOn(subject, productID, vulnerabilityID)
	if len(visible) == 0 {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}

	var rows []struct {
		placeRow
		PlaceIdentity string `bun:"place_identity"`
		Consumer      string `bun:"consumer"`
		FixedIn       string `bun:"fixed_in"`
	}
	err = placeColumns(s.db.NewSelect().TableExpr(`"finding" AS "f"`), productID).
		ColumnExpr(`f.place_identity AS "place_identity"`).
		ColumnExpr(`COALESCE(uc.name, '') AS "consumer"`).
		ColumnExpr(`COALESCE(f.fixed_in, '') AS "fixed_in"`).
		Where("f.target_id = ?", targetID).
		Where("f.vulnerability_id = ?", vulnerabilityID).
		// The fold rather than the one component named. One judgment covers
		// the whole fold, with no narrowing within it: curl and libcurl4t64
		// are one source package, so a decision about the issue in one of them
		// is a decision about it in both — and offering the places of one
		// binary alone would let somebody answer a third of the work and read
		// as having answered it.
		Where(FoldedOn+` = (SELECT c2."fold_key" FROM "component" AS "c2" WHERE c2.id = ?)`,
			componentID).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		OrderExpr("consumer, place_identity, component_upstream, consumer_upstream").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read where this sits: %w", err)
	}

	order := []string{}
	grouped := map[string][]placeRow{}
	consumers := map[string]string{}
	fixes := map[string]string{}
	for _, row := range rows {
		if _, seen := grouped[row.PlaceIdentity]; !seen {
			order = append(order, row.PlaceIdentity)
			consumers[row.PlaceIdentity] = row.Consumer
			fixes[row.PlaceIdentity] = row.FixedIn
		}
		grouped[row.PlaceIdentity] = append(grouped[row.PlaceIdentity], row.placeRow)
	}

	places := make([]Deciding, 0, len(order))
	for _, identity := range order {
		at := grouped[identity]
		places = append(places, Deciding{
			ProductID: productID, VulnerabilityID: vulnerabilityID, PlaceIdentity: identity,
			Visibility:        access.AsVisibility(at[0].Visibility),
			ComponentUpstream: at[0].ComponentUpstream,
			ConsumerUpstream:  at[0].ConsumerUpstream,
			SeverityCenti:     at[0].score(),
			DueAt:             earliestDue(at),
			FixedIn:           fixes[identity],
			Consumer:          consumers[identity],
			OnTag:             at[0].OnTag == 1,
			Places:            len(at),
			distinctVersions:  distinctVersions(at),
		})
	}
	return places, nil
}

// placeColumns adds the joins and the column expressions a place row is read
// from, to a query over finding AS "f".
//
// The eight expressions and the reasoning behind two of them were written out
// verbatim in three queries here. Each copy still compiles and still returns
// rows when one of them gains a column, so nothing notices a site left behind
// — and what these feed is the key a decision expires on, which is the one
// thing in this package that must not differ between the read that writes it
// and the read that matches it.
//
// It does not take the ordering with it: the three order differently, and what
// a decision is keyed on must not depend on what the database returned first.
func placeColumns(q *bun.SelectQuery, productID int64) *bun.SelectQuery {
	return q.
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		Join(rating.Here, productID).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr(`f.visibility AS "visibility"`).
		// The upstream version where one is stated, and the component's own
		// where none is. Most packages are not forks and state no upstream at
		// all — measured on a real image, 88% of them — so reading only the
		// stated one left the version half of the key empty for almost
		// everything, and a key that never changes is a decision that never
		// lapses. A dismissal written about one version would suppress the
		// same issue in every later one, forever.
		//
		// Falling back to the shipped version asks again on a packaging
		// revision that changed no code, which only the upstream version
		// lapsing would rather avoid. That is the safe direction to be wrong
		// in: asking twice costs somebody a minute, and not asking costs a
		// vulnerability nobody looked at. The case only the upstream version
		// lapsing is actually about — a fork carrying its own version while
		// the issue lives upstream — is exactly the case that states an
		// upstream, so it is unaffected.
		ColumnExpr(ComponentUpstreamExpr+` AS "component_upstream"`).
		ColumnExpr(ConsumerUpstreamExpr+` AS "consumer_upstream"`).
		// The three the rating in force is worked out from, scored by the
		// project's one rule rather than by a second one in SQL: an
		// assessment writes the word and never the published score, so the
		// score alone says an issue rated critical here is worth zero.
		ColumnExpr(`COALESCE(v.severity, '') AS "published_severity"`).
		ColumnExpr(`COALESCE(ir.severity, '') AS "rated_here"`).
		ColumnExpr(`COALESCE(v.score_centi, 0) AS "score_centi"`).
		// The deadline, because a promise to act is gated against the earliest
		// one among what the act covers. Read from the rows rather than
		// supplied, like the versions and the visibility: it is a fact about
		// the place, and a caller free to state it would be choosing whether
		// their own commitment needed a second person.
		ColumnExpr(`f.due_at AS "due_at"`).
		// A release built once. A tag cannot change, so what may
		// be said about a finding on one is narrower, and that is a fact about
		// the build rather than about who is asking.
		ColumnExpr(`CASE WHEN st.kind = ? THEN 1 ELSE 0 END AS "on_tag"`, catalog.Tag)
}
