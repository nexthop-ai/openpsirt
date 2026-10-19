// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// NotArguedAway says a finding `f` is work nobody has argued away: the build made
// no claim covering it, and no supplier's statement answers it on any route up
// the tree. A row answered either way stays open, because what it answers is
// not the whole of the place, and it is not work while it does.
//
// One spelling, because every reader asking whether a row is somebody's work
// asks this: the deadline lists, the overdue counts, the review routing, and
// the notifications.
const NotArguedAway = `("f"."suppressed_by" IS NULL AND "f"."stated_by" IS NULL)`

// LatestAtItsPlace says no row of the same issue has been recorded at the same
// place in the same build after the finding `f`.
//
// A run records a new row rather than reopening a closed one, so a place
// closed by a supplier's statement and recorded again later, at another
// version or closed another way, holds rows the later one stands for. Ordered
// by identifier rather than by moment: a version moving closes the row before
// and records the row after at one moment.
const LatestAtItsPlace = `NOT EXISTS (SELECT 1 FROM "finding" AS "lt"
	WHERE "lt"."target_id" = "f"."target_id" AND "lt"."vulnerability_id" = "f"."vulnerability_id"
	  AND "lt"."place_identity" = "f"."place_identity" AND "lt"."id" > "f"."id")`

// Decidable says a finding `f` is one somebody may decide about: open, or
// closed by a supplier's statement and the latest row at its place. A person
// who disagrees with a supplier marks the place affected, and the next run
// opens it again, so the place has to be reachable while the statement has it
// closed.
const Decidable = `("f"."closed_at" IS NULL OR ("f"."closed_because" = '` + string(Disclaimed) + "' AND " +
	LatestAtItsPlace + "))"

// disclaiming is what a run needs to apply suppliers' statements: the
// statements that can close a finding in this build, the graph they are placed
// in, and the places a person has said are affected.
//
// A supplier speaking about its own product speaks about what sits inside it
// (REQ-31). Which statements those are is decided once per run, and where each
// one lands is decided per product rather than per finding: two passes over the
// build's edges for each product a statement names.
type disclaiming struct {
	said     []Statement
	byIssue  map[string][]int
	affected map[affectedAt]bool
	// decided is every place a person has decided about, whatever they
	// decided, read only where an upstream's statement could close one. A
	// local decision stands over an upstream's word either way.
	decided map[affectedAt]bool
	*placer
}

// placer is where products sit in one build: its components, the edges between
// them read downward, and each product's placement once it has been asked for.
//
// A build's own claim about a component inside one of its products and a
// supplier's statement about its own product are placed alike, so they share
// one walk per product.
type placer struct {
	inv      inventory
	children map[int64][]int64
	placed   map[string]*placement
	// root is the build's own component. It is the product every claim is
	// about already, and never a product inside the build.
	root int64
	// names caches whether a product names any component of the build.
	names map[string]bool
	// images is what the build states for each image it holds by name,
	// which is the version a product naming one is placed at.
	images map[int64]graph.ImageVersion
}

// placing reads the build's root and turns its places into a placer.
func placing(ctx context.Context, db bun.IDB, targetID int64, inv inventory,
	places consumers) (*placer, error) {

	p := &placer{inv: inv, children: map[int64][]int64{}, placed: map[string]*placement{},
		names: map[string]bool{}}
	// What each component pulls in, the edges read the other way. Zero is
	// the build's root, as it is for a place.
	for child, above := range places {
		for _, consumer := range above {
			p.children[consumer] = append(p.children[consumer], child)
		}
	}
	var roots []int64
	if err := db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		ColumnExpr(`"n"."component_id"`).
		Where(`"n"."target_id" = ?`, targetID).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`"n"."is_root" = ?`, true).
		Scan(ctx, &roots); err != nil {
		return nil, fmt.Errorf("read the build's own component: %w", err)
	}
	if len(roots) > 0 {
		p.root = roots[0]
	}
	images, err := graph.StatedImages(ctx, db, targetID)
	if err != nil {
		return nil, err
	}
	p.images = images
	return p, nil
}

// asStated is a component as this build states it: an image held by name
// carries the version and the identifier the build stated for it.
func (p *placer) asStated(c graph.Component) graph.Component {
	if stated, ok := p.images[c.ID]; ok {
		c.Version = stated.Version
		if stated.Purl != "" {
			c.Purl = stated.Purl
		}
	}
	return c
}

// reaches reports whether a build's claim naming the product given reaches a
// component at the place its consumer is.
//
// A claim naming no product, or naming one no component of the build is, is
// about the build: the build's root, or a name the build's producer gave the
// whole of it. One naming a component of the build applies only where every
// route to the place runs through that component at the version the claim
// names, and never to the product itself.
func (p *placer) reaches(product *sbom.Target, component graph.Component, consumerID int64) bool {
	if product == nil || !p.ships(*product) {
		return true
	}
	if consumerID == 0 {
		return false
	}
	at := p.place(*product)
	if at.product[component.ID] {
		return false
	}
	return at.at(consumerID) == answersAll
}

// ships reports whether a product names a component of the build other than
// its root, at any version.
func (p *placer) ships(product sbom.Target) bool {
	key := product.Purl + "\x00" + product.Name
	if held, ok := p.names[key]; ok {
		return held
	}
	found := false
	for id, c := range p.inv.byID {
		if id != p.root && isProduct(product, c, false) {
			found = true
			break
		}
	}
	p.names[key] = found
	return found
}

// placement is where one supplier's product sits in a build: its components,
// everything beneath them, and everything the root reaches without passing
// through one of them.
type placement struct {
	product map[int64]bool
	under   map[int64]bool
	outside map[int64]bool
}

// affectedAt is a place a person has said an issue applies at, at the
// versions the decision was keyed on.
type affectedAt struct {
	vulnerabilityID int64
	placeIdentity   string
	component       string
	consumer        string
}

// answer is how a statement stands at one place.
type answer int

const (
	// answersNone is a place the statement says nothing about.
	answersNone answer = iota
	// answersSome is a place reached through the product and outside it as
	// well: the statement answers the routes through the product, and nobody
	// has answered the rest.
	answersSome
	// answersAll is a place every route to which runs through the product.
	answersAll
)

// disclaimers reads what can close a finding in this build: the product's
// standing statements that a supplier's own product is not affected, and an
// upstream's statements that a component is not affected or is fixed for
// anybody shipping it, about any of the issues the run reported, naming a
// version.
//
// A statement naming a product with no version is about every release of it,
// past and future, and stays evidence. Matched on every name the issues go by,
// because which identifier a publisher chose is a preference of whichever
// database they consulted.
func disclaimers(ctx context.Context, db bun.IDB, productID int64, issues []Named,
	issueIDs []int64, placed *placer) (*disclaiming, error) {

	d := &disclaiming{byIssue: map[string][]int{}, placer: placed}
	var names []string
	seen := map[string]bool{}
	for _, issue := range issues {
		for _, name := range append([]string{issue.Identifier}, issue.Aliases...) {
			if name = folded(name); name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		return d, nil
	}
	// Split and OR-ed rather than one list: a run reports thousands of issues,
	// and a statement binding them all is refused by two of the four engines.
	err := db.NewSelect().Model(&d.said).
		Where(`"ss"."product_id" = ?`, productID).
		Where(`"ss"."superseded_at" IS NULL`).
		Where(`"ss"."declined_at" IS NULL`).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			for from := 0; from < len(names); from += database.BatchSize {
				q = q.WhereOr(`"ss"."vulnerability" IN (?)`,
					bun.List(names[from:min(from+database.BatchSize, len(names))]))
			}
			return q
		}).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			// A supplier's word about its own product closes only where it
			// says not affected. An upstream's word about a component closes
			// where it says not affected or fixed, at the version it names.
			return q.WhereOr(`"ss"."status" = ? AND "ss"."placement" = ? AND "ss"."within_about" IS NOT NULL`,
				string(sbom.NotAffected), PlacedInside).
				WhereOr(`"ss"."status" = ? AND "ss"."placement" = ? AND "ss"."about" <> ?`,
					string(sbom.NotAffected), PlacedProduct, "").
				WhereOr(`"ss"."status" IN (?) AND "ss"."placement" = ? AND "ss"."source" = ? AND "ss"."about" <> ?`,
					bun.List(upstreamCloses()), PlacedAnybody, FromUpstream, "")
		}).
		Order("ss.id").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read what suppliers say about their products: %w", err)
	}
	if len(d.said) == 0 {
		return d, nil
	}
	for i, one := range d.said {
		d.byIssue[one.Vulnerability] = append(d.byIssue[one.Vulnerability], i)
	}
	d.affected, err = standingPlaces(ctx, db, productID, issueIDs, OutcomeAffected)
	if err != nil {
		return nil, err
	}
	if slices.ContainsFunc(d.said, func(one Statement) bool { return one.Placement == PlacedAnybody }) {
		if d.decided, err = standingPlaces(ctx, db, productID, issueIDs, ""); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// upstreamCloses is what an upstream's statement says where it closes a
// finding: that the component at that version is not affected, or is fixed.
// Nothing else it says closes anything (REQ-31).
func upstreamCloses() []string {
	return []string{string(sbom.NotAffected), string(sbom.AlreadyFixed)}
}

// standingPlaces is every place in this product a person has decided one of
// these issues at, by a decision that stands, keyed by the issue a decision is
// about now, merged issues included. Only decisions of the outcome given,
// where one is given.
//
// A disagreement with a supplier goes through the ordinary route: somebody
// marks the place affected, and the statement does not close it there. Any
// decision at all stands over an upstream's statement.
func standingPlaces(ctx context.Context, db bun.IDB, productID int64,
	issueIDs []int64, outcome string) (map[affectedAt]bool, error) {

	var rows []struct {
		VulnerabilityID int64  `bun:"vulnerability_id"`
		PlaceIdentity   string `bun:"place_identity"`
		Component       string `bun:"component"`
		Consumer        string `bun:"consumer"`
		Outcome         string `bun:"outcome"`
	}
	standing, held := InForce()
	issues, ids := database.InAnyOf(`"dv"."issue_id"`, issueIDs)
	q := db.NewSelect().
		TableExpr(Decisions).
		Join(`JOIN "claim" AS "cl" ON "cl"."id" = "de"."claim_id"`).
		ColumnExpr(`"dv"."issue_id" AS "vulnerability_id"`).
		ColumnExpr(`"de"."place_identity" AS "place_identity"`).
		ColumnExpr(`COALESCE("de"."component_upstream_version", '') AS "component"`).
		ColumnExpr(`COALESCE("de"."consumer_upstream_version", '') AS "consumer"`).
		ColumnExpr(`"cl"."outcome" AS "outcome"`).
		Where(`"de"."product_id" = ?`, productID).
		Where(`"de"."live_key" IS NOT NULL`).
		Where(standing, held...).
		Where(issues, ids...)
	if outcome != "" {
		q = q.Where(`"cl"."outcome" = ?`, outcome)
	}
	err := q.Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read where people have said an issue applies: %w", err)
	}
	out := make(map[affectedAt]bool, len(rows))
	for _, row := range rows {
		if row.Outcome == OutcomeMismatched {
			// A claim that the match is wrong stands at whatever version the
			// place holds, so it is keyed on the place alone.
			out[affectedAt{vulnerabilityID: row.VulnerabilityID, placeIdentity: row.PlaceIdentity}] = true
			continue
		}
		out[affectedAt{row.VulnerabilityID, row.PlaceIdentity, row.Component, row.Consumer}] = true
	}
	return out, nil
}

// answering is the statement that answers an issue at one place, and whether
// it answers every route there.
//
// A statement answering every route is preferred over one answering some, and
// among either the oldest stands, so the answer does not move between runs.
func (d *disclaiming) answering(issue Named, vulnerabilityID int64, component graph.Component,
	consumerID int64) (*int64, answer) {

	if len(d.said) == 0 {
		return nil, answersNone
	}
	var candidates []int
	for _, name := range append([]string{issue.Identifier}, issue.Aliases...) {
		candidates = append(candidates, d.byIssue[folded(name)]...)
	}
	if len(candidates) == 0 {
		return nil, answersNone
	}
	slices.Sort(candidates)
	candidates = slices.Compact(candidates)

	// Zero is the build's root, which no supplier's product holds; an
	// upstream speaks for the component wherever it sits, the root included.
	consumer := d.inv.byID[consumerID]
	here := affectedAt{vulnerabilityID, PlaceIdentity(component.Name, consumer.Name),
		upstreamOf(component), upstreamOf(consumer)}
	if d.affected[here] {
		return nil, answersNone
	}

	var some *int64
	described := describedOf(component)
	for _, i := range candidates {
		one := d.said[i]
		if one.Placement == PlacedAnybody {
			// An upstream speaks for the component wherever it ships, at the
			// version it names and no other, and never where somebody here
			// decided.
			anyVersion := affectedAt{vulnerabilityID: here.vulnerabilityID, placeIdentity: here.placeIdentity}
			if d.decided[here] || d.decided[anyVersion] || !sameComponent(one, d.asStated(component)) {
				continue
			}
			id := one.ID
			return &id, answersAll
		}
		if consumerID == 0 {
			continue
		}
		product := suppliedProduct(one)
		if one.Placement == PlacedInside {
			// A statement about a component inside the product is about that
			// component, and the product places it.
			about := sbom.Target{Purl: one.Purl, Name: one.Component, Version: one.About}
			if !about.Covers(described) {
				continue
			}
		}
		p := d.place(product)
		if p.product[component.ID] {
			// A finding on the product itself, which a cycle in the graph can
			// put beneath it, is evidence.
			continue
		}
		switch p.at(consumerID) {
		case answersAll:
			id := one.ID
			return &id, answersAll
		case answersSome:
			if some == nil {
				id := one.ID
				some = &id
			}
		}
	}
	if some != nil {
		return some, answersSome
	}
	return nil, answersNone
}

// sameComponent reports whether an upstream's statement names this component:
// the same package identifier, its version aside, and the same version. A
// statement naming no package identifier names nothing here.
func sameComponent(one Statement, c graph.Component) bool {
	base, version := graph.PackageOf(one.Purl)
	if version == "" {
		version = one.About
	}
	held, heldVersion := graph.PackageOf(c.Purl)
	if heldVersion == "" {
		heldVersion = c.Version
	}
	return base != "" && base == held && version != "" && version == heldVersion
}

// suppliedProduct is the supplier's product a statement names: the product the
// component ships inside, or the component itself where the statement named
// nothing it ships inside.
func suppliedProduct(one Statement) sbom.Target {
	if one.Placement == PlacedInside {
		return sbom.Target{Purl: one.WithinPurl, Name: one.Within, Version: one.WithinAbout}
	}
	return sbom.Target{Purl: one.Purl, Name: one.Component, Version: one.About}
}

// place is where a product sits in this build, worked out once per product
// however many statements and claims name it.
//
// The product is matched exactly at the version the statement names: a
// statement about one release says nothing about the next. One naming no
// version is placed nowhere.
func (d *placer) place(product sbom.Target) *placement {
	key := product.Purl + "\x00" + product.Name + "\x00" + product.VersionNamed()
	if held, ok := d.placed[key]; ok {
		return held
	}
	p := &placement{product: map[int64]bool{}, under: map[int64]bool{}, outside: map[int64]bool{}}
	d.placed[key] = p
	if product.VersionNamed() == "" {
		return p
	}
	for id, c := range d.inv.byID {
		if id == d.root {
			continue
		}
		if isProduct(product, d.asStated(c), true) {
			p.product[id] = true
		}
	}
	if len(p.product) == 0 {
		return p
	}
	// Everything beneath the product.
	var queue []int64
	for id := range p.product {
		queue = append(queue, d.children[id]...)
	}
	for len(queue) > 0 {
		at := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if p.under[at] {
			continue
		}
		p.under[at] = true
		queue = append(queue, d.children[at]...)
	}
	// Everything the root reaches without passing through the product.
	queue = append(queue, d.children[0]...)
	for len(queue) > 0 {
		at := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if p.outside[at] || p.product[at] {
			continue
		}
		p.outside[at] = true
		queue = append(queue, d.children[at]...)
	}
	return p
}

// isProduct reports whether a component is the supplier's product: by the
// package identifier the statement names, where it names one of a package,
// and otherwise by the identifier or by the component's own name. With
// atVersion, at the version the statement names as well.
//
// Never by what the component was built from. A fork of the supplier's source
// carries the supplier's name as the name it was built from, and a build of
// the supplier's source is not the supplier's product.
func isProduct(product sbom.Target, c graph.Component, atVersion bool) bool {
	base, version := graph.PackageOf(product.Purl)
	if version == "" {
		version = product.Version
	}
	held, heldVersion := graph.PackageOf(c.Purl)
	if heldVersion == "" {
		heldVersion = c.Version
	}
	switch {
	case base != "" && !strings.HasPrefix(base, "pkg:generic/"):
		if base != held {
			return false
		}
	case base != "" && base == held:
		// A generic identifier names a product by what the inventory calls
		// it in its own identifier, which the name it gives may not repeat:
		// pkg:generic/sonic-utilities beside "SONiC utilities".
	case base != "" && !sbom.GenericNamespaceAgrees(base, c.Purl):
		return false
	case product.Name == "" || !strings.EqualFold(product.Name, c.Name):
		return false
	}
	return !atVersion || (version != "" && version == heldVersion)
}

// at is how the product stands at a place whose consumer is the component
// given: every route to the place runs through the product, some do, or none.
//
// A place is a component and what directly pulls it in, so every route to it
// runs through its consumer. The product answers every route where the
// consumer is the product, or where the consumer is beneath it and the root
// cannot reach it any other way.
func (p *placement) at(consumerID int64) answer {
	switch {
	case p.product[consumerID]:
		return answersAll
	case !p.under[consumerID]:
		return answersNone
	case p.outside[consumerID]:
		return answersSome
	}
	return answersAll
}
