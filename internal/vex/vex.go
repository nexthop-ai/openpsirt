// Package vex writes what we have decided about the third-party components a
// build ships, in the format a customer's own scanner reads.
//
// **This is the document third-party components belong in.** Advisories are
// about flaws in our own product and are not issued for known CVEs in
// dependencies — but a customer running a scanner against a shipped
// image gets a list of those CVEs and asks what we say about them, which is
// more often than they ask for an advisory. "We ship openssl 3.5.6, this CVE,
// not affected, vulnerable code not present" is exactly a VEX statement.
//
// **It is mostly formatting over decisions already made and approved.** Every
// "not applicable" claim already carries the VEX vocabulary, so the
// justification needs no translation. What makes it safe to publish is the
// approval that was already required: generating this puts our dismissals in
// writing, machine-readable, in front of every customer, which is the feature
// and the risk in one sentence.
//
// **OpenVEX rather than CSAF-VEX**, because it is the format this deployment
// already reads: a document we write and a document we read being the
// same format is what lets one deployment's output be another's input, and
// what keeps one shape to get right rather than two.
package vex

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/version"
)

// The namespace the format states, and the one a reader matches on.
const namespace = "https://openvex.dev/ns/v0.2.0"

// Statements is one VEX document about one build.
//
// Named for what it carries rather than "Document", because the API's schema
// registry keys types by their bare name and an advisory is a document too —
// two types called the same thing in one schema is a collision that surfaces
// as a panic at start-up rather than as a compile error.
type Statements struct {
	Context string `json:"@context"`
	// ID names this document. A reader keeps documents by it, so it carries
	// the build and the moment rather than being a bare number.
	ID     string `json:"@id"`
	Author string `json:"author"`
	// Tooling says what wrote it, read from the binary rather than held in a
	// variable something has to remember to set.
	Tooling    string      `json:"tooling"`
	Timestamp  time.Time   `json:"timestamp"`
	Version    int         `json:"version"`
	Statements []Statement `json:"statements"`
}

// Statement is what we say about one issue in one component.
type Statement struct {
	Vulnerability Issue     `json:"vulnerability"`
	Timestamp     time.Time `json:"timestamp"`
	Products      []Shipped `json:"products"`
	Status        string    `json:"status"`
	// Justification is the standard category, present only for
	// not_affected. It is the same vocabulary a dismissal already records.
	Justification string `json:"justification,omitempty"`
	// ImpactStatement is the reasoning somebody wrote, which is the part that
	// is worth reading and the part a second person agreed to.
	ImpactStatement string `json:"impact_statement,omitempty"`
}

// Issue is a vulnerability, by the name it is filed under here.
type Issue struct {
	Name string `json:"name"`
	// Aliases are the other names it answers to, so a reader searching by
	// the one their scanner used finds the statement.
	Aliases []string `json:"aliases,omitempty"`
}

// Shipped is what somebody has: the build, with the component the statement is
// about underneath it.
//
// The build rather than the component, because a VEX statement is about a
// thing somebody has — and what they have is our image, which happens to
// contain that library.
type Shipped struct {
	ID            string   `json:"@id"`
	Subcomponents []Inside `json:"subcomponents,omitempty"`
}

// Inside is a component of what ships, by its package identifier.
type Inside struct {
	ID string `json:"@id"`
}

// Store writes VEX documents.
type Store struct {
	db  *bun.DB
	now func() time.Time
}

// NewStore returns a store over db.
func NewStore(db *bun.DB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// For writes the document for one build.
//
// **Approved claims only.** A proposal is one person's opinion and this
// document is the deployment's word to a customer — the two-person rule is
// what makes publishing a dismissal safe, and a document carrying unapproved
// ones would route around it.
//
// **Public findings only.** Every statement names an issue and a component in
// something we ship, so a document built from undisclosed work would announce
// the undisclosed work. `undisclosed` includes them for somebody who may read
// them, which is a preview rather than a thing to publish, and it is refused
// for anybody who may not.
//
// **Two statuses, and silence for everything else.** `not_affected` and
// `fixed` are what a generated VEX document names, and they are the two a
// customer's scanner can act on. A deferral is deliberately absent rather than
// exported as anything: a deferred item exports as affected and never as
// not-affected, and silence already reads as
// affected in this format, which is the honest answer for something we have
// only postponed.
func (s *Store) For(ctx context.Context, subject access.Subject, publisher publisher.Named,
	product, stream, variant string, undisclosed bool) (*Statements, error) {

	if !publisher.Stated() {
		return nil, fmt.Errorf("this deployment has not said who it publishes as, " +
			"so a document has nobody to name as its author")
	}
	names := catalog.NewStore(s.db)
	named, err := names.LocateVisible(ctx, subject, product, stream, variant)
	if err != nil {
		return nil, err
	}
	target, err := names.ExistingTarget(ctx, named.StreamID, named.VariantID)
	if err != nil {
		return nil, err
	}
	visible := []access.Visibility{access.Public}
	if undisclosed {
		if !subject.Reads(access.Private, named.ProductID) {
			return nil, access.Denied("read undisclosed work here")
		}
		visible = append(visible, access.Private)
	}

	var rows []struct {
		VulnerabilityID int64     `bun:"vulnerability_id"`
		Identifier      string    `bun:"identifier"`
		Component       string    `bun:"component"`
		Purl            string    `bun:"purl"`
		Outcome         string    `bun:"outcome"`
		Justification   string    `bun:"justification"`
		Reasoning       string    `bun:"reasoning"`
		DecidedAt       time.Time `bun:"decided_at"`
	}
	// One statement per issue and component, from the claims that stand and
	// have been agreed to. Joined from the findings this build actually holds:
	// a decision is a claim about a product's code and reaches every build
	// whose versions match it, so what belongs in this document is what this
	// build ships rather than everything the product has ever decided.
	err = s.db.NewSelect().
		TableExpr(`finding AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		Join(`LEFT JOIN "decision" AS "de" ON de.vulnerability_id = f.vulnerability_id
			AND de.place_identity = f.place_identity
			AND de.product_id = ?
			AND de.state = 'approved'
			AND de.live_key IS NOT NULL
			AND COALESCE(de.component_upstream_version, '') =
				COALESCE(NULLIF(c.upstream_version, ''), c.version, '')
			AND COALESCE(de.consumer_upstream_version, '') =
				COALESCE(NULLIF(uc.upstream_version, ''), uc.version, '')`, named.ProductID).
		// The argument, which is where the outcome lives. The outcome test is
		// part of the join rather than a filter, as it was on the decision:
		// what the counting below asks is whether *every* open place is
		// dismissed, and a filter would drop the places that are not.
		Join(`LEFT JOIN "claim" AS "cl" ON cl.id = de.claim_id
			AND cl.outcome IN ('not-applicable', 'already-fixed')`).
		Join(`LEFT JOIN "claim_revision" AS "dr" ON dr.id = cl.revision_id`).
		ColumnExpr(`v.id AS "vulnerability_id"`).
		ColumnExpr(`v.identifier AS "identifier"`).
		ColumnExpr(`c.name AS "component"`).
		ColumnExpr(`COALESCE(c.purl, '') AS "purl"`).
		ColumnExpr(`MIN(cl.outcome) AS "outcome"`).
		// The words and the moment of the earliest of them, which is the claim
		// that has stood longest about this component. Where several places
		// were decided separately the document has one thing to say and has to
		// choose which; the first is the one a reader can check against the
		// record.
		ColumnExpr(`COALESCE(MIN(cl.justification), '') AS "justification"`).
		ColumnExpr(`COALESCE(MIN(dr.body), '') AS "reasoning"`).
		ColumnExpr(`MIN(de.proposed_at) AS "decided_at"`).
		Where("f.target_id = ?", target.ID).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		// The issue's key is grouped alongside its name so the aliases can be
		// looked up per issue. Selecting it without grouping it is accepted by
		// SQLite and refused by PostgreSQL, which is the whole reason a query
		// is proved on more than one engine.
		//
		// Grouped by the issue and the component and nothing about the
		// decision, because a statement is about a product and a component and
		// the format has no finer grain to say it at. Two places decided in
		// separate sittings differ in when and in what was written, and
		// grouping on those emitted the same claim twice — or, where the
		// outcomes differed, two statements contradicting each other about one
		// component.
		GroupExpr("v.id, v.identifier, c.name, c.purl").
		// Every open place agreed, and agreed the same way. The join is left,
		// so a place nobody has dismissed contributes a row with no decision:
		// counting them is how "all of them" is asked. One dismissal at one
		// place used to speak for a component open at forty-four others — a
		// machine-readable "not affected" about something that is affected,
		// published to every customer running a scanner.
		Having("COUNT(cl.id) = COUNT(*)").
		Having("COUNT(DISTINCT cl.outcome) = 1").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what stands about this build: %w", err)
	}

	moment := s.now().UTC()
	id := fmt.Sprintf("%s/vex/%s-%s-%s-%s", publisher.Namespace,
		product, stream, variant, moment.Format("20060102150405"))
	doc := &Statements{
		Context: namespace, ID: id, Author: publisher.Name,
		Tooling:   "OpenPSIRT " + version.Get().Version,
		Timestamp: moment, Version: 1,
		Statements: make([]Statement, 0, len(rows)),
	}
	// What else each issue is called. The whole point of the field is that
	// a customer's scanner matched under the name *its* database uses,
	// which is often not the one we filed under — a later CVE for a flaw
	// first reported under a vendor identifier, or the reverse. A document
	// declaring the field and never filling it answers nobody searching by
	// the name they have, which is the one search this document exists to
	// satisfy.
	issues := make([]int64, 0, len(rows))
	for _, row := range rows {
		issues = append(issues, row.VulnerabilityID)
	}
	alsoCalled, err := s.namesOf(ctx, issues)
	if err != nil {
		return nil, err
	}

	shipped := product + ":" + stream + ":" + variant
	for _, row := range rows {
		about := row.Purl
		if about == "" {
			// A component with no package identifier is named by the name the
			// build calls it. Less use to a machine and better than dropping
			// the statement: the reader can still match it by hand, and a
			// silent omission reads as "no claim" — which is the one thing
			// this document must not say by accident.
			about = row.Component
		}
		statement := Statement{
			Vulnerability: Issue{Name: row.Identifier, Aliases: alsoCalled[row.VulnerabilityID]},
			Timestamp:     row.DecidedAt.UTC(),
			Products: []Shipped{{
				ID: shipped, Subcomponents: []Inside{{ID: about}},
			}},
			Status:          statusOf(row.Outcome),
			ImpactStatement: row.Reasoning,
		}
		if statement.Status == "not_affected" {
			statement.Justification = row.Justification
		}
		doc.Statements = append(doc.Statements, statement)
	}

	// Ordered here rather than by the engine, so the document is byte-for-byte
	// the same whatever it was generated against — which is what lets somebody
	// diff two of them and see a real change rather than a reordering.
	sort.Slice(doc.Statements, func(i, j int) bool {
		a, b := doc.Statements[i], doc.Statements[j]
		if a.Vulnerability.Name != b.Vulnerability.Name {
			return a.Vulnerability.Name < b.Vulnerability.Name
		}
		return a.Products[0].Subcomponents[0].ID < b.Products[0].Subcomponents[0].ID
	})
	return doc, nil
}

// statusOf turns an outcome into what the format calls it.
//
// Only the two a VEX document per build names arrive here. A deferral never
// does: publishing it as not-affected would tell the world we assessed
// something as harmless when we had only postponed it, and silence already
// reads as affected.
func statusOf(outcome string) string {
	if outcome == "already-fixed" {
		return "fixed"
	}
	return "not_affected"
}

// Publishable reports whether a deployment has said who it publishes as, for a
// caller that needs to tell a configuration gap from a bad request.
func Publishable(p publisher.Named) bool { return p.Stated() }

// namesOf is what each of these issues is also called, keyed by issue.
//
// One read for the whole document rather than one per statement: a build with
// a thousand agreed dismissals is a thousand round trips otherwise, and this
// is generated on request.
func (s *Store) namesOf(ctx context.Context, issues []int64) (map[int64][]string, error) {
	out := map[int64][]string{}
	if len(issues) == 0 {
		return out, nil
	}
	var rows []struct {
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Identifier      string `bun:"identifier"`
	}
	err := s.db.NewSelect().Model((*finding.Alias)(nil)).
		Join(`JOIN "vulnerability" AS "v" ON v.id = va.vulnerability_id`).
		ColumnExpr(`va.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`va.identifier AS "identifier"`).
		Where("va.vulnerability_id IN (?)", bun.List(issues)).
		// The other names, so not the one the statement is already
		// filed under. The alias table holds every name an issue
		// answers to including its own, which is what makes identity
		// span them ; a document repeating the primary in its own
		// alias list says nothing and reads as a mistake.
		Where("va.identifier <> v.identifier").
		OrderExpr("va.identifier").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what these issues are also called: %w", err)
	}
	for _, row := range rows {
		out[row.VulnerabilityID] = append(out[row.VulnerabilityID], row.Identifier)
	}
	return out, nil
}
