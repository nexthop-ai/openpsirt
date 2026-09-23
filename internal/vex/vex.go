// Package vex writes what we have decided about the third-party components a
// build ships, in the format a customer's own scanner reads.
//
// This is the document third-party components belong in. Advisories are
// about flaws in our own product and are not issued for known CVEs in
// dependencies — but a customer running a scanner against a shipped
// image gets a list of those CVEs and asks what we say about them, which is
// more often than they ask for an advisory. "We ship openssl 3.5.6, this CVE,
// not affected, vulnerable code not present" is exactly a VEX statement.
//
// It is mostly formatting over decisions already made and approved. Every
// "not applicable" claim carries the VEX vocabulary, so the justification
// needs no translation. What makes it safe to publish is the approval the
// claim already required: generating this puts our dismissals in writing,
// machine-readable, in front of every customer, which is the feature and the
// risk in one sentence.
//
// OpenVEX rather than CSAF-VEX, because it is the format this deployment
// already reads: a document we write and a document we read being the
// same format is what lets one deployment's output be another's input, and
// what keeps one shape to get right rather than two.
package vex

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/version"
)

// The namespace the format states, and the one a reader matches on.
const namespace = "https://openvex.dev/ns/v0.2.0"

// ErrTooLarge is returned when a build stands on more dismissals than one
// document carries.
//
// Named rather than answered as a fault, because it is something the caller
// can act on: narrow to a variant, or ask about a build that argues less. A
// bare error reaches the route as "the document could not be generated" with a
// 500, which reads as the tool being broken.
var ErrTooLarge = errors.New("more dismissals than one document carries")

// Statements is one VEX document about one build.
//
// Named for what it carries rather than "Document", because the API's schema
// registry keys types by their bare name and an advisory is a document too —
// two types called the same thing in one schema is a collision that surfaces
// as a panic at start-up rather than as a compile error.
type Statements struct {
	Context string `json:"@context"`
	// ID names this document, and names it the same way every time it is
	// generated for one build. A reader keeps documents by it and tells two
	// revisions of one document from two documents by whether it matches, so
	// it carries the build and nothing that moves.
	ID     string `json:"@id"`
	Author string `json:"author"`
	// Tooling says what wrote it, read from the binary rather than held in a
	// variable something has to remember to set.
	Tooling   string    `json:"tooling"`
	Timestamp time.Time `json:"timestamp"`
	// Version is which revision of this document this is, counting from one.
	// It is one past what has gone out: a document nobody has published is
	// the first, and the next one generated after an issuance is the second.
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
	// ActionStatement is what a holder can do about a flaw that is not going
	// to be fixed. The format requires one on an affected statement, which is
	// why silence is not an option there and why only a claim carrying a
	// mitigation is published as one.
	ActionStatement string `json:"action_statement,omitempty"`
	// ImpactStatement is what stops the flaw, where somebody named it.
	//
	// The mitigation rather than the reasoning. The reasoning is what a
	// triager wrote for a second person to check, addressed to a reader who
	// can see the record it argues against; published it becomes this
	// deployment's review of itself, machine-readable, in front of every
	// customer running a scanner. Where no mitigation was named the field is
	// absent, because the justification beside it is what the format asks for
	// and silence says less wrongly than the wrong text.
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
	// most is how many statements one document carries, or zero for the
	// shipped number. Carried on the store so a test can bring it down to a
	// fixture rather than building a fixture up to it, which is how the
	// routing reach is tested for the same reason.
	most int
	// generated runs between the document being generated and the write that
	// records it. Set by a test that has to commit a second issuance inside
	// that window; nil everywhere else.
	generated func()
}

// NewStore returns a store over db.
func NewStore(db *bun.DB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// NewStoreCarrying returns a store whose documents carry at most most
// statements, for a test that wants the refusal rather than the document.
func NewStoreCarrying(db *bun.DB, most int) *Store {
	s := NewStore(db)
	s.most = most
	return s
}

// carrying is how many statements one document holds.
func (s *Store) carrying() int {
	if s.most > 0 {
		return s.most
	}
	return database.AWholeDocument.Most
}

// For writes the document for one build.
//
// Approved claims only. A proposal is one person's opinion and this
// document is the deployment's word to a customer — the two-person rule is
// what makes publishing a dismissal safe, and a document carrying unapproved
// ones would route around it.
//
// Public findings only. Every statement names an issue and a component in
// something we ship, so a document built from undisclosed work would announce
// the undisclosed work. `undisclosed` includes them for somebody who may read
// them, which is a preview rather than a thing to publish, and it is refused
// for anybody who may not.
//
// Two statuses, and silence for everything else. `not_affected` and `fixed`
// are what a generated VEX document names, and they are the two a customer's
// scanner can act on. A deferral is deliberately absent rather than exported
// as anything: a deferred item exports as affected and never as not-affected,
// and silence already reads as affected in this format, which is the honest
// answer for something we have only postponed.
func (s *Store) For(ctx context.Context, subject access.Subject, who publisher.Named,
	product, stream, variant string, undisclosed bool) (*Statements, error) {

	if !who.Stated() {
		return nil, errNoPublisher
	}
	named, target, err := s.locate(ctx, subject, product, stream, variant)
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
	return s.document(ctx, who, named, target, visible)
}

// errNoPublisher says the deployment has not been told who it publishes as.
//
// Asked by the two acts that build a document, and not by the read of what has
// gone out. That read names no author and assembles nothing, so refusing it
// answers a question nobody asked with a sentence about a field the answer
// does not carry.
var errNoPublisher = errors.New("this deployment has not said who it publishes as, " +
	"so a document has nobody to name as its author")

// locate resolves the build a document is asked for and refuses anybody who
// may not read it.
//
// One place, because generating a document, recording that one went out and
// reading what has all ask the same question of the same names. Asked again it
// is a second set of round trips for an answer already in hand.
func (s *Store) locate(ctx context.Context, subject access.Subject,
	product, stream, variant string) (*catalog.Named, *catalog.Target, error) {

	names := catalog.NewStore(s.db)
	named, err := names.LocateVisible(ctx, subject, product, stream, variant)
	if err != nil {
		return nil, nil, err
	}
	// The document is about the whole build, so asking for it is a
	// product-wide question. The lookup above admits somebody brought into one
	// case here — the names their own issue sits at have to resolve, or the
	// grant refuses them the one thing it gave — and that is not an answer to
	// this one. Asked before the build is resolved any further.
	if !subject.Reads(access.Public, named.ProductID) {
		return nil, nil, access.Denied(
			fmt.Sprintf("read findings in product %d", named.ProductID))
	}
	target, err := names.ExistingTarget(ctx, named.StreamID, named.VariantID)
	if err != nil {
		return nil, nil, err
	}
	return named, target, nil
}

// document assembles what stands about one build, at the visibilities asked
// for.
func (s *Store) document(ctx context.Context, who publisher.Named, named *catalog.Named,
	target *catalog.Target, visible []access.Visibility) (*Statements, error) {

	var rows []struct {
		VulnerabilityID int64     `bun:"vulnerability_id"`
		Identifier      string    `bun:"identifier"`
		Component       string    `bun:"component"`
		Purl            string    `bun:"purl"`
		Outcome         string    `bun:"outcome"`
		DecidedBy       int64     `bun:"decided_by"`
		Justification   string    `bun:"-"`
		Mitigation      string    `bun:"-"`
		DecidedAt       time.Time `bun:"-"`
	}
	// One statement per issue and component, from the claims that stand and
	// have been agreed to. Joined from the findings this build actually holds:
	// a decision is a claim about a product's code and reaches every build
	// whose versions match it, so what belongs in this document is what this
	// build ships rather than everything the product has ever decided.
	err := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		Join(`LEFT JOIN "decision" AS "de" ON de.vulnerability_id = f.vulnerability_id
			AND de.place_identity = f.place_identity
			AND de.product_id = ?
			AND de.state = 'approved'
			AND de.live_key IS NOT NULL
			AND (EXISTS (SELECT 1 FROM "claim" AS "mc"
					WHERE mc.id = de.claim_id AND mc.outcome = 'mismatched')
				OR (COALESCE(de.component_upstream_version, '') =
					COALESCE(NULLIF(c.upstream_version, ''), c.version, '')
				AND COALESCE(de.consumer_upstream_version, '') =
					COALESCE(NULLIF(uc.upstream_version, ''), uc.version, '')))`, named.ProductID).
		// The argument, which is where the outcome lives. The outcome test is
		// part of the join rather than a filter, as it was on the decision:
		// what the counting below asks is whether *every* open place is
		// dismissed, and a filter would drop the places that are not.
		// A claim that will not be fixed joins only where it says what a
		// holder can do instead. The format requires an action on an affected
		// statement, so one without a mitigation has nothing to publish — and
		// left out it falls through to silence, which already reads as
		// affected and is the honest answer.
		Join(`LEFT JOIN "claim" AS "cl" ON cl.id = de.claim_id
			AND (cl.outcome IN ('not-applicable', 'mismatched', 'already-fixed')
				OR (cl.outcome = 'wont-fix' AND COALESCE(cl.mitigation, '') <> ''))`).
		ColumnExpr(`v.id AS "vulnerability_id"`).
		ColumnExpr(`v.identifier AS "identifier"`).
		ColumnExpr(`c.name AS "component"`).
		ColumnExpr(`COALESCE(c.purl, '') AS "purl"`).
		// Safe as an aggregate, because the grouping below refuses a component
		// whose places disagree about the outcome.
		ColumnExpr(`MIN(cl.outcome) AS "outcome"`).
		// The decision the words come from, rather than the words.
		//
		// The earliest of them, which is the claim that has stood longest
		// about this component: where several places were decided separately
		// the document has one thing to say and has to choose which, and the
		// first is the one a reader can check against the record. A decision's
		// identifier is assigned when it is written, so the lowest is the
		// first written.
		//
		// Read off one decision rather than taken column by column. Three
		// independent minima are three answers from three claims: a category
		// from one, the prose explaining a different reason from another, and
		// a timestamp from a third — published, machine-readable, to every
		// customer running a scanner.
		ColumnExpr(`MIN(de.id) AS "decided_by"`).
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
		// counting them is how "all of them" is asked. Without it, one
		// dismissal at one place speaks for a component open at forty-four
		// others — a machine-readable "not affected" about something that is
		// affected, published to every customer running a scanner.
		Having("COUNT(cl.id) = COUNT(*)").
		Having("COUNT(DISTINCT cl.outcome) = 1").
		// One more than the ceiling, so that reaching it is distinguishable
		// from landing on it exactly.
		Limit(s.carrying()+1).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what stands about this build: %w", err)
	}
	// Refused rather than truncated. There is no second request for the rest
	// of a document, and one that stopped at a ceiling would say "nothing is
	// claimed about this" by omission about everything past it — to every
	// customer running a scanner, which is the one thing a document of
	// dismissals must never say.
	//
	// Named, so the caller can answer it as something to narrow rather than as
	// this being broken. Returned bare it fell through to "the document could
	// not be generated" with a 500, and the sentence saying which build and
	// what the limit is went to the log instead of to the person who can act
	// on it.
	if len(rows) > s.carrying() {
		return nil, fmt.Errorf("%w: %s %s %s stands on more than %d agreed claims: a "+
			"document that stopped at the limit would say nothing is claimed about "+
			"everything past it",
			ErrTooLarge, named.Product, named.Stream, named.Variant, s.carrying())
	}

	// The words each of those decisions rests on, read off the decision the
	// statement is about. One statement for the document rather than one per
	// component.
	decided := make([]int64, 0, len(rows))
	for _, row := range rows {
		decided = append(decided, row.DecidedBy)
	}
	said, err := s.wordsOf(ctx, decided)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i].Justification = said[rows[i].DecidedBy].justification
		rows[i].Mitigation = said[rows[i].DecidedBy].mitigation
		rows[i].DecidedAt = said[rows[i].DecidedBy].proposedAt
	}

	// Which revision this is, read from what has gone out for this build.
	// A document generated twice with nothing published in between is the
	// same revision, which is what its identifier staying still says.
	revision, err := s.revision(ctx, target.ID)
	if err != nil {
		return nil, err
	}
	doc := &Statements{
		Context: namespace, ID: identify(who, named), Author: who.Name,
		Tooling:   "OpenPSIRT " + version.Get().Version,
		Timestamp: s.now().UTC(), Version: revision,
		Statements: make([]Statement, 0, len(rows)),
	}
	// The other names each issue goes by. The whole point of the field is that
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

	shipped := build(named)
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
			Status: statusOf(row.Outcome),
		}
		// The same sentence goes in a different field depending on what is
		// being said about it. On a claim that something does not apply it is
		// why, beside the category a machine reads; on one that will not be
		// fixed it is what to do instead, which is the field the format asks
		// for and the reason such a claim is published at all.
		switch statement.Status {
		case "not_affected":
			statement.Justification = row.Justification
			statement.ImpactStatement = row.Mitigation
		case "affected":
			statement.ActionStatement = row.Mitigation
		}
		doc.Statements = append(doc.Statements, statement)
	}

	// Ordered here rather than by the engine, so the document is byte-for-byte
	// the same whatever engine generated it, which is what lets somebody diff
	// two of them and see a real change rather than a reordering.
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
// Only the four a VEX document per build names arrive here. A deferral never
// does: publishing it as not-affected would tell the world we assessed
// something as harmless when we had only postponed it, and silence already
// reads as affected.
//
// A claim that the scanner matched something that is not here publishes as
// not-affected, carrying the reason it states: that the component is absent,
// or that what ships is not the vulnerable code. Both are what the format's
// vocabulary already says, so nothing about the match being ours to correct
// has to be explained to a reader outside.
//
// A claim that will not be fixed is affected rather than dismissed, which is
// what it says: the flaw is there and is staying. It reaches a customer only
// this way — it is a standing property of a shipped feature, so no scan closes
// it and no advisory is issued about it, and under silence it would never be
// said at all.
func statusOf(outcome string) string {
	switch outcome {
	case "already-fixed":
		return "fixed"
	case "wont-fix":
		return "affected"
	default:
		return "not_affected"
	}
}

// identify is what the document calls itself, which is the same string every
// time it is generated for one build.
//
// The publisher's own namespace and the build, and nothing that moves. A
// reader holding two documents tells a revision of one from a second document
// by whether the identifier matches, so an identifier carrying the moment
// answers that question wrongly however finely it is formatted.
//
// The names are the stored ones rather than the ones the request spelled. A
// name people type is matched without regard to capitals, so the same build
// asked for two ways is one document and has to be called one thing.
func identify(who publisher.Named, named *catalog.Named) string {
	return fmt.Sprintf("%s/vex/%s", who.Namespace, build(named))
}

// build is how the thing somebody holds is named in the document.
func build(named *catalog.Named) string {
	return named.Product + ":" + named.Stream + ":" + named.Variant
}

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
	// Split and OR-ed rather than one list. A build with a thousand agreed
	// dismissals is a thousand identifiers here and a large one is far more,
	// and a statement binding them all is refused by two of the four engines.
	where, args := database.InAnyOf("va.vulnerability_id", issues)
	err := s.db.NewSelect().Model((*finding.Alias)(nil)).
		Join(`JOIN "vulnerability" AS "v" ON v.id = va.vulnerability_id`).
		ColumnExpr(`va.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`va.identifier AS "identifier"`).
		Where(where, args...).
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

// words are what one decision claimed, as a statement repeats it.
type words struct {
	justification string
	mitigation    string
	proposedAt    time.Time
}

// wordsOf reads what each of these decisions states for publication.
//
// One statement for the document rather than one per component, and one row per
// decision rather than a column at a time: the category, the mitigation and the
// moment have to come from the same claim, or the document says one thing in
// the field a machine reads and another in the field a person does.
//
// The reasoning is not read here at all. It is written for a second person
// inside this deployment, and the surest way for it not to be published is for
// the query that builds the document never to fetch it.
func (s *Store) wordsOf(ctx context.Context, decisions []int64) (map[int64]words, error) {
	out := map[int64]words{}
	if len(decisions) == 0 {
		return out, nil
	}
	var rows []struct {
		ID            int64     `bun:"id"`
		Justification string    `bun:"justification"`
		Mitigation    string    `bun:"mitigation"`
		ProposedAt    time.Time `bun:"proposed_at"`
	}
	where, args := database.InAnyOf("de.id", decisions)
	if err := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		ColumnExpr(`de.id AS "id"`).
		ColumnExpr(`COALESCE(cl.justification, '') AS "justification"`).
		ColumnExpr(`COALESCE(cl.mitigation, '') AS "mitigation"`).
		ColumnExpr(`de.proposed_at AS "proposed_at"`).
		Where(where, args...).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what these claims say: %w", err)
	}
	for _, row := range rows {
		out[row.ID] = words{
			justification: row.Justification, mitigation: row.Mitigation,
			proposedAt: row.ProposedAt,
		}
	}
	return out, nil
}
