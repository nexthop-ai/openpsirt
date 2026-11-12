// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

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
// "not applicable" decision carries the VEX vocabulary, so the justification
// needs no translation. What makes it safe to publish is the approval the
// decision already required: generating this puts our dismissals in writing,
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
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/triage"
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
var ErrTooLarge = refusal.New("more dismissals than one document carries")

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
	// LastUpdated is when this revision was released, where the document has
	// had more than the one moment it was assembled at: a published document
	// first went out at its timestamp and was last revised at this.
	LastUpdated *time.Time `json:"last_updated,omitempty"`
	// Version is which revision of this document this is, counting from one.
	// It is one past what has gone out: a document nobody has published is
	// the first, and the next one generated after an issuance is the second.
	Version    int         `json:"version"`
	Statements []Statement `json:"statements"`
}

// MarshalJSON writes the document as the format defines it and nothing else.
//
// A type that writes its own bytes is sent as it writes them, so the schema
// link the API framework adds to a response, a key OpenVEX does not define
// naming this deployment's own address, stays out of a document a customer
// is handed.
func (s Statements) MarshalJSON() ([]byte, error) {
	type declared Statements
	return json.Marshal(declared(s))
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
	// to be fixed, or that no fix is planned where the decision named
	// nothing. The format requires one on an affected statement.
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
// about underneath it, or the component of the build that pulls it in where the
// statement is about one occurrence.
//
// The build rather than the component, because a VEX statement is about a
// thing somebody has — and what they have is our image, which happens to
// contain that library. The build is named by its inventory's root, which a
// scanner reading the inventory and this document together matches on.
type Shipped struct {
	ID            string   `json:"@id"`
	Subcomponents []Inside `json:"subcomponents,omitempty"`
}

// Inside is a component of what ships, by its package identifier.
type Inside struct {
	ID string `json:"@id"`
}

// Kind is which document about a build is meant: what this deployment agreed
// to, or that with what suppliers state about their own products beside it.
//
// Each is a document of its own, with an identifier and revisions of its own.
// A toggle on one document would have a reader holding it watch statements
// vanish and return as whoever generated it chose, which reads as a retraction
// nobody made.
type Kind string

const (
	// Ours is what this deployment agreed to and the patches the build
	// declares. The default, because putting a supplier's word under this
	// deployment's name is a choice somebody makes on purpose.
	Ours Kind = "ours"
	// WithSuppliers is that, and beside it what a supplier states about its
	// own product where the statement closed every occurrence of a component in
	// the build, attributed to the supplier.
	WithSuppliers Kind = "with-suppliers"
)

// Kinds are the documents about a build, in the order they are offered.
func Kinds() []Kind { return []Kind{Ours, WithSuppliers} }

// Store writes VEX documents.
type Store struct {
	db  *bun.DB
	now func() time.Time
	// most is how many statements one document carries, or zero for the
	// shipped number. Carried on the store so a test can bring it down to a
	// fixture rather than building a fixture up to it, which is how the
	// assignment rule reach is tested for the same reason.
	most int
	// generated runs between the document being generated and the write that
	// records it. Set by a test that has to commit a second issuance inside
	// that window; nil everywhere else.
	generated func()
	// reads is the transaction a document is generated in, where it is
	// generated for the write that records it, and nil otherwise.
	reads bun.IDB
}

// idb is what a document is read from: the transaction recording it, or the
// database.
func (s *Store) idb() bun.IDB {
	if s.reads != nil {
		return s.reads
	}
	return s.db
}

// within is the store reading from tx, so a document generated for the write
// recording it describes the database that write commits to.
func (s *Store) within(tx bun.IDB) *Store {
	inside := *s
	inside.reads = tx
	return &inside
}

// NewStore returns a store over db.
func NewStore(db *bun.DB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// NewStoreCarrying returns a store whose documents carry at most most
// statements. Zero or less is the ceiling a document is built to hold.
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
// Approved decisions only, besides the build's own patches. A proposal is one
// person's opinion and this document is the deployment's word to a customer —
// the two-person rule is what makes publishing a dismissal safe, and a
// document carrying unapproved ones would route around it. A patch the build
// declares is applied without a decision here, and is said as fixed.
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
	product, branchOrTag, variant string, undisclosed bool, kind Kind) (*Statements, error) {

	if !who.Stated() {
		return nil, ErrNoPublisher
	}
	named, build, err := s.locate(ctx, subject, product, branchOrTag, variant)
	if err != nil {
		return nil, err
	}
	// Disclosed work, and undisclosed work for a preview. Security testing material
	// is never disclosed, so no document carries it.
	// The reader is whoever the document reaches: everybody, for disclosed
	// work, and the person asking, for a preview.
	visible := []access.Visibility{access.Public}
	reader := access.Published([]int64{named.ProductID})
	if undisclosed {
		if !subject.Reads(access.Private, named.ProductID) {
			return nil, access.Denied("read undisclosed work here")
		}
		visible = append(visible, access.Private)
		reader = subject
	}
	return s.document(ctx, who, named, build, visible, reader, kind)
}

// ErrNoPublisher says the deployment has not been told who it publishes as.
//
// Asked by the two acts that build a document, and not by the read of what has
// gone out. That read names no author and assembles nothing, so refusing it
// answers a question nobody asked with a sentence about a field the answer
// does not carry.
var ErrNoPublisher = refusal.New("this deployment has not said who it publishes as, " +
	"so a document has nobody to name as its author")

// locate resolves the build a document is asked for and refuses anybody who
// may not read it.
//
// One place, because generating a document, recording that one went out and
// reading what has all ask the same question of the same names. Asked again it
// is a second set of round trips for an answer already in hand.
func (s *Store) locate(ctx context.Context, subject access.Subject,
	product, branchOrTag, variant string) (*catalog.Named, *catalog.Build, error) {

	names := catalog.NewStore(s.db)
	named, err := names.LocateVisible(ctx, subject, product, branchOrTag, variant)
	if err != nil {
		return nil, nil, err
	}
	// The document is about the whole build, so asking for it is a
	// product-wide question. The lookup above admits somebody brought into one
	// case here — the names their own issue sits at have to resolve, or the
	// grant refuses them the one thing it gave — and that is not an answer to
	// this one. Asked before the build is resolved any further.
	//
	// Asked of disclosed work. A document is disclosed work alone, and a row
	// saying one went out is as much a disclosure as the document, so reading
	// only undisclosed work in the product reaches neither.
	if !subject.Reads(access.Public, named.ProductID) {
		return nil, nil, access.Denied(
			fmt.Sprintf("read disclosed findings in product %d", named.ProductID))
	}
	build, err := names.ExistingBuild(ctx, named.BranchOrTagID, named.VariantID)
	if err != nil {
		return nil, nil, err
	}
	return named, build, nil
}

// document assembles what stands about one build, at the visibilities asked
// for, as the reader it reaches may be told it.
func (s *Store) document(ctx context.Context, who publisher.Named, named *catalog.Named,
	build *catalog.Build, visible []access.Visibility, reader access.Subject,
	kind Kind) (*Statements, error) {

	if kind != Ours && kind != WithSuppliers {
		return nil, refusal.Errorf("%q is not a kind of document this writes", kind)
	}

	// An issue's other names are withheld by the reach of the reader the
	// document reaches. A preview's reader may read undisclosed work in this
	// product, which says nothing of a flaw recorded in another product or at
	// security testing visibility.
	got, err := s.gather(ctx, named, build.ID, gathering{
		visible: visible, reach: &reader, suppliers: kind == WithSuppliers,
	})
	if err != nil {
		return nil, err
	}
	rows, placed, fixed, stated := got.rows, got.placed, got.fixed, got.stated
	said, alsoCalled := got.said, got.alsoCalled

	// Which revision this is, read from what has gone out for this build.
	// A document generated twice with nothing published in between is the
	// same revision, which is what its identifier staying still says.
	revision, err := s.revision(ctx, build.ID, kind)
	if err != nil {
		return nil, err
	}
	doc := &Statements{
		Context: namespace, ID: identify(who, named, kind), Author: who.Name,
		Tooling:   "OpenPSIRT " + version.Get().Version,
		Timestamp: s.now().UTC(), Version: revision,
		Statements: make([]Statement, 0, len(rows)),
	}
	shipped := got.root
	for _, row := range rows {
		statement, err := claimed(Issue{Name: row.Identifier, Aliases: alsoCalled[row.VulnerabilityID]},
			shipped, subject(row.Purl, row.Component), row.Outcome, said[row.DecidedBy])
		if err != nil {
			return nil, err
		}
		doc.Statements = append(doc.Statements, statement)
	}
	// An occurrence stated on its own names what pulls the component in as the
	// product, so a reader applies it beneath that product and nowhere else.
	for _, row := range placed {
		statement, err := claimed(Issue{Name: row.Identifier, Aliases: alsoCalled[row.VulnerabilityID]},
			row.ConsumerPurl, subject(row.Purl, row.Component), row.Outcome, said[row.DecidedBy])
		if err != nil {
			return nil, err
		}
		doc.Statements = append(doc.Statements, statement)
	}
	for _, row := range fixed {
		doc.Statements = append(doc.Statements, Statement{
			Vulnerability: Issue{Name: row.Identifier, Aliases: alsoCalled[row.VulnerabilityID]},
			Timestamp:     row.PatchedAt.UTC(),
			Products: []Shipped{{
				ID: shipped, Subcomponents: []Inside{{ID: subject(row.Purl, row.Component)}},
			}},
			Status: "fixed",
		})
	}

	// What suppliers state. An agreed decision is said only of a component with
	// an occurrence open, and a supplier's statement only of one with none, so the
	// two never speak about one issue in one component.
	for _, row := range stated {
		doc.Statements = append(doc.Statements, Statement{
			Vulnerability: Issue{Name: row.Identifier, Aliases: alsoCalled[row.VulnerabilityID]},
			Timestamp:     row.ClosedAt.UTC(),
			Products: []Shipped{{
				ID: shipped, Subcomponents: []Inside{{ID: subject(row.Purl, row.Component)}},
			}},
			Status:          "not_affected",
			Justification:   known(row.Justification),
			ImpactStatement: row.attributed(),
		})
	}

	// Ordered here rather than by the engine, so the document is byte-for-byte
	// the same whatever engine generated it, which is what lets somebody diff
	// two of them and see a real change rather than a reordering.
	sort.Slice(doc.Statements, func(i, j int) bool {
		a, b := doc.Statements[i], doc.Statements[j]
		if a.Vulnerability.Name != b.Vulnerability.Name {
			return a.Vulnerability.Name < b.Vulnerability.Name
		}
		if a.Products[0].Subcomponents[0].ID != b.Products[0].Subcomponents[0].ID {
			return a.Products[0].Subcomponents[0].ID < b.Products[0].Subcomponents[0].ID
		}
		return a.Products[0].ID < b.Products[0].ID
	})
	return doc, nil
}

// gathering is what one build's statements are read at: the visibilities,
// the reader whose reach withholds an issue's other names, nil to withhold
// none, and which further kinds of statement are read.
type gathering struct {
	visible   []access.Visibility
	reach     *access.Subject
	suppliers bool
	affected  bool
}

// gathered is what one build's statements are made from.
type gathered struct {
	rows     []finding.CoveredGroup
	placed   []finding.OccurrenceCovered
	affected []finding.AffectedGroup
	fixed    []fixedByPatch
	stated   []statedBySupplier
	// said is the words of each decision a statement rests on, by the
	// occurrence it decided.
	said map[int64]finding.Stated
	// alsoCalled is each issue's other names, less those withheld.
	alsoCalled map[int64][]string
	// root is what the build's statements name as the product.
	root string
}

// gather reads what one build's statements are made from, the per-build
// document and the published facts alike, so a rule about what a statement
// rests on or withholds holds for both.
//
// One statement per issue and component, from the decisions that stand and
// have been agreed to. Read from the findings this build actually holds: a
// decision is about a product's code and reaches every build whose versions
// match it, so what belongs is what this build ships rather than everything
// the product has ever decided.
//
// Grouped by the issue and the component and nothing about the decision,
// because a statement is about a product and a component and the format has
// no finer grain to say it at. Two occurrences decided in separate sittings
// differ in when and in what was written, and grouping on those emits the same
// decision twice, or, where the outcomes differ, two statements contradicting
// each other about one component. Where a component's occurrences disagree,
// each occurrence a decision covers is stated on its own, naming what pulls the
// component in as the product.
func (s *Store) gather(ctx context.Context, named *catalog.Named, buildID int64,
	at gathering) (*gathered, error) {

	got := &gathered{}
	var err error
	if got.rows, got.placed, err = finding.CoveredInBuild(ctx, s.idb(), named.ProductID, buildID,
		at.visible, s.carrying()); err != nil {
		return nil, err
	}
	if at.affected {
		if got.affected, err = finding.AffectedInBuild(ctx, s.idb(), named.ProductID, buildID,
			at.visible, s.carrying()); err != nil {
			return nil, err
		}
	}
	if got.fixed, err = s.patched(ctx, buildID, at.visible); err != nil {
		return nil, err
	}
	if at.suppliers {
		if got.stated, err = s.disclaimed(ctx, buildID, at.visible); err != nil {
			return nil, err
		}
	}
	// Refused rather than truncated. There is no second request for the rest
	// of a document, and one that stopped at a ceiling would say "nothing is
	// claimed about this" by omission about everything past it, to every
	// customer running a scanner. Named, so the caller answers it as something
	// to narrow and the sentence saying which build and what the limit is
	// reaches the person who can act on it.
	if len(got.rows)+len(got.placed)+len(got.affected)+len(got.fixed)+len(got.stated) > s.carrying() {
		return nil, fmt.Errorf("%w: %s %s %s states more than %d statements: a "+
			"document that stopped at the limit would say nothing is claimed about "+
			"everything past it",
			ErrTooLarge, named.Product, named.BranchOrTag, named.Variant, s.carrying())
	}

	// The words each decision rests on, read off the decision the statement
	// is about.
	decided := make([]int64, 0, len(got.rows)+len(got.placed)+len(got.affected))
	issues := make([]int64, 0, len(got.rows)+len(got.placed)+len(got.affected)+
		len(got.fixed)+len(got.stated))
	for _, row := range got.rows {
		decided, issues = append(decided, row.DecidedBy), append(issues, row.VulnerabilityID)
	}
	for _, row := range got.placed {
		decided, issues = append(decided, row.DecidedBy), append(issues, row.VulnerabilityID)
	}
	for _, row := range got.affected {
		decided, issues = append(decided, row.DecidedBy), append(issues, row.VulnerabilityID)
	}
	for _, row := range got.fixed {
		issues = append(issues, row.VulnerabilityID)
	}
	for _, row := range got.stated {
		issues = append(issues, row.VulnerabilityID)
	}
	if got.said, err = finding.StatedBy(ctx, s.idb(), decided); err != nil {
		return nil, err
	}
	// The other names each issue goes by: a customer's scanner matches under
	// the name its database uses, which is often not the one filed under here.
	if got.alsoCalled, err = s.namesOf(ctx, issues); err != nil {
		return nil, err
	}
	// No other name of an issue that a flaw of ours recorded out of the
	// reader's reach wrote onto it is published: one of them is the name
	// minted for it.
	if at.reach != nil {
		withheld, err := finding.RecordedOutOfReach(ctx, s.idb(), *at.reach, issues)
		if err != nil {
			return nil, err
		}
		for issue := range withheld {
			delete(got.alsoCalled, issue)
		}
	}
	if got.root, err = s.rootOf(ctx, named, buildID); err != nil {
		return nil, err
	}
	return got, nil
}

// fixedByPatch is an issue a patch the build declares has fixed in one
// component.
type fixedByPatch struct {
	VulnerabilityID int64
	Identifier      string
	Component       string
	Purl            string
	PatchedAt       time.Time
}

// patched reads what the build's own patches fix, which is said as fixed.
//
// The build's word stands without a decision here, so what it fixes is
// published beside what this deployment agreed to. A statement is made only
// while all of these hold:
//
//   - the component still ships in this build
//   - no occurrence of a component of that name and package identifier is open
//     against the issue
//   - the claim that closed it is one the build still makes
//
// A build that drops the patch reopens the finding, and the statement goes
// with it.
func (s *Store) patched(ctx context.Context, buildID int64,
	visible []access.Visibility) ([]fixedByPatch, error) {

	rows, err := s.closed(ctx, buildID, visible, finding.Patched)
	if err != nil {
		return nil, fmt.Errorf("read what the build's patches fix: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	ids := make([]int64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.First)
	}
	var dated []struct {
		ID       int64     `bun:"id"`
		ClosedAt time.Time `bun:"closed_at"`
	}
	where, args := database.InAnyOf(`"f"."id"`, ids)
	if err := s.idb().NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`"f"."id" AS "id"`).
		ColumnExpr(`"f"."closed_at" AS "closed_at"`).
		Where(where, args...).
		Scan(ctx, &dated); err != nil {
		return nil, fmt.Errorf("read when the build's patches were seen: %w", err)
	}
	when := make(map[int64]time.Time, len(dated))
	for _, row := range dated {
		when[row.ID] = row.ClosedAt
	}

	return datedFixes(rows, when), nil
}

// datedFixes states each group fixed as of the moment its first finding
// closed. A group whose finding the second read missed is left out, as a
// supplier's statement is: a fix dated the zero moment is a claim nobody made.
func datedFixes(rows []closedGroup, when map[int64]time.Time) []fixedByPatch {
	fixed := make([]fixedByPatch, 0, len(rows))
	for _, row := range rows {
		at, found := when[row.First]
		if !found {
			continue
		}
		fixed = append(fixed, fixedByPatch{
			VulnerabilityID: row.VulnerabilityID, Identifier: row.Identifier,
			Component: row.Component, Purl: row.Purl, PatchedAt: at,
		})
	}
	return fixed
}

// known is a supplier's justification where it is one the format defines, and
// nothing otherwise. A supplier's document is not checked against the
// vocabulary as it is read, and this document publishes it under this
// deployment's name; the impact statement beside it satisfies the format
// without one.
func known(justification string) string {
	for _, each := range triage.Justifications() {
		if string(each) == justification {
			return justification
		}
	}
	return ""
}

// statedBySupplier is an issue a supplier's statement about its own product
// closed at every occurrence of one component in the build.
type statedBySupplier struct {
	VulnerabilityID int64
	Identifier      string
	Component       string
	Purl            string
	Publisher       string
	Product         string
	Version         string
	Justification   string
	Statement       string
	Document        string
	ClosedAt        time.Time
}

// attributed is what the supplier said, in their name: whose statement it is,
// which product of theirs it is about, the document it is in, and their words.
func (s statedBySupplier) attributed() string {
	product := s.Product
	if s.Version != "" {
		product += " " + s.Version
	}
	said := fmt.Sprintf("Per %s, in %s: %s is not affected.", s.Publisher, s.Document, product)
	if s.Statement != "" {
		said += " " + s.Statement
	}
	return said
}

// disclaimed reads what suppliers' statements about their own products, and an
// upstream's statements that a component is not affected, close in this
// build, which the document carrying them says as not affected.
//
// Under the guard the build's own patches stand under, and for the same
// reason: the format says "this product, this component, not affected", so a
// statement is made only while all of these hold:
//
//   - the component still ships in this build
//   - no occurrence of a component of that name and package identifier is open
//     against the issue
//   - the statement that closed it still stands
//   - nothing has been recorded at its occurrence since, the build's own patch
//     included
//   - no other supplier's statement closed an occurrence of it
func (s *Store) disclaimed(ctx context.Context, buildID int64,
	visible []access.Visibility) ([]statedBySupplier, error) {

	rows, err := s.closed(ctx, buildID, visible, finding.Disclaimed)
	if err != nil {
		return nil, fmt.Errorf("read what suppliers' statements close: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	ids := make([]int64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.First)
	}
	var read []supplierWords
	where, args := database.InAnyOf(`"f"."id"`, ids)
	if err := s.idb().NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "received_vex_statement" AS "ss" ON "ss"."id" = "f"."stated_by"`).
		Join(finding.WordsJoin("ss")).
		ColumnExpr(`"f"."id" AS "id"`).
		ColumnExpr(`"f"."closed_at" AS "closed_at"`).
		ColumnExpr(`"ss"."publisher" AS "publisher"`).
		ColumnExpr(`COALESCE("ss"."within", "ss"."component") AS "product"`).
		ColumnExpr(`COALESCE("ss"."within_about", "ss"."about") AS "version"`).
		ColumnExpr(`COALESCE("ss"."justification", '') AS "justification"`).
		ColumnExpr(finding.WordsColumn+` AS "statement"`).
		ColumnExpr(`"ss"."document" AS "document"`).
		Where(where, args...).
		Scan(ctx, &read); err != nil {
		return nil, fmt.Errorf("read the statements that closed them: %w", err)
	}
	return attributedTo(rows, read), nil
}

// supplierWords is the statement that closed one finding, and when it did.
type supplierWords struct {
	ID            int64     `bun:"id"`
	ClosedAt      time.Time `bun:"closed_at"`
	Publisher     string    `bun:"publisher"`
	Product       string    `bun:"product"`
	Version       string    `bun:"version"`
	Justification string    `bun:"justification"`
	Statement     string    `bun:"statement"`
	Document      string    `bun:"document"`
}

// attributedTo states each group in the words of the statement that closed
// its first finding. A group whose finding the second read did not find is
// left out: the two reads are separate, and stating it in the words of
// whichever statement came first would put one supplier's name on another's
// product.
func attributedTo(rows []closedGroup, read []supplierWords) []statedBySupplier {
	byID := make(map[int64]int, len(read))
	for i, row := range read {
		byID[row.ID] = i
	}
	stated := make([]statedBySupplier, 0, len(rows))
	for _, row := range rows {
		at, found := byID[row.First]
		if !found {
			continue
		}
		one := read[at]
		stated = append(stated, statedBySupplier{
			VulnerabilityID: row.VulnerabilityID, Identifier: row.Identifier,
			Component: row.Component, Purl: row.Purl,
			Publisher: one.Publisher, Product: one.Product, Version: one.Version,
			Justification: one.Justification, Statement: one.Statement,
			Document: one.Document, ClosedAt: one.ClosedAt,
		})
	}
	return stated
}

// statusOf turns an outcome into what the format calls it, and is empty for
// an outcome the format is not told about.
//
// Only the four a VEX document per build names arrive here. A deferral never
// does: publishing it as not-affected would tell the world we assessed
// something as harmless when we had only postponed it, and silence already
// reads as affected. An outcome missing from the table is refused rather
// than published under a default, because the only safe default on a
// published document is to say nothing.
//
// A decision that the scanner matched something that is not here publishes as
// not-affected, carrying the reason it states: that the component is absent,
// or that what ships is not the vulnerable code. Both are what the format's
// vocabulary already says, so nothing about the match being ours to correct
// has to be explained to a reader outside.
//
// A decision that it will not be fixed is affected rather than dismissed, which is
// what it says: the flaw is there and is staying. It reaches a customer only
// this way — it is a standing property of a shipped feature, so no scan closes
// it and no advisory is issued about it, and under silence it would never be
// said at all.
func statusOf(outcome string) string {
	return statuses[outcome]
}

// statuses is the format's status for each outcome a document states.
var statuses = map[string]string{
	finding.OutcomeNotApplicable: NotAffected,
	finding.OutcomeMismatched:    NotAffected,
	finding.OutcomeAlreadyFixed:  Fixed,
	finding.OutcomeWontFix:       Affected,
}

// subject is what a statement names the component by: its package
// identifier, or where it has none, the name the build calls it.
//
// Less use to a machine and better than dropping the statement: the reader can
// still match it by hand, and a silent omission reads as "no claim", which is
// the one thing this document must not say by accident.
func subject(purl, component string) string {
	if purl == "" {
		return component
	}
	return purl
}

// fields is what an agreed decision states, field by field: its status, and
// the words that go with that status.
type fields struct {
	status, justification, impact, action string
}

// fieldsOf is what an agreed decision states, by its outcome and the words it
// rests on.
//
// The same sentence goes in a different field depending on what is being said
// about it. On a decision that something does not apply it is why, beside the
// category a machine reads; on one that will not be fixed it is what to do
// instead, which is the field the format asks for.
//
// A decision that will not be fixed and names nothing to do instead says that
// no fix is planned: both formats require an action on an affected statement,
// and the reasoning behind the decision is a triager's argument to a second
// person, never published.
func fieldsOf(outcome string, words finding.Stated) (fields, error) {
	out := fields{status: statusOf(outcome)}
	switch out.status {
	case "":
		return fields{}, fmt.Errorf("outcome %q has no VEX status", outcome)
	case NotAffected:
		out.justification = words.Justification
		out.impact = words.Mitigation
	case Affected:
		out.action = words.Mitigation
		if strings.TrimSpace(out.action) == "" {
			out.action = NoFixPlanned
		}
	}
	return out, nil
}

// claimed is the statement an agreed decision makes about one component beneath
// one product, in the words the decision it rests on states.
func claimed(issue Issue, product, about, outcome string, words finding.Stated) (Statement, error) {
	stated, err := fieldsOf(outcome, words)
	if err != nil {
		return Statement{}, err
	}
	return Statement{
		Vulnerability: issue,
		Timestamp:     words.ProposedAt.UTC(),
		Products:      []Shipped{{ID: product, Subcomponents: []Inside{{ID: about}}}},
		Status:        stated.status, Justification: stated.justification,
		ImpactStatement: stated.impact, ActionStatement: stated.action,
	}, nil
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
//
// The document carrying suppliers' statements is a second document, so it is
// called something else.
func identify(who publisher.Named, named *catalog.Named, kind Kind) string {
	if kind == WithSuppliers {
		return fmt.Sprintf("%s/vex/%s/%s", who.Namespace, build(named), WithSuppliers)
	}
	return fmt.Sprintf("%s/vex/%s", who.Namespace, build(named))
}

// build is how the thing somebody holds is named in the document's identifier.
func build(named *catalog.Named) string {
	return named.Product + ":" + named.BranchOrTag + ":" + named.Variant
}

// rootOf is how a statement names the build: the package identifier its
// inventory gave its root, which is what a scanner reading the two together
// matches the product against, and what a deployment loading both reads as the
// build's own claim. The build's names stand in where the inventory named no
// root by a package identifier that states a version.
func (s *Store) rootOf(ctx context.Context, named *catalog.Named, buildID int64) (string, error) {
	var root string
	err := s.idb().NewSelect().
		TableExpr(`"build" AS "t"`).
		Join(`JOIN "scan" AS "sc" ON "sc"."id" = "t"."last_scan_id"`).
		ColumnExpr(`COALESCE("sc"."root_identifier", '')`).
		Where(`"t"."id" = ?`, buildID).
		Scan(ctx, &root)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("read how the build names itself: %w", err)
	}
	// An identifier naming no version names every release of the product,
	// and a reader applies a statement about it to all of them.
	if _, version := graph.PackageOf(root); version == "" {
		return build(named), nil
	}
	return root, nil
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
	where, args := database.InAnyOf(`"va"."vulnerability_id"`, issues)
	err := s.idb().NewSelect().Model((*finding.Alias)(nil)).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "va"."vulnerability_id"`).
		ColumnExpr(`"va"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"va"."identifier" AS "identifier"`).
		Where(where, args...).
		// The other names, so not the one the statement is already
		// filed under. The alias table holds every name an issue
		// answers to including its own, which is what makes identity
		// span them ; a document repeating the primary in its own
		// alias list says nothing and reads as a mistake.
		Where(`"va"."identifier" <> "v"."identifier"`).
		OrderExpr(`"va"."identifier"`).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what these issues are also called: %w", err)
	}
	for _, row := range rows {
		out[row.VulnerabilityID] = append(out[row.VulnerabilityID], row.Identifier)
	}
	return out, nil
}
