// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// Statement is what a third party's document says about a component we ship.
//
// A third layer beside the build's own claims and our decisions: evidence, and
// a prefill. A supplier's statement that its own product is not affected is
// also applied, by the run, at the places that product occupies (REQ-31).
type Statement struct {
	bun.BaseModel `bun:"table:vex_statement,alias:ss"`

	ID        int64 `bun:"id,pk,autoincrement"`
	ProductID int64 `bun:"product_id,notnull"`
	// Publisher is who published it and Vulnerability and Component what
	// it is about. All three are normalized on the way in, so a match is
	// an equality test rather than something an engine is asked to fold —
	// the four fold differently outside ASCII, and asking them to would
	// make whether a statement attaches to a finding depend on which one
	// is running. It also leaves the index over these columns usable,
	// which wrapping them in a function did not.
	Publisher     string `bun:"publisher,notnull"`
	Vulnerability string `bun:"vulnerability,notnull"`
	Purl          string `bun:"purl"`
	Component     string `bun:"component,notnull"`
	// About is which version the publisher spoke about, where they named one.
	// Stored rather than read back out of the identifier: a publisher that
	// states products and no package identifier states the version as the
	// branch its product sits in, and there is nothing to read it out of.
	About string `bun:"about,notnull"`
	// WithinPurl, Within and WithinAbout are the product the component ships
	// inside, where the document named one: its package identifier, its name,
	// folded, and the version it was stated at. A supplier speaking about its
	// own product speaks about what sits inside it, so these are what place
	// the statement in a build. All three empty where the document named the
	// component alone.
	WithinPurl  string `bun:"within_purl,nullzero"`
	Within      string `bun:"within,nullzero"`
	WithinAbout string `bun:"within_about,nullzero"`
	// Placement is what the statement names its supplier's product as:
	// PlacedInside, PlacedProduct, or empty for a package named alone and for
	// a statement recorded before it was read. Only a placed statement closes
	// anything (REQ-31).
	Placement string `bun:"placement,nullzero"`
	// Status is what they said in the format's own vocabulary, Justification
	// the term they gave for it, and Statement the reasoning — which is the
	// part worth having, because the status is in the fix state already.
	Status        string `bun:"status,notnull"`
	Justification string `bun:"justification"`
	Statement     string `bun:"statement"`
	// Source is which kind of document carried it and Identifier the name the
	// publisher gave that document, where it carries one. Together they are
	// what a later upload supersedes on, and Identifier is what a reader
	// recognizes an advisory by — a file name is what a client called it.
	Source     string `bun:"source,notnull"`
	Identifier string `bun:"document_id"`
	// Document and Digest say which file it arrived as and what it hashed to,
	// so a revision can be noticed rather than silently replacing what an
	// approval was granted against.
	Document   string     `bun:"document,notnull"`
	Digest     string     `bun:"digest,notnull"`
	UploadedBy int64      `bun:"uploaded_by,notnull"`
	UploadedAt time.Time  `bun:"uploaded_at,notnull"`
	Superseded *time.Time `bun:"superseded_at"`
}

// StatementOf is one claim a document makes, about one of the components it
// names, in the shape it is recorded in.
//
// One constructor for the upload path and the supplier path, so the two record
// the same columns from the same claim.
func StatementOf(claim sbom.Suppression, at sbom.Target) Statement {
	said := Statement{
		Vulnerability: claim.Vulnerability,
		Purl:          at.Purl,
		About:         at.VersionNamed(),
		Component:     at.ComponentNamed(),
		Status:        string(claim.Status),
		Justification: claim.Justification,
		Statement:     claim.Statement,
	}
	switch {
	case at.Within != nil:
		said.WithinPurl = at.Within.Purl
		said.Within = at.Within.ComponentNamed()
		said.WithinAbout = at.Within.VersionNamed()
		said.Placement = PlacedInside
	case !packaged(at.Purl):
		said.Placement = PlacedProduct
	}
	return said
}

// What a statement names its supplier's product as.
const (
	// PlacedInside is a component inside a product the document named.
	PlacedInside = "inside"
	// PlacedProduct is a product named alone, by no package identifier: an
	// equipment vendor's appliance, or a product spelled as a source tree.
	PlacedProduct = "product"
)

// packaged reports whether a target is named by the package identifier of an
// ecosystem's package, which a distribution's own build and a rebuild of its
// source share, rather than as a product.
func packaged(purl string) bool {
	parts := graph.PartsOfPurl(purl)
	return parts.Name != "" && parts.Type != sourceTree
}

// The two kinds of document a third party's judgment arrives in.
//
// They differ in what a later upload replaces, which is a property of the
// document rather than of the claims inside it: a statement set is a
// publisher's whole answer and an advisory is one announcement among hundreds.
const (
	// FromVex is a VEX document — OpenVEX or the CSAF VEX profile.
	FromVex = "vex"
	// FromAdvisory is a supplier's CSAF security advisory.
	FromAdvisory = "advisory"
)

// Supplied is where a set of statements came from.
//
// The key a later upload supersedes on travels with the claims rather than
// being worked out beside them, so that no caller can record an advisory under
// a statement set's key.
type Supplied struct {
	// Source is FromVex or FromAdvisory, and Identifier the name the publisher
	// gave the document. An advisory carries one and a statement set does not:
	// a publisher issues one statement set and hundreds of advisories.
	//
	// The identifier is matched exactly rather than folded. It is an identity
	// a provider hands over, read out of the document every time, so two
	// spellings of it never arrive; the publisher is a name somebody may type
	// into the other path and is folded there.
	Source     string
	Identifier string
	// Publisher is whose judgment it is, Document the file it arrived as and
	// Digest what that file hashed to.
	Publisher string
	Document  string
	Digest    string
}

// Sources are the kinds of document a third party's judgment arrives in, in
// the order they were built.
//
// Named here because the API offers it as a closed vocabulary, and a list
// retyped beside a route is one that drifts from what the store writes.
func Sources() []string {
	return []string{FromVex, FromAdvisory}
}

// VexStatuses are the statuses the exchange format defines, in its own order.
//
// The format's vocabulary rather than ours, named here because two things
// depend on it: what a caller may narrow a list by, and which of them offers a
// prefill.
func VexStatuses() []string {
	return []string{"not_affected", "affected", "fixed", "under_investigation"}
}

// BuildSayings are what the build's own claims say about an open finding, in
// the format's vocabulary. A claim that the shipped code is fixed closes every
// finding it covers, so it is never one an open finding is narrowed by.
func BuildSayings() []string {
	return []string{"not_affected", "affected", "under_investigation"}
}

// OutcomesOffered are the outcomes a publisher's statement can prefill.
//
// Derived from the mapping rather than listed beside it: a status that starts
// offering something, or stops, changes this without anybody remembering to
// edit a second list.
func OutcomesOffered() []string {
	var offered []string
	for _, status := range VexStatuses() {
		if outcome, offers := (Statement{Status: status}).Prefills(); offers {
			offered = append(offered, outcome)
		}
	}
	return offered
}

// Prefills is the outcome a statement offers, and whether it offers one.
//
// A distribution saying it will not fix something is not the distribution
// saying it is not affected. Debian's `no-dsa`, Ubuntu's `ignored`
// and Red Hat's will-not-fix all mean *affected, and judged minor* — so they
// offer a will-not-fix, never a dismissal. Prefilling `not-applicable` from one
// would record a claim the publisher never made, with their name on it, which
// is the one way a third party's evidence turns into a lie rather than into
// help.
func (s Statement) Prefills() (outcome string, offers bool) {
	switch s.Status {
	case "not_affected":
		// The one status that *is* a claim of non-applicability, and the
		// justification is the publisher's own term from the same vocabulary
		// ours uses.
		return "not-applicable", true
	case "affected":
		// They say it applies and they are not fixing it here, which is a
		// will-not-fix in our vocabulary and never a dismissal.
		return "wont-fix", true
	case "fixed":
		return "already-fixed", true
	}
	// Under investigation offers nothing: it is a publisher saying they do not
	// know yet, and a prefill from it would be a judgment nobody made.
	return "", false
}

// PrefillsFor is the outcome a statement offers for a component at a version.
//
// A statement naming a version is about that version. A publisher saying a
// vulnerability is fixed in 1.1.1k is not saying anything about 1.1.1j, and an
// advisory says exactly this for a living: it exists to name the version that
// carries the fix. Offered against a different version it would record a claim
// the publisher never made, with their name on it.
//
// A statement naming no version is about whatever is shipped, which the format
// says and which is how a publisher states something about a family. Those
// offer what the status offers.
//
// The statement is still shown either way. Which versions a publisher spoke
// about is what a triager reading the evidence wants; what changes here is
// only whether a control comes prefilled with somebody else's answer.
func (s Statement) PrefillsFor(version string) (outcome string, offers bool) {
	outcome, offers = s.Prefills()
	if !offers {
		return "", false
	}
	said := s.About
	if said == "" || said == strings.TrimSpace(version) {
		return outcome, true
	}
	return "", false
}

// valid refuses a document whose key would collapse into somebody else's.
//
// Refused in the store as well as at the endpoint, because this is reachable
// from any other caller and every one of these is a key rather than a label.
func (from Supplied) valid() error {
	switch from.Source {
	case FromVex:
		if from.Identifier != "" {
			return refusal.Errorf("a statement set is a publisher's whole answer and is " +
				"replaced as one, so it is not identified by a document name")
		}
	case FromAdvisory:
		if strings.TrimSpace(from.Identifier) == "" {
			return refusal.Errorf("an advisory is replaced by the name its publisher gave " +
				"it, and this one carries none")
		}
		if utf8.RuneCountInString(from.Identifier) > MostDocumentName {
			return refusal.Errorf("the name the publisher gave it is longer than the %d "+
				"characters this records", MostDocumentName)
		}
	default:
		return refusal.Errorf("a document of kind %q, which is not one this records",
			from.Source)
	}
	if strings.TrimSpace(from.Publisher) == "" {
		return refusal.Errorf("a statement is somebody's, and this document names nobody")
	}
	if utf8.RuneCountInString(from.Publisher) > MostPublisher {
		return refusal.Errorf("who published it is longer than the %d characters this records",
			MostPublisher)
	}
	return nil
}

// RecordStatements replaces what one publisher has said about one product in
// one document.
//
// Superseded rather than deleted: what an approval was granted on the strength
// of has to stay readable, which is the same reason a withdrawn decision is a
// state rather than a delete. What this document replaces is set aside and
// what it says is written — so "they changed their mind" is a fact the record
// holds rather than one it silently loses.
//
// What it replaces is the document's own kind. A publisher's statement set is
// their whole answer, so a later one replaces the one before it. One of their
// advisories is one announcement among hundreds, so it replaces the advisory
// of the same name and leaves the rest of what they have published standing —
// and neither kind touches the other, because uploading a publisher's
// statement set would otherwise set aside every advisory of theirs on record.
//
// A claim the document repeats word for word keeps its row and stands in the
// new document. Only a claim it no longer makes is set aside.
func (s *Store) RecordStatements(ctx context.Context, by access.Subject, productID int64,
	from Supplied, said []Statement) (recorded, superseded int, err error) {

	if err := from.valid(); err != nil {
		return 0, 0, err
	}
	publisher := strings.ToLower(strings.TrimSpace(from.Publisher))
	identifier := strings.TrimSpace(from.Identifier)
	now := s.now().UTC().Truncate(time.Microsecond)
	err = database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		recorded, superseded = 0, 0

		for i := range said {
			said[i].Vulnerability = folded(said[i].Vulnerability)
			said[i].Component = folded(said[i].Component)
			said[i].Within = folded(said[i].Within)
		}

		// The same bytes read the same way change nothing, so nothing is
		// written. Where the reading of the same bytes differs from what
		// stands, the reading is recorded below, so uploading a document again
		// is how rows stored under an earlier reading are brought up to date.
		var standing []Statement
		err := tx.NewSelect().Model(&standing).
			Column("id", "vulnerability", "purl", "component", "about", "within_purl", "within",
				"within_about", "placement", "status", "justification", "statement").
			Where("product_id = ?", productID).
			Where("publisher = ?", publisher).
			Where("source = ?", from.Source).
			Where("document_id = ?", identifier).
			Where("digest = ?", from.Digest).
			Where("superseded_at IS NULL").
			Scan(ctx)
		if err != nil {
			return fmt.Errorf("ask what is already held: %w", err)
		}
		if len(standing) > 0 && sameReading(standing, said) {
			// What the document says is what the record already holds.
			recorded = len(standing)
			return nil
		}
		// What stands under this document's key, whatever bytes it arrived
		// as. A claim the document repeats word for word keeps its row, brought
		// up to date with the document it now stands in and where it places
		// its supplier's product. Only a claim the document no longer makes is
		// set aside, because a superseded claim is what tells everyone holding
		// an approved decision that cited it that the publisher changed what
		// they published — and repeated, they did not. A fetched advisory's
		// digest covers which of its claims were kept as well as its bytes, so
		// the same advisory read again differs in digest whenever the product
		// ships something it did not.
		var held []Statement
		heldBy := tx.NewSelect().Model(&held).
			Column("id", "vulnerability", "purl", "component", "about", "within_purl", "within",
				"within_about", "placement", "status", "justification", "statement").
			Where("product_id = ?", productID).
			Where("publisher = ?", publisher).
			Where("source = ?", from.Source).
			Where("superseded_at IS NULL")
		if from.Source == FromAdvisory {
			heldBy = heldBy.Where("document_id = ?", identifier)
		}
		if err := heldBy.Scan(ctx); err != nil {
			return fmt.Errorf("ask what they said before: %w", err)
		}
		repeated, gone, fresh := pairRepeated(held, said)

		err = database.IDsInBatches(ctx, gone, func(ctx context.Context, batch []int64) error {
			_, err := tx.NewUpdate().Model((*Statement)(nil)).
				Set("superseded_at = ?", now).
				Where("id IN (?)", bun.List(batch)).Exec(ctx)
			return err
		})
		if err != nil {
			return fmt.Errorf("set aside what they said before: %w", err)
		}
		superseded = len(gone)

		for placed, ids := range repeated {
			err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
				_, err := tx.NewUpdate().Model((*Statement)(nil)).
					Set("within_purl = ?", nullable(placed.WithinPurl)).
					Set("within = ?", nullable(placed.Within)).
					Set("within_about = ?", nullable(placed.WithinAbout)).
					Set("placement = ?", nullable(placed.Placement)).
					Set("document = ?", from.Document).
					Set("digest = ?", from.Digest).
					Set("restated_at = ?", now).
					Where("id IN (?)", bun.List(batch)).Exec(ctx)
				return err
			})
			if err != nil {
				return fmt.Errorf("keep what they said again: %w", err)
			}
			recorded += len(ids)
		}

		said = fresh
		for i := range said {
			// The store assigns identity, so a key on the way in is cleared
			// rather than stated. The engine writes the key it assigned back
			// into the value it inserted, and this closure is re-run whole
			// when a transaction is retried — so a second attempt over the
			// same claims would state keys the first attempt was given, and
			// the write that a retry exists to repeat is the one that cannot
			// happen twice.
			said[i].ID = 0
			said[i].ProductID = productID
			said[i].Publisher = publisher
			said[i].Source, said[i].Identifier = from.Source, identifier
			said[i].Document, said[i].Digest = from.Document, from.Digest
			said[i].UploadedBy, said[i].UploadedAt = by.ID, now
			said[i].Superseded = nil
		}
		// Written in batches rather than one statement each. A publisher's
		// statement set is a few thousand claims and one real security
		// advisory about a kernel is 95,139, so the round trips are the whole
		// cost. That advisory, a row at a time: 27.9 seconds on PostgreSQL,
		// 10.0 on MariaDB, 9.0 on MySQL, 7.3 on SQLite. In batches: 5.4, 1.2,
		// 1.4 and 1.3. The caller is waiting on the answer, so this is a
		// request rather than a background pass.
		//
		// The batch is sized for the narrowest engine rather than for the
		// fastest: PostgreSQL binds at most 65,535 parameters in one
		// statement.
		for from := 0; from < len(said); from += statementsPerInsert {
			to := min(from+statementsPerInsert, len(said))
			batch := said[from:to]
			if _, err := tx.NewInsert().Model(&batch).Exec(ctx); err != nil {
				return fmt.Errorf("record what they said: %w", err)
			}
			recorded += len(batch)
		}
		return nil
	})
	return recorded, superseded, err
}

// SaidAbout is what VEX publishers have said about one issue at one component
// in one build, newest first, standing statements only.
//
// Matched on the issue's name and its aliases, because which identifier a
// publisher chose is a preference of whichever database they consulted.
//
// A statement naming the product a component ships inside, where this product
// ships that product, is about the component where it sits inside it: evidence
// where the product is above the component in this build and nowhere else
// (REQ-31). A product this product does not ship, such as the platform a
// distribution composes its packages into, places nothing, and its statement
// is evidence by package. A statement naming a product alone is evidence on
// the product and on whatever sits beneath it.
func (s *Store) SaidAbout(ctx context.Context, subject access.Subject, productID,
	vulnerabilityID int64, names []string, component, purl string,
	targetID, componentID int64) ([]Statement, error) {

	// Asked about the issue rather than about the product, because what comes
	// back is narrowed to this issue's names and this component — it is
	// evidence for the one finding, and a collaborator brought in on that
	// finding is who it is for. Asked product-wide, the detail route answered
	// a fault for the one row their grant exists to let them open.
	if _, err := access.ReadableOn(subject, productID, vulnerabilityID); err != nil {
		return nil, err
	}
	if len(names) == 0 || strings.TrimSpace(component) == "" {
		return nil, nil
	}
	lowered := make([]string, 0, len(names))
	for _, name := range names {
		lowered = append(lowered, folded(name))
	}
	var said []Statement
	err := s.db.NewSelect().Model(&said).
		Where("product_id = ?", productID).
		Where("superseded_at IS NULL").
		Where("vulnerability IN (?)", bun.List(lowered)).
		Where("component = ?", folded(component)).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read what publishers have said about this: %w", err)
	}
	said = namingTheSamePackage(said, purl)

	above, err := graph.NewStore(s.db).Above(ctx, subject, targetID, componentID)
	if err != nil {
		return nil, err
	}
	shipped, err := s.shipsProducts(ctx, productID, said)
	if err != nil {
		return nil, err
	}
	kept := make([]Statement, 0, len(said))
	for _, one := range said {
		if one.Within == "" || !shipped[one.Within] || placedAbove(one, above) {
			kept = append(kept, one)
		}
	}

	// A statement naming a product alone, about a product above this
	// component.
	if len(above) > 0 {
		aboveNames := make([]string, 0, len(above))
		for _, c := range above {
			aboveNames = append(aboveNames, folded(c.Name))
		}
		var beneath []Statement
		err := s.db.NewSelect().Model(&beneath).
			Where("product_id = ?", productID).
			Where("superseded_at IS NULL").
			Where("placement = ?", PlacedProduct).
			Where("vulnerability IN (?)", bun.List(lowered)).
			Where("component IN (?)", bun.List(aboveNames)).
			Scan(ctx)
		if err != nil {
			return nil, fmt.Errorf("read what publishers have said about what this sits in: %w", err)
		}
		for _, one := range beneath {
			if placedAbove(one, above) {
				kept = append(kept, one)
			}
		}
	}
	slices.SortFunc(kept, func(a, b Statement) int {
		if c := b.UploadedAt.Compare(a.UploadedAt); c != 0 {
			return c
		}
		return cmp.Compare(b.ID, a.ID)
	})
	return slices.CompactFunc(kept, func(a, b Statement) bool { return a.ID == b.ID }), nil
}

// shipsProducts is which of the products these statements name a component
// ships inside are shipped by any build of this product, by name.
func (s *Store) shipsProducts(ctx context.Context, productID int64,
	said []Statement) (map[string]bool, error) {

	var named []string
	for _, one := range said {
		if one.Within != "" {
			named = append(named, one.Within)
		}
	}
	shipped := map[string]bool{}
	if len(named) == 0 {
		return shipped, nil
	}
	var rows []string
	err := s.db.NewSelect().
		Distinct().
		TableExpr(`"component" AS "pc"`).
		ColumnExpr(`pc.name_folded`).
		Join(`JOIN "graph_node" AS "pn" ON pn.component_id = pc.id`).
		Join(`JOIN "target" AS "pt" ON pt.id = pn.target_id`).
		Join(`JOIN "stream" AS "ps" ON ps.id = pt.stream_id`).
		Where("ps.product_id = ?", productID).
		Where("pn.closed_scan_id IS NULL").
		Where("pc.name_folded IN (?)", bun.List(named)).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which suppliers' products this ships: %w", err)
	}
	for _, name := range rows {
		shipped[name] = true
	}
	return shipped, nil
}

// placedAbove reports whether the product a statement names is one of these
// components, at whatever version: a statement about Y 4.2 is evidence on what
// sits inside Y 4.3, and only closes anything at 4.2.
func placedAbove(one Statement, above []graph.Component) bool {
	product := suppliedProduct(one)
	for _, c := range above {
		if isProduct(product, c, false) {
			return true
		}
	}
	return false
}

// namingTheSamePackage drops statements whose package identifier names
// something other than this component.
//
// The stored name is the short one, because that is what a component in the
// graph is called and matching on anything else would match nothing. A short
// name is not a package, though: two registries and two namespaces hold
// different packages under one, so a publisher's statement about
// `pkg:npm/@acme/parser` was shown against every component called `parser`,
// from anywhere, with that publisher's name on it.
//
// Compared in the type and the namespace, never the version: a statement says
// which versions it is about in its own terms, and this only asks whether the
// two are the same package.
//
// A claim against a source tree is kept however it was named: with no package
// identifier at all, and with one of the generic type. The two are the same
// claim and the matching rules match them the same way (DESIGN-ingest.md), so
// narrowing the generic spelling away here hides the evidence for a
// suppression already applied — the finding is gone and what a publisher said
// about it is not on the page.
func namingTheSamePackage(said []Statement, purl string) []Statement {
	here := graph.PartsOfPurl(purl)
	if here.Name == "" {
		return said
	}
	kept := make([]Statement, 0, len(said))
	for _, one := range said {
		there := graph.PartsOfPurl(one.Purl)
		if there.Name == "" || there.Type == sourceTree {
			kept = append(kept, one)
			continue
		}
		if there.Type != here.Type ||
			!strings.EqualFold(there.Namespace, here.Namespace) {
			continue
		}
		kept = append(kept, one)
	}
	return kept
}

// sourceTree is the package type a source tree is named with where it is named
// as a package identifier at all.
const sourceTree = "generic"

// statementsPerInsert is how many claims one insert states.
//
// Bounded by what an engine will bind in one statement rather than by what is
// fast: PostgreSQL takes 65,535 parameters, and five hundred claims leave room
// for a hundred and thirty columns each, so a column added to a claim does not
// make the bound the thing that breaks.
const statementsPerInsert = 500

// MostPublisher is how long the name of whoever published a statement may be,
// and MostDocumentName how long the name the publisher gave the document may
// be.
//
// The width of the columns they are stored in, derived rather than typed so
// that moving that width moves these with it. Refused rather than shortened:
// both are part of the key a later upload supersedes on, so two names agreeing
// for that many characters would collapse into one and the second upload would
// set aside statements it has nothing to do with.
const (
	MostPublisher    = database.NameWidth
	MostDocumentName = database.NameWidth
)

// claimOf is what a statement claims, leaving out where it places its
// supplier's product.
func claimOf(one Statement) string {
	return strings.Join([]string{one.Vulnerability, one.Purl, one.Component,
		one.About, one.Status, one.Justification, one.Statement}, "\x00")
}

// placementOf is where a statement places its supplier's product.
func placementOf(one Statement) string {
	return strings.Join([]string{one.WithinPurl, one.Within, one.WithinAbout, one.Placement}, "\x00")
}

// placed is where a statement places its supplier's product, which a
// repeated claim takes from the document repeating it.
type placed struct {
	WithinPurl, Within, WithinAbout, Placement string
}

// pairRepeated pairs each claim a document makes with a standing row making
// the same claim, and answers the repeated rows by where the document now
// places them, the standing rows the document no longer makes, and the claims
// it makes that nothing stands for.
//
// A repeat is the same claim placing the supplier's product in the same place.
// A claim moved to another release of the product is a different claim, and
// what an approval was granted on stays readable as it was. A row recorded
// before its product was read places nothing, and pairs with the same claim
// placed anywhere, once no exact repeat wants it. Rows are paired in a fixed
// order on both sides, so two identical claims placed in two products each
// keep one row.
func pairRepeated(held, said []Statement) (map[placed][]int64, []int64, []Statement) {
	sorted := slices.Clone(held)
	slices.SortFunc(sorted, func(a, b Statement) int { return cmp.Compare(a.ID, b.ID) })
	exactly := func(one Statement) string { return claimOf(one) + "\x00" + placementOf(one) }
	exact, unplaced := map[string][]Statement{}, map[string][]Statement{}
	for _, row := range sorted {
		if row.Placement == "" && row.Within == "" {
			unplaced[claimOf(row)] = append(unplaced[claimOf(row)], row)
			continue
		}
		exact[exactly(row)] = append(exact[exactly(row)], row)
	}
	saying := slices.Clone(said)
	slices.SortStableFunc(saying, func(a, b Statement) int {
		return strings.Compare(exactly(a), exactly(b))
	})

	repeated := map[placed][]int64{}
	keep := func(one Statement, row Statement) {
		at := placed{one.WithinPurl, one.Within, one.WithinAbout, one.Placement}
		repeated[at] = append(repeated[at], row.ID)
	}
	// Exact repeats first, so a row recorded before its product was read
	// never takes a claim a placed row repeats.
	var rest []Statement
	for _, one := range saying {
		if rows := exact[exactly(one)]; len(rows) > 0 {
			keep(one, rows[0])
			exact[exactly(one)] = rows[1:]
			continue
		}
		rest = append(rest, one)
	}
	var fresh []Statement
	for _, one := range rest {
		if rows := unplaced[claimOf(one)]; len(rows) > 0 {
			keep(one, rows[0])
			unplaced[claimOf(one)] = rows[1:]
			continue
		}
		fresh = append(fresh, one)
	}
	var gone []int64
	for _, left := range []map[string][]Statement{exact, unplaced} {
		for _, rows := range left {
			for _, row := range rows {
				gone = append(gone, row.ID)
			}
		}
	}
	slices.Sort(gone)
	return repeated, gone, fresh
}

// nullable is a value written as a null where it is empty, the way the
// columns it is written into hold an absence.
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// sameReading reports whether two sets of statements say the same things,
// in any order. Only what a reader derives from the document is compared.
func sameReading(held, said []Statement) bool {
	if len(held) != len(said) {
		return false
	}
	reading := func(rows []Statement) []string {
		out := make([]string, len(rows))
		for i, one := range rows {
			out[i] = strings.Join([]string{one.Vulnerability, one.Purl, one.Component,
				one.About, one.WithinPurl, one.Within, one.WithinAbout, one.Placement, one.Status,
				one.Justification, one.Statement}, "\x00")
		}
		slices.Sort(out)
		return out
	}
	return slices.Equal(reading(held), reading(said))
}

// folded is how a name is stored so that every engine compares it alike: the
// fold a component's own name is stored under, cut to the same width.
//
// Done here rather than by the engine because the four do not agree: SQLite's
// LOWER folds ASCII and nothing else, while the three servers fold the whole
// character set. Cut at the column's width, because a longer value is refused
// by the three servers and kept whole by SQLite.
func folded(name string) string {
	return graph.Folded(name)
}
