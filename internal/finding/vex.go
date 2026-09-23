// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Statement is what a third party's document says about a component we ship.
//
// A third layer beside the build's own claims and our decisions. Evidence, and
// a prefill; never applied to anything by itself.
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
			return fmt.Errorf("a statement set is a publisher's whole answer and is " +
				"replaced as one, so it is not identified by a document name")
		}
	case FromAdvisory:
		if strings.TrimSpace(from.Identifier) == "" {
			return fmt.Errorf("an advisory is replaced by the name its publisher gave " +
				"it, and this one carries none")
		}
		if utf8.RuneCountInString(from.Identifier) > MostDocumentName {
			return fmt.Errorf("the name the publisher gave it is longer than the %d "+
				"characters this records", MostDocumentName)
		}
	default:
		return fmt.Errorf("a document of kind %q, which is not one this records",
			from.Source)
	}
	if strings.TrimSpace(from.Publisher) == "" {
		return fmt.Errorf("a statement is somebody's, and this document names nobody")
	}
	if utf8.RuneCountInString(from.Publisher) > MostPublisher {
		return fmt.Errorf("who published it is longer than the %d characters this records",
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

		// The same bytes arriving again change nothing, so nothing is
		// written. Set aside and rewritten, every standing claim gets a new
		// identity and a superseded moment — and a superseded claim is what
		// tells everyone holding an approved decision that cited it that the
		// publisher has changed what they published. Re-syncing a publisher's
		// directory is the ordinary operation once advisories arrive one per
		// issue, so that notice would fire on every pass and say nothing.
		standing, err := tx.NewSelect().Model((*Statement)(nil)).
			Where("product_id = ?", productID).
			Where("publisher = ?", publisher).
			Where("source = ?", from.Source).
			Where("document_id = ?", identifier).
			Where("digest = ?", from.Digest).
			Where("superseded_at IS NULL").
			Count(ctx)
		if err != nil {
			return fmt.Errorf("ask what is already held: %w", err)
		}
		if standing > 0 {
			// What the document says is what the record already holds.
			recorded = standing
			return nil
		}

		setting := tx.NewUpdate().Model((*Statement)(nil)).
			Set("superseded_at = ?", now).
			Where("product_id = ?", productID).
			Where("publisher = ?", publisher).
			Where("source = ?", from.Source).
			Where("superseded_at IS NULL")
		if from.Source == FromAdvisory {
			setting = setting.Where("document_id = ?", identifier)
		}
		res, err := setting.Exec(ctx)
		if err != nil {
			return fmt.Errorf("set aside what they said before: %w", err)
		}
		n, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("set aside what they said before: %w", err)
		}
		superseded = int(n)
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
			said[i].Vulnerability = folded(said[i].Vulnerability)
			said[i].Component = folded(said[i].Component)
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
		// statement, and a claim states fourteen columns.
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

// SaidAbout is what VEX publishers have said about one issue at one component,
// newest first, standing statements only.
//
// Matched on the issue's name and its aliases, because which identifier a
// publisher chose is a preference of whichever database they consulted.
func (s *Store) SaidAbout(ctx context.Context, subject access.Subject, productID,
	vulnerabilityID int64, names []string, component, purl string) ([]Statement, error) {

	// Asked about the issue rather than about the product, because what comes
	// back is narrowed to this issue's names and this component — it is
	// evidence for the one finding, and a collaborator brought in on that
	// finding is who it is for. Asked product-wide, the detail route answered
	// a fault for the one row their grant exists to let them open.
	if !access.SeesOn(subject, productID, vulnerabilityID) {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
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
		Order("uploaded_at DESC", "id DESC").Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read what publishers have said about this: %w", err)
	}
	return namingTheSamePackage(said, purl), nil
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
// fast: PostgreSQL takes 65,535 parameters, and a claim states fourteen
// columns, so this leaves room for a column being added without the bound
// becoming the thing that breaks.
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

// folded is how a name is stored so that every engine compares it alike.
//
// Done here rather than by the engine because the four do not agree: SQLite's
// LOWER folds ASCII and nothing else, while the three servers fold the whole
// character set — so a component named with any letter outside ASCII matched a
// statement on three engines and not on the fourth, and which one a deployment
// runs decided whether a publisher's judgment reached a finding. Normalizing
// on write is the same answer matching a typed name without capitals gives for
// every other name people type.
func folded(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
