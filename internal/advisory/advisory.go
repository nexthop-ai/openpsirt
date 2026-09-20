// Package advisory turns what is held about a flaw in our own product into a
// document somebody can publish.
//
// We own the triage record; whoever publishes owns the published advisory.
// The document is never sent anywhere and nothing here goes out over the
// network: it is assembled from what is held and handed over. What is kept is
// the record that one went out and the digest of what was generated, which is
// what makes "is what is published still what we would generate" answerable.
// That is the question that decides whether an integration works or rots, and
// keeping both ends as the source of truth is how it rots.
//
// Only a flaw in what we ship. A known issue in a third-party component is
// dependency hygiene that a consumer can already read out of the
// inventory, and issuing a vendor advisory for every upstream CVE in a
// dependency is not what an advisory is. So this refuses an issue this
// deployment did not record, by name, rather than producing a document that
// looks the same and means something else.
package advisory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/version"
)

// ErrNotOurs says the issue is not one this deployment recorded.
var ErrNotOurs = errors.New(
	"an advisory is about a flaw in what we ship, and this issue was reported by a scanner")

// ErrNoPublisher says the deployment has not been told who it publishes as.
//
// Wrapped by missingPublisher, which names the variable that is not set: the
// person who sees this cannot fix it, and the operator who can is reading a
// relayed message rather than sitting at the process.
var ErrNoPublisher = errors.New("this deployment has not been configured with a publisher")

// missingPublisher says which half of the publisher is missing.
func missingPublisher(p publisher.Named) error {
	switch {
	case p.Name == "" && p.Namespace == "":
		return fmt.Errorf("%w: set OPENPSIRT_PUBLISHER_NAME and OPENPSIRT_PUBLISHER_NAMESPACE",
			ErrNoPublisher)
	case p.Name == "":
		return fmt.Errorf("%w: OPENPSIRT_PUBLISHER_NAME is not set", ErrNoPublisher)
	default:
		return fmt.Errorf("%w: OPENPSIRT_PUBLISHER_NAMESPACE is not set", ErrNoPublisher)
	}
}

// ErrNoSuchIssue says the product holds nothing under that identifier.
var ErrNoSuchIssue = errors.New("this product holds no issue by that name")

// Document is a CSAF 2.0 document.
//
// The field names and their shapes are the standard's, not ours, so they are
// spelled as it spells them and are exempt from this codebase's spelling rule
// for the same reason a producer's field names are.
type Document struct {
	Document    Meta        `json:"document"`
	ProductTree ProductTree `json:"product_tree"`
	// Vulnerabilities holds one entry per issue the advisory covers, which
	// is what lets several flaws released together be one document on one
	// date. Each aggregates to a product and a version range rather than to
	// a path: a reader is asking whether they are affected, and the answer
	// is a release.
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Meta is the document's own description.
type Meta struct {
	// Category is what kind of document this is, and it follows what the
	// document can actually support rather than what would sound better. The
	// security-advisory profile's own tests are what decides it; the VEX
	// profile is the one that carries "not affected, and here is why", and
	// those justifications are not assembled here.
	Category     string        `json:"category"`
	CSAFVersion  string        `json:"csaf_version"`
	Title        string        `json:"title"`
	Publisher    Issuer        `json:"publisher"`
	Tracking     Tracking      `json:"tracking"`
	Notes        []Note        `json:"notes,omitempty"`
	References   []Reference   `json:"references,omitempty"`
	Distribution *Distribution `json:"distribution,omitempty"`
	Language     string        `json:"lang,omitempty"`
}

// Issuer is the publisher as the document carries it.
type Issuer struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// Tracking is the document's identity and where it is in its life.
type Tracking struct {
	ID string `json:"id"`
	// Status is draft while nobody outside has been told.
	//
	// Reaching a disclosure date discloses nothing — it escalates, and a
	// person decides — so a document about an undisclosed flaw is prepared
	// rather than issued, and says so in the one field a reader of a CSAF
	// document checks before acting on it.
	Status             string     `json:"status"`
	Version            string     `json:"version"`
	InitialReleaseDate time.Time  `json:"initial_release_date"`
	CurrentReleaseDate time.Time  `json:"current_release_date"`
	Generator          *Generator `json:"generator,omitempty"`
	RevisionHistory    []Revision `json:"revision_history"`
}

// Generator names what assembled the document.
type Generator struct {
	Engine Engine    `json:"engine"`
	Date   time.Time `json:"date"`
}

// Engine is the software that generated it.
type Engine struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Revision is one entry in the document's history.
type Revision struct {
	Number  string    `json:"number"`
	Date    time.Time `json:"date"`
	Summary string    `json:"summary"`
}

// Note is prose attached to a document or a vulnerability.
type Note struct {
	Category string `json:"category"`
	Title    string `json:"title,omitempty"`
	Text     string `json:"text"`
}

// ProductTree names everything the document can make a statement about.
type ProductTree struct {
	Branches []Branch `json:"branches,omitempty"`
}

// Branch is one level of that naming.
type Branch struct {
	Category string   `json:"category"`
	Name     string   `json:"name"`
	Branches []Branch `json:"branches,omitempty"`
	Product  *Named   `json:"product,omitempty"`
}

// Named is a leaf of the product tree: something a status can be stated about.
type Named struct {
	Name string `json:"name"`
	ID   string `json:"product_id"`
	// Helper is how a reader matches this release against something they
	// already hold, where the build said what it is.
	Helper *IdentificationHelper `json:"product_identification_helper,omitempty"`
}

// IdentificationHelper is what a release called itself, in a spelling a machine
// can compare.
//
// The identifier the build declared, never one minted here. An identifier
// only helps if it appears on both sides of the comparison, and one invented
// here appears on one: a reader holding our image has whatever our build wrote
// into its inventory, which is this exact string if they ingested that
// document. A plausible identifier nothing outside this deployment has seen is
// worse than none, because a reader matches on it and misses.
//
// It is read from the scan rather than from the component, because the root
// component is stored by name alone: a package identifier carries the version,
// and the root's version moves every build.
type IdentificationHelper struct {
	Purl string `json:"purl,omitempty"`
}

// Vulnerability is the flaw and what is true of it in each release.
type Vulnerability struct {
	// CVE where it has one, and IDs otherwise. An identifier this
	// deployment minted is not a CVE and saying it is in that field would
	// be a claim nobody assigned.
	CVE   string   `json:"cve,omitempty"`
	IDs   []Issued `json:"ids,omitempty"`
	Title string   `json:"title,omitempty"`
	Notes []Note   `json:"notes,omitempty"`
	// Status is which releases the flaw is in and which it is out of.
	Status Status `json:"product_status"`
	// CWE is what kind of flaw this is, where the catalog knows the name.
	CWE *Weakness `json:"cwe,omitempty"`
	// Scores is what is held about the flaw beyond which releases carry
	// it: what it scored, what a holder of an affected release can do, and
	// whoever asked to be credited for telling us.
	Scores          []Score          `json:"scores,omitempty"`
	Remediations    []Remediation    `json:"remediations,omitempty"`
	Acknowledgments []Acknowledgment `json:"acknowledgments,omitempty"`
	// DiscoveryDate is when this deployment first recorded it, which is what
	// it knows. When somebody outside found it is not something it holds.
	DiscoveryDate string `json:"discovery_date,omitempty"`
}

// Weakness is the kind of flaw, as the standard carries it.
//
// One, and both halves of it. The standard states a weakness as the
// identifier and the name the catalog gives it, and a consumer's validator
// compares the pair — so an issue classified several ways states the one the
// data calls the root cause, and one whose name the catalog does not know
// states nothing. A name invented to fill the field is the single thing in the
// document guaranteed to be caught.
type Weakness struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Issued is an identifier somebody else's system knows this by.
type Issued struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

// Status is which releases the flaw is in and which it is out of.
//
// A release that held the flaw and no longer does is named as fixed rather
// than left out, because leaving it out reads identically to a release that
// never shipped the thing at all — and those are opposite answers, one of them
// the one a reader is hoping for.
//
// A person's own decision about a release — not affected, and the reason why —
// is the VEX half, and is not assembled here.
type Status struct {
	KnownAffected []string `json:"known_affected,omitempty"`
	Fixed         []string `json:"fixed,omitempty"`
}

// Store assembles advisories.
type Store struct {
	db  *bun.DB
	now func() time.Time
}

// NewStore returns a store over db.
func NewStore(db *bun.DB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// ForAdvisory assembles the document for one advisory.
//
// One entry per issue the advisory covers, and one product branch per product
// those issues are covered in. The standard carries vulnerabilities as an
// array, which is what lets several embargoed flaws be released together as
// one document on one date.
func (s *Store) ForAdvisory(ctx context.Context, subject access.Subject, who publisher.Named,
	identifier string) (*Document, error) {

	doc, _, err := s.forAdvisory(ctx, subject, who, identifier)
	return doc, err
}

// forAdvisory is the same, answering with the advisory it resolved on the way.
//
// Recording an issuance needs the advisory the document was built from, and
// asked for it again it resolved it a second time — round trips for an answer
// already in hand, and a window in which what the advisory covers changed
// between the document being hashed and the issuance being keyed.
func (s *Store) forAdvisory(ctx context.Context, subject access.Subject, who publisher.Named,
	identifier string) (*Document, *Advisory, error) {

	if !who.Stated() {
		return nil, nil, missingPublisher(who)
	}
	// Authorized before anything is assembled, and refused whole: byName turns
	// away an advisory covering a product this reader may not see, because a
	// document with one of its products quietly left out reads as a complete
	// statement about a product it says nothing about.
	row, err := s.byName(ctx, subject, identifier)
	if err != nil {
		return nil, nil, err
	}
	held, err := s.covers(ctx, row.ID)
	if err != nil {
		return nil, nil, err
	}
	if len(held) == 0 {
		return nil, nil, ErrNothingToSay
	}
	gone, err := s.issuances(ctx, row.ID)
	if err != nil {
		return nil, nil, err
	}

	now := s.now().UTC()
	assembled := &assembly{who: who, seen: map[string]bool{}}
	for _, one := range held {
		if err := s.cover(ctx, subject, assembled, one); err != nil {
			return nil, nil, err
		}
	}

	// The earliest recording among the issues it covers. A document dates
	// itself from when this deployment first knew about what it is about, and
	// an advisory about several flaws first knew about the oldest of them.
	opened := assembled.opened
	history := revisions(opened, gone, now)

	doc := &Document{}
	doc.Document = Meta{
		// Filled in once the document is assembled, from what it turned out
		// to carry. Claiming the security-advisory profile while failing its
		// tests describes the document as something it is not, and a reader's
		// tooling drops it on exactly that.
		CSAFVersion: "2.0",
		Title:       titleOf(row, assembled),
		Language:    "en-US",
		Publisher: Issuer{
			Category: categoryOf(who), Name: who.Name,
			Namespace: who.Namespace,
		},
		Tracking: Tracking{
			// The advisory's own name. A document naming an issue's
			// identifier as its own tracking identifier claims to be the
			// authority on that issue, which a coordinator is and this
			// deployment is not.
			ID: row.Identifier, Status: assembled.status(),
			// The number of the last entry in the history below, rather than
			// a second count of the same thing. Counted separately the two
			// disagree the moment an advisory has been issued once: the
			// history numbers this document N+2 and the version says N+1,
			// and a validator compares them.
			Version:            history[len(history)-1].Number,
			InitialReleaseDate: opened,
			CurrentReleaseDate: now,
			// The build that wrote it, read from the binary rather than held in
			// a variable something has to remember to set — one nobody set
			// says the document was generated by a version that does not
			// exist.
			Generator: &Generator{
				Engine: Engine{Name: "OpenPSIRT", Version: version.Get().Version},
				Date:   now,
			},
			RevisionHistory: history,
		},
	}
	doc.Document.References = assembled.pointers
	doc.Document.Distribution = distributionFor(doc.Document.Tracking.Status)
	doc.ProductTree = ProductTree{Branches: []Branch{{
		Category: "vendor", Name: who.Name, Branches: assembled.products,
	}}}
	doc.Vulnerabilities = assembled.vulnerabilities
	doc.Document.Category = profileOf(doc)
	return doc, row, nil
}

// assembly is a document being built out of what several issues carry.
//
// One place for the parts that are per-document rather than per-issue: the
// product tree branches, which two issues in one product share, and the
// addresses, which two issues may both point at.
type assembly struct {
	who publisher.Named
	// products is one branch per product, in the order the issues were added,
	// each holding the releases any of its issues named. A release named by
	// two issues is one branch that both statuses point at.
	products []Branch
	// at is where each product's branch sits in products, and seen is every
	// release already named, so neither is written twice.
	at   map[string]int
	seen map[string]bool

	vulnerabilities []Vulnerability
	pointers        []Reference
	pointed         map[string]bool
	// opened is the earliest recording among the issues, and undisclosed says
	// any of them is still held back.
	opened      time.Time
	undisclosed bool
}

// status is what the document's tracking says about where it is in its life.
//
// Read from the disclosure of the issues it covers rather than from a decision
// somebody made about the document. Reaching a disclosure date discloses
// nothing, so a document about anything still held back says it is a draft.
func (a *assembly) status() string {
	if a.undisclosed {
		return "draft"
	}
	return "final"
}

// titleOf is what the document calls itself.
//
// What somebody titled it, where they did. An advisory covering several flaws
// has no one sentence that describes it, so what stands in is the product it
// is about and how many flaws it names — a title naming one of them would
// describe the document as being about that one.
func titleOf(row *Advisory, a *assembly) string {
	if row.Title != "" {
		return row.Title
	}
	if len(a.vulnerabilities) == 1 {
		return a.vulnerabilities[0].Title
	}
	return fmt.Sprintf("%s: %d issues", row.Identifier, len(a.vulnerabilities))
}

// Release is one build of the product and where it stands on the issue.
type Release struct {
	Stream  string
	Variant string
	// Holds says the issue is open there. False is a release that held it and
	// no longer does, which is the one that was fixed.
	Holds bool
	// Identifier is what this build's own inventory called the thing it is
	// about, and empty where that document named no component of its own.
	Identifier string
}

// Name is how the release is written in the document.
func (r Release) Name() string { return r.Stream + " (" + r.Variant + ")" }

// ProductID is the identifier statements refer to it by. A release is named by
// its stream and its variant together, never by one of them: the same branch
// built two ways is two builds, and naming only the branch would claim
// something about hardware nobody built for.
func (r Release) ProductID(product string) string {
	return product + ":" + r.Stream + ":" + r.Variant
}

// ours reads the issue and the finding this deployment recorded for it, and
// refuses one that a scanner reported.
func (s *Store) ours(ctx context.Context, subject access.Subject, productID int64,
	identifier string) (*finding.Vulnerability, *finding.Finding, error) {

	var issue finding.Vulnerability
	err := s.db.NewSelect().Model(&issue).
		Where("identifier = ?", identifier).
		Limit(1).Scan(ctx)
	if err != nil {
		return nil, nil, database.FromRead(err, ErrNoSuchIssue,
			fmt.Sprintf("look up what issue %q is", identifier))
	}

	// The earliest finding of this issue in this product that a person
	// recorded. Earliest because it is what the document dates itself from,
	// and a flaw recorded once and later found in a second release is one
	// flaw with one discovery.
	var row finding.Finding
	err = s.db.NewSelect().Model(&row).
		Join(`JOIN "target" AS "t" ON t.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = t.stream_id`).
		Where("st.product_id = ?", productID).
		Where("f.vulnerability_id = ?", issue.ID).
		Where("f.visibility IN (?)", bun.List(access.Visible(subject, productID))).
		Where("f.kind = ?", finding.Entered).
		OrderExpr("f.opened_at ASC, f.id ASC").
		Limit(1).Scan(ctx)
	if err != nil && !database.IsNoRows(err) {
		return nil, nil, fmt.Errorf("look up what we recorded about %q: %w", identifier, err)
	}
	if err != nil {
		// The issue's presence here and its ownership are told
		// apart deliberately: the first is a typo and the second is a scope
		// rule somebody has to understand.
		held, here := s.here(ctx, subject, productID, issue.ID)
		if here != nil {
			return nil, nil, here
		}
		if held {
			return nil, nil, ErrNotOurs
		}
		return nil, nil, ErrNoSuchIssue
	}
	return &issue, &row, nil
}

// here reports whether the product holds this issue at all, however it arrived.
//
// It decides which of two refusals the caller is given, so a count it could not
// make is reported rather than read as a zero: "this product holds no issue by
// that name" is a statement about the catalog, and a failed read does not
// support it.
func (s *Store) here(ctx context.Context, subject access.Subject,
	productID, issueID int64) (bool, error) {

	count, err := s.db.NewSelect().Model((*finding.Finding)(nil)).
		Join(`JOIN "target" AS "t" ON t.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = t.stream_id`).
		Where("st.product_id = ?", productID).
		Where("f.vulnerability_id = ?", issueID).
		Where("f.visibility IN (?)", bun.List(access.Visible(subject, productID))).
		Count(ctx)
	if err != nil {
		return false, fmt.Errorf("count where issue %d sits here: %w", issueID, err)
	}
	return count > 0, nil
}

// releases reports every build of the product that holds this issue or once
// did, which is what an advisory states something about.
func (s *Store) releases(ctx context.Context, subject access.Subject,
	productID, issueID int64) ([]Release, error) {

	var rows []struct {
		Stream  string `bun:"stream"`
		Variant string `bun:"variant"`
		Open    int    `bun:"open"`
		Root    string `bun:"root_identifier"`
	}
	// One statement rather than one per build: a product with thirty tags
	// would otherwise be thirty round trips to write one document, and the
	// answer would be assembled from thirty moments rather than one.
	err := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "t" ON t.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = t.stream_id`).
		Join(`JOIN "variant" AS "va" ON va.id = t.variant_id`).
		// This build's own name for itself, from the scan that
		// inventory arrived on. Joined on the target's current scan, which is
		// one row by key, so it cannot multiply the findings counted below.
		Join(`LEFT JOIN "scan" AS "sc" ON sc.id = t.last_scan_id`).
		ColumnExpr(`st.name AS "stream"`).
		ColumnExpr(`va.name AS "variant"`).
		// Counted rather than filtered, so a release that held the flaw and no
		// longer does is still a row — that is the release somebody upgrades
		// to, and dropping it would leave finished work indistinguishable
		// from a release that never shipped the thing.
		ColumnExpr(`COUNT(CASE WHEN f.closed_at IS NULL THEN 1 END) AS "open"`).
		// One value per build, aggregated because the grouping is on the
		// build's names rather than on its key.
		ColumnExpr(`MIN(COALESCE(sc.root_identifier, '')) AS "root_identifier"`).
		Where("st.product_id = ?", productID).
		Where("f.vulnerability_id = ?", issueID).
		Where("f.visibility IN (?)", bun.List(access.Visible(subject, productID))).
		GroupExpr("st.name, va.name").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which releases this is in: %w", err)
	}

	releases := make([]Release, 0, len(rows))
	for _, row := range rows {
		releases = append(releases, Release{
			Stream: row.Stream, Variant: row.Variant, Holds: row.Open > 0,
			Identifier: row.Root,
		})
	}
	// Ordered here rather than by the engine, so the document is byte-for-byte
	// the same whatever it was generated against — which is what lets somebody
	// diff two of them and see a real change.
	sort.Slice(releases, func(i, j int) bool {
		if releases[i].Stream != releases[j].Stream {
			return releases[i].Stream < releases[j].Stream
		}
		return releases[i].Variant < releases[j].Variant
	})
	return releases, nil
}

func categoryOf(p publisher.Named) string {
	if p.Category == "" {
		return "vendor"
	}
	return p.Category
}

// summaryOf is what the flaw is, in the words of whoever recorded it.
func summaryOf(issue *finding.Vulnerability, identifier string) string {
	if issue.Description != "" {
		return issue.Description
	}
	return identifier
}

// isCVE says the issue is filed under a CVE rather than under an identifier
// this deployment minted.
func isCVE(identifier string) bool {
	return len(identifier) > 4 && identifier[:4] == "CVE-"
}

// namesOf is every identifier an issue answers to.
//
// Read for the document rather than for the screen: a reader searching by the
// name a coordinator gave them has to find this, and the name we minted is
// usually not the one they have.
func (s *Store) namesOf(ctx context.Context, id int64) ([]string, error) {
	var names []string
	err := s.db.NewSelect().Model((*finding.Alias)(nil)).
		ColumnExpr("va.identifier").
		Where("va.vulnerability_id = ?", id).
		OrderExpr("va.identifier").
		Scan(ctx, &names)
	if err != nil {
		return nil, fmt.Errorf("read what this issue is also called: %w", err)
	}
	return names, nil
}

// Issuance is one time an advisory went out.
//
// A fact about a moment rather than a derived value: what was published on a
// date cannot be worked out again once the record it was generated from has
// moved on — a release is added, a decision is revised, a fix lands. If it is
// not written down when it happens it is gone.
type Issuance struct {
	bun.BaseModel `bun:"table:advisory_issuance,alias:ai"`

	ID int64 `bun:"id,pk,autoincrement"`
	// AdvisoryID is what this is an issuance of. Keyed on the advisory, which
	// is what makes a revision of a document covering two issues one record
	// rather than two.
	AdvisoryID int64 `bun:"advisory_id,notnull"`
	// Ordinal is which issuance this is, counting from one. It is what the
	// document's version says, and a validator checks that a revised document
	// carries a higher one than the last.
	Ordinal int `bun:"ordinal,notnull"`
	// Digest is what went out, hashed. The document itself belongs to
	// whoever published it; this is what makes "is what is published still
	// what we generated" a question with a yes or no.
	Digest   string    `bun:"digest,notnull"`
	Summary  string    `bun:"summary"`
	IssuedBy int64     `bun:"issued_by,notnull"`
	IssuedAt time.Time `bun:"issued_at,notnull"`
}

// Issued records that an advisory went out, and returns what was recorded.
//
// The digest is taken from the document as it is now, generated inside
// this call rather than supplied by the caller. A caller-supplied digest is a
// digest of whatever they say — and the question this exists to answer is
// whether what is published is still what we would generate, which only means
// something if both sides come from here.
//
// The ordinal is read and used in one transaction, so two people recording an
// issuance at the same moment cannot be handed the same number.
func (s *Store) Issued(ctx context.Context, subject access.Subject, who publisher.Named,
	identifier, summary string) (*Issuance, error) {

	// The submission policy, before the summary is stored. It is typed prose
	// that goes into the published revision history, so what is in the column
	// has to be known to have passed what was in force when it arrived.
	summary = strings.TrimSpace(summary)
	if err := markdown.Check(summary); err != nil {
		return nil, err
	}

	// One resolution, which the document was built from. Asked again it was
	// more round trips for an answer already in hand — and what the advisory
	// covers changing in between would key the issuance on a document that was
	// never hashed.
	doc, row, err := s.forAdvisory(ctx, subject, who, identifier)
	if err != nil {
		return nil, err
	}
	// Hashed over what the document *says*, with the parts that move for
	// reasons other than the content left out.
	//
	// The question this answers is "is what is published still what we would
	// generate", and every one of these makes that unanswerable: the current
	// release date and the generator's date change every time it is asked for;
	// the version and the revision history change *because* it was issued, so
	// a document hashed with them can never match the digest of the issuance
	// before it, however unchanged its substance. What is left is the title,
	// the notes, the product tree and the vulnerability — which is the part a
	// reader acts on and the part that must not have quietly moved.
	settled := *doc
	settled.Document.Tracking.CurrentReleaseDate = time.Time{}
	settled.Document.Tracking.Generator = nil
	settled.Document.Tracking.Version = ""
	settled.Document.Tracking.RevisionHistory = nil
	body, err := json.Marshal(settled)
	if err != nil {
		return nil, fmt.Errorf("hash what went out: %w", err)
	}
	sum := sha256.Sum256(body)

	issuedAt := s.now().UTC().Truncate(time.Microsecond)
	var recorded *Issuance
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		// Built inside, because an insert writes the generated identifier back
		// into the model and the ordinal below is read from the database. A
		// retry of a rolled-back attempt would re-insert a model carrying both
		// of that attempt's answers.
		recorded = &Issuance{
			AdvisoryID: row.ID,
			Digest:     hex.EncodeToString(sum[:]), Summary: summary,
			IssuedBy: subject.ID, IssuedAt: issuedAt,
		}
		// Scanned into a value rather than read through a cursor: a cursor
		// left open while the insert runs is two statements interleaved on one
		// connection, which one engine tolerates and another refuses.
		var highest int
		if err := tx.NewSelect().Model((*Issuance)(nil)).
			ColumnExpr("COALESCE(MAX(ordinal), 0)").
			Where("advisory_id = ?", row.ID).
			Scan(ctx, &highest); err != nil {
			return err
		}
		recorded.Ordinal = highest + 1
		_, err := tx.NewInsert().Model(recorded).Exec(ctx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("record that it went out: %w", err)
	}
	return recorded, nil
}

// Issuances is what has gone out for one advisory, newest first.
//
// Readable without generating a document. Every issuance is already in the
// document's own revision history, which is right for a reader of the document
// — but it made "has this gone out, and is what is published still what we
// would generate" a question you had to build a CSAF document to answer.
// Somebody deciding whether to publish a revision is asking before they
// generate anything.
//
// Narrowed the way the document is: an advisory covering a product this reader
// may not see is one they are told does not exist, and a count of its
// issuances is as much a disclosure as the document.
func (s *Store) Issuances(ctx context.Context, subject access.Subject,
	identifier string) ([]Issuance, error) {

	row, err := s.byName(ctx, subject, identifier)
	if err != nil {
		return nil, err
	}
	return s.issuances(ctx, row.ID)
}

// issuances is what has gone out for one advisory, oldest first.
//
// Oldest first because it becomes the revision history, which a document
// states in the order it happened.
func (s *Store) issuances(ctx context.Context, advisoryID int64) ([]Issuance, error) {
	var rows []Issuance
	err := s.db.NewSelect().Model(&rows).
		Where("advisory_id = ?", advisoryID).
		OrderExpr("ai.ordinal ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read what has gone out: %w", err)
	}
	return rows, nil
}

func revisions(opened time.Time, gone []Issuance, now time.Time) []Revision {
	out := make([]Revision, 0, len(gone)+2)
	out = append(out, Revision{Number: "1", Date: opened, Summary: "Recorded in OpenPSIRT"})
	for _, one := range gone {
		summary := one.Summary
		if summary == "" {
			summary = "Issued"
		}
		out = append(out, Revision{
			Number: strconv.Itoa(one.Ordinal + 1), Date: one.IssuedAt.UTC(), Summary: summary,
		})
	}
	// Only where something has gone out before. A document nobody has
	// published is not a revision of anything: its newest entry is the flaw
	// being recorded, which is what it describes.
	//
	// It is also the one case where counting the version separately agrees
	// with the history by accident, which is why the disagreement shows only
	// once an advisory has been issued.
	if len(gone) > 0 {
		out = append(out, Revision{
			Number: strconv.Itoa(len(gone) + 2), Date: now,
			Summary: "Generated, not yet issued",
		})
	}
	return out
}

// cover adds what one issue in one product contributes to the document.
//
// Its entry among the vulnerabilities, its product's branch in the tree, and
// the addresses it points at. A product branch and a release branch are each
// written once however many issues name them: written twice, a reader's
// tooling sees two products where the document means one.
func (s *Store) cover(ctx context.Context, subject access.Subject,
	a *assembly, one Covered) error {

	issue, entered, err := s.ours(ctx, subject, one.ProductID, one.Issue)
	if err != nil {
		return err
	}
	aliases, err := s.namesOf(ctx, issue.ID)
	if err != nil {
		return err
	}
	releases, err := s.releases(ctx, subject, one.ProductID, issue.ID)
	if err != nil {
		return err
	}
	pointers, err := s.referencesTo(ctx, issue)
	if err != nil {
		return err
	}
	credited, err := s.creditedFor(ctx, one.ProductID, issue.ID)
	if err != nil {
		return err
	}

	opened := entered.OpenedAt.UTC()
	if a.opened.IsZero() || opened.Before(a.opened) {
		a.opened = opened
	}
	if entered.Visibility == access.Private {
		a.undisclosed = true
	}

	summary := summaryOf(issue, one.Issue)
	vulnerability := Vulnerability{
		Title:           summary,
		IDs:             []Issued{{SystemName: a.who.Name, Text: one.Issue}},
		Acknowledgments: credited,
	}
	// The same sentence the entry carries, on the note a reader of one
	// vulnerability stops at. The profile asks for both, and two readers is
	// what it is asking about: somebody scanning the document and somebody
	// whose tooling walked to this entry.
	if summary != "" {
		vulnerability.Notes = []Note{{Category: "description", Title: "Summary", Text: summary}}
	}
	// A CVE assigned later is another name for the same issue, and the issue
	// is then filed under it. Where that has happened the document says so in
	// the field a reader looks in.
	if isCVE(issue.Identifier) {
		vulnerability.CVE = issue.Identifier
	}
	// And every other name it goes by, in the field that carries names. A
	// reader searching by the identifier a coordinator gave them finds this
	// document, which is the one lookup a published advisory exists to serve —
	// and the CVE is filled in from an alias where the issue is still filed
	// under the identifier we minted.
	for _, name := range aliases {
		if name == one.Issue || name == issue.Identifier {
			continue
		}
		vulnerability.IDs = append(vulnerability.IDs, Issued{SystemName: "alias", Text: name})
		if vulnerability.CVE == "" && isCVE(name) {
			vulnerability.CVE = name
		}
	}
	if !entered.OpenedAt.IsZero() {
		vulnerability.DiscoveryDate = opened.Format("2006-01-02")
	}
	if vulnerability.CWE, err = weaknessOf(ctx, s.db, issue.ID); err != nil {
		return err
	}

	// One branch per release, under the product, under the publisher. The
	// tree names releases rather than components on purpose: an advisory
	// aggregates to a product and a version range, and a reader of one is
	// asking "am I affected", which a dependency path does not answer.
	fixed := make([]Named, 0, len(releases))
	rated := make([]string, 0, len(releases))
	for _, release := range releases {
		leaf := Named{
			Name: fmt.Sprintf("%s %s", one.ProductName, release.Name()),
			ID:   release.ProductID(one.Product),
		}
		// Only where it is the shape the standard states. The string is a
		// producer's, taken from a scan file, and a scan file is hostile input
		// (REQ-66): one that wrote something other than a package identifier
		// into the field the root is declared in would fail a customer's
		// validator on the whole document rather than on this field, which
		// is a worse outcome than the field being absent.
		if isPackageIdentifier(release.Identifier) {
			leaf.Helper = &IdentificationHelper{Purl: release.Identifier}
		}
		a.release(one, release, leaf)
		if release.Holds {
			vulnerability.Status.KnownAffected = append(
				vulnerability.Status.KnownAffected, leaf.ID)
		} else {
			vulnerability.Status.Fixed = append(vulnerability.Status.Fixed, leaf.ID)
			fixed = append(fixed, leaf)
		}
		// Every release the entry names, which is what a rating is stated for:
		// the score is the flaw's, and the flaw is the same flaw in each.
		rated = append(rated, leaf.ID)
	}
	vulnerability.Scores = scoresFor(issue, rated)
	vulnerability.Remediations = remediationsFor(fixed, vulnerability.Status.KnownAffected)

	a.vulnerabilities = append(a.vulnerabilities, vulnerability)
	a.point(pointers)
	return nil
}

// release records one release under its product's branch, once.
func (a *assembly) release(one Covered, of Release, leaf Named) {
	if a.at == nil {
		a.at = map[string]int{}
	}
	where, held := a.at[one.Product]
	if !held {
		a.products = append(a.products, Branch{
			Category: "product_name", Name: one.ProductName,
		})
		where = len(a.products) - 1
		a.at[one.Product] = where
	}
	if a.seen[leaf.ID] {
		return
	}
	a.seen[leaf.ID] = true
	a.products[where].Branches = append(a.products[where].Branches, Branch{
		Category: "product_version", Name: of.Name(), Product: &leaf,
	})
}

// point adds addresses the document does not already carry.
//
// Each address once. Two issues written up on one page is ordinary, and a
// document naming it twice reads as two places to go.
func (a *assembly) point(pointers []Reference) {
	if a.pointed == nil {
		a.pointed = map[string]bool{}
	}
	for _, one := range pointers {
		if a.pointed[one.URL] {
			continue
		}
		a.pointed[one.URL] = true
		a.pointers = append(a.pointers, one)
	}
}
