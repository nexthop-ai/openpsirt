// Package advisory turns what is held about a flaw in our own product into a
// document somebody can publish.
//
// **We own the triage record; whoever publishes owns the published advisory**
// . Nothing here records that a document was issued, and nothing goes
// out over the network: the document is assembled from what is held and handed
// over. That is the question that decides whether an integration works or
// rots, and keeping both ends as the source of truth is how it rots.
//
// **Only a flaw in what we ship**. A known issue in a third-party
// component is dependency hygiene that a consumer can already read out of the
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
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
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
		return fmt.Errorf("%w: set %sPUBLISHER_NAME and %sPUBLISHER_NAMESPACE",
			ErrNoPublisher, envPrefix, envPrefix)
	case p.Name == "":
		return fmt.Errorf("%w: %sPUBLISHER_NAME is not set", ErrNoPublisher, envPrefix)
	default:
		return fmt.Errorf("%w: %sPUBLISHER_NAMESPACE is not set", ErrNoPublisher, envPrefix)
	}
}

// envPrefix is how the settings are spelled in the environment, repeated here
// rather than imported: the configuration package reads this one, and a cycle
// for the sake of a five-character string is a worse trade than the string.
const envPrefix = "OPENPSIRT_"

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
	// Vulnerabilities holds one entry. An advisory aggregates a product
	// and a version range rather than a path, and this is about one flaw.
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Meta is the document's own description.
type Meta struct {
	// Category is what kind of document this is. It follows what the document
	// can actually support rather than what would sound better: the VEX
	// profile is the one that carries "not affected, and here is why", and
	// those justifications are not assembled here yet.
	Category    string   `json:"category"`
	CSAFVersion string   `json:"csaf_version"`
	Title       string   `json:"title"`
	Publisher   Issuer   `json:"publisher"`
	Tracking    Tracking `json:"tracking"`
	Notes       []Note   `json:"notes,omitempty"`
	Language    string   `json:"lang,omitempty"`
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
	// DiscoveryDate is when this deployment first recorded it, which is what
	// it knows. When somebody outside found it is not something it holds.
	DiscoveryDate string `json:"discovery_date,omitempty"`
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
// What a person decided about a release — not affected, and the reason why —
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

// For assembles the advisory for one issue in one product.
func (s *Store) For(ctx context.Context, subject access.Subject, who publisher.Named,
	product, identifier string) (*Document, error) {

	if !who.Stated() {
		return nil, missingPublisher(who)
	}
	named, err := catalog.NewStore(s.db).ProductByName(ctx, product)
	if err != nil {
		return nil, err
	}
	// Authorized before the identifier is resolved, so a name nobody holds
	// and a name somebody holds come back the same way.
	if subject.Kind != access.Person || !subject.Sees(named.ID) {
		return nil, ErrNoSuchIssue
	}

	issue, entered, err := s.ours(ctx, subject, named.ID, identifier)
	if err != nil {
		return nil, err
	}
	aliases, err := s.namesOf(ctx, issue.ID)
	if err != nil {
		return nil, err
	}
	// What has already gone out for this flaw. A second document for the
	// same one has to carry a higher version and a revision history, and
	// both are things a CSAF validator checks — a document that fails
	// validation is one a customer's tooling drops.
	gone, err := s.issuances(ctx, named.ID, issue.ID)
	if err != nil {
		return nil, err
	}

	releases, err := s.releases(ctx, subject, named.ID, issue.ID)
	if err != nil {
		return nil, err
	}

	now := s.now().UTC()
	shown := named.DisplayName
	if shown == "" {
		shown = named.Name
	}

	doc := &Document{}
	doc.Document = Meta{
		// A security advisory rather than the VEX profile, because what this
		// carries is which releases are affected and which are fixed. The VEX
		// profile's point is the not-affected justification, and claiming that
		// category while carrying none of them would describe the document as
		// something it is not.
		Category:    "csaf_security_advisory",
		CSAFVersion: "2.0",
		Title:       fmt.Sprintf("%s: %s", shown, summaryOf(issue, identifier)),
		Language:    "en-US",
		Publisher: Issuer{
			Category: categoryOf(who), Name: who.Name,
			Namespace: who.Namespace,
		},
		Tracking: Tracking{
			ID: identifier, Status: statusOf(entered),
			// One past what has gone out: this document is the next revision,
			// and a validator compares it against the history below.
			Version:            strconv.Itoa(len(gone) + 1),
			InitialReleaseDate: entered.OpenedAt.UTC(),
			CurrentReleaseDate: now,
			// Which build wrote it, read from the binary rather than held in
			// a variable something has to remember to set — one nobody set
			// says the document was generated by a version that does not
			// exist.
			Generator: &Generator{
				Engine: Engine{Name: "OpenPSIRT", Version: version.Get().Version},
				Date:   now,
			},
			RevisionHistory: revisions(entered.OpenedAt.UTC(), gone, now),
		},
	}
	if text := summaryOf(issue, identifier); text != "" {
		doc.Document.Notes = []Note{{Category: "description", Title: "Summary", Text: text}}
	}

	vulnerability := Vulnerability{
		Title: summaryOf(issue, identifier),
		IDs:   []Issued{{SystemName: who.Name, Text: identifier}},
	}
	// A CVE assigned later is another name for the same issue, and the
	// issue is then filed under it. Where that has happened the document
	// says so in the field a reader looks in.
	if isCVE(issue.Identifier) {
		vulnerability.CVE = issue.Identifier
	}
	// And every other name it goes by, in the field that carries names . A
	// reader searching by the identifier a coordinator gave them finds
	// this document, which is the one lookup a published advisory exists
	// to serve — and the CVE is filled in from an alias where the issue is
	// still filed under the identifier we minted.
	for _, name := range aliases {
		if name == identifier || name == issue.Identifier {
			continue
		}
		vulnerability.IDs = append(vulnerability.IDs, Issued{SystemName: "alias", Text: name})
		if vulnerability.CVE == "" && isCVE(name) {
			vulnerability.CVE = name
		}
	}
	if !entered.OpenedAt.IsZero() {
		vulnerability.DiscoveryDate = entered.OpenedAt.UTC().Format("2006-01-02")
	}

	// One branch per release, under the product, under the publisher. The
	// tree names releases rather than components on purpose: an advisory
	// aggregates to a product and a version range, and a reader of one is
	// asking "am I affected", which a dependency path does not answer .
	versions := make([]Branch, 0, len(releases))
	for _, release := range releases {
		versions = append(versions, Branch{
			Category: "product_version", Name: release.Name(),
			Product: &Named{
				Name: fmt.Sprintf("%s %s", shown, release.Name()),
				ID:   release.ProductID(product),
			},
		})
		if release.Holds {
			vulnerability.Status.KnownAffected = append(
				vulnerability.Status.KnownAffected, release.ProductID(product))
		} else {
			vulnerability.Status.Fixed = append(
				vulnerability.Status.Fixed, release.ProductID(product))
		}
	}
	doc.ProductTree = ProductTree{Branches: []Branch{{
		Category: "vendor", Name: who.Name,
		Branches: []Branch{{
			Category: "product_name", Name: shown, Branches: versions,
		}},
	}}}
	doc.Vulnerabilities = []Vulnerability{vulnerability}
	return doc, nil
}

// Release is one build of the product and where it stands on the issue.
type Release struct {
	Stream  string
	Variant string
	// Holds says the issue is open there. False is a release that held it and
	// no longer does, which is the one that was fixed.
	Holds bool
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
		return nil, nil, ErrNoSuchIssue
	}

	// The earliest finding of this issue in this product that a person
	// recorded. Earliest because it is what the document dates itself from,
	// and a flaw recorded once and later found in a second release is one
	// flaw with one discovery.
	var row finding.Finding
	err = s.db.NewSelect().Model(&row).
		Join("JOIN target AS t ON t.id = f.target_id").
		Join("JOIN stream AS st ON st.id = t.stream_id").
		Where("st.product_id = ?", productID).
		Where("f.vulnerability_id = ?", issue.ID).
		Where("f.visibility IN (?)", bun.List(access.Visible(subject, productID))).
		Where("f.kind = ?", finding.Entered).
		OrderExpr("f.opened_at ASC, f.id ASC").
		Limit(1).Scan(ctx)
	if err != nil {
		// Whether the issue is here at all and whether it is ours are told
		// apart deliberately: the first is a typo and the second is a scope
		// rule somebody has to understand.
		if s.here(ctx, subject, productID, issue.ID) {
			return nil, nil, ErrNotOurs
		}
		return nil, nil, ErrNoSuchIssue
	}
	return &issue, &row, nil
}

// here reports whether the product holds this issue at all, however it arrived.
func (s *Store) here(ctx context.Context, subject access.Subject,
	productID, issueID int64) bool {

	count, err := s.db.NewSelect().Model((*finding.Finding)(nil)).
		Join("JOIN target AS t ON t.id = f.target_id").
		Join("JOIN stream AS st ON st.id = t.stream_id").
		Where("st.product_id = ?", productID).
		Where("f.vulnerability_id = ?", issueID).
		Where("f.visibility IN (?)", bun.List(access.Visible(subject, productID))).
		Count(ctx)
	return err == nil && count > 0
}

// releases reports every build of the product that holds this issue or once
// did, which is what an advisory states something about.
func (s *Store) releases(ctx context.Context, subject access.Subject,
	productID, issueID int64) ([]Release, error) {

	var rows []struct {
		Stream  string `bun:"stream"`
		Variant string `bun:"variant"`
		Open    int    `bun:"open"`
	}
	// One statement rather than one per build: a product with thirty tags
	// would otherwise be thirty round trips to write one document, and the
	// answer would be assembled from thirty moments rather than one.
	err := s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN target AS t ON t.id = f.target_id").
		Join("JOIN stream AS st ON st.id = t.stream_id").
		Join("JOIN variant AS va ON va.id = t.variant_id").
		ColumnExpr("st.name AS stream").
		ColumnExpr("va.name AS variant").
		// Counted rather than filtered, so a release that held the flaw and no
		// longer does is still a row — that is the release somebody upgrades
		// to, and dropping it would leave finished work indistinguishable
		// from a release that never shipped the thing.
		ColumnExpr("COUNT(CASE WHEN f.closed_at IS NULL THEN 1 END) AS open").
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

// statusOf says where the document sits in its life.
func statusOf(row *finding.Finding) string {
	if row.Visibility == access.Private {
		return "draft"
	}
	return "final"
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

// Issuance is one time an advisory for one flaw went out.
//
// A fact about a moment rather than a derived value: what was published on a
// date cannot be worked out again once the record it was generated from has
// moved on — a release is added, a decision is revised, a fix lands. If it is
// not written down when it happens it is gone.
type Issuance struct {
	bun.BaseModel `bun:"table:advisory_issuance,alias:ai"`

	ID              int64 `bun:"id,pk,autoincrement"`
	ProductID       int64 `bun:"product_id,notnull"`
	VulnerabilityID int64 `bun:"vulnerability_id,notnull"`
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

// Issued records that an advisory for this flaw went out, and returns what was
// recorded.
//
// **The digest is taken from the document as it is now**, generated inside
// this call rather than supplied by the caller. A caller-supplied digest is a
// digest of whatever they say — and the question this exists to answer is
// whether what is published is still what we would generate, which only means
// something if both sides come from here.
//
// The ordinal is read and used in one transaction, so two people recording an
// issuance at the same moment cannot be handed the same number.
func (s *Store) Issued(ctx context.Context, subject access.Subject, who publisher.Named,
	product, identifier, summary string) (*Issuance, error) {

	doc, err := s.For(ctx, subject, who, product, identifier)
	if err != nil {
		return nil, err
	}
	named, err := catalog.NewStore(s.db).ProductByName(ctx, product)
	if err != nil {
		return nil, err
	}
	issue, _, err := s.ours(ctx, subject, named.ID, identifier)
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

	recorded := &Issuance{
		ProductID: named.ID, VulnerabilityID: issue.ID,
		Digest: hex.EncodeToString(sum[:]), Summary: strings.TrimSpace(summary),
		IssuedBy: subject.ID, IssuedAt: s.now().UTC().Truncate(time.Microsecond),
	}
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		// Scanned into a value rather than read through a cursor: a cursor
		// left open while the insert runs is two statements interleaved on one
		// connection, which one engine tolerates and another refuses.
		var highest int
		if err := tx.NewSelect().Model((*Issuance)(nil)).
			ColumnExpr("COALESCE(MAX(ordinal), 0)").
			Where("product_id = ?", named.ID).
			Where("vulnerability_id = ?", issue.ID).
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

// Issuances is what has gone out for one flaw in one product, newest first.
//
// **Readable without generating a document.** Every issuance is already in the
// document's own revision history, which is right for a reader of the document
// — but it made "has an advisory gone out for this, and is what is published
// still what we would generate" a question you had to build a CSAF document to
// answer. Somebody deciding whether to publish a revision is asking before
// they generate anything.
//
// Narrowed like everything else: an advisory is about a flaw in a product, so
// whoever may read that product's findings may read what went out about them.
func (s *Store) Issuances(ctx context.Context, subject access.Subject,
	product, identifier string) ([]Issuance, error) {

	named, err := catalog.NewStore(s.db).ProductByName(ctx, product)
	if err != nil {
		return nil, err
	}
	if !subject.Sees(named.ID) {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", named.ID))
	}
	// Authorized before the identifier is resolved, so a name nobody holds
	// and a name in a product this reader cannot see answer alike.
	issue, _, err := s.ours(ctx, subject, named.ID, identifier)
	if err != nil {
		return nil, err
	}
	gone, err := s.issuances(ctx, named.ID, issue.ID)
	if err != nil {
		return nil, err
	}
	// Newest first, unlike the document's history: a screen is answering "what
	// is the state of this now", and a document is telling a story from the
	// beginning.
	for i, j := 0, len(gone)-1; i < j; i, j = i+1, j-1 {
		gone[i], gone[j] = gone[j], gone[i]
	}
	return gone, nil
}

// issuances is what has gone out for one flaw, oldest first.
func (s *Store) issuances(ctx context.Context, productID, issueID int64) ([]Issuance, error) {
	var rows []Issuance
	err := s.db.NewSelect().Model(&rows).
		Where("product_id = ?", productID).
		Where("vulnerability_id = ?", issueID).
		Order("ordinal").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read what has gone out: %w", err)
	}
	return rows, nil
}

// revisions is the history a reader of the document sees.
//
// The first entry is the day the flaw was recorded here, which is what the
// document dates itself from. Every issuance after that is an entry of its
// own, because the point of the history is that a reader can tell one revision
// from another — and the last entry is this document, which has not gone out
// yet and says so.
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
	if len(gone) > 0 {
		out = append(out, Revision{
			Number: strconv.Itoa(len(gone) + 2), Date: now,
			Summary: "Generated, not yet issued",
		})
	}
	return out
}
