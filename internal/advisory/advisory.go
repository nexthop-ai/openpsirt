// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package advisory turns what is held about a flaw in our own product into a
// document somebody can publish.
//
// We own the triage record; whoever publishes owns the published advisory.
// Nothing here goes out over the network: a document is assembled from what is
// held and handed over. What is kept is the record that one went out, the
// bytes that went out, and the digest of the part of them that says what the
// document states — which is what makes "is what is published still what we
// would generate" answerable. That is the question that decides whether an
// integration works or rots, and keeping both ends as the source of truth is
// how it rots.
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
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/version"
)

// ErrNotOurs says the issue is not one this deployment recorded.
var ErrNotOurs = refusal.New(
	"an advisory is about a flaw in what we ship, and this issue was reported by a scanner")

// ErrNoPublisher says the deployment has not been told who it publishes as.
//
// Wrapped by missingPublisher, which names the setting that is not set, by
// its variable and by its key in a configuration file: the
// person who sees this cannot fix it, and the operator who can is reading a
// relayed message rather than sitting at the process.
var ErrNoPublisher = refusal.New("this deployment has not been configured with a publisher")

// missingPublisher says which half of the publisher is missing.
func missingPublisher(p publisher.Named) error {
	switch {
	case p.Name == "" && p.Namespace == "":
		return fmt.Errorf("%w: set OPENPSIRT_PUBLISHER_NAME and OPENPSIRT_PUBLISHER_NAMESPACE, "+
			"or publisher.name and publisher.namespace in a configuration file", ErrNoPublisher)
	case p.Name == "":
		return fmt.Errorf("%w: set OPENPSIRT_PUBLISHER_NAME, or publisher.name in a configuration file",
			ErrNoPublisher)
	default:
		return fmt.Errorf("%w: set OPENPSIRT_PUBLISHER_NAMESPACE, or publisher.namespace in a "+
			"configuration file", ErrNoPublisher)
	}
}

// ErrNoSuchIssue says the product holds nothing under that identifier.
var ErrNoSuchIssue = refusal.New("this product holds no issue by that name")

// Store assembles advisories.
type Store struct {
	db  *bun.DB
	now func() time.Time
	// beforeWrite runs between the ordinal being read and the row being
	// written, and what it answers is returned from the closure. Set by a
	// test that has to lose that race on purpose; nil everywhere else,
	// because losing it for real needs a second writer committing inside
	// this transaction's window, which one engine will not let another
	// connection do.
	beforeWrite func() error
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
	held, err := s.covers(ctx, row)
	if err != nil {
		return nil, nil, err
	}
	if len(held) == 0 {
		return nil, nil, ErrNothingToSay
	}
	gone, err := s.issuances(ctx, subject, row)
	if err != nil {
		return nil, nil, err
	}
	// Where the document is in its life, read from what people did about it.
	// Published or not, and whether a second person agrees to what it says
	// now — never from the embargo, which answers a different question and
	// which the distribution label below still asks.
	agreed, err := s.agreed(ctx, row)
	if err != nil {
		return nil, nil, err
	}

	now := s.now().UTC()
	assembled := &assembly{who: who, advisory: row.ID, seen: map[string]bool{}}
	for _, one := range held {
		if err := s.cover(ctx, subject, assembled, one); err != nil {
			return nil, nil, err
		}
	}

	// The earliest recording among the issues it covers. A document dates
	// itself from when this deployment first knew about what it is about, and
	// an advisory about several flaws first knew about the oldest of them.
	//
	// Once it has gone out, the moment recorded then. What a published
	// document says its first release was is not something a later edit may
	// move: naming an older flaw would take the document into a different
	// year folder, leaving the file a reader already found where it was and
	// named by no list.
	opened := assembled.opened
	if row.ReleasedFrom != nil {
		opened = row.ReleasedFrom.UTC()
	}
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
			ID: row.Identifier, Status: statusOf(len(gone) > 0, len(agreed) > 0),
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
	// Where this document is published, stated last and only where the
	// deployment has said where that is. It is built from what the document
	// already carries, so the address it states and the file the directory
	// writes are one rule rather than two.
	if who.Publishes() {
		doc.Document.References = append(doc.Document.References, selfReference(who, doc))
	}
	doc.Document.Distribution = distributionFor(assembled.undisclosed)
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
	// advisory is the one being assembled, whose marks of a release as
	// affected are part of what it says.
	advisory int64
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

// titleOf is what the document calls itself.
//
// What somebody titled it, where they did. An advisory covering several flaws
// has no one sentence that describes it, so what stands in is its own name and
// how many flaws it covers — a title naming one of them would describe the
// document as being about that one.
func titleOf(row *Advisory, a *assembly) string {
	if row.Title != "" {
		return row.Title
	}
	if len(a.vulnerabilities) == 1 {
		return a.vulnerabilities[0].Title
	}
	return fmt.Sprintf("%s: %d issues", row.Identifier, len(a.vulnerabilities))
}

// ours reads the issue and the finding this deployment recorded for it, and
// refuses one that a scanner reported.
func (s *Store) ours(ctx context.Context, subject access.Subject, productID int64,
	identifier string) (*finding.Vulnerability, *finding.Finding, error) {

	var issue finding.Vulnerability
	// The folded column, folded the way it was stored, so an identifier
	// typed with other capitals is the same issue.
	err := s.db.NewSelect().Model(&issue).
		Where("identifier_folded = ?", finding.FoldIdentifier(identifier)).
		Limit(1).Scan(ctx)
	if err != nil {
		return nil, nil, database.FromRead(err, ErrNoSuchIssue,
			fmt.Sprintf("look up what issue %q is", identifier))
	}
	// A name that merged into another issue is read as the issue it merged
	// into, which holds its findings.
	if issue.IssueID != issue.ID {
		standing := issue.IssueID
		issue = finding.Vulnerability{}
		if err := s.db.NewSelect().Model(&issue).
			Where("vu.id = ?", standing).Scan(ctx); err != nil {
			return nil, nil, fmt.Errorf("look up the issue %q merged into: %w", identifier, err)
		}
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
