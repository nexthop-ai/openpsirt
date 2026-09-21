package advisory

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/weakness"
)

// The parts of the document that carry what is held about the flaw rather than
// what identifies the document: where a reader can go, what the flaw scored,
// what an affected release can do about it, and who is credited.
//
// Only what is held. Nothing here derives a fact the record does not carry.
// A field the standard defines and this deployment has no data for is left out,
// because an advisory is read by somebody deciding whether to act.

// Reference is somewhere a reader can go about the flaw.
//
// Category is the standard's: "external" for somebody else's page, "self" for
// this document at its published address. Nothing here publishes, so nothing
// states a self reference — a self reference to an address that answers
// nothing is worse than none, because a reader's tooling follows it.
type Reference struct {
	Category string `json:"category,omitempty"`
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}

// Distribution says how the document may be passed on.
type Distribution struct {
	TLP *TLP `json:"tlp,omitempty"`
}

// TLP is the label a reader shares the document by.
type TLP struct {
	Label string `json:"label"`
	URL   string `json:"url,omitempty"`
}

// tlpURL is where the labels are defined. The standard asks for the URL of the
// definition the label is taken from rather than assuming one.
const tlpURL = "https://www.first.org/tlp/"

// Score is one rating of the flaw and which releases it was rated for.
type Score struct {
	CVSSv3 *CVSSv3 `json:"cvss_v3,omitempty"`
	// Products is which releases the rating is stated for. The standard
	// requires it: a score with nothing to attach to is a number in a
	// document.
	Products []string `json:"products"`
}

// CVSSv3 is a base score as the standard carries it.
//
// The field names are the CVSS schema's, which is why they are spelled in its
// casing rather than this codebase's — the same exemption the CSAF field names
// have.
type CVSSv3 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// Remediation is what somebody holding a release can do about the flaw.
type Remediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

// Acknowledgment is whoever told us, named the way they asked to be named.
type Acknowledgment struct {
	Names   []string `json:"names,omitempty"`
	Summary string   `json:"summary,omitempty"`
}

// referencesTo is every address this deployment holds about the flaw.
//
// On the document rather than on the vulnerability. The document is about
// one flaw, so the two lists would hold the same addresses, and the standard's
// security-advisory profile requires the document's. One list, in the place
// that is asked for.
func (s *Store) referencesTo(ctx context.Context,
	issue *finding.Vulnerability) ([]Reference, error) {

	var rows []finding.Reference
	err := s.db.NewSelect().Model(&rows).
		Where("vr.vulnerability_id = ?", issue.ID).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read where this issue is written up: %w", err)
	}

	held := make([]Reference, 0, len(rows)+1)
	if url := strings.TrimSpace(issue.Advisory); url != "" {
		held = append(held, Reference{Summary: "Advisory", URL: url})
	}
	for _, row := range rows {
		held = append(held, Reference{Summary: summaryOfKind(row.Kind), URL: strings.TrimSpace(row.URL)})
	}

	seen := map[string]bool{}
	out := make([]Reference, 0, len(held))
	for _, one := range held {
		// An address a scanner or a feed supplied, going into a document
		// somebody else's tooling will follow. The same rule an address
		// stored beside a claim goes through, for the stronger case: this one
		// leaves the deployment.
		if one.URL == "" || seen[one.URL] || markdown.Addressable(one.URL) != nil {
			continue
		}
		seen[one.URL] = true
		one.Category = "external"
		out = append(out, one)
	}
	// Ordered here rather than by the engine, for the reason the releases are:
	// two documents generated from the same facts are the same bytes, and the
	// engines do not agree on how text compares.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Summary != out[j].Summary {
			return out[i].Summary < out[j].Summary
		}
		return out[i].URL < out[j].URL
	})
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// summaryOfKind says what a reference appears to be, in the words a reader of
// the document gets rather than the stored value.
func summaryOfKind(kind finding.ReferenceKind) string {
	switch kind {
	case finding.Patch:
		return "Patch"
	case finding.AdvisoryRef:
		return "Advisory"
	default:
		return "Report"
	}
}

// creditedFor is whoever reported the flaw, where they said how to name them.
//
// The credit and nothing else. Somebody reporting a flaw under a name gave
// it so we could reply, not so it could be published; the credit field is the
// one they answered the publication question with, and "anonymous" is a real
// answer to it. So a report with a reporter and no credit is acknowledged as
// nobody.
//
// Narrowed to the product the document is about, which is how the report is
// keyed: an issue's identity spans its aliases, so a report read on the issue
// alone is readable from every product that ever recorded a shared name.
func (s *Store) creditedFor(ctx context.Context, productID,
	issueID int64) ([]Acknowledgment, error) {

	var credits []string
	err := s.db.NewSelect().Model((*finding.WhoTold)(nil)).
		ColumnExpr("fr.credit").
		Where("fr.vulnerability_id = ?", issueID).
		Where("fr.product_id = ?", productID).
		Scan(ctx, &credits)
	if err != nil {
		return nil, fmt.Errorf("read who is credited for this: %w", err)
	}

	names := make([]string, 0, len(credits))
	for _, credit := range credits {
		if credit = strings.TrimSpace(credit); credit != "" {
			names = append(names, credit)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	sort.Strings(names)
	return []Acknowledgment{{Names: names, Summary: "Reported this flaw"}}, nil
}

// carriedByCSAF is the scoring schemes a CSAF 2.0 document has a field for.
//
// The standard's score object holds a version 2 score and a version 3 score,
// and version 4 arrives with CSAF 2.1. So a flaw assessed under version 4 is
// published with no score at all: the number is recorded and shown here, and
// the document states what it has a place to state.
var carriedByCSAF = map[string]bool{"3.0": true, "3.1": true}

// scoresFor is what the flaw scored, stated for every release the document
// names.
//
// Worked out from the vector rather than read alongside it, which is the rule
// the record is written under: a stored number and a stored vector that
// disagree have nothing to say which was meant, and the standard's own
// consumers recompute.
//
// A vector under a scheme this deployment does not score, or one the document
// has no field for, yields nothing rather than a number in the wrong place.
func scoresFor(issue *finding.Vulnerability, products []string) []Score {
	if len(products) == 0 || strings.TrimSpace(issue.Vector) == "" {
		return nil
	}
	scored, err := finding.Score(issue.Vector)
	if err != nil || scored == nil {
		return nil
	}
	if !carriedByCSAF[scored.Scheme()] {
		return nil
	}
	return []Score{{
		CVSSv3: &CVSSv3{
			Version:      scored.Scheme(),
			VectorString: scored.Vector,
			BaseScore:    float64(scored.ScoreCenti) / 100,
			BaseSeverity: strings.ToUpper(scored.Severity),
		},
		Products: products,
	}}
}

// remediationsFor is what a reader can do, from what is true now.
//
// It names the releases. "Update to a release in which this flaw is fixed"
// is the instruction with the answer left out, and the answer is three lines
// away in the same function. A reader then has to find the fixed set in the
// product status and match identifiers by hand — which is the work a document
// exists to save.
//
// Not the earliest fixed release. Picking one means ordering release names,
// which this does not do for the reason nothing else here does: an ordering
// that answers confidently for a pair it cannot order is worse than none. All
// of them, in the order the tree names them, and the reader picks.
//
// Stated for the releases that carry the flaw, which is who a remediation
// is for: CSAF § 3.2.3.12.6 defines the product identifiers as what the item
// applies to, and § 3.2.3.12.1 defines a vendor fix as one for the affected
// product. Pointed at the releases that are already fixed, the customer who
// has to act reads an advisory with no remediation for them, and the release
// that needs nothing is told to update. Which release to move to is what the
// details say.
//
// Nothing about planned work. A commitment is one build's plan, agreed to
// inside this deployment; the same sentence in a published advisory is a
// promise to a customer about a date, and whether to make one is the
// publisher's.
func remediationsFor(fixed []Named, affected []string) []Remediation {
	// Nothing to remediate where nothing carries it: a document about a flaw
	// every release has left behind is a record rather than a warning.
	if len(affected) == 0 {
		return nil
	}
	if len(fixed) > 0 {
		names := make([]string, 0, len(fixed))
		for _, one := range fixed {
			names = append(names, one.Name)
		}
		return []Remediation{{
			Category: "vendor_fix",
			Details: "Update to a release in which this flaw is fixed: " +
				strings.Join(names, ", ") + ".",
			ProductIDs: affected,
		}}
	}
	return []Remediation{{
		Category:   "none_available",
		Details:    "No release fixing this is available.",
		ProductIDs: affected,
	}}
}

// weaknessOf is what kind of flaw this is, where the catalog knows the name.
//
// The root cause, and only where something said which. The standard carries
// one weakness per flaw and an issue is commonly classified as several, so a
// document that stated the first of them would be stating a claim nobody made.
// Asked of the row the data marked rather than of the order they sort in: a
// report that called nothing the root cause leaves this saying nothing, which
// is the same answer every other field the record cannot fill gives.
//
// The name comes from the catalog rather than from anything held here, because
// a validator compares the pair against the catalog and nothing else would
// match. An identifier it does not assign — a category, a view, a number a
// newer catalog added — states nothing, which is the same answer this file
// gives everywhere: a field the record cannot fill is left out.
//
// A failed read is not a classification, and is answered as a failure. Saying
// nothing here reads as "this flaw has no kind", which is a statement about the
// issue that a database that would not answer does not support — and it would
// publish a document silently missing the field, byte-identical to one about a
// flaw nobody classified.
func weaknessOf(ctx context.Context, db bun.IDB, issueID int64) (*Weakness, error) {
	var held []string
	if err := db.NewSelect().Model((*finding.Weakness)(nil)).
		ColumnExpr("vw.cwe").
		Where("vw.vulnerability_id = ?", issueID).
		Where("vw.is_primary = ?", true).
		OrderExpr("vw.cwe").
		Limit(1).Scan(ctx, &held); err != nil {
		return nil, fmt.Errorf("read what kind of flaw this is: %w", err)
	}
	if len(held) == 0 {
		return nil, nil
	}
	name, known := weakness.Name(held[0])
	if !known {
		return nil, nil
	}
	return &Weakness{ID: held[0], Name: name}, nil
}

// isPackageIdentifier says the string is the shape the standard states for a
// product identification helper.
//
// The standard's own pattern, which a consumer's validator applies to the whole
// document: a scheme, a type drawn from a small set of characters, and a name
// after the separator. Nothing here interprets it further — what is being
// refused is a value that is not an identifier at all, not one naming something
// unexpected.
func isPackageIdentifier(s string) bool { return packageIdentifier.MatchString(s) }

var packageIdentifier = regexp.MustCompile(`^pkg:[A-Za-z.\-+][A-Za-z0-9.\-+]*/.+`)

// distributionFor is how far the document may travel.
//
// The embargo, read from the issues rather than from the tracking status.
// Handing a document about a flaw nobody outside has been told about to
// somebody who may pass it on is the disclosure the embargo exists to hold,
// and that is true of a document at any point in its editorial life — a
// finished one most of all.
//
// The labels are the standard's four, which is why a disclosed document is
// WHITE rather than the word the protocol renamed it to.
func distributionFor(undisclosed bool) *Distribution {
	label := "WHITE"
	if undisclosed {
		label = "RED"
	}
	return &Distribution{TLP: &TLP{Label: label, URL: tlpURL}}
}

// profileOf is the category the document may honestly declare.
//
// CSAF 2.0 § 4.4. The security-advisory profile is the base profile plus a
// product tree, the vulnerabilities, and notes and a status on each of them.
// Notes and references on the *document* are § 4.3's requirement — the
// informational advisory, which is the profile for a document that carries no
// vulnerabilities at all and therefore has nothing but prose and somewhere to
// go.
//
// Gated on § 4.3's list, a flaw nobody outside has written up — which is
// every flaw of our own before a feed carries it — declared the base profile,
// and a customer's tooling filtering for security advisories skipped it.
//
// The VEX profile is a separate question and is not assembled here: its point
// is the not-affected justification.
func profileOf(doc *Document) string {
	return Categorized(doc)
}

// Categorized is the same question asked of a document somebody already has.
//
// Exported so the rule can be watched to fail: the arm that refuses is
// unreachable through the store, because every document it assembles carries a
// product tree and one vulnerability.
func Categorized(doc *Document) string {
	if len(doc.ProductTree.Branches) == 0 || len(doc.Vulnerabilities) == 0 {
		return "csaf_base"
	}
	for _, one := range doc.Vulnerabilities {
		if len(one.Notes) == 0 {
			return "csaf_base"
		}
		if len(one.Status.KnownAffected) == 0 && len(one.Status.Fixed) == 0 {
			return "csaf_base"
		}
	}
	return "csaf_security_advisory"
}
