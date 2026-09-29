// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

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
	releases, err := releases(ctx, s.db, subject, a.advisory, one.ProductID, issue.ID)
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
		vulnerability.DiscoveryDate = opened.UTC().Format(time.RFC3339)
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
	// The affected releases split by what can be done about them: the ones a
	// fix is for, and the ones a decision says will not be fixed, with what
	// stops the flaw there where the decision named it.
	var fixable []string
	unfixed := &noFix{}
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
		switch release.Status() {
		case KnownNotAffected:
			// Why, beside the status: the decision's reason as the flag a
			// machine reads, and what stops the flaw as the impact a person
			// reads, where the decision named it. Never the reasoning, which
			// is the argument a triager put to a second person here.
			vulnerability.Status.KnownNotAffected = append(
				vulnerability.Status.KnownNotAffected, leaf.ID)
			vulnerability.Flags = flagged(vulnerability.Flags, release.Grounds.Reason, leaf.ID)
			if release.Grounds.Mitigation != "" {
				vulnerability.Threats = threatened(vulnerability.Threats,
					release.Grounds.Mitigation, leaf.ID)
			}
			// Neither scored nor remediated: a rating is stated for a
			// release the flaw is in, and a remediation for a release that
			// has to act.
			continue
		case Fixed:
			vulnerability.Status.Fixed = append(vulnerability.Status.Fixed, leaf.ID)
			fixed = append(fixed, leaf)
		default:
			vulnerability.Status.KnownAffected = append(
				vulnerability.Status.KnownAffected, leaf.ID)
			if release.NoFixPlanned() {
				unfixed.add(leaf.ID, release.Grounds.Mitigation)
			} else {
				fixable = append(fixable, leaf.ID)
			}
		}
		// Every release the flaw is or was in, which is what a rating is
		// stated for: the score is the flaw's, and the flaw is the same flaw
		// in each.
		rated = append(rated, leaf.ID)
	}
	ratings, err := finding.NewVulnerabilities(s.db).Ratings(ctx, issue.ID)
	if err != nil {
		return err
	}
	vulnerability.Scores = scoresFor(issue, ratings, rated)
	vulnerability.Remediations = remediationsFor(fixed, fixable, unfixed)

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

// flagged adds a release to the flag for its reason, opening one where no
// release before it gave that reason. One flag per reason, in the order the
// releases are named.
func flagged(flags []Flag, reason, release string) []Flag {
	for i := range flags {
		if flags[i].Label == reason {
			flags[i].ProductIDs = append(flags[i].ProductIDs, release)
			return flags
		}
	}
	return append(flags, Flag{Label: reason, ProductIDs: []string{release}})
}

// threatened adds a release to the impact statement carrying its
// mitigation, opening one where no release before it named that mitigation.
func threatened(threats []Threat, mitigation, release string) []Threat {
	for i := range threats {
		if threats[i].Details == mitigation {
			threats[i].ProductIDs = append(threats[i].ProductIDs, release)
			return threats
		}
	}
	return append(threats, Threat{Category: "impact", Details: mitigation,
		ProductIDs: []string{release}})
}
