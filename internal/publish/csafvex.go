// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package publish

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/version"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

// vexProfile is the category a CSAF document of the VEX profile declares.
const vexProfile = "csaf_vex"

// revision is one revision of a document: its number, when the first and this
// one were released, and every revision so far, this one last.
type revision struct {
	Version int
	First   time.Time
	Current time.Time
	History []advisory.Revision
}

// The relationship a component of a build is stated through. The standard's
// word for a component that ships as part of a product by default.
const partOf = "default_component_of"

// precedence orders the statuses a product identifier could be listed under
// twice, the most cautious first. A document listing one product under two
// statuses is refused by every validator, and a reader is better told the
// cautious answer than a contradiction.
var precedence = map[string]int{
	vex.Affected: 0, vex.Fixed: 1, vex.NotAffected: 2,
}

// vexDocuments is a CSAF VEX document for every issue anything is stated about
// in the product.
func (g *Generator) vexDocuments(product *catalog.Product, builds []*built,
	described map[int64]string) []Generated {

	var out []Generated
	for _, facts := range byIssue(builds) {
		out = append(out, g.vexDocument(product, facts, described[facts[0].fact.VulnerabilityID]))
	}
	return out
}

// vexDocument is the CSAF VEX document about one issue in one product.
//
// One document per issue, across every branch, tag and variant, because that
// is the question a reader asks of it: this CVE, in what I ship from them. A
// statement names the component by its exact package identifier, never a
// branch head, and holds either for anybody shipping the component — stated
// about the component's own product entry — or for this product's build
// alone, stated about the component as part of that build through a
// relationship.
func (g *Generator) vexDocument(product *catalog.Product, facts []placed, described string) Generated {
	issue := facts[0].fact
	tracking := "VEX-" + product.Name + "-" + issue.Issue
	title := issue.Issue + " in " + product.DisplayName

	tree, statuses := g.treeFor(product, facts)
	vulnerability := advisory.Vulnerability{Status: statuses.status}
	if advisory.IsCVE(issue.Issue) {
		vulnerability.CVE = issue.Issue
	} else {
		vulnerability.IDs = append(vulnerability.IDs,
			advisory.Issued{SystemName: systemOf(issue.Issue), Text: issue.Issue})
	}
	for _, alias := range issue.Aliases {
		if vulnerability.CVE == "" && advisory.IsCVE(alias) {
			vulnerability.CVE = alias
			continue
		}
		vulnerability.IDs = append(vulnerability.IDs,
			advisory.Issued{SystemName: systemOf(alias), Text: alias})
	}
	summary := described
	if strings.TrimSpace(summary) == "" {
		summary = issue.Issue
	}
	vulnerability.Notes = []advisory.Note{{Category: "description", Title: "Summary", Text: summary}}
	vulnerability.Flags = statuses.flags()
	vulnerability.Threats = statuses.threats()
	vulnerability.Remediations = statuses.remediations()

	// The address it states and the publisher it names are part of what it
	// says: moved, every document is revised to say the new ones rather than
	// the feed alone.
	stated := struct {
		Address         string                   `json:"address"`
		Publisher       advisory.Issuer          `json:"publisher"`
		Title           string                   `json:"title"`
		ProductTree     advisory.ProductTree     `json:"product_tree"`
		Vulnerabilities []advisory.Vulnerability `json:"vulnerabilities"`
	}{g.base, advisory.IssuerOf(g.who), title, tree, []advisory.Vulnerability{vulnerability}}
	// A struct of strings and slices of strings marshals without fault.
	digestOver, _ := json.Marshal(stated)

	path := func(at revision) string {
		return DirectoryPath + advisory.PathOf(tracking, at.First)
	}
	return Generated{
		Kind: CSAFVEX, Subject: issue.Issue, TrackingID: tracking, Title: title,
		Settled: settled(digestOver), path: path,
		render: func(at revision) ([]byte, error) {
			doc := advisory.Document{
				Document: advisory.Meta{
					Category: vexProfile, CSAFVersion: advisory.CSAFVersion, Title: title,
					Language: "en-US", Publisher: advisory.IssuerOf(g.who),
					Tracking: advisory.Tracking{
						ID: tracking, Status: "final", Version: fmt.Sprint(at.Version),
						InitialReleaseDate: at.First, CurrentReleaseDate: at.Current,
						Generator: &advisory.Generator{
							Engine: advisory.Engine{Name: "OpenPSIRT", Version: version.Get().Version},
							Date:   at.Current,
						},
						RevisionHistory: at.History,
					},
					References: []advisory.Reference{{
						Category: "self", Summary: tracking, URL: g.base + path(at),
					}},
					Distribution: advisory.DistributionFor(false),
				},
				ProductTree:     tree,
				Vulnerabilities: []advisory.Vulnerability{vulnerability},
			}
			body, err := json.Marshal(doc)
			if err != nil {
				return nil, fmt.Errorf("write the VEX document about %s: %w", issue.Issue, err)
			}
			return body, nil
		},
	}
}

// systemOf is the system an identifier that is not a CVE belongs to, read
// from what it opens with.
func systemOf(identifier string) string {
	if cut := strings.Index(identifier, "-"); cut > 0 {
		return identifier[:cut]
	}
	return "alias"
}

// listing is what a document states about each product it names: the status
// each is listed under, and the reasons and actions beside them.
type listing struct {
	status advisory.Status
	// at is the status each product identifier is listed under, so one listed
	// twice keeps the more cautious.
	at map[string]vex.Fact
}

// treeFor is the product tree naming everything the facts are about, and the
// status each named product is listed under.
func (g *Generator) treeFor(product *catalog.Product, facts []placed) (advisory.ProductTree, *listing) {
	alone := portableForm(facts)
	named := &listing{at: map[string]vex.Fact{}}
	versions := map[string]advisory.Branch{}
	components := map[string]advisory.Named{}
	relationships := map[string]advisory.Relationship{}

	component := func(subject, purl string) string {
		id := subject
		if purl == "" {
			id = "component:" + subject
		}
		if _, ok := components[id]; !ok {
			components[id] = advisory.Named{Name: subject, ID: id, Helper: helperOf(purl)}
		}
		return id
	}
	for _, one := range facts {
		fact := one.fact
		part := component(fact.Subject(), fact.Purl)
		if fact.Within == "" && alone[fact.Subject()] {
			named.list(part, fact)
			continue
		}
		var within, withinName string
		if fact.Within != "" {
			within = component(fact.Within, fact.Within)
			withinName = fact.Within
		} else {
			within = one.build.id(product.Name)
			withinName = product.DisplayName + " " + one.build.streamShown + " (" + one.build.variantShown + ")"
			if _, ok := versions[within]; !ok {
				leaf := &advisory.Named{Name: withinName, ID: within, Helper: helperOf(one.build.root)}
				versions[within] = advisory.Branch{
					Category: "product_version",
					Name:     one.build.stream + " (" + one.build.variant + ")",
					Product:  leaf,
				}
			}
		}
		id := part + "|" + within
		if _, ok := relationships[id]; !ok {
			relationships[id] = advisory.Relationship{
				Category:  partOf,
				Named:     advisory.Named{Name: fact.Subject() + " as part of " + withinName, ID: id, Helper: helperOf(fact.Purl)},
				Reference: part, Within: within,
			}
		}
		named.list(id, fact)
	}

	tree := advisory.ProductTree{}
	if len(versions) > 0 {
		var leaves []advisory.Branch
		for _, key := range sortedKeys(versions) {
			leaves = append(leaves, versions[key])
		}
		tree.Branches = []advisory.Branch{{Category: "vendor", Name: g.who.Name,
			Branches: []advisory.Branch{{Category: "product_name", Name: product.DisplayName,
				Branches: leaves}}}}
	}
	for _, key := range sortedKeys(components) {
		tree.FullNames = append(tree.FullNames, components[key])
	}
	for _, key := range sortedKeys(relationships) {
		tree.Relationships = append(tree.Relationships, relationships[key])
	}
	named.settle()
	return tree, named
}

// list names one product under the status a fact states, keeping the more
// cautious where it is named twice.
func (l *listing) list(id string, fact vex.Fact) {
	if was, ok := l.at[id]; ok && precedence[was.Status] <= precedence[fact.Status] {
		return
	}
	l.at[id] = fact
}

// settle writes the status lists, each in order of identifier.
func (l *listing) settle() {
	for _, id := range sortedKeys(l.at) {
		switch l.at[id].Status {
		case vex.NotAffected:
			l.status.KnownNotAffected = append(l.status.KnownNotAffected, id)
		case vex.Fixed:
			l.status.Fixed = append(l.status.Fixed, id)
		case vex.Affected:
			l.status.KnownAffected = append(l.status.KnownAffected, id)
		}
	}
}

// flags is one flag per reason a product is not affected, naming the products
// it is given for.
func (l *listing) flags() []advisory.Flag {
	by := map[string][]string{}
	for _, id := range sortedKeys(l.at) {
		if fact := l.at[id]; fact.Status == vex.NotAffected && fact.Justification != "" {
			by[fact.Justification] = append(by[fact.Justification], id)
		}
	}
	var out []advisory.Flag
	for _, label := range sortedKeys(by) {
		out = append(out, advisory.Flag{Label: label, ProductIDs: by[label]})
	}
	return out
}

// threats is what stops the flaw in a product not affected, where somebody
// named it, one statement per mitigation.
func (l *listing) threats() []advisory.Threat {
	by := map[string][]string{}
	for _, id := range sortedKeys(l.at) {
		if fact := l.at[id]; fact.Status == vex.NotAffected && fact.Impact != "" {
			by[fact.Impact] = append(by[fact.Impact], id)
		}
	}
	var out []advisory.Threat
	for _, details := range sortedKeys(by) {
		out = append(out, advisory.Threat{Category: "impact", Details: details, ProductIDs: by[details]})
	}
	return out
}

// remediations is what a holder of an affected product can do: that no fix is
// planned, or none is available yet, and what to do instead where the claim
// named it.
func (l *listing) remediations() []advisory.Remediation {
	type said struct{ category, details string }
	by := map[said][]string{}
	for _, id := range sortedKeys(l.at) {
		fact := l.at[id]
		if fact.Status != vex.Affected {
			continue
		}
		switch fact.Action {
		case vex.NoFixYet:
			by[said{"none_available", fact.Action}] = append(by[said{"none_available", fact.Action}], id)
		case vex.NoFixPlanned:
			by[said{"no_fix_planned", fact.Action}] = append(by[said{"no_fix_planned", fact.Action}], id)
		default:
			// A claim that will not be fixed, naming what to do instead.
			planned := said{"no_fix_planned", vex.NoFixPlanned}
			by[planned] = append(by[planned], id)
			by[said{"mitigation", fact.Action}] = append(by[said{"mitigation", fact.Action}], id)
		}
	}
	keys := make([]said, 0, len(by))
	for key := range by {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].category != keys[j].category {
			return keys[i].category < keys[j].category
		}
		return keys[i].details < keys[j].details
	})
	var out []advisory.Remediation
	for _, key := range keys {
		out = append(out, advisory.Remediation{Category: key.category, Details: key.details,
			ProductIDs: by[key]})
	}
	return out
}

// sortedKeys is a map's keys in order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// helperOf is what a reader matches a component by: its package identifier,
// where the build stated one.
//
// A value from somebody else's inventory that is not a package identifier is
// left out rather than stated: the standard's schema refuses it, and one
// refused helper fails the whole document.
func helperOf(purl string) *advisory.IdentificationHelper {
	if !advisory.IsPackageIdentifier(purl) {
		return nil
	}
	return &advisory.IdentificationHelper{Purl: purl}
}
