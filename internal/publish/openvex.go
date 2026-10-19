// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package publish

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/version"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

// openVEXContext is the namespace an OpenVEX document states.
const openVEXContext = "https://openvex.dev/ns/v0.2.0"

// openVEXDocuments is an OpenVEX document for every branch and tag of the
// product anything is stated about, at what each of its variants last
// scanned.
//
// One per branch or tag, for a scanner: what it holds is one build, and what
// it asks is what is true of that build now.
func (g *Generator) openVEXDocuments(product *catalog.Product, builds []*built) []Generated {
	streams := map[string][]*built{}
	shown := map[string]string{}
	for _, one := range builds {
		streams[one.stream] = append(streams[one.stream], one)
		shown[one.stream] = one.streamShown
	}
	var out []Generated
	for _, stream := range sortedKeys(streams) {
		if doc, ok := g.openVEXDocument(product, stream, shown[stream], streams[stream]); ok {
			out = append(out, doc)
		}
	}
	return out
}

// openVEXDocument is the OpenVEX document about one branch or tag, or nothing
// where nothing is stated about it.
//
// A statement holding for anybody shipping the component names the component
// as the product, alone. One holding for this build names the build as the
// product with the component beneath it, and one about one place names the
// component that pulls it in, the way the document of one build does. A reader
// tells the two apart by whether the product has subcomponents.
func (g *Generator) openVEXDocument(product *catalog.Product, stream, streamShown string,
	builds []*built) (Generated, bool) {

	var facts []placed
	for _, one := range builds {
		for _, fact := range one.facts {
			facts = append(facts, placed{build: one, fact: fact})
		}
	}
	if len(facts) == 0 {
		return Generated{}, false
	}
	alone := map[string]bool{}
	for _, group := range byIssue(builds) {
		for key, portable := range portableForm(group) {
			alone[group[0].fact.Issue+"\x00"+key] = portable
		}
	}

	type keyed struct {
		key       string
		statement vex.Statement
	}
	held := map[string]*keyed{}
	for _, one := range facts {
		fact := one.fact
		var shipped vex.Shipped
		switch {
		case fact.Within != "":
			shipped = vex.Shipped{ID: fact.Within, Subcomponents: []vex.Inside{{ID: fact.Subject()}}}
		case alone[fact.Issue+"\x00"+fact.Subject()]:
			shipped = vex.Shipped{ID: fact.Subject()}
		default:
			root := one.build.root
			if root == "" {
				root = one.build.id(product.Name)
			}
			shipped = vex.Shipped{ID: root, Subcomponents: []vex.Inside{{ID: fact.Subject()}}}
		}
		statement := vex.Statement{
			Vulnerability: vex.Issue{Name: fact.Issue, Aliases: fact.Aliases},
			Timestamp:     fact.Since, Products: []vex.Shipped{shipped}, Status: fact.Status,
			Justification: fact.Justification, ImpactStatement: fact.Impact,
		}
		if fact.Status == vex.Affected {
			statement.ActionStatement = fact.Action
		}
		// One statement however many variants say it: the same thing said
		// about the same product is one statement, stated from when it was
		// first true.
		undated := statement
		undated.Timestamp = time.Time{}
		// A struct of strings marshals without fault.
		raw, _ := json.Marshal(undated)
		key := string(raw)
		if was, ok := held[key]; ok {
			if statement.Timestamp.Before(was.statement.Timestamp) {
				was.statement.Timestamp = statement.Timestamp
			}
			continue
		}
		held[key] = &keyed{key: key, statement: statement}
	}
	statements := make([]vex.Statement, 0, len(held))
	for _, key := range sortedKeys(held) {
		statements = append(statements, held[key].statement)
	}
	sort.SliceStable(statements, func(i, j int) bool {
		a, b := statements[i], statements[j]
		if a.Vulnerability.Name != b.Vulnerability.Name {
			return a.Vulnerability.Name < b.Vulnerability.Name
		}
		return a.Products[0].ID < b.Products[0].ID
	})
	// Statements carry their own moments, and those are part of what the
	// document states: a statement made again later is a different statement.
	// So are the address it names itself by and its author.
	digestOver, _ := json.Marshal(struct {
		Address    string          `json:"address"`
		Author     string          `json:"author"`
		Statements []vex.Statement `json:"statements"`
	}{g.base, g.who.Name, statements})

	path := OpenVEXPath + segment(product.Name) + "/" + segment(stream) + ".json"
	title := product.DisplayName + " " + streamShown
	return Generated{
		Kind: OpenVEX, Subject: stream, TrackingID: g.base + path, Title: title,
		Settled: settled(digestOver),
		path:    func(revision) string { return path },
		render: func(at revision) ([]byte, error) {
			updated := at.Current
			doc := vex.Statements{
				Context: openVEXContext, ID: g.base + path, Author: g.who.Name,
				Tooling:   "OpenPSIRT " + version.Get().Version,
				Timestamp: at.First, LastUpdated: &updated, Version: at.Version,
				Statements: statements,
			}
			body, err := json.Marshal(doc)
			if err != nil {
				return nil, fmt.Errorf("write the OpenVEX document about %s: %w", stream, err)
			}
			return body, nil
		},
	}, true
}

// segment is a name as one segment of a path.
//
// Escaped the way a path segment is, and a name that is only dots escaped
// further, since a client resolves "." and ".." before asking.
func segment(name string) string {
	escaped := url.PathEscape(name)
	if strings.Trim(escaped, ".") == "" {
		return strings.ReplaceAll(escaped, ".", "%2E")
	}
	return escaped
}
