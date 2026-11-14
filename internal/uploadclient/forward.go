// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package uploadclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// sarifDoc reads a SARIF 2.1.0 document from any tool, to be forwarded with
// this client's additions.
type sarifDoc struct{}

func (sarifDoc) name() string { return "SARIF" }

func (sarifDoc) detects(data []byte) bool {
	trimmed := bytes.TrimLeft(data, " \t\r\n\uFEFF")
	return len(trimmed) > 0 && trimmed[0] == '{' && bytes.Contains(data, []byte(`"runs"`))
}

func (sarifDoc) read(data []byte) ([]obj, error) {
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte("\uFEFF"))))
	dec.UseNumber()
	var doc obj
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	if v := str(doc, "version"); v != sarifVersion {
		return nil, fmt.Errorf("SARIF version %q is not %s", v, sarifVersion)
	}
	runs := objects(doc, "runs")
	if len(runs) == 0 {
		return nil, errors.New("the document holds no run")
	}
	return runs, nil
}

const sarifVersion = "2.1.0"

// settled is what settling a run left out, counted for the report.
type settled struct {
	contents, fixes, snippets, markdown, attachments, invocation, run, result int
}

// runProperty is the prefix of the run properties the deployment reads.
const runProperty = "openpsirt/"

// settle makes a run self-contained and free of source text: every reference
// by position resolved to what it names, every path placed in the checkout,
// and whole files, proposed fixes, attachments, snippets, markdown and every
// member, at any depth, that the deployment does not read removed. It runs
// before runs of one tool are merged, since a position and a named starting
// point mean something only within the run that states them.
func settle(run obj, at *placer) settled {
	var out settled
	driver := child(child(run, "tool"), "driver")
	extensions := objects(child(run, "tool"), "extensions")
	artifacts := objects(run, "artifacts")
	for _, a := range artifacts {
		if _, ok := a["contents"]; ok {
			out.contents++
		}
	}
	bases := map[string]obj{}
	for name, v := range child(run, "originalUriBaseIds") {
		if b, ok := v.(obj); ok {
			bases[name] = b
		}
	}
	place := func(loc obj) {
		art := child(child(loc, "physicalLocation"), "artifactLocation")
		if art == nil {
			return
		}
		if str(art, "uri") == "" {
			if i, ok := num(art, "index"); ok && i >= 0 && i < len(artifacts) {
				if from := child(artifacts[i], "location"); from != nil {
					art["uri"], art["uriBaseId"] = from["uri"], from["uriBaseId"]
				}
			}
		}
		delete(art, "index")
		at.rewrite(art, bases)
		validRegion(child(child(loc, "physicalLocation"), "region"))
	}
	for _, res := range objects(run, "results") {
		resolveRule(res, driver, extensions)
		if _, ok := res["fixes"]; ok {
			out.fixes += len(items(res, "fixes"))
			delete(res, "fixes")
		}
		// An attachment is a file the tool attached, with regions of its
		// text, and nothing the deployment reads.
		if _, ok := res["attachments"]; ok {
			out.attachments += len(items(res, "attachments"))
			delete(res, "attachments")
		}
	}
	// What the deployment does not read is removed before anything is
	// walked, so nothing is placed or counted in what is never sent.
	out.result += prune(run["results"], resultShape)
	out.invocation += prune(run["invocations"], invocationShape)
	delete(run, "artifacts")
	delete(run, "originalUriBaseIds")
	// The client writes the repositories itself, from the checkout.
	delete(run, "versionControlProvenance")
	out.run += prune(run, runShape)
	properties := child(run, "properties")
	for key := range properties {
		if !strings.HasPrefix(key, runProperty) && key != unitsKey {
			delete(properties, key)
			out.run++
		}
	}
	eachLocation(run, place)
	// Every snippet and every markdown text wherever it stands, since SARIF
	// allows a physical location, and so a snippet, in more than one place.
	out.snippets += stripSnippets(run)
	eachMessage(run, func(m obj) { out.markdown += plainMessage(m) })
	return out
}

// resolveRule names a result's rule by its identifier. A rule cited by
// position is looked up in the component the result names, and the position
// removed, since merging runs reorders their rules. A rule of an extension
// keeps naming its extension, since the driver or another extension may
// define the same identifier.
func resolveRule(res obj, driver obj, extensions []obj) {
	ref := child(res, "rule")
	id := str(res, "ruleId")
	if id == "" {
		id = str(ref, "id")
	}
	c, named := extensionOf(child(ref, "toolComponent"), extensions)
	if id == "" {
		index, ok := num(res, "ruleIndex")
		if n, has := num(ref, "index"); has {
			index, ok = n, true
		}
		component := driver
		if named {
			component = nil
			if c >= 0 && c < len(extensions) {
				component = extensions[c]
			}
		}
		if rules := objects(component, "rules"); ok && index >= 0 && index < len(rules) {
			id = str(rules[index], "id")
		}
	}
	if id != "" {
		res["ruleId"] = id
	}
	delete(res, "ruleIndex")
	delete(res, "rule")
	if id != "" && named && c >= 0 && c < len(extensions) {
		res["rule"] = obj{"id": id, "toolComponent": obj{"index": c}}
	}
}

// extensionOf is the position of the extension a component reference names:
// by position, or else by GUID, or else by name. It is false for a reference
// to the driver or to nothing the run lists.
func extensionOf(ref obj, extensions []obj) (int, bool) {
	if ref == nil {
		return 0, false
	}
	if i, ok := num(ref, "index"); ok {
		return i, true
	}
	for _, key := range []string{"guid", "name"} {
		want := str(ref, key)
		if want == "" {
			continue
		}
		for i, ext := range extensions {
			// A GUID is hexadecimal written in either case; a name is as written.
			if got := str(ext, key); got == want || key == "guid" && strings.EqualFold(got, want) {
				return i, true
			}
		}
	}
	return 0, false
}

// validRegion removes the end of a region that ends before it starts. clang's
// SARIF writer gives such a region to a range ending inside a macro
// expansion; its start is right.
func validRegion(r obj) {
	if r == nil {
		return
	}
	start, _ := num(r, "startLine")
	end, hasEnd := num(r, "endLine")
	startCol, _ := num(r, "startColumn")
	endCol, hasEndCol := num(r, "endColumn")
	if hasEnd && end < start || (!hasEnd || end == start) && hasEndCol && endCol < startCol {
		delete(r, "endLine")
		delete(r, "endColumn")
	}
}

// plainMessage reduces a message to its text, reporting whether it held
// markdown. A message with markdown and no text takes the words the markdown
// shows as its text.
func plainMessage(m obj) int {
	if m == nil {
		return 0
	}
	md, ok := m["markdown"].(string)
	if !ok {
		return 0
	}
	if str(m, "text") == "" {
		m["text"] = markdown.Text(md)
	}
	delete(m, "markdown")
	return 1
}

// moves is where one run's components and rules sit once merged: each
// extension's position, and each rule's position in the driver or in its
// extension, by the run's own positions.
type moves struct {
	components  map[int]int
	driverRules map[int]int
	rules       map[int]map[int]int
}

// renumber rewrites the positions a result's rule cites to the merged run's:
// the rule's position and its extension's, the extension named by position,
// GUID or name. A rule the merge keeps no position for loses its position and
// keeps its identifier. A notification's rule and descriptor are not
// forwarded, and a relationship's target and a result's taxa may name a
// taxonomy by position instead, which nothing here reads, so they are left as
// written.
func renumber(run obj, m moves) {
	extensions := objects(child(run, "tool"), "extensions")
	at := func(ref obj) {
		if ref == nil {
			return
		}
		component := child(ref, "toolComponent")
		c, named := extensionOf(component, extensions)
		byRule := m.driverRules
		if named {
			byRule = m.rules[c]
		}
		if j, ok := num(ref, "index"); ok {
			if to, ok := byRule[j]; ok {
				ref["index"] = to
			} else {
				delete(ref, "index")
			}
		}
		// A component named by GUID or name is written by position too, since
		// the merged list may hold two of one name.
		if named {
			if to, ok := m.components[c]; ok {
				component["index"] = to
			}
		}
	}
	for _, res := range objects(run, "results") {
		at(child(res, "rule"))
	}
}

// merge folds the runs of one tool into one: clang writes a document per
// translation unit, and the deployment reads one run of each tool. The
// driver's rules are listed once, by identifier, and each extension's within
// that extension, extensions of two runs being one where they share a name, a
// GUID and a version, and an extension with neither name nor GUID its own. A result names its rule by identifier after settling, and a rule of an
// extension by its extension's position, which is rewritten to the merged
// list's.
func merge(runs []obj) obj {
	if len(runs) == 1 {
		return runs[0]
	}
	first := runs[0]
	driver := ensure(ensure(first, "tool"), "driver")
	seen := map[string]int{}
	var rules list
	var results, invocations list
	var extensions list
	extensionAt := map[string]int{}
	extensionRules := []map[string]int{}
	units, counted := 0, false
	for _, run := range runs {
		tool := child(run, "tool")
		m := moves{components: map[int]int{}, driverRules: map[int]int{}, rules: map[int]map[int]int{}}
		for j, rule := range objects(child(tool, "driver"), "rules") {
			id := str(rule, "id")
			if id == "" {
				continue
			}
			if _, ok := seen[id]; !ok {
				seen[id] = len(rules)
				rules = append(rules, rule)
			}
			m.driverRules[j] = seen[id]
		}
		inRun := map[int]bool{}
		for i, ext := range objects(tool, "extensions") {
			key := str(ext, "name") + "\x00" + strings.ToLower(str(ext, "guid")) + "\x00" + str(ext, "version")
			at, ok := extensionAt[key]
			// An extension with neither a name nor a GUID is its own, and one
			// run's extensions are never one another.
			if !ok || str(ext, "name") == "" && str(ext, "guid") == "" || inRun[at] {
				at = len(extensions)
				if _, kept := extensionAt[key]; !kept {
					extensionAt[key] = at
				}
				kept := obj{}
				for k, v := range ext {
					kept[k] = v
				}
				kept["rules"] = list{}
				extensions = append(extensions, kept)
				extensionRules = append(extensionRules, map[string]int{})
			}
			inRun[at] = true
			m.components[i] = at
			m.rules[i] = map[int]int{}
			merged := extensions[at].(obj)
			for j, rule := range objects(ext, "rules") {
				id := str(rule, "id")
				if id == "" {
					continue
				}
				if _, ok := extensionRules[at][id]; !ok {
					extensionRules[at][id] = len(merged["rules"].(list))
					merged["rules"] = append(merged["rules"].(list), rule)
				}
				m.rules[i][j] = extensionRules[at][id]
			}
		}
		renumber(run, m)
		if str(driver, "version") == "" {
			if v := str(child(tool, "driver"), "version"); v != "" {
				driver["version"] = v
			}
		}
		// An empty list is a tool that ran and found nothing, and an absent
		// one a tool that did not run, so a merged run ran where any did.
		if l, ok := run["results"].(list); ok {
			if results == nil {
				results = list{}
			}
			results = append(results, l...)
		}
		invocations = append(invocations, items(run, "invocations")...)
		if n, ok := num(child(run, "properties"), unitsKey); ok {
			units, counted = units+n, true
		}
	}
	driver["rules"] = rules
	if len(extensions) > 0 {
		child(first, "tool")["extensions"] = extensions
	} else {
		delete(child(first, "tool"), "extensions")
	}
	if results != nil {
		first["results"] = results
	} else {
		delete(first, "results")
	}
	if len(invocations) > 0 {
		first["invocations"] = invocations
	}
	if counted {
		ensure(first, "properties")[unitsKey] = units
	}
	return first
}
