// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysisclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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
	contents, fixes, snippets, markdown int
}

// settle makes a run self-contained and free of source text: every reference
// by position resolved to what it names, every path placed in the checkout,
// and whole files, proposed fixes, snippets and markdown removed. It runs
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
		out.markdown += plainMessage(child(res, "message"))
		eachLocation(res, func(loc obj) {
			place(loc)
			out.snippets += dropSnippets(loc)
			out.markdown += plainMessage(child(loc, "message"))
		})
		for _, flow := range objects(res, "codeFlows") {
			out.markdown += plainMessage(child(flow, "message"))
		}
	}
	for _, component := range append([]obj{driver}, extensions...) {
		for _, rule := range objects(component, "rules") {
			for _, key := range []string{"shortDescription", "fullDescription", "help"} {
				out.markdown += plainMessage(child(rule, key))
			}
		}
	}
	delete(run, "artifacts")
	delete(run, "originalUriBaseIds")
	// The client writes the repositories itself, from the checkout.
	delete(run, "versionControlProvenance")
	return out
}

// resolveRule names a result's rule by its identifier. A rule cited by
// position is looked up in the component the result names, and the position
// removed, since merging runs reorders their rules.
func resolveRule(res obj, driver obj, extensions []obj) {
	ref := child(res, "rule")
	id := str(res, "ruleId")
	if id == "" {
		id = str(ref, "id")
	}
	if id == "" {
		index, ok := num(res, "ruleIndex")
		if n, has := num(ref, "index"); has {
			index, ok = n, true
		}
		component := driver
		if c, has := num(child(ref, "toolComponent"), "index"); has {
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
// markdown. A message with markdown and no text keeps the markdown as its
// text, which the deployment shows as text and never renders.
func plainMessage(m obj) int {
	if m == nil {
		return 0
	}
	md, ok := m["markdown"].(string)
	if !ok {
		return 0
	}
	if str(m, "text") == "" {
		m["text"] = md
	}
	delete(m, "markdown")
	return 1
}

// dropSnippets removes the source text a location's regions carry.
func dropSnippets(loc obj) int {
	n := 0
	physical := child(loc, "physicalLocation")
	for _, key := range []string{"region", "contextRegion"} {
		r := child(physical, key)
		if _, ok := r["snippet"]; ok {
			delete(r, "snippet")
			n++
		}
	}
	return n
}

// merge folds the runs of one tool into one: clang writes a document per
// translation unit, and the deployment reads one run of each tool. Rules are
// listed once, by identifier, and every result names its rule by identifier
// after settling, so an extension's rules join the driver's.
func merge(runs []obj) obj {
	if len(runs) == 1 {
		return runs[0]
	}
	first := runs[0]
	driver := ensure(ensure(first, "tool"), "driver")
	seen := map[string]bool{}
	var rules list
	var results, invocations list
	units, counted := 0, false
	for _, run := range runs {
		tool := child(run, "tool")
		for _, component := range append([]obj{child(tool, "driver")}, objects(tool, "extensions")...) {
			for _, rule := range objects(component, "rules") {
				if id := str(rule, "id"); id != "" && !seen[id] {
					seen[id] = true
					rules = append(rules, rule)
				}
			}
		}
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
	delete(child(first, "tool"), "extensions")
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
