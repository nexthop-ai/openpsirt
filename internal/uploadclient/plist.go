// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package uploadclient

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// clangPlist reads the clang static analyzer's plist output, one document
// per translation unit. It carries what clang's SARIF writer leaves out: the
// issue hash in every clang release, the enclosing function, and the call
// depth of every step. Its regions are the analyzer's own source locations,
// with none of the invalid ranges the SARIF writer produces inside a macro
// expansion.
type clangPlist struct{}

func (clangPlist) name() string { return "clang plist" }

func (clangPlist) detects(data []byte) bool {
	head := data[:min(len(data), 512)]
	return bytes.Contains(head, []byte("<plist")) && bytes.Contains(data, []byte("<key>diagnostics</key>"))
}

// clangHelp is where clang documents a checker, keyed by its name in lower
// case with dots as dashes, the address clang's own SARIF writer gives.
const clangHelp = "https://clang.llvm.org/docs/analyzer/checkers.html#"

func (clangPlist) read(data []byte) ([]obj, error) {
	v, err := parsePlist(data)
	if err != nil {
		return nil, fmt.Errorf("not a property list: %w", err)
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("a clang property list holds a dictionary at its top")
	}
	if _, ok := doc["HTMLDiagnostics_files"]; ok {
		return nil, errors.New("this property list was written beside HTML reports, which carry source; write plist-multi-file instead")
	}
	var files []string
	for _, f := range plistList(doc["files"]) {
		s, _ := f.(string)
		files = append(files, s)
	}
	version, _ := doc["clang_version"].(string)
	rules := map[string]obj{}
	var order []string
	results := list{}
	for _, d := range plistList(doc["diagnostics"]) {
		diag, ok := d.(map[string]any)
		if !ok {
			continue
		}
		check, _ := diag["check_name"].(string)
		if check == "" {
			continue
		}
		if _, ok := rules[check]; !ok {
			kind, _ := diag["type"].(string)
			rules[check] = obj{
				"id": check, "name": check,
				"shortDescription": obj{"text": kind},
				"helpUri":          clangHelp + strings.ReplaceAll(strings.ToLower(check), ".", "-"),
			}
			order = append(order, check)
		}
		results = append(results, clangResult(diag, files))
	}
	ruleList := list{}
	for _, id := range order {
		ruleList = append(ruleList, rules[id])
	}
	return []obj{{
		"tool":    obj{"driver": obj{"name": "clang", "version": version, "rules": ruleList}},
		"results": results,
		"properties": obj{
			// A plist is one translation unit that was analyzed. A unit that
			// failed to compile writes none.
			unitsKey: 1,
		},
	}}, nil
}

// unitsKey is a property the readers set on the runs they make, counting the
// units each covers. It is replaced by the run parameters before anything is
// written.
const unitsKey = "openpsirt-client/units"

func clangResult(diag map[string]any, files []string) obj {
	description, _ := diag["description"].(string)
	check, _ := diag["check_name"].(string)
	loc := plistLocation(diag["location"], files)
	steps := clangSteps(diag, files)
	if function, _ := diag["issue_context"].(string); function != "" {
		loc["logicalLocations"] = list{obj{"name": function, "kind": "function"}}
	}
	// The diagnostic's last step names the range the result is about.
	if len(steps) > 0 {
		last := child(steps[len(steps)-1].(obj), "location")
		if r := child(child(last, "physicalLocation"), "region"); r != nil {
			own := child(child(loc, "physicalLocation"), "region")
			if sameStart(own, r) {
				for _, k := range []string{"endLine", "endColumn"} {
					if v, ok := r[k]; ok {
						own[k] = v
					}
				}
			}
		}
	}
	result := obj{
		"ruleId":    check,
		"level":     "warning",
		"message":   obj{"text": description},
		"locations": list{loc},
	}
	if hash, _ := diag["issue_hash_content_of_line_in_context"].(string); hash != "" {
		result["partialFingerprints"] = obj{schemeClang: hash}
	}
	if len(steps) > 0 {
		result["codeFlows"] = list{obj{"threadFlows": list{obj{"locations": steps}}}}
	}
	return result
}

// The fingerprint schemes the client writes or reads.
const (
	schemeClang   = "clang/issueHash/v1"
	schemeContext = "openpsirt/context/v1"
)

func sameStart(a, b obj) bool {
	al, _ := num(a, "startLine")
	bl, _ := num(b, "startLine")
	ac, _ := num(a, "startColumn")
	bc, _ := num(b, "startColumn")
	return al == bl && ac == bc
}

// clangSteps is the diagnostic's path as flow steps: each event, with its
// call depth and the function it is in. The function at each depth is read
// off the path itself: "Calling 'f'" names the function the next depth is
// in, and "Entered call from 'g'" names the one the depth above is in.
func clangSteps(diag map[string]any, files []string) list {
	var events []map[string]any
	for _, p := range plistList(diag["path"]) {
		piece, ok := p.(map[string]any)
		if ok && piece["kind"] == "event" {
			events = append(events, piece)
		}
	}
	functions := map[int]string{}
	for _, e := range events {
		depth := plistInt(e["depth"])
		message, _ := e["message"].(string)
		if name, ok := quoted(message, "Entered call from "); ok && depth > 0 {
			if _, known := functions[depth-1]; !known {
				functions[depth-1] = name
			}
		}
	}
	if _, known := functions[0]; !known {
		if f, _ := diag["issue_context"].(string); f != "" && maxDepth(events) == 0 {
			functions[0] = f
		}
	}
	steps := list{}
	pending := map[int]string{}
	for _, e := range events {
		depth := plistInt(e["depth"])
		if name, ok := pending[depth]; ok {
			functions[depth] = name
			delete(pending, depth)
		}
		message, _ := e["message"].(string)
		loc := plistLocation(e["location"], files)
		if r := plistRange(e["ranges"]); r != nil {
			region := child(child(loc, "physicalLocation"), "region")
			if sameStart(region, r) {
				for _, k := range []string{"endLine", "endColumn"} {
					if v, ok := r[k]; ok {
						region[k] = v
					}
				}
			}
		}
		loc["message"] = obj{"text": message}
		if f := functions[depth]; f != "" {
			loc["logicalLocations"] = list{obj{"name": f, "kind": "function"}}
		}
		steps = append(steps, obj{"location": loc, "nestingLevel": depth})
		if name, ok := quoted(message, "Calling "); ok {
			pending[depth+1] = name
		}
	}
	return steps
}

func maxDepth(events []map[string]any) int {
	most := 0
	for _, e := range events {
		most = max(most, plistInt(e["depth"]))
	}
	return most
}

// quoted is the last single-quoted name in a message that opens with prefix:
// "Calling 'updateShardId'" is updateShardId, and "Calling constructor for
// 'Port'" is Port.
func quoted(message, prefix string) (string, bool) {
	if !strings.HasPrefix(message, prefix) {
		return "", false
	}
	end := strings.LastIndexByte(message, '\'')
	if end <= 0 {
		return "", false
	}
	start := strings.LastIndexByte(message[:end], '\'')
	if start < 0 || start+1 >= end {
		return "", false
	}
	return message[start+1 : end], true
}

// plistLocation is a SARIF location for one of the plist's line, column and
// file-index triples.
func plistLocation(v any, files []string) obj {
	at, _ := v.(map[string]any)
	file := ""
	if i := plistInt(at["file"]); i >= 0 && i < len(files) {
		file = files[i]
	}
	region := obj{}
	if n := plistInt(at["line"]); n > 0 {
		region["startLine"] = n
	}
	if n := plistInt(at["col"]); n > 0 {
		region["startColumn"] = n
	}
	return obj{"physicalLocation": obj{"artifactLocation": obj{"uri": file}, "region": region}}
}

// plistRange is the region of an event's first range. The plist's end column
// is the last character's, and SARIF's is the one after it.
func plistRange(v any) obj {
	ranges := plistList(v)
	if len(ranges) == 0 {
		return nil
	}
	pair := plistList(ranges[0])
	if len(pair) != 2 {
		return nil
	}
	from, _ := pair[0].(map[string]any)
	to, _ := pair[1].(map[string]any)
	if plistInt(from["file"]) != plistInt(to["file"]) {
		return nil
	}
	start, end := plistInt(from["line"]), plistInt(to["line"])
	startCol, endCol := plistInt(from["col"]), plistInt(to["col"])
	if start <= 0 || end < start || (end == start && endCol < startCol) {
		return nil
	}
	return obj{"startLine": start, "startColumn": startCol, "endLine": end, "endColumn": endCol + 1}
}

func plistList(v any) []any {
	l, _ := v.([]any)
	return l
}

func plistInt(v any) int {
	n, ok := v.(int)
	if !ok {
		return -1
	}
	return n
}

// parsePlist reads an XML property list into maps, slices, strings, whole
// numbers and booleans. Reals, dates and data are read as their text.
func parsePlist(data []byte) (any, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	// A property list names Apple's document type, which nothing here fetches.
	dec.Strict = true
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if start, ok := tok.(xml.StartElement); ok {
			if start.Name.Local != "plist" {
				return nil, fmt.Errorf("the document is <%s>, not a property list", start.Name.Local)
			}
			return plistValue(dec, 0)
		}
	}
}

// plistDepth bounds how deeply a property list may nest. clang's nests five
// deep.
const plistDepth = 64

func plistValue(dec *xml.Decoder, depth int) (any, error) {
	if depth > plistDepth {
		return nil, errors.New("the property list nests too deeply")
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return plistElement(dec, t, depth)
		case xml.EndElement:
			return nil, io.EOF
		}
	}
}

func plistElement(dec *xml.Decoder, start xml.StartElement, depth int) (any, error) {
	switch start.Name.Local {
	case "dict":
		out := map[string]any{}
		for {
			key, done, err := plistKey(dec)
			if err != nil || done {
				return out, err
			}
			v, err := plistValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = v
		}
	case "array":
		out := []any{}
		for {
			v, err := plistValue(dec, depth+1)
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
	case "true", "false":
		if err := dec.Skip(); err != nil {
			return nil, err
		}
		return start.Name.Local == "true", nil
	case "integer":
		var s string
		if err := dec.DecodeElement(&s, &start); err != nil {
			return nil, err
		}
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("integer %q: %w", s, err)
		}
		return n, nil
	default:
		var s string
		if err := dec.DecodeElement(&s, &start); err != nil {
			return nil, err
		}
		return s, nil
	}
}

// plistKey reads a dictionary's next key, reporting done at its end.
func plistKey(dec *xml.Decoder) (string, bool, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local != "key" {
				return "", false, fmt.Errorf("a dictionary holds <%s> where a key belongs", t.Name.Local)
			}
			var key string
			if err := dec.DecodeElement(&key, &t); err != nil {
				return "", false, err
			}
			return key, false, nil
		case xml.EndElement:
			return "", true, nil
		}
	}
}
