// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package uploadclient

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

// cppcheckXML reads cppcheck's XML output, version 2. It carries a CWE on each
// result, which cppcheck's SARIF does not.
type cppcheckXML struct{}

func (cppcheckXML) name() string { return "cppcheck XML" }

func (cppcheckXML) detects(data []byte) bool {
	head := data[:min(len(data), 512)]
	return bytes.Contains(head, []byte("<results")) && bytes.Contains(head, []byte("<cppcheck"))
}

type cppcheckDoc struct {
	Version string `xml:"version,attr"`
	Tool    struct {
		Version string `xml:"version,attr"`
	} `xml:"cppcheck"`
	Errors []struct {
		ID        string `xml:"id,attr"`
		Severity  string `xml:"severity,attr"`
		Msg       string `xml:"msg,attr"`
		CWE       string `xml:"cwe,attr"`
		Hash      string `xml:"hash,attr"`
		Locations []struct {
			File   string `xml:"file,attr"`
			Line   int    `xml:"line,attr"`
			Column int    `xml:"column,attr"`
			Info   string `xml:"info,attr"`
		} `xml:"location"`
	} `xml:"errors>error"`
}

// cppcheckLevels is the SARIF level of each cppcheck severity that reports a
// problem in the code. The others — information and debug — are cppcheck
// describing its own run, and are not results.
var cppcheckLevels = map[string]string{
	"error":       "error",
	"warning":     "warning",
	"style":       "note",
	"performance": "note",
	"portability": "note",
}

// schemeCppcheck is the fingerprint cppcheck's SARIF writes, and the one its
// XML's hash is written as, so the two outputs of one run match each other.
const schemeCppcheck = "hash/v1"

func (cppcheckXML) read(data []byte) ([]obj, error) {
	var doc cppcheckDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("not cppcheck XML: %w", err)
	}
	if doc.Version != "2" {
		return nil, fmt.Errorf("cppcheck XML version %q is not 2; run cppcheck with --xml", doc.Version)
	}
	rules := map[string]obj{}
	var order []string
	results := list{}
	for _, e := range doc.Errors {
		level, ok := cppcheckLevels[e.Severity]
		if !ok || e.ID == "" || len(e.Locations) == 0 {
			continue
		}
		rule, ok := rules[e.ID]
		if !ok {
			rule = obj{"id": e.ID, "shortDescription": obj{"text": ""}, "defaultConfiguration": obj{"level": level}}
			rules[e.ID] = rule
			order = append(order, e.ID)
		}
		if n, err := strconv.Atoi(strings.TrimSpace(e.CWE)); err == nil && n > 0 {
			tag := "external/cwe/cwe-" + strconv.Itoa(n)
			props := ensure(rule, "properties")
			tags, _ := props["tags"].(list)
			if !containsTag(tags, tag) {
				props["tags"] = append(tags, tag)
			}
		}
		// The XML lists the place the result is about first, and the places
		// that lead to it after.
		var locations, related list
		for i, l := range e.Locations {
			region := obj{}
			if l.Line > 0 {
				region["startLine"] = l.Line
			}
			if l.Column > 0 {
				region["startColumn"] = l.Column
			}
			loc := obj{"physicalLocation": obj{"artifactLocation": obj{"uri": l.File}, "region": region}}
			if i == 0 {
				locations = append(locations, loc)
				continue
			}
			if l.Info != "" {
				loc["message"] = obj{"text": l.Info}
			}
			related = append(related, loc)
		}
		result := obj{"ruleId": e.ID, "level": level, "message": obj{"text": e.Msg}, "locations": locations}
		if len(related) > 0 {
			result["relatedLocations"] = related
		}
		if e.Hash != "" {
			result["partialFingerprints"] = obj{schemeCppcheck: e.Hash}
		}
		results = append(results, result)
	}
	ruleList := list{}
	for _, id := range order {
		ruleList = append(ruleList, rules[id])
	}
	return []obj{{
		"tool":    obj{"driver": obj{"name": "Cppcheck", "version": doc.Tool.Version, "rules": ruleList}},
		"results": results,
	}}, nil
}

func containsTag(tags list, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}
