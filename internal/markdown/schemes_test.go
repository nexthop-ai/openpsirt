// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package markdown

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// sharedSchemes is the file the interface's renderer is held to as well.
func sharedSchemes(t *testing.T) (link, address []string) {
	t.Helper()
	source, err := os.ReadFile("../../testdata/link-schemes.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Link    []string `json:"link"`
		Address []string `json:"address"`
	}
	if err := json.Unmarshal(source, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Link) == 0 || len(doc.Address) == 0 {
		t.Fatal("the shared file names no schemes, so this checked nothing")
	}
	return doc.Link, doc.Address
}

func TestTheLinkSchemesAreTheOnesTheInterfaceIsHeldTo(t *testing.T) {
	link, address := sharedSchemes(t)
	if !slices.Equal(linkSchemes[:], link) {
		t.Errorf("a link may use %v here and %v in testdata/link-schemes.json",
			linkSchemes, link)
	}
	if !slices.Equal(addressSchemes[:], address) {
		t.Errorf("an address may name %v here and %v in testdata/link-schemes.json",
			addressSchemes, address)
	}
	for _, each := range link {
		if !allowedScheme(each) {
			t.Errorf("%q is in the shared list and refused in a link", each)
		}
	}
	for _, each := range []string{"javascript", "data", "vbscript", "file", ""} {
		if allowedScheme(each) {
			t.Errorf("%q is accepted in a link", each)
		}
	}
}

func TestAnAddressInADocumentNamesOnlyTheSchemesThatLeaveTheDeployment(t *testing.T) {
	_, address := sharedSchemes(t)
	samples := map[string]string{
		"http":   "http://example.com/a",
		"https":  "https://example.com/a",
		"mailto": "mailto:psirt@example.com",
	}
	for _, each := range address {
		sample, ok := samples[each]
		if !ok {
			t.Errorf("no sample address for %q", each)
			continue
		}
		if err := Autolinkable(sample); err != nil {
			t.Errorf("%s is refused as a document address: %v", sample, err)
		}
	}
	for _, each := range []string{"attachment:0123456789abcdef0123456789abcdef", "issue:CVE-2026-1234"} {
		if Autolinkable(each) == nil {
			t.Errorf("%s is accepted as a document address", each)
		}
	}
}

func TestARefusedSchemeIsAnsweredWithEveryOneALinkMayUse(t *testing.T) {
	if got, want := SchemesSaid(), "http, https, mailto, attachment or issue"; got != want {
		t.Errorf("the refusal offers %q, want %q", got, want)
	}
}
