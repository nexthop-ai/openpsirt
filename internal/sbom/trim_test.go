// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAQuotedFieldIsCutWithoutCopyingIt(t *testing.T) {
	long := strings.Repeat("a", 1<<20)
	got := trim(long)
	if n := utf8.RuneCountInString(got); n != 121 || !strings.HasSuffix(got, "…") {
		t.Fatalf("a megabyte field was quoted as %d characters", n)
	}
	// One allocation, the joined result. Converting the field to characters
	// first is a second allocation four times the field's size.
	if allocs := testing.AllocsPerRun(5, func() { _ = trim(long) }); allocs > 1 {
		t.Fatalf("quoting a megabyte field made %v allocations", allocs)
	}
	if got := trim("short"); got != "short" {
		t.Fatalf("a short field was quoted as %q", got)
	}
	exact := strings.Repeat("漢", 120)
	if got := trim(exact); got != exact {
		t.Fatal("a field of exactly the bound was cut")
	}
}

func TestAnUnrecognizedFormatNameIsQuotedBounded(t *testing.T) {
	body := `{"bomFormat":"` + strings.Repeat("a", 1<<20) + `","specVersion":"1.5"}`
	_, err := ReadHeader(strings.NewReader(body), DefaultLimits())
	if err == nil {
		t.Fatal("a document naming another format was read")
	}
	if len(err.Error()) > 1024 {
		t.Fatalf("the refusal quoted %d bytes of the file", len(err.Error()))
	}
}
