// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestALongIdentifierOutsideASCIIStaysStorableAfterItIsCut(t *testing.T) {
	// An identifier arrives in a scanner's report and both stored forms are
	// bounded to the width of an indexed column, so the cut can fall inside a
	// character. Half a character is stored as a replacement character, and
	// the stored form then matches no identifier a later scan reports.
	identifier := strings.Repeat("é", 200)
	if folded := FoldIdentifier(identifier); !utf8.ValidString(folded) {
		t.Errorf("the folded identifier is not valid UTF-8: %q", folded)
	}
	if named := normalize(identifier); !utf8.ValidString(named) {
		t.Errorf("the normalized identifier is not valid UTF-8: %q", named)
	}
}

func TestAnIssueNameThatIsADotSegmentIsNoName(t *testing.T) {
	// Every address about an issue carries its name as a path segment, and a
	// browser resolves "." and ".." away.
	named := Addressed(Named{Identifier: "..", Aliases: []string{".", "GHSA-2222-3333-4444"}})
	if named.Identifier != "GHSA-2222-3333-4444" || len(named.Aliases) != 0 {
		t.Errorf("the issue goes by %q, also %q", named.Identifier, named.Aliases)
	}
	if got := Addressed(Named{Identifier: "..", Aliases: []string{"."}}); got.Identifier != "" {
		t.Errorf("an issue named only by dot segments goes by %q", got.Identifier)
	}
	// Interning refuses what has no name left, wherever the report came from.
	if _, _, err := prepared(Named{Identifier: "..", Aliases: []string{"."}}); err == nil {
		t.Error("an issue named only by dot segments was kept")
	}
}
