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
	// character. PostgreSQL refuses invalid UTF-8 outright and MySQL and
	// MariaDB refuse it in strict mode, so the whole scan would fail to
	// record on three engines of four.
	identifier := strings.Repeat("é", 200)
	if folded := foldIdentifier(identifier); !utf8.ValidString(folded) {
		t.Errorf("the folded identifier is not valid UTF-8: %q", folded)
	}
	if named := normalize(identifier); !utf8.ValidString(named) {
		t.Errorf("the normalized identifier is not valid UTF-8: %q", named)
	}
}
