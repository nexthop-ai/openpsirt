// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// This file holds v0.13.0's rules for folding a name, which the v0.14.0
// upgrade reads by these names. An upgrade carries its own copy of a rule, so
// a later change to the application's leaves what it wrote as it was.

// foldedV0130 is a name folded as v0.13.0 folds it: trimmed, in lower case,
// and cut to the folded column's width in characters.
func foldedV0130(name string) string {
	folded := strings.ToLower(strings.TrimSpace(name))
	kept := 0
	for at := range folded {
		if kept == database.NameWidth {
			return folded[:at]
		}
		kept++
	}
	return folded
}

// printableV0130 is s without its control characters, every other byte kept,
// a malformed sequence included.
func printableV0130(s string) string {
	var b strings.Builder
	for rest := s; rest != ""; {
		r, size := utf8.DecodeRuneInString(rest)
		if (r == utf8.RuneError && size == 1) || !unicode.IsControl(r) {
			b.WriteString(rest[:size])
		}
		rest = rest[size:]
	}
	return b.String()
}
