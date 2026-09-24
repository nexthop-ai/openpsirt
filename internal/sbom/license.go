// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom

import "strings"

// licenseExpression is one license statement as a producer wrote it, or
// nothing where it states that it knows nothing.
//
// NOASSERTION and NONE are the format's words for "not stated" and "stated
// as absent", and neither is a license somebody can be asked about.
func licenseExpression(said string) string {
	return strings.TrimSpace(sentinel(said))
}

// conjunction is several license statements about one component read as one.
//
// A producer listing several licenses for one package means the package is
// under all of them — a distribution's copyright file names each license a
// part of the source is under — and the SPDX expression for that is a
// conjunction. An expression that is itself compound, joining licenses with
// AND, OR or WITH, is parenthesized so the result still reads one way. Repeats are dropped and the order is the
// producer's.
func conjunction(said []string) string {
	var parts []string
	seen := map[string]bool{}
	for _, one := range said {
		one = licenseExpression(one)
		if one == "" || seen[one] {
			continue
		}
		seen[one] = true
		parts = append(parts, one)
	}
	if len(parts) == 1 {
		return parts[0]
	}
	for i, one := range parts {
		if compound(one) && !wrapped(one) {
			parts[i] = "(" + one + ")"
		}
	}
	return strings.Join(parts, " AND ")
}

// compound reports whether an expression joins licenses with an operator. A
// name a producer wrote with spaces in it — "Apache License 2.0" — is one
// license and is left as written.
func compound(expression string) bool {
	upper := " " + strings.ToUpper(expression) + " "
	for _, operator := range []string{" AND ", " OR ", " WITH "} {
		if strings.Contains(upper, operator) {
			return true
		}
	}
	return false
}

// wrapped reports whether an expression is one parenthesized group: its first
// parenthesis closes at its last character. "(MIT) OR (BSD-2-Clause)" starts and
// ends with one and is two groups.
func wrapped(expression string) bool {
	if !strings.HasPrefix(expression, "(") {
		return false
	}
	depth := 0
	for i, r := range expression {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i == len(expression)-1
			}
		}
	}
	return false
}
