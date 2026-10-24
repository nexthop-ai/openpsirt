// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/nexthop-ai/openpsirt/internal/sarif"
)

// schemes is the fingerprints a key is built from, in the order they are
// preferred. The client's own content fingerprint is first, because it is the
// same for every tool. Any other scheme a result carries comes after these,
// in name order.
var schemes = []string{
	"openpsirt/context/v1",
	"clang/issueHash/v1",
	"hash/v1",
	"primaryLocationLineHash",
}

// fingerprint is the one a key is built from, and its scheme. Empty where the
// result carries none.
func fingerprint(of map[string]string) (scheme, value string) {
	for _, s := range schemes {
		if v := of[s]; v != "" {
			return s, v
		}
	}
	rest := make([]string, 0, len(of))
	for s, v := range of {
		if v != "" {
			rest = append(rest, s)
		}
	}
	if len(rest) == 0 {
		return "", ""
	}
	sort.Strings(rest)
	return rest[0], of[rest[0]]
}

// withoutDigits is a message with its digits taken out and its spaces
// collapsed. A message quoting a line number or a count changes when lines
// move, and the flaw it describes does not.
func withoutDigits(message string) string {
	var b strings.Builder
	space := false
	for _, r := range message {
		switch {
		case unicode.IsDigit(r):
			continue
		case unicode.IsSpace(r):
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}

// chain is the functions a result's path passes through, in order, each named
// once where consecutive steps share it.
func chain(steps []sarif.PlacedStep) string {
	var names []string
	for _, s := range steps {
		if s.Function == "" {
			continue
		}
		if len(names) > 0 && names[len(names)-1] == s.Function {
			continue
		}
		names = append(names, s.Function)
	}
	return strings.Join(names, " → ")
}

// Keyed is a result with what an exact match compares.
type Keyed struct {
	sarif.Placed
	// Rule is the issue the result is filed under: the tool and its rule.
	Rule   string
	Scheme string
	Print  string
	Chain  string
	Key    string
	// Remote is the repository the result's file is in, normalized; empty
	// where the run names none.
	Remote string
}

// key is a digest of everything an exact match compares: the rule, the path,
// the fingerprint or the line where there is none, the message without its
// digits, the function and the call chain. A fingerprint a document supplies
// is one part of the key and never the whole of it.
func key(rule string, p sarif.Placed) Keyed {
	scheme, print := fingerprint(p.Fingerprints)
	k := Keyed{Placed: p, Rule: rule, Scheme: scheme, Print: print, Chain: chain(p.Steps)}
	where := "fingerprint " + scheme + " " + print
	if print == "" {
		where = "line " + strconv.Itoa(p.StartLine)
	}
	sum := sha256.New()
	for _, part := range []string{rule, p.Path, where, withoutDigits(p.Message), p.Function, k.Chain} {
		sum.Write([]byte(part))
		sum.Write([]byte{0})
	}
	k.Key = hex.EncodeToString(sum.Sum(nil))
	return k
}

// identity is the place a result first seen in a series is minted at. Matching
// carries it to every later sighting, so a decision keyed on it reaches each
// build the result is seen in.
func identity(seriesID int64, k string) string {
	sum := sha256.Sum256([]byte("lead\x00" + strconv.FormatInt(seriesID, 10) + "\x00" + k))
	return hex.EncodeToString(sum[:])
}

// ruleName is what a rule's issue is filed under: the tool's name in lower
// case and the rule's identifier, joined by a slash. Two analyzers reuse rule
// names, and no published vulnerability identifier holds a slash.
func ruleName(tool, rule string) string {
	return strings.ToLower(strings.TrimSpace(tool)) + "/" + strings.TrimSpace(rule)
}
