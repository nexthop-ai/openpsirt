// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package weakness

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// common is the screen's own names for the weaknesses a real backlog is made
// of, most common first.
//
// The order is the answer a picker offers before anything is typed, and the
// order a search ranks its matches in. The first four are the most common in a
// kernel image — a memory leak, a race, improper locking and a double free —
// and a kernel carries most of what is open against a switch image. The
// twenty-five after them are the published CWE Top 25 of 2024, in its order.
// The rest are in the order of their numbers.
var common = []struct{ id, short string }{
	{"CWE-401", "Missing release of memory after effective lifetime"},
	{"CWE-362", "Race condition"},
	{"CWE-667", "Improper locking"},
	{"CWE-415", "Double free"},

	{"CWE-79", "Cross-site scripting"},
	{"CWE-787", "Out-of-bounds write"},
	{"CWE-89", "SQL injection"},
	{"CWE-352", "Cross-site request forgery"},
	{"CWE-22", "Path traversal"},
	{"CWE-125", "Out-of-bounds read"},
	{"CWE-78", "OS command injection"},
	{"CWE-416", "Use after free"},
	{"CWE-862", "Missing authorization"},
	{"CWE-434", "Unrestricted upload of a dangerous file"},
	{"CWE-94", "Code injection"},
	{"CWE-20", "Improper input validation"},
	{"CWE-77", "Command injection"},
	{"CWE-287", "Improper authentication"},
	{"CWE-269", "Improper privilege management"},
	{"CWE-502", "Deserialization of untrusted data"},
	{"CWE-200", "Exposure of sensitive information"},
	{"CWE-863", "Incorrect authorization"},
	{"CWE-918", "Server-side request forgery"},
	{"CWE-119", "Buffer overflow"},
	{"CWE-476", "Null pointer dereference"},
	{"CWE-798", "Hard-coded credentials"},
	{"CWE-190", "Integer overflow"},
	{"CWE-400", "Uncontrolled resource consumption"},
	{"CWE-306", "Missing authentication for a critical function"},

	{"CWE-59", "Link following"},
	{"CWE-120", "Buffer copy without checking the size of the input"},
	{"CWE-121", "Stack-based buffer overflow"},
	{"CWE-122", "Heap-based buffer overflow"},
	{"CWE-191", "Integer underflow"},
	{"CWE-193", "Off-by-one error"},
	{"CWE-284", "Improper access control"},
	{"CWE-295", "Improper certificate validation"},
	{"CWE-327", "Use of a broken or risky cryptographic algorithm"},
	{"CWE-330", "Use of insufficiently random values"},
	{"CWE-369", "Divide by zero"},
	{"CWE-404", "Improper resource shutdown or release"},
	{"CWE-457", "Use of an uninitialized variable"},
	{"CWE-522", "Insufficiently protected credentials"},
	{"CWE-601", "Open redirect"},
	{"CWE-611", "XML external entity reference"},
	{"CWE-617", "Reachable assertion"},
	{"CWE-681", "Incorrect conversion between numeric types"},
	{"CWE-732", "Incorrect permission assignment for a critical resource"},
	{"CWE-770", "Allocation of resources without limits or throttling"},
	{"CWE-772", "Missing release of resource after effective lifetime"},
	{"CWE-835", "Infinite loop"},
	{"CWE-843", "Type confusion"},
	{"CWE-908", "Use of an uninitialized resource"},
}

// Named is one weakness under both of its names.
type Named struct {
	// ID is the identifier, as the standard spells it: CWE- and a number.
	ID string
	// Name is what the catalog calls it. Empty where the catalog does not
	// assign the identifier.
	Name string
	// Short is what a screen calls it. Empty for every weakness outside the
	// common ones.
	Short string
}

// shortNames and rank are the common list keyed by identifier, and ordered is
// every identifier either list names, most common first.
var (
	shortNames = map[string]string{}
	rank       = map[string]int{}
	ordered    []string
)

func init() {
	for i, each := range common {
		shortNames[each.id] = each.short
		rank[each.id] = i
	}
	for id := range names {
		ordered = append(ordered, id)
	}
	for id := range shortNames {
		if _, known := names[id]; !known {
			ordered = append(ordered, id)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return before(ordered[i], ordered[j]) })
}

// before orders two identifiers most common first: the common ones in their
// own order, then every other by its number.
func before(a, b string) bool {
	ra, commonA := rank[a]
	rb, commonB := rank[b]
	switch {
	case commonA && commonB:
		return ra < rb
	case commonA != commonB:
		return commonA
	}
	return number(a) < number(b)
}

// number is the numeric part of an identifier, and zero for one without one.
func number(id string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(id, "CWE-"))
	return n
}

// shortOf is what a screen calls this identifier, and whether it has a name
// of its own.
func shortOf(id string) (string, bool) {
	short, known := shortNames[id]
	return short, known
}

// Of is one identifier under both of its names, either of them empty where
// its list does not hold it.
//
// Taken as it was recorded — trimmed and upper-cased, which is the form a
// finding holds — so a lookup and the record agree about what is the same
// identifier.
func Of(id string) Named {
	clean := strings.ToUpper(strings.TrimSpace(id))
	name, _ := Name(clean)
	short, _ := shortOf(clean)
	return Named{ID: clean, Name: name, Short: short}
}

// numbered is a search for a number: CWE- and digits, or the digits alone.
var numbered = regexp.MustCompile(`^(?:CWE-?)?([0-9]{1,6})$`)

// Find is the weaknesses a search matches, most common first, at most limit of
// them.
//
// A search by number matches every identifier whose number begins with the
// digits typed, and the identifier typed exactly comes first. A search by
// words matches a weakness whose names, taken together, hold every word
// somewhere, without regard to capitals. Nothing typed is the common list in
// its own order, which is what a picker offers before anybody types.
func Find(search string, limit int) []Named {
	search = strings.ToUpper(strings.TrimSpace(search))
	var match func(id string) bool
	exact := ""
	switch digits := numbered.FindStringSubmatch(search); {
	case search == "":
		match = func(id string) bool { _, listed := rank[id]; return listed }
	case digits != nil:
		exact = "CWE-" + digits[1]
		match = func(id string) bool { return strings.HasPrefix(id, exact) }
	default:
		words := strings.Fields(strings.ToLower(search))
		match = func(id string) bool {
			short, _ := shortOf(id)
			name, _ := Name(id)
			said := strings.ToLower(short + " " + name)
			for _, word := range words {
				if !strings.Contains(said, word) {
					return false
				}
			}
			return true
		}
	}

	out := []Named{}
	if exact != "" {
		if one := Of(exact); one.Name != "" || one.Short != "" {
			out = append(out, one)
		}
	}
	for _, id := range ordered {
		if len(out) >= limit {
			break
		}
		if id != exact && match(id) {
			out = append(out, Of(id))
		}
	}
	return out
}
