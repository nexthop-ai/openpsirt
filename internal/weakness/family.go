// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package weakness

// mostDepth bounds a walk up the hierarchy. The research view is a tree a
// few levels deep, so a walk this long is a cycle in a published catalog.
const mostDepth = 16

// Family is the class a weakness belongs to: itself where it is a class or a
// pillar, and otherwise the nearest class up its primary parents in the
// research view. Tools disagree about the number for one flaw — one overflow
// was CWE-788, 119 and 121 from three tools — and agree about its family. A
// pillar ends the walk only where it is the weakness itself: a pillar holds
// flaws as unlike as a null dereference and a condition always true, which
// share CWE-710. A weakness the catalog does not place, and one whose walk
// reaches a pillar with no class between, is its own family.
func Family(id string) string {
	id = Canonical(id)
	at := id
	for range mostDepth {
		if classes[at] && (at == id || !pillars[at]) {
			return at
		}
		parent, ok := parents[at]
		if !ok {
			return id
		}
		at = parent
	}
	return id
}

// Tier is how likely a weakness is to be a flaw worth fixing first, from
// TierOther up to TierMemory.
type Tier int

const (
	// TierOther is everything below: style, dead code, a weakness no tier
	// names, and no weakness at all.
	TierOther Tier = iota
	// TierResource is a resource or an error left unhandled: a leak, a
	// missing check, a loop with no bound.
	TierResource
	// TierInjection is input reaching where it should not: injection, a
	// path, a race.
	TierInjection
	// TierMemory is memory safety: a bound overrun, a freed or null
	// pointer, a value read before it is written, an integer that wraps.
	TierMemory
)

// tiers is the weaknesses each tier names. A weakness takes the tier of the
// nearest of itself and its ancestors named here, so naming a class names
// everything under it, and a weakness named here outranks its own class.
var tiers = map[string]Tier{
	"CWE-119": TierMemory,    // a bound overrun, and use after free and double free under it
	"CWE-476": TierMemory,    // a null pointer, filed under coding standards
	"CWE-824": TierMemory,    // an uninitialized pointer
	"CWE-908": TierMemory,    // a value read before it is written
	"CWE-457": TierMemory,    // a variable read before it is written
	"CWE-190": TierMemory,    // an integer that wraps, which is how most overruns begin
	"CWE-134": TierMemory,    // a format string the caller controls
	"CWE-74":  TierInjection, // injection of every kind
	"CWE-77":  TierInjection,
	"CWE-943": TierInjection,
	"CWE-20":  TierInjection, // input not validated
	"CWE-706": TierInjection, // a path or name resolved wrongly
	"CWE-362": TierInjection, // a race
	"CWE-404": TierResource,  // a resource not released
	"CWE-754": TierResource,  // an unusual condition not checked
	"CWE-665": TierResource,  // initialization done wrongly
	"CWE-834": TierResource,  // iteration with no bound
	"CWE-682": TierResource,  // a calculation done wrongly
}

// TierOf is the tier of a weakness.
func TierOf(id string) Tier {
	at := Canonical(id)
	for range mostDepth {
		if tier, ok := tiers[at]; ok {
			return tier
		}
		parent, ok := parents[at]
		if !ok {
			return TierOther
		}
		at = parent
	}
	return TierOther
}
