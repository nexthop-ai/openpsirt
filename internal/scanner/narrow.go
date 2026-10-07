// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"fmt"

	"github.com/nexthop-ai/openpsirt/internal/cverecord"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// narrow reads what each issue's CVE record says about the component it was
// matched in, and marks a match the record excludes (REQ-31).
//
// The component read is the inventory's, not the scanner's account of it: the
// inventory carries the CPE and the upstream name and version a record is tied
// by, and the scanner's artifact carries neither.
//
// Where the record names a fix on the component's own branch and the
// component is upstream's own release, that fix replaces the scanner's. A
// scanner matching by an upstream range names the fix on whichever branch the
// range was cut from, and moving to it would mean leaving the branch the
// component is on. A distribution's package keeps its feed's fix, which is in
// the distribution's numbering and already on its branch.
func narrow(snapshot *cverecord.Snapshot, components []graph.Described, reported []finding.Reported) error {
	if snapshot == nil {
		return nil
	}
	byIdentity := make(map[string]graph.Described, len(components))
	for _, c := range components {
		byIdentity[c.Identity()] = c
	}
	for i := range reported {
		r := &reported[i]
		component, held := byIdentity[r.Component.Identity()]
		if !held {
			continue
		}
		identifiers := append([]string{r.Issue.Identifier}, r.Issue.Aliases...)
		verdict := snapshot.Decide(identifiers, component)
		if verdict.Narrows() {
			lines, err := json.Marshal(verdict.Unaffected)
			if err != nil {
				return fmt.Errorf("record why %s is unaffected: %w", r.Issue.Identifier, err)
			}
			r.Unaffected = string(lines)
			continue
		}
		if verdict.BranchFix != "" && upstreamRelease(component) {
			r.FixState = finding.FixedUpstream
			r.FixedIn = verdict.BranchFix
			// The date the scanner gave is the other branch's fix, and the
			// record states no date for this one.
			r.FixedAt = nil
		}
	}
	return nil
}

// upstreamRelease reports whether a component is upstream's own release
// rather than a distribution's package of it.
func upstreamRelease(component graph.Described) bool {
	switch graph.PartsOfPurl(component.Purl).Type {
	case "deb", "rpm", "apk", "alpm":
		return false
	default:
		return true
	}
}
