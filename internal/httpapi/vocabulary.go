// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// The closed vocabularies the API offers, built from the package that owns
// them.
//
// A vocabulary retyped beside a route is a second copy of it: a word the domain
// gains is then accepted by the store and refused by the route, and a route
// that carries no list at all types its field as a bare string where its
// neighbours give a union. Asked of the package that owns the words, the
// document cannot say something the store does not mean.
//
// A subset is a named rule in `internal/triage` rather than a shorter literal
// here, so what is left out is stated and stays stated.

// words is a closed vocabulary as a schema, in the order the domain lists it.
func words[T ~string](all []T) *huma.Schema {
	offered := make([]any, 0, len(all))
	for _, each := range all {
		offered = append(offered, string(each))
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}

// outcome is a decision's own word, any of them.
type outcome string

// Schema answers with every outcome the domain recognizes, in its order.
func (outcome) Schema(huma.Registry) *huma.Schema { return words(triage.Outcomes()) }

// outcomeOneAtATime is the outcomes one act may record against one finding.
type outcomeOneAtATime string

// Schema answers with the outcomes one act may record against one finding.
func (outcomeOneAtATime) Schema(huma.Registry) *huma.Schema {
	return words(triage.OutcomesOneAtATime())
}

// outcomeInBulk is the outcomes one act may record against many issues.
type outcomeInBulk string

// Schema answers with the outcomes one act may record against many issues.
func (outcomeInBulk) Schema(huma.Registry) *huma.Schema { return words(triage.OutcomesInBulk()) }

// justification is the reason something does not apply.
type justification string

// Schema answers with the reasons the exchange format defines.
func (justification) Schema(huma.Registry) *huma.Schema { return words(triage.Justifications()) }

// plainly is a repeatable query parameter's words as plain strings, which is
// the form the stores take.
func plainly[T ~string](all []T) []string {
	out := make([]string, 0, len(all))
	for _, each := range all {
		out = append(out, string(each))
	}
	return out
}

// outcomeHidingRisk is the outcomes that take something out of the working
// queue, which is what the need for a second person turns on.
type outcomeHidingRisk string

// Schema answers with the outcomes that hide risk.
func (outcomeHidingRisk) Schema(huma.Registry) *huma.Schema {
	return words(triage.OutcomesThatHideRisk())
}

// outcomeOffered is the outcome a publisher's statement prefills, where it
// prefills one.
type outcomeOffered string

// Schema answers with the outcomes a statement can offer, derived from the
// mapping that decides which of them it is.
func (outcomeOffered) Schema(huma.Registry) *huma.Schema {
	return words(finding.OutcomesOffered())
}

// evidenceSource is which kind of document a publisher's statement arrived in.
type evidenceSource string

// Schema answers with the kinds of document a statement can arrive in.
func (evidenceSource) Schema(huma.Registry) *huma.Schema { return words(finding.Sources()) }

// vexStatus is a publisher's own word, in the exchange format's vocabulary.
type vexStatus string

// Schema answers with the statuses the format defines.
func (vexStatus) Schema(huma.Registry) *huma.Schema { return words(finding.VexStatuses()) }

// origin is where a finding came from, as a narrowing.
type origin string

// Schema answers with the words the narrowing takes.
func (origin) Schema(huma.Registry) *huma.Schema { return words(finding.Origins()) }

// role is a role somebody holds, as the access package lists them.
//
// Retyped beside the route as a literal, it is the drift this file exists to
// stop: `access.Roles` calls itself a floor rather than a ceiling, so a role
// added there is accepted by the store and refused by the route.
type role string

// Schema offers the roles the access package knows.
func (role) Schema(_ huma.Registry) *huma.Schema { return words(access.Roles()) }
