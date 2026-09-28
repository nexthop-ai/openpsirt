// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/cvss"
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
// A subset is a named rule in the package that owns the vocabulary rather than
// a shorter literal here, so what is left out is stated and stays stated.

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

// roleOrOver is a role over a product or a right over the whole deployment,
// which is what a group binding may hand out.
type roleOrOver string

// Schema offers the roles and then the rights over the deployment.
func (roleOrOver) Schema(huma.Registry) *huma.Schema {
	return words(append(plainly(access.Roles()), plainly(access.OverTheDeployment())...))
}

// lineKind is whether a release line moves.
type lineKind string

// Schema offers every kind a release line can be.
func (lineKind) Schema(huma.Registry) *huma.Schema { return words(catalog.Kinds()) }

// act is an act on an embargo.
type act string

// Schema offers the acts the finding package knows.
func (act) Schema(huma.Registry) *huma.Schema { return words(finding.Acts()) }

// disposition is what a report was judged to be, any of them.
type disposition string

// Schema offers every disposition.
func (disposition) Schema(huma.Registry) *huma.Schema { return words(finding.Dispositions()) }

// dispositionRulable is a disposition a ruling may carry.
type dispositionRulable string

// Schema offers the dispositions a ruling may carry.
func (dispositionRulable) Schema(huma.Registry) *huma.Schema {
	return words(which(finding.Dispositions(), finding.Disposition.Rulable))
}

// dispositionWaiting is a disposition that waits for a second person.
type dispositionWaiting string

// Schema offers the dispositions that need a second person.
func (dispositionWaiting) Schema(huma.Registry) *huma.Schema {
	return words(which(finding.Dispositions(), finding.Disposition.NeedsSecondPerson))
}

// happened is what became of a claim.
type happened string

// Schema offers every word for what became of a claim.
func (happened) Schema(huma.Registry) *huma.Schema { return words(triage.WhatHappenedAll()) }

// claimState is the state a decision row has reached.
type claimState string

// Schema offers every state a decision row can reach.
func (claimState) Schema(huma.Registry) *huma.Schema { return words(triage.States()) }

// claimStateLive is a state in which a row still holds its key.
type claimStateLive string

// Schema offers the states in which a row still holds its key.
func (claimStateLive) Schema(huma.Registry) *huma.Schema {
	return words(which(triage.States(), triage.State.Live))
}

// claimStateEnded is a state in which a row has stopped applying.
type claimStateEnded string

// Schema offers the states in which a row has stopped applying.
func (claimStateEnded) Schema(huma.Registry) *huma.Schema {
	return words(which(triage.States(), triage.State.Ended))
}

// claimKind is what sort of action a claim was.
type claimKind string

// Schema offers every sort of action a claim can be.
func (claimKind) Schema(huma.Registry) *huma.Schema { return words(triage.ClaimKinds()) }

// standing is how far a group or a place has been decided.
type standing string

// Schema offers every standing, in the order the list offers them.
func (standing) Schema(huma.Registry) *huma.Schema { return words(finding.ClaimStandings()) }

// standingUnsettled is a standing that is not agreed.
type standingUnsettled string

// Schema offers every standing but agreed.
func (standingUnsettled) Schema(huma.Registry) *huma.Schema {
	return words(which(finding.ClaimStandings(), finding.ClaimStanding.Unsettled))
}

// band is one of the four rated words, worst first.
type band string

// Schema offers the four rated words, worst first.
func (band) Schema(huma.Registry) *huma.Schema { return words(finding.Bands()) }

// rating is one of the four rated words.
type rating string

// Schema offers the four rated words, least first.
func (rating) Schema(huma.Registry) *huma.Schema { return words(finding.LeastFirst()) }

// recordable is a severity somebody may record.
type recordable string

// Schema offers every severity word somebody may record, worst first.
func (recordable) Schema(huma.Registry) *huma.Schema { return words(finding.Recordable()) }

// line is a triage line, or the word for none.
type line string

// Schema offers the words a line may be set to.
func (line) Schema(huma.Registry) *huma.Schema { return words(finding.TriageFloors()) }

// lineOrClear is a triage line, the word for none, or empty to follow the
// deployment.
type lineOrClear string

// Schema offers the words a line may be set to, and the empty word.
func (lineOrClear) Schema(huma.Registry) *huma.Schema {
	return words(append(finding.TriageFloors(), ""))
}

// scoreBand is the band a score falls in.
type scoreBand string

// Schema offers every band a score can fall in, least first.
func (scoreBand) Schema(huma.Registry) *huma.Schema { return words(cvss.Bands()) }

// which is the words of a vocabulary a rule of its own keeps, in its order.
// A subset is the domain's rule applied, never a shorter list typed here.
func which[T ~string](all []T, keeps func(T) bool) []T {
	out := make([]T, 0, len(all))
	for _, each := range all {
		if keeps(each) {
			out = append(out, each)
		}
	}
	return out
}

// as is a repeatable query parameter's words as the domain's own type, which is
// the form a store takes them in.
func as[To ~string, From ~string](all []From) []To {
	out := make([]To, 0, len(all))
	for _, each := range all {
		out = append(out, To(each))
	}
	return out
}
