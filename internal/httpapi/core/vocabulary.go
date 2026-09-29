// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

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

// Outcome is a decision's own word, any of them.
type Outcome string

// Schema answers with every outcome the domain recognizes, in its order.
func (Outcome) Schema(huma.Registry) *huma.Schema { return words(triage.Outcomes()) }

// OutcomeOneAtATime is the outcomes one act may record against one finding.
type OutcomeOneAtATime string

// Schema answers with the outcomes one act may record against one finding.
func (OutcomeOneAtATime) Schema(huma.Registry) *huma.Schema {
	return words(triage.OutcomesOneAtATime())
}

// OutcomeInBulk is the outcomes one act may record against many issues.
type OutcomeInBulk string

// Schema answers with the outcomes one act may record against many issues.
func (OutcomeInBulk) Schema(huma.Registry) *huma.Schema { return words(triage.OutcomesInBulk()) }

// Justification is the reason something does not apply.
type Justification string

// Schema answers with the reasons the exchange format defines.
func (Justification) Schema(huma.Registry) *huma.Schema { return words(triage.Justifications()) }

// plainly is a repeatable query parameter's words as plain strings, which is
// the form the stores take.
func plainly[T ~string](all []T) []string {
	out := make([]string, 0, len(all))
	for _, each := range all {
		out = append(out, string(each))
	}
	return out
}

// OutcomeHidingRisk is the outcomes that take something out of the working
// queue, which is what the need for a second person turns on.
type OutcomeHidingRisk string

// Schema answers with the outcomes that hide risk.
func (OutcomeHidingRisk) Schema(huma.Registry) *huma.Schema {
	return words(triage.OutcomesThatHideRisk())
}

// OutcomeOffered is the outcome a publisher's statement prefills, where it
// prefills one.
type OutcomeOffered string

// Schema answers with the outcomes a statement can offer, derived from the
// mapping that decides which of them it is.
func (OutcomeOffered) Schema(huma.Registry) *huma.Schema {
	return words(finding.OutcomesOffered())
}

// EvidenceSource is which kind of document a publisher's statement arrived in.
type EvidenceSource string

// Schema answers with the kinds of document a statement can arrive in.
func (EvidenceSource) Schema(huma.Registry) *huma.Schema { return words(finding.Sources()) }

// vexStatus is a publisher's own word, in the exchange format's vocabulary.
type vexStatus string

// Schema answers with the statuses the format defines.
func (vexStatus) Schema(huma.Registry) *huma.Schema { return words(finding.VexStatuses()) }

// origin is where a finding came from, as a narrowing.
type origin string

// Schema answers with the words the narrowing takes.
func (origin) Schema(huma.Registry) *huma.Schema { return words(finding.Origins()) }

// Role is a role somebody holds, as the access package lists them.
//
// Retyped beside the route as a literal, it is the drift this file exists to
// stop: `access.Roles` calls itself a floor rather than a ceiling, so a role
// added there is accepted by the store and refused by the route.
type Role string

// Schema offers the roles the access package knows.
func (Role) Schema(_ huma.Registry) *huma.Schema { return words(access.Roles()) }

// RoleOrOver is a role over a product or a right over the whole deployment,
// which is what a group binding may hand out.
type RoleOrOver string

// Schema offers the roles and then the rights over the deployment.
func (RoleOrOver) Schema(huma.Registry) *huma.Schema {
	return words(append(plainly(access.Roles()), plainly(access.OverTheDeployment())...))
}

// LineKind is whether a release line moves.
type LineKind string

// Schema offers every kind a release line can be.
func (LineKind) Schema(huma.Registry) *huma.Schema { return words(catalog.Kinds()) }

// Act is an act on an embargo.
type Act string

// Schema offers the acts the finding package knows.
func (Act) Schema(huma.Registry) *huma.Schema { return words(finding.Acts()) }

// Disposition is what a report was judged to be, any of them.
type Disposition string

// Schema offers every disposition.
func (Disposition) Schema(huma.Registry) *huma.Schema { return words(finding.Dispositions()) }

// DispositionRulable is a disposition a ruling may carry.
type DispositionRulable string

// Schema offers the dispositions a ruling may carry.
func (DispositionRulable) Schema(huma.Registry) *huma.Schema {
	return words(Which(finding.Dispositions(), finding.Disposition.Rulable))
}

// DispositionWaiting is a disposition that waits for a second person.
type DispositionWaiting string

// Schema offers the dispositions that need a second person.
func (DispositionWaiting) Schema(huma.Registry) *huma.Schema {
	return words(Which(finding.Dispositions(), finding.Disposition.NeedsSecondPerson))
}

// Happened is what became of a claim.
type Happened string

// Schema offers every word for what became of a claim.
func (Happened) Schema(huma.Registry) *huma.Schema { return words(triage.WhatHappenedAll()) }

// ClaimState is the state a decision row has reached.
type ClaimState string

// Schema offers every state a decision row can reach.
func (ClaimState) Schema(huma.Registry) *huma.Schema { return words(triage.States()) }

// ClaimStateLive is a state in which a row still holds its key.
type ClaimStateLive string

// Schema offers the states in which a row still holds its key.
func (ClaimStateLive) Schema(huma.Registry) *huma.Schema {
	return words(Which(triage.States(), triage.State.Live))
}

// ClaimStateEnded is a state in which a row has stopped applying.
type ClaimStateEnded string

// Schema offers the states in which a row has stopped applying.
func (ClaimStateEnded) Schema(huma.Registry) *huma.Schema {
	return words(Which(triage.States(), triage.State.Ended))
}

// QueueReason is why a claim waits in the review queue.
type QueueReason string

// Schema offers every reason, in the order the queue offers them.
func (QueueReason) Schema(huma.Registry) *huma.Schema { return words(triage.QueueReasons()) }

// ClaimKind is what sort of action a claim was.
type ClaimKind string

// Schema offers every sort of action a claim can be.
func (ClaimKind) Schema(huma.Registry) *huma.Schema { return words(triage.ClaimKinds()) }

// Standing is how far a group or a place has been decided.
type Standing string

// Schema offers every standing, in the order the list offers them.
func (Standing) Schema(huma.Registry) *huma.Schema { return words(finding.ClaimStandings()) }

// StandingUnsettled is a standing that is not agreed.
type StandingUnsettled string

// Schema offers every standing but agreed.
func (StandingUnsettled) Schema(huma.Registry) *huma.Schema {
	return words(Which(finding.ClaimStandings(), finding.ClaimStanding.Unsettled))
}

// Band is one of the four rated words, worst first.
type Band string

// Schema offers the four rated words, worst first.
func (Band) Schema(huma.Registry) *huma.Schema { return words(finding.Bands()) }

// Rating is one of the four rated words.
type Rating string

// Schema offers the four rated words, least first.
func (Rating) Schema(huma.Registry) *huma.Schema { return words(finding.LeastFirst()) }

// Recordable is a severity somebody may record.
type Recordable string

// Schema offers every severity word somebody may record, worst first.
func (Recordable) Schema(huma.Registry) *huma.Schema { return words(finding.Recordable()) }

// Line is a triage line, or the word for none.
type Line string

// Schema offers the words a line may be set to.
func (Line) Schema(huma.Registry) *huma.Schema { return words(finding.TriageFloors()) }

// lineOrClear is a triage line, the word for none, or empty to follow the
// deployment.
type lineOrClear string

// Schema offers the words a line may be set to, and the empty word.
func (lineOrClear) Schema(huma.Registry) *huma.Schema {
	return words(append(finding.TriageFloors(), ""))
}

// ScoreBand is the band a score falls in.
type ScoreBand string

// Schema offers every band a score can fall in, least first.
func (ScoreBand) Schema(huma.Registry) *huma.Schema { return words(cvss.Bands()) }

// Which is the words of a vocabulary a rule of its own keeps, in its order.
// A subset is the domain's rule applied, never a shorter list typed here.
func Which[T ~string](all []T, keeps func(T) bool) []T {
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
