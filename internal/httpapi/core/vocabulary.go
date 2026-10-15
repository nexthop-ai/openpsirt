// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/currency"
	"github.com/nexthop-ai/openpsirt/internal/cvss"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/obligation"
	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/trail"
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

// buildSaying is what the build's own claims say about an open finding.
type buildSaying string

// Schema answers with the statuses an open finding's claim can hold.
func (buildSaying) Schema(huma.Registry) *huma.Schema { return words(finding.BuildSayings()) }

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

// ClaimStates is the state a set of decision rows shares, or the word for rows
// that do not share one.
type ClaimStates string

// Schema offers every state a decision row can reach, and the word for several.
func (ClaimStates) Schema(huma.Registry) *huma.Schema {
	all := make([]string, 0, len(triage.States())+1)
	for _, state := range triage.States() {
		all = append(all, string(state))
	}
	return words(append(all, triage.SeveralStates))
}

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

// FixState is what upstream has done about an issue.
type FixState string

// Schema offers every word for what upstream has done.
func (FixState) Schema(huma.Registry) *huma.Schema { return words(finding.FixStates()) }

// Unmatchable is why the scanner has no way to match a component.
type Unmatchable string

// Schema offers every reason, in the order a component is tested against them.
func (Unmatchable) Schema(huma.Registry) *huma.Schema { return words(graph.Reasons) }

// NoDeadline is why a finding carries no deadline.
type NoDeadline string

// Schema offers every reason a finding carries no deadline, narrowest first.
func (NoDeadline) Schema(huma.Registry) *huma.Schema { return words(finding.NoDeadlines()) }

// DeclaredScope is a scope a producer declared, in the producer's own word.
type DeclaredScope string

// Schema offers every scope word an inventory reader records.
func (DeclaredScope) Schema(huma.Registry) *huma.Schema { return words(sbom.Scopes()) }

// PlannedEither is the word a request carries to ask for planned and unplanned
// work alike. The store reads it as no narrowing at all.
const PlannedEither = "either"

// Planned is whether a promised upgrade covers a finding, as a request asks it.
type Planned string

// Schema offers the two narrowings the store takes, and the word for neither.
func (Planned) Schema(huma.Registry) *huma.Schema {
	return words([]string{string(finding.PlannedOnly), string(finding.NotPlanned), PlannedEither})
}

// Support is whether a release is still in support.
type Support string

// Schema offers both states of support.
func (Support) Schema(huma.Registry) *huma.Schema { return words(finding.Supports()) }

// Assignee is who is dealing with a group, as a findings list asks it.
type Assignee string

// Schema offers every word a findings list asks who is dealing with a group in.
func (Assignee) Schema(huma.Registry) *huma.Schema { return words(finding.Assignees()) }

// UpgradeState is the state a promised upgrade is in.
type UpgradeState string

// Schema offers every state a promised upgrade can be in.
func (UpgradeState) Schema(huma.Registry) *huma.Schema { return words(finding.UpgradeStates()) }

// MatchRoute is the route a scanner took to a finding.
type MatchRoute string

// Schema offers every route a scanner takes.
func (MatchRoute) Schema(huma.Registry) *huma.Schema { return words(finding.MatchRoutes()) }

// ReferenceKind is what a reference appears to be.
type ReferenceKind string

// Schema offers every kind a reference can appear to be.
func (ReferenceKind) Schema(huma.Registry) *huma.Schema { return words(finding.ReferenceKinds()) }

// AssessmentState is the state an assessment has reached.
type AssessmentState string

// Schema offers every state an assessment passes through.
func (AssessmentState) Schema(huma.Registry) *huma.Schema {
	return words(finding.AssessmentStates())
}

// RulingState is where a ruling stands.
type RulingState string

// Schema offers every state a ruling can stand in.
func (RulingState) Schema(huma.Registry) *huma.Schema { return words(finding.RulingStates()) }

// Platform is how a destination is reached.
type Platform string

// Schema offers every way a destination is reached.
func (Platform) Schema(huma.Registry) *huma.Schema { return words(notify.Platforms()) }

// NotificationKind is what a notification is about.
type NotificationKind string

// Schema offers every kind of notification.
func (NotificationKind) Schema(huma.Registry) *huma.Schema { return words(notify.Kinds()) }

// DestinationKind is the notifications a destination takes, as a response
// says it: one kind, or the word for all of them. A request names it as typed,
// because the store folds its case.
type DestinationKind string

// Schema offers every kind of notification, and then the word for all of them.
func (DestinationKind) Schema(huma.Registry) *huma.Schema {
	return words(append(plainly(notify.Kinds()), notify.Everything))
}

// Lifetime is how long a notification is worth showing.
type Lifetime string

// Schema offers both lifetimes.
func (Lifetime) Schema(huma.Registry) *huma.Schema { return words(notify.Lifetimes()) }

// Progress is how far an upload has got.
type Progress string

// Schema offers every state an upload can reach.
func (Progress) Schema(huma.Registry) *huma.Schema { return words(ingest.Progresses()) }

// DocumentKind is what a document a build sent is.
type DocumentKind string

// Schema offers every kind of document a build sends.
func (DocumentKind) Schema(huma.Registry) *huma.Schema { return words(ingest.Kinds()) }

// Mode is how roles are assigned.
type Mode string

// Schema offers both ways roles can be assigned.
func (Mode) Schema(huma.Registry) *huma.Schema { return words(access.Modes()) }

// GrantSource is where a grant came from.
type GrantSource string

// Schema offers both places a grant can come from.
func (GrantSource) Schema(huma.Registry) *huma.Schema { return words(access.Sources()) }

// EmailSource is who last decided somebody's address.
type EmailSource string

// Schema offers every source that decides an address.
func (EmailSource) Schema(huma.Registry) *huma.Schema { return words(access.EmailSources()) }

// PartyKind is whether a party is a person or a team.
type PartyKind string

// Schema offers both sorts of party.
func (PartyKind) Schema(huma.Registry) *huma.Schema { return words(access.PartyKinds()) }

// RepositoryState is where one patch repository stands.
type RepositoryState string

// Schema offers every state a repository can stand in.
func (RepositoryState) Schema(huma.Registry) *huma.Schema { return words(patchbranch.States()) }

// VisitStep is what a visit to a patch repository is doing.
type VisitStep string

// Schema offers every step a visit can be at.
func (VisitStep) Schema(huma.Registry) *huma.Schema { return words(patchbranch.Steps()) }

// Unanswered is why a component has no upstream answer.
type Unanswered string

// Schema offers every reason a component has no upstream answer.
func (Unanswered) Schema(huma.Registry) *huma.Schema { return words(currency.Whys()) }

// TrailKind is the kind of thing an administrative change changed.
type TrailKind string

// Schema offers every kind of administrative change.
func (TrailKind) Schema(huma.Registry) *huma.Schema { return words(trail.Kinds()) }

// TrailActor is what made an administrative change.
type TrailActor string

// Schema offers every actor a change can have.
func (TrailActor) Schema(huma.Registry) *huma.Schema { return words(trail.Actors()) }

// Malice is what a notice said about whether an attack was malicious.
type Malice string

// Schema offers every word a notice may say about malice.
func (Malice) Schema(huma.Registry) *huma.Schema { return words(obligation.Malice) }

// AdvisoryStatus is where an advisory document is in its life.
type AdvisoryStatus string

// Schema offers every status a document can carry.
func (AdvisoryStatus) Schema(huma.Registry) *huma.Schema { return words(advisory.Statuses()) }

// ReleaseStatus is what a document states about one release.
type ReleaseStatus string

// Schema offers every status a document can state about a release.
func (ReleaseStatus) Schema(huma.Registry) *huma.Schema {
	return words(advisory.ReleaseStatuses())
}

// SettingKind is the type of a setting's value.
type SettingKind string

// Schema offers every kind a setting's value can be.
func (SettingKind) Schema(huma.Registry) *huma.Schema { return words(setting.Kinds()) }

// SettingSection is the part of the settings a setting is filed under.
type SettingSection string

// Schema offers every section, in the order a screen shows them.
func (SettingSection) Schema(huma.Registry) *huma.Schema { return words(setting.Sections()) }

// Visibility is whether something has been disclosed.
type Visibility string

// Schema offers both visibilities, disclosed first.
func (Visibility) Schema(huma.Registry) *huma.Schema { return words(access.Visibilities()) }

// ChangeKind is what one scan did to one name.
type ChangeKind string

// Schema offers every kind of change, in the order the delta counts them.
func (ChangeKind) Schema(huma.Registry) *huma.Schema { return words(graph.ChangeKinds()) }

// VariantSpread is how a group is spread over the variants of a branch, as a
// request narrows by it.
type VariantSpread string

// Schema offers every narrowing by spread.
func (VariantSpread) Schema(huma.Registry) *huma.Schema { return words(finding.VariantSpreads()) }

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
