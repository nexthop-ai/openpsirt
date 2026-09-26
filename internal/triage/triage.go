// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package triage holds what people decide about findings, and the rules for
// when a decision stops applying.
//
// The shape everything here rests on: a decision is a claim about a
// combination of code, not about a release. It is keyed structurally — which
// issue, in which component, under which consumer — and it stops applying when
// the code it was about changes. Those two are kept apart deliberately:
// identity is structural and expiry is version-based, and letting either reach
// into the other is how an unrelated bump at the top of a build invalidates a
// judgment made about a leaf.
package triage

// Outcome is what somebody decided about a finding.
//
// More than two. A vocabulary with only "affects us" and "does not" has
// nowhere to put the most common real answer, which is "yes, but not now" —
// and the absence shows up as people recording it as one of the other two,
// after which no report can tell the difference.
type Outcome string

const (
	// Affected means it applies and goes to remediation.
	Affected Outcome = "affected"
	// NotApplicable means it does not affect this product here.
	NotApplicable Outcome = "not-applicable"
	// Mismatched means the scanner matched this against something it is not.
	// The finding is wrong rather than answered.
	//
	// A claim about identity, where every other outcome is a judgment about
	// risk. That is what makes it the one outcome the versions do not expire:
	// a decision is stored under the versions it was a claim about and stops
	// applying when they move, which is right for how dangerous something is
	// and wrong for whether the thing is there at all. A version bump does
	// not make a wrong match right, so without this the same wrong match
	// comes back at every point release and somebody answers it again.
	Mismatched Outcome = "mismatched"
	// Deferred means it affects us and is not being worked on until a date.
	Deferred Outcome = "deferred"
	// WontFix means it affects us and will not be addressed.
	WontFix Outcome = "wont-fix"
	// AlreadyFixed means the version shipping here carries the fix,
	// although nothing here can see that it does.
	//
	// The case is a distribution's package: a backported patch does not
	// move the upstream version, so a scanner comparing a published
	// identifier against an upstream range fires whether or not whoever
	// packages it has already dealt with it. None of the other four says
	// this. It is not "does not affect us" — the code is there and it was
	// affected — and the exchange format keeps the two apart as well, with
	// a status of its own rather than a reason under "not affected".
	AlreadyFixed Outcome = "already-fixed"
	// UpgradeNeeded means the answer here is moving the component to a newer
	// version, and somebody has committed to doing it by a date.
	//
	// It is not a dismissal and not a deferral. A deferral says "not now and
	// no plan"; this says "the plan is this version, held by this party, by
	// this date", and the scans decide whether it happened — nobody marks
	// their own work done. Written in bulk from an upgrade rather than one at
	// a time, because a bump answers many issues at once.
	UpgradeNeeded Outcome = "upgrade-needed"
	// PatchNeeded means the answer here is a backported patch, and the
	// version does not move.
	//
	// The other half of the same intent at the other grain: an upgrade is
	// about a component and this is about one issue. It closes the way a
	// backport closes — the build's next inventory declares the patch it
	// carries and says what it resolves, so the finding goes without the
	// version moving, which no version comparison could have seen.
	PatchNeeded Outcome = "patch-needed"
)

// Outcomes are all of them, in the order a person meets them.
func Outcomes() []Outcome {
	return []Outcome{Affected, NotApplicable, Mismatched, Deferred, WontFix,
		AlreadyFixed, UpgradeNeeded, PatchNeeded}
}

// OutcomesOneAtATime are the outcomes one act may record against one finding.
//
// Everything but a promised upgrade. A bump answers many issues at once and is
// written from the upgrade that promises it, so offering it here would be a
// second way to record the same thing with no upgrade behind it.
func OutcomesOneAtATime() []Outcome {
	kept := make([]Outcome, 0, len(Outcomes()))
	for _, each := range Outcomes() {
		if each != UpgradeNeeded {
			kept = append(kept, each)
		}
	}
	return kept
}

// OutcomesInBulk are the outcomes one act may record against many issues.
//
// Everything that is not a commitment: a commitment names one component or one
// issue, a party and a date the work lands by, and a bulk write names none of
// those.
func OutcomesInBulk() []Outcome {
	kept := make([]Outcome, 0, len(Outcomes()))
	for _, each := range Outcomes() {
		if !each.Commits() {
			kept = append(kept, each)
		}
	}
	return kept
}

// OutcomesThatHideRisk are the outcomes that take something out of the working
// queue, which is what needing a second person turns on.
func OutcomesThatHideRisk() []Outcome {
	kept := make([]Outcome, 0, len(Outcomes()))
	for _, each := range Outcomes() {
		if each.HidesRisk() {
			kept = append(kept, each)
		}
	}
	return kept
}

// OutcomesDismissing are the outcomes that claim no further work is needed:
// it does not apply, the match is wrong, it will not be fixed, the fix is
// already here.
//
// Told apart from the rest of what hides risk by carrying no date. A deferral
// says when somebody will look again and a commitment says when the work
// lands, so each of those is a statement about the future that something later
// checks; these close the question, and nothing re-opens it.
//
// Named rather than written out at each site. Spelled as a literal list
// wherever it is asked, an outcome added to some of those sites and not the
// others goes quietly uncounted — which is a condition reporting that a
// control held.
func OutcomesDismissing() []Outcome {
	kept := make([]Outcome, 0, len(Outcomes()))
	for _, each := range Outcomes() {
		if each.HidesRisk() && !each.Dated() {
			kept = append(kept, each)
		}
	}
	return kept
}

// Valid reports whether o is one we recognize.
func (o Outcome) Valid() bool {
	for _, known := range Outcomes() {
		if o == known {
			return true
		}
	}
	return false
}

// HidesRisk reports whether recording this takes something out of the working
// queue.
//
// The distinction the review queue is built on: hiding risk needs a second
// person, and putting it back does not. "Affected" is the only one that leaves
// the issue visible as an issue.
//
// The two commitments hide it as well, and that is deliberate: work with a
// plan and a date on it should not come back round to somebody the next
// morning. What keeps that from being an ungated deferral is where the gate
// sits rather than whether there is one — a commitment inside the deadline
// already set for the work is ordinary triage, and one past it is deferring
// the worst thing it covers. See NeedsApproval.
func (o Outcome) HidesRisk() bool { return o != Affected }

// Commits reports whether this outcome is a promise to act by a date.
//
// The two of them differ from every other outcome in what the date means. A
// deferral's date is when somebody will look again; these are when the thing
// will be done, and the scans say whether it was.
func (o Outcome) Commits() bool { return o == UpgradeNeeded || o == PatchNeeded }

// Dated reports whether this outcome stores a date.
//
// Three of them do: a deferral says when somebody will look again, and the two
// that promise to act say when the work will be done. It is not the same
// question as Commits — a deferral's date is a review date rather than a
// commitment — and the difference matters where what is being asked is whether
// an outcome makes a statement about the future at all.
func (o Outcome) Dated() bool { return o.Commits() || o == Deferred }

// StandsAtAnyVersion reports whether a claim with this outcome keeps applying
// when the code under it moves.
//
// One outcome does. Identity is structural and expiry is version-based, and
// neither reaches into the other: a claim that the match itself is wrong is
// about the first, so the second has nothing to say about it. Every other
// outcome is a judgment made under the versions it was made against, and a
// judgment about risk that outlived them would be the bump at the top of a
// build failing to re-open a question somebody has to answer again.
func (o Outcome) StandsAtAnyVersion() bool { return o == Mismatched }

// NeedsJustification reports whether this outcome says which recognized reason
// applies, which is a claim two of them make.
//
// Both are claims that something is not the problem here, and which reason
// applies is the whole of what each says. The rest are claims about priority
// or about work, and a reason on one of those states something the claim does
// not make.
func (o Outcome) NeedsJustification() bool {
	return o == NotApplicable || o == Mismatched
}

// Justification is why something does not affect us.
//
// The vocabulary is the one the exchange format already defines rather than
// one of ours. It encodes exactly this reasoning, it is what a consumer of our
// published statements will expect, and using it makes publishing them close
// to free — whereas a private vocabulary would need a mapping that nobody
// maintains and that loses meaning at every step.
type Justification string

const (
	// ComponentNotPresent means the component is not in what ships, whatever
	// the inventory says.
	ComponentNotPresent Justification = "component_not_present"
	// CodeNotPresent means the component ships without the vulnerable code.
	CodeNotPresent Justification = "vulnerable_code_not_present"
	// CodeNotInExecutePath means the vulnerable code ships and never runs.
	CodeNotInExecutePath Justification = "vulnerable_code_not_in_execute_path"
	// CodeNotReachableByAdversary means it runs but nothing an attacker
	// controls reaches it.
	CodeNotReachableByAdversary Justification = "vulnerable_code_cannot_be_controlled_by_adversary"
	// MitigationsExist means something already in place stops it.
	MitigationsExist Justification = "inline_mitigations_already_exist"
)

// AboutIdentity reports whether this reason claims something is not there,
// rather than that what is there cannot be reached or is already stopped.
//
// The distinction a correction turns on. A correction does not lapse when the
// code moves, so the reason behind one has to be a reason no version bump can
// answer. That something is absent is such a reason; that it is unreachable or
// already mitigated is a claim about surroundings and configuration, which a
// bump changes all the time — recorded as a correction it would put a judgment
// about risk beyond the rule that re-examines it.
func (j Justification) AboutIdentity() bool {
	return j == ComponentNotPresent || j == CodeNotPresent
}

// IndifferentToSeverity reports whether this reason holds however bad the
// issue is: the code is not there, or it never runs.
func (j Justification) IndifferentToSeverity() bool {
	return j.AboutIdentity() || j == CodeNotInExecutePath
}

// JustificationsCorrecting are the reasons a correction may state.
//
// Named here rather than written out where it is enforced, so that what is
// left out is stated once and stays stated.
func JustificationsCorrecting() []Justification {
	kept := make([]Justification, 0, len(Justifications()))
	for _, each := range Justifications() {
		if each.AboutIdentity() {
			kept = append(kept, each)
		}
	}
	return kept
}

// Justifications are the recognized categories.
func Justifications() []Justification {
	return []Justification{
		ComponentNotPresent, CodeNotPresent, CodeNotInExecutePath,
		CodeNotReachableByAdversary, MitigationsExist,
	}
}

// Valid reports whether j is one we recognize.
func (j Justification) Valid() bool {
	for _, known := range Justifications() {
		if j == known {
			return true
		}
	}
	return false
}

// State is where a decision has got to.
//
// Append-only in spirit: a decision moves forward and what it was before stays
// readable, so the record reads as proposed, approved, withdrawn rather than
// as whatever it happens to be now.
type State string

const (
	// Proposed means somebody has claimed it and nobody has agreed yet.
	Proposed State = "proposed"
	// Approved means a second person agreed, against one specific revision of
	// the reasoning.
	Approved State = "approved"
	// Withdrawn means it no longer applies because somebody took it back.
	Withdrawn State = "withdrawn"
	// LapsedState means the code it was a claim about changed. Named for what
	// it is rather than for the word alone, because "lapsed" reads as a verb
	// everywhere else in this package.
	LapsedState State = "lapsed"
)
