// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// The outcomes a decision records, as they are stored. The triage package owns
// what each one means and declares its own vocabulary from these, because it
// imports this package and this package asks about several of them in the
// statements it builds: one spelling, so neither side can rename a word the
// other still matches.
const (
	// OutcomeAffected says an issue applies. A standing decision of it at an
	// occurrence keeps a supplier's statement from closing the finding there.
	OutcomeAffected = "affected"
	// OutcomeNotApplicable says it does not affect the product here.
	OutcomeNotApplicable = "not-applicable"
	// OutcomeMismatched says the scanner matched something that is not here: a
	// decision about identity, which covers an occurrence whatever versions it
	// holds.
	OutcomeMismatched = "mismatched"
	// OutcomeDeferred says it applies and is not being worked on until a date.
	OutcomeDeferred = "deferred"
	// OutcomeWontFix says it applies and will not be addressed.
	OutcomeWontFix = "wont-fix"
	// OutcomeAlreadyFixed says the version shipping here carries the fix.
	OutcomeAlreadyFixed = "already-fixed"
	// OutcomeUpgradeNeeded promises a move to a newer version by a date.
	OutcomeUpgradeNeeded = "upgrade-needed"
	// OutcomePatchNeeded promises a backported patch by a date.
	OutcomePatchNeeded = "patch-needed"
	// OutcomeDismissed says a code finding is not a real flaw, or not one to act on,
	// for the reason it states.
	OutcomeDismissed = "dismissed"
	// OutcomeNotSecurity says a code finding is a real flaw that does no harm: a
	// crash on a path no input reaches, a leak in a tool that exits.
	OutcomeNotSecurity = "not-security"
	// OutcomeConfirmed says a code finding is a real flaw.
	OutcomeConfirmed = "confirmed"
)

// AnyVersionOutcomes are the outcomes a decision covers its occurrence with
// whatever versions the occurrence holds: a wrong match, which is about
// identity, and every outcome about a code finding, whose occurrence is the code finding
// itself.
func AnyVersionOutcomes() []string {
	return []string{OutcomeMismatched, OutcomeDismissed, OutcomeNotSecurity, OutcomeConfirmed}
}

// anyVersionList is AnyVersionOutcomes as the list a statement compares an
// outcome against.
const anyVersionList = `'` + OutcomeMismatched + `', '` + OutcomeDismissed + `', '` +
	OutcomeNotSecurity + `', '` + OutcomeConfirmed + `'`
