// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// The outcomes a claim records, as they are stored. The triage package owns
// what each one means and declares its own vocabulary from these, because it
// imports this package and this package asks about several of them in the
// statements it builds: one spelling, so neither side can rename a word the
// other still matches.
const (
	// OutcomeAffected says an issue applies. A standing decision of it at a
	// place keeps a supplier's statement from closing the finding there.
	OutcomeAffected = "affected"
	// OutcomeNotApplicable says it does not affect the product here.
	OutcomeNotApplicable = "not-applicable"
	// OutcomeMismatched says the scanner matched something that is not here:
	// a claim about identity, which covers a place whatever versions it holds.
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
)
