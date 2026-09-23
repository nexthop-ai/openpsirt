// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

// Declared is what one act recorded.
//
// Shared by the acts that answer many places at once, so "how much did that
// write" means one thing rather than one thing per act.
type Declared struct {
	// ClaimID is the one claim the whole act was recorded under, which is what
	// an approver agrees to where this outcome needs one.
	ClaimID int64
	// Decisions is how many places were answered and Targets how many
	// build-level intents were recorded.
	Decisions int
	Targets   int
	// Issues and Components are what it reached, for saying so back.
	Issues     int
	Components int
	// Waiting says a second person has to agree. Only ever true for the
	// outcomes that promise to act, and then only when the date is past
	// the earliest deadline among what the act covers.
	Waiting bool
	// Held is how many findings were handed to the party carrying this, where
	// one was named. Reported rather than assumed from the decision count:
	// assignment is product-wide and a decision is per place, so the two
	// numbers answer different questions and would be read as one.
	Held int
}
