// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// Origin is where a finding came from, as a narrowing.
//
// Three answers rather than two, which is why it is a word: a list can be
// asked for what a person recorded, for what a scanner reported, or for both,
// and a flag cannot send the answer for both.
type Origin string

const (
	// RecordedByHand keeps only what a person entered here. Those are the only
	// ones a person may close by hand.
	RecordedByHand Origin = "manual"
	// ReportedByAScanner keeps only what a scan found.
	ReportedByAScanner Origin = "scanner"
)

// Origins are the words the narrowing takes.
func Origins() []Origin { return []Origin{ReportedByAScanner, RecordedByHand} }
