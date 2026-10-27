// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi

// DecisionsShown sets how many decided occurrences the issue document
// carries, and answers what puts it back.
func DecisionsShown(n int) func() {
	was := howManyDecisions
	howManyDecisions = n
	return func() { howManyDecisions = was }
}
