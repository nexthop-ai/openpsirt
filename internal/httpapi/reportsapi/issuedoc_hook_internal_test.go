// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi

// JudgmentsShown sets how many judgments the issue document carries, and
// answers what puts it back.
func JudgmentsShown(n int) func() {
	was := howManyJudgments
	howManyJudgments = n
	return func() { howManyJudgments = was }
}
