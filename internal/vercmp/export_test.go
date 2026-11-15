// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vercmp

// Longest is how long a string may be and still be a version.
const Longest = longest

// PyPIPreRanks is every pre-release spelling and the rank it reads as.
var PyPIPreRanks = pypiPreRanks

// PyPIPreRank is the pre-release rank a PyPI version reads as.
func PyPIPreRank(v string) (int, bool) {
	read, ok := pypiRead(v)
	return read.preRank, ok
}
