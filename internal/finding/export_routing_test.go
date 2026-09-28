// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import "github.com/uptrace/bun"

// NewStoreReaching is a store whose rules may name at most this many places in
// one build.
//
// For the test alone, which has to show the refusal without building a fixture
// of two thousand components: what is being checked is that the cap refuses,
// and a slow fixture says the same thing.
func NewStoreReaching(db bun.IDB, reach int) *Store {
	s := NewStore(db)
	s.reach = reach
	return s
}
