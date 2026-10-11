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

// NewStoreCountingApart is a store reading each binary's count in a statement
// of its own once a source package has more than this many binaries.
//
// For the test alone: past the bound the count takes another path, and a
// source package with hundreds of binaries is a slow fixture saying the same
// thing.
func NewStoreCountingApart(db bun.IDB, columns int) *Store {
	s := NewStore(db)
	s.binaryColumns = columns
	return s
}
