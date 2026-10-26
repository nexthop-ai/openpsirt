// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"

	"github.com/uptrace/bun"
)

// Narrowed names whose reading a write may have taken away.
type Narrowed struct {
	// People are the people who may read less than before.
	People []int64
	// Teams are teams whose members may read less than before, beyond the
	// teams those people are on.
	Teams []int64
	// Everybody is a write that moved every grant at once.
	Everybody bool
}

// HandBack hands back the work a write left with a holder who no longer reads
// it, inside that write's transaction. The package holding the work supplies
// it, since this one cannot see that work.
type HandBack func(ctx context.Context, db bun.IDB, narrowed Narrowed) error

// HandingBack returns a store whose own narrowing writes hand back what they
// leave unreadable: a sign-in rewriting what groups derive, and a change of
// role mode. Every other narrowing write is an administrator's act, whose
// handler hands back in the same transaction and reports how much moved.
func (s *Store) HandingBack(handBack HandBack) *Store {
	with := *s
	with.handBack = handBack
	return &with
}

// handBackAfter runs the hand-back over this store's handle, where one was
// supplied.
func (s *Store) handBackAfter(ctx context.Context, narrowed Narrowed) error {
	if s.handBack == nil {
		return nil
	}
	return s.handBack(ctx, s.db, narrowed)
}
