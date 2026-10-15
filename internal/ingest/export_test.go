// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest

import "github.com/uptrace/bun"

// DB is the handle the store writes through, for queries a test makes that
// this package does not wrap.
func (s *Store) DB() bun.IDB { return s.db }

// BeforeApplying runs fn between a scan's parse and the transaction applying
// it, which is where a newer scan can arrive.
func (r *Reader) BeforeApplying(fn func()) *Reader {
	r.beforeApply = fn
	return r
}
