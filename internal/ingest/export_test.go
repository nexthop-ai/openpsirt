// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest

// BeforeApplying runs fn between a scan's parse and the transaction applying
// it, which is where a newer scan can arrive.
func (r *Reader) BeforeApplying(fn func()) *Reader {
	r.beforeApply = fn
	return r
}
