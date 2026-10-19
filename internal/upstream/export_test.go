// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package upstream

// TakingAtMost has a reader take at most n documents a read, so a test reaches
// a read that stops at its bound without publishing two hundred.
func TakingAtMost(r *Reader, n int) { r.most = n }
