// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package upstream

import "context"

// TakingAtMost has a reader take at most n documents a read, so a test reaches
// a read that stops at its bound without publishing two hundred.
func TakingAtMost(r *Reader, n int) { r.most = n }

// ListingAtMost has a reader take listings naming at most n entries, so a test
// reaches the bound without serving thousands.
func ListingAtMost(r *Reader, n int) { r.listed = n }

// Keeping has a reader ask keep for the lease, as a pass does.
func Keeping(r *Reader, keep func(context.Context) (bool, error)) { r.keep = keep }
