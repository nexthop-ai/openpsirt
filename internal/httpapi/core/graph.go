// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Browsing resolves a build somebody may look at.
func Browsing(ctx context.Context, in Deps, product, branchOrTag, variant string) (access.Subject, int64, error) {
	subject, _, buildID, err := BrowsingIn(ctx, in, product, branchOrTag, variant)
	return subject, buildID, err
}

// BrowsingIn is Browsing answering the product as well, for a read whose
// rights are the product's.
func BrowsingIn(ctx context.Context, in Deps, product, branchOrTag, variant string) (access.Subject, int64, int64, error) {
	subject, err := Reading(ctx)
	if err != nil {
		return access.Subject{}, 0, 0, err
	}
	named, err := LocatedVisibly(ctx, in, subject, product, branchOrTag, variant)
	if err != nil {
		return access.Subject{}, 0, 0, err
	}
	build, err := BuildRow(ctx, in, named.BranchOrTagID, named.VariantID)
	if err != nil {
		return access.Subject{}, 0, 0, err
	}
	return subject, named.ProductID, build.ID, nil
}
