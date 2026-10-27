// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Browsing resolves a build somebody may look at.
func Browsing(ctx context.Context, in Deps, product, branchOrTag, variant string) (access.Subject, int64, error) {
	subject, err := Reading(ctx)
	if err != nil {
		return access.Subject{}, 0, err
	}
	named, err := LocatedVisibly(ctx, in, subject, product, branchOrTag, variant)
	if err != nil {
		return access.Subject{}, 0, err
	}
	build, err := BuildRow(ctx, in, named.BranchOrTagID, named.VariantID)
	if err != nil {
		return access.Subject{}, 0, err
	}
	return subject, build.ID, nil
}
