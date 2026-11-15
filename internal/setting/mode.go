// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package setting

import (
	"context"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Mode reads where roles come from, per request.
//
// Read rather than held because replicas restart one at a time, and the one
// that applied configuration last is what every replica has to answer by. A
// read that fails answers with the mode that derives nothing, which is the
// safe direction.
func (s *Store) Mode() func(context.Context) access.Mode {
	return func(ctx context.Context) access.Mode {
		stored, _, err := s.Get(ctx, RoleMode)
		if err != nil {
			return access.Direct
		}
		return access.AsMode(stored)
	}
}
