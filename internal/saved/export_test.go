// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package saved

import "time"

// WithClock reads the time from now.
func (s *Store) WithClock(now func() time.Time) *Store {
	s.now = now
	return s
}
