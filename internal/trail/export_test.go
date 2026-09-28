// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package trail

import "time"

// SetClock fixes the moment a record is stamped with, so a test can write
// rows that share a timestamp or sit either side of a boundary.
func (s *Store) SetClock(now func() time.Time) { s.now = now }
