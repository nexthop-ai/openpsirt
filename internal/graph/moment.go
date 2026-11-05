// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import "fmt"

// Moment is when an inventory is read: as it stands now, or as it stood once
// one scan of its build was applied.
//
// Scans of a build apply in identifier order, and a row is held from the scan
// that opened it until the scan that closed it, so the inventory a scan left
// is every row opened at or before it and not closed by then.
type Moment struct{ scan int64 }

// Now is the inventory as it stands.
var Now = Moment{}

// AtScan is the inventory as it stood once this scan was applied.
func AtScan(scanID int64) Moment { return Moment{scan: scanID} }

// Held is the condition that a row under this alias is held at the moment,
// with its arguments.
func (m Moment) Held(alias string) (string, []any) {
	if m.scan == 0 {
		return fmt.Sprintf(`"%s"."closed_scan_id" IS NULL`, alias), nil
	}
	return fmt.Sprintf(`"%[1]s"."opened_scan_id" <= ? AND ("%[1]s"."closed_scan_id" IS NULL OR "%[1]s"."closed_scan_id" > ?)`,
		alias), []any{m.scan, m.scan}
}

// IsNow says the moment is the inventory as it stands.
func (m Moment) IsNow() bool { return m.scan == 0 }
