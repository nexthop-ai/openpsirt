// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"strconv"
	"strings"
)

// MeasuredBody is the tooling a build's numbers were produced with.
//
// Not decoration. A build reporting nothing wrong and a build last measured
// against a vulnerability database from March look identical on every screen
// without this, and they are not the same statement at all.
type MeasuredBody struct {
	Scanner         string `json:"scanner" doc:"The scanner that produced the findings"`
	ScannerVersion  string `json:"scanner_version,omitempty"`
	DatabaseVersion string `json:"database_version,omitempty" doc:"The vulnerability database it read"`
	RecordsVersion  string `json:"records_version,omitempty" doc:"The CVE record snapshot matches were narrowed with, as the moment it describes. Absent where the run read none"`
	RanAt           string `json:"ran_at,omitempty" doc:"The moment that run finished"`
	// RanHere says we ran it rather than a build sending what its own scanner
	// found. Counts are only comparable between builds measured the same way,
	// so a report mixing the two without saying would be a rumor.
	RanHere bool `json:"ran_here,omitempty" doc:"We ran the scanner, rather than the build sending what its own found"`
	// The rest of the chain, for a report read against what shipped: the
	// upload, the inventory inside it, and where to fetch that inventory. An
	// auditor follows shipped artifact, inventory, run, scanner and database,
	// disposition — and a report naming only the run is the last two links of
	// five.
	//
	// Absent where the caller is describing a run alone, which is what a
	// finding and a receipt do.
	Run          int64  `json:"run,omitempty" doc:"The scanner run these came from"`
	Scan         int64  `json:"scan,omitempty" doc:"The upload the build's contents came from, as the receipt names it"`
	ScanHash     string `json:"scan_hash,omitempty" doc:"The hash of what was uploaded"`
	BuiltAt      string `json:"built_at,omitempty" doc:"The build time it describes"`
	Document     int64  `json:"document,omitempty" doc:"The inventory that was read, as the receipt names it"`
	DocumentHash string `json:"document_hash,omitempty" doc:"The hash of the inventory as it arrived"`
	// DocumentHeld distinguishes an inventory whose bytes were let go from one
	// nothing knows about: a tagged release keeps its documents and a branch
	// build does not, and a hash nobody can fetch the bytes for is a claim
	// rather than evidence.
	DocumentHeld *bool  `json:"document_held,omitempty" doc:"Whether the inventory itself is still here"`
	DocumentAt   string `json:"document_at,omitempty" doc:"The address of the inventory that was read. Absent where its contents were let go"`
}

// Stating is the same facts as a file's header.
func (m *MeasuredBody) Stating() []Stated {
	if m == nil {
		return nil
	}
	return []Stated{
		{"scan", strconv.FormatInt(m.Scan, 10)},
		{"inventory hash", m.DocumentHash},
		{"scanner", strings.TrimSpace(m.Scanner + " " + m.ScannerVersion)},
		{"vulnerability data", m.DatabaseVersion},
		{"CVE records", m.RecordsVersion},
		{"run", stringOrNone(m.Run)},
		{"measured at", m.RanAt},
	}
}

// stringOrNone writes an identifier nothing answered as nothing rather than as
// a zero, which reads as a row that exists.
func stringOrNone(id int64) string {
	if id == 0 {
		return ""
	}
	return strconv.FormatInt(id, 10)
}
