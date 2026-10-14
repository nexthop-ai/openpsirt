// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package cverecord

import (
	"errors"
	"testing"
)

// Bounds are the bounds a test may lower. A zero field leaves its bound as it
// is.
type Bounds struct {
	Records       int
	Line          int
	SnapshotBytes int64
	Members       int
	Record        uint64
	Inner         int64
	Archive       int64
}

// LowerBounds lowers the bounds named for the rest of the test.
func LowerBounds(t testing.TB, b Bounds) {
	t.Helper()
	was := Bounds{mostRecords, longestLine, mostSnapshotBytes, mostMembers, largestRecord, largestInner, largestArchive}
	set := func(b Bounds) {
		mostRecords, longestLine, mostSnapshotBytes = b.Records, b.Line, b.SnapshotBytes
		mostMembers, largestRecord, largestInner, largestArchive = b.Members, b.Record, b.Inner, b.Archive
	}
	next := was
	if b.Records != 0 {
		next.Records = b.Records
	}
	if b.Line != 0 {
		next.Line = b.Line
	}
	if b.SnapshotBytes != 0 {
		next.SnapshotBytes = b.SnapshotBytes
	}
	if b.Members != 0 {
		next.Members = b.Members
	}
	if b.Record != 0 {
		next.Record = b.Record
	}
	if b.Inner != 0 {
		next.Inner = b.Inner
	}
	if b.Archive != 0 {
		next.Archive = b.Archive
	}
	set(next)
	t.Cleanup(func() { set(was) })
}

// IsTooLarge reports whether an error is a refusal for passing a bound.
func IsTooLarge(err error) bool {
	var refused tooLarge
	return errors.As(err, &refused)
}

// CountMembers is countMembers.
var CountMembers = countMembers
