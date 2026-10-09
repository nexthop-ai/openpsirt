// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"time"
)

// FixedBecause is how a closure is said in a release note, for the test.
//
// Exported for the test alone: it is what the note writes beside each line,
// and what is being held is that every closure counting as a fix has words —
// otherwise a reader gets the issue and the component with nothing after them.
func FixedBecause(because Closure) string { return fixedBecause(because) }

// RankCase is the severity ordering as SQL, and WordAt its inverse, for the
// test.
//
// Exported for the test alone: the two are what every list orders by and what
// the bundle page turns a rank back into, and a mapping that disagrees with
// its own inverse about a band is the defect they were written to end.
func RankCase(over string, otherwise int) string { return rankCase(over, otherwise) }

// WordAt is the severity word a rank stands for.
func WordAt(rank int) string { return wordAt(rank) }

// Exploiting reports whether a packed urgency carries an exploitation signal
// at all, for the test.
//
// Exported for the test alone: the number is written at ingest and read back
// by queries through a threshold, so what the tests hold is that the two
// agree. It says nothing about which of the two signals is on — the number
// cannot, which is why the columns beside it exist.
func Exploiting(urgency int64) bool { return urgency >= exploiting }

// JudgingAfter puts fn between a judgment reading the report and writing to
// it, for the test.
//
// Exported for the test alone: the condition on the write exists for two
// people judging one claim at the same moment, and the read above it answers
// every input a single caller can produce — so without a way into that window
// the condition can be deleted with the suite green.
func (s *Store) JudgingAfter(fn func()) { s.afterReadingReport = fn }

// Clock replaces the moment the store reads, for the test.
//
// Exported for the test alone: an identifier and a reference carry the year
// they were minted in, so a test asserting the year has to fix the moment the
// store reads rather than the one the suite happens to run at.
func (s *Store) Clock(now func() time.Time) { s.now = now }

// KindAsked is the kind the list's filter finds a package identifier by, for
// the test: identifiers a producer spells oddly are too many shapes to route
// each through a scan.
func KindAsked(purl string) string { return kindAsked(purl) }

// InternAlone is Intern with every report resolved alone from the database
// and no copy left out, for the test comparing it with resolving a run of
// reports from one read.
func (v *Vulnerabilities) InternAlone(ctx context.Context, reported []Named) (map[string]int64, error) {
	return v.intern(ctx, reported, true)
}

// Absorbed is how many issues the last interning merged into another.
func (v *Vulnerabilities) Absorbed() int { return len(v.absorbed) }
