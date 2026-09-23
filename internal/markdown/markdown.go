// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package markdown is the one place text a person typed becomes markup.
//
// Two halves, kept apart deliberately.
//
// The policy runs once, on the server, at submission — before anything is
// stored. What is permitted, which links survive, and what a reference
// resolves to are decided there, because that is the half that cannot be
// duplicated: it is the security control, and it needs data and authorization
// checks no client holds.
//
// Rendering runs on the way out, every time. What is stored is the source and
// never the markup, because a sanitizer fixed next year does nothing for
// markup already sitting in a database — and because the same text has to
// reach a browser, an email and an export, which is three renders from one
// source.
package markdown

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// MaxBytes bounds a single field.
//
// Rendering is work somebody else asks us to do, and what is stored is kept
// forever under an append-only rule. A bound also means a pathological input
// fails one request rather than a replica.
const MaxBytes = 64 << 10

// Fault is something wrong with submitted text, and where.
//
// The position is the point. "Remote images are not allowed" against forty
// lines of justification means hunting for it, and a person who cannot find
// what to fix rewrites the whole thing or gives up on explaining themselves.
type Fault struct {
	// Line is 1-indexed, and 0 where the fault is about the text as a whole.
	Line int
	// Offending is the text that caused it, so the reader can search for it.
	Offending string
	Reason    string
	// err is the sentinel this fault is one of, where there is one.
	//
	// Kept beside the sentence rather than instead of it: the reason is
	// written for a person to read and the sentinel is for a caller to match,
	// and a package that exports one has said callers may match it.
	err error
}

// Unwrap answers the sentinel a fault carries, so errors.Is can match it.
//
// ErrTooLong was exported — which announces exactly that — and formatted into
// a string with no wrapping, so no caller could ever match it. An exported
// sentinel nothing can use as one is a contract stated and not kept.
func (f Fault) Unwrap() error { return f.err }

func (f Fault) Error() string {
	if f.Line == 0 {
		return f.Reason
	}
	if f.Offending == "" {
		return fmt.Sprintf("line %d: %s", f.Line, f.Reason)
	}
	return fmt.Sprintf("line %d: %s (%q)", f.Line, f.Reason, f.Offending)
}

// Faults is everything wrong with one submission.
//
// All of it, not the first. Somebody fixing one problem and resubmitting to
// find the next is how a person learns to write nothing but plain sentences,
// which loses the reason markdown is here at all.
type Faults []Fault

// Unwrap answers every fault, so errors.Is over the whole refusal matches a
// sentinel any one of them carries.
func (f Faults) Unwrap() []error {
	all := make([]error, 0, len(f))
	for _, fault := range f {
		all = append(all, fault)
	}
	return all
}

func (f Faults) Error() string {
	reasons := make([]string, 0, len(f))
	for _, fault := range f {
		reasons = append(reasons, fault.Error())
	}
	return strings.Join(reasons, "; ")
}

// MaxFaults is how many problems one refusal names.
//
// Exported so a test can assert the cap fired rather than counting to a
// number of its own, which would pass whatever the cap became.
const MaxFaults = 20

// ErrTooLong is returned for text past the bound.
var ErrTooLong = errors.New("that is longer than a justification may be")

// Check reports everything wrong with submitted text.
//
// Run before storage. Stored text is then known to have passed the policy that
// was in force when it arrived — which is not the same as being safe forever,
// which is why rendering sanitizes as well.
func Check(source string) error {
	if len(source) > MaxBytes {
		return Faults{{
			Reason: fmt.Sprintf("%s (%d bytes, limit %d)", ErrTooLong, len(source), MaxBytes),
			err:    ErrTooLong,
		}}
	}
	if !utf8.ValidString(source) {
		return Faults{{Reason: "that is not text this can read"}}
	}

	found := inspect(source)
	if len(found) == 0 {
		return nil
	}
	// Capped. A field of nothing but refused links produces one fault per line
	// and an answer many times the size of what was sent, which is a way to
	// make a refusal expensive. Somebody with sixty problems does not need
	// sixty told to them at once either.
	if len(found) > MaxFaults {
		found = append(found[:MaxFaults:MaxFaults], Fault{
			Reason: fmt.Sprintf("and more besides — fix these %d first", MaxFaults),
		})
	}
	return Faults(found)
}
