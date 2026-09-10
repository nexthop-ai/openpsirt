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
}

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

func (f Faults) Error() string {
	reasons := make([]string, 0, len(f))
	for _, fault := range f {
		reasons = append(reasons, fault.Error())
	}
	return strings.Join(reasons, "; ")
}

// maxFaults bounds how many problems one refusal reports.
const maxFaults = 20

// ErrTooLong is returned for text past the bound.
var ErrTooLong = errors.New("that is longer than a justification may be")

// Check reports everything wrong with submitted text.
//
// Run before storage. Stored text is then known to have passed the policy that
// was in force when it arrived — which is not the same as being safe forever,
// which is why rendering sanitizes as well.
func Check(source string) error {
	if len(source) > MaxBytes {
		return Faults{{Reason: fmt.Sprintf("%s (%d bytes, limit %d)", ErrTooLong, len(source), MaxBytes)}}
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
	if len(found) > maxFaults {
		found = append(found[:maxFaults:maxFaults], Fault{
			Reason: fmt.Sprintf("and more besides — fix these %d first", maxFaults),
		})
	}
	return Faults(found)
}
