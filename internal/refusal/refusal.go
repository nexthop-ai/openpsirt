// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package refusal marks a sentence written for whoever asked.
//
// A store returns two kinds of error through one return: a sentence written
// for a person, naming what they asked for and why it cannot be done, and a
// fault — a query that failed, an object store that did not answer — whose
// text carries statement text, addresses and credentials. Only the first is
// published. An error is published when its chain holds a refusal, and is
// answered as a fault in fixed words otherwise, so a fault nobody classified
// is withheld rather than passed on.
//
// A refusal wraps what its format wraps, so a sentinel matched by identity is
// still matched through one, and a refusal wrapped in a caller's context is
// still a refusal.
package refusal

import (
	"errors"
	"fmt"
)

// Refusal is a sentence a caller may read.
type Refusal struct{ err error }

// Error is the sentence.
func (r Refusal) Error() string { return r.err.Error() }

// Unwrap is the sentence as fmt built it, which unwraps to whatever its
// format wrapped.
func (r Refusal) Unwrap() error { return r.err }

// New is a refusal saying text.
func New(text string) error { return Refusal{err: errors.New(text)} }

// Errorf is a refusal formatted the way fmt.Errorf formats, wrapping what %w
// names.
func Errorf(format string, a ...any) error {
	return Refusal{err: fmt.Errorf(format, a...)}
}

// Sentence is a type every value of which is a sentence for the caller: a
// fault in a piece of writing, a name that reaches more than one thing. It
// carries fields a caller reads, so it is a type of its own rather than a
// refusal built with New, and it says so with this method.
type Sentence interface {
	error
	Refused()
}

// In reports whether err's chain holds a refusal or a sentence, and so whether
// its text may be published.
func In(err error) bool {
	var r Refusal
	var s Sentence
	return errors.As(err, &r) || errors.As(err, &s)
}
