// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package setting

// Kind is the type of a setting's value.
//
// Named because the kinds are checked differently, and a value checked as the
// wrong kind is stored and then silently ignored.
type Kind string

const (
	// Duration is a length of time.
	Duration Kind = "duration"
	// Count is a count of things.
	Count Kind = "count"
	// Size is a count of bytes. Checked exactly as a count is — the write
	// path cannot tell them apart and does not need to — and named separately
	// because a screen must: 26214400 is twenty-five megabytes and nobody
	// reads it as that, so the mistake available in a raw byte field is a
	// factor of a thousand.
	Size Kind = "size"
	// Percent is a share of something the deployment holds rather than a
	// count of things. Checked as one to a hundred: a share above the whole
	// is a threshold nothing can reach, which is a setting somebody changed
	// and got nothing from.
	Percent Kind = "percent"
	// Word is one of a few words.
	Word Kind = "word"
	// Switch is on or off.
	Switch Kind = "switch"
)

// Kinds is every kind a setting's value can be.
func Kinds() []Kind { return []Kind{Duration, Count, Size, Percent, Word, Switch} }

// Section is the part of the settings a screen files a setting under.
type Section string

const (
	// Deadlines is how long a finding may stay open, by severity.
	Deadlines Section = "deadlines"
	// Own is how long a flaw in our own product may stay open.
	Own Section = "own"
	// Triage is how decisions are made and agreed.
	Triage Section = "triage"
	// Disclosure is how long an embargo runs.
	Disclosure Section = "disclosure"
	// Scanning is when builds are scanned and what counts as quiet or stale.
	Scanning Section = "scanning"
	// Signin is sign-in, personal tokens and accounts.
	Signin Section = "signin"
	// Limits is how much one request may do.
	Limits Section = "limits"
	// Outbound is what leaves the deployment.
	Outbound Section = "outbound"
)

// Sections is every section, in the order a screen shows them.
func Sections() []Section {
	return []Section{Deadlines, Own, Triage, Disclosure, Scanning, Signin, Limits, Outbound}
}
