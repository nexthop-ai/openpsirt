// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package markdown

import "strings"

// Addressable refuses an address a person should not be handed as a link.
//
// The same rule links inside text go through, applied to an address stored on
// its own — where the work on a claim is happening, which is typed by whoever
// holds triage and rendered to whoever approves. An empty one is allowed and
// means there is nowhere to point.
//
// It is not about scripts. A browser refuses `javascript:` in a link and the
// page's own policy refuses it again; what neither refuses is a custom
// application scheme — `ms-msdt:`, `search-ms:`, an installed handler nobody
// here has heard of — which hands a privileged person's click to a program on
// their machine. That is the class this restriction exists for everywhere else
// in this system, and an address stored beside a claim is no different for
// being stored rather than written in a sentence.
//
// The same judgment, not a second one shaped like it. This stopped at the
// scheme, so `attachment:../../etc/passwd` and a bare `issue:` were stored on
// their own and refused inside a link — the two halves of one rule disagreeing,
// which is the divergence attachmentFault was written to close and this
// reintroduced on the field an approver reads.
func Addressable(address string) error {
	if address == "" {
		return nil
	}
	// Line zero, because there is no text to be on a line of. Fault.Error
	// leaves the position out for that, so the message reads as a sentence
	// about the address rather than about line 0 of nothing.
	if fault, bad := destinationFault(0, address); bad {
		return fault
	}
	return nil
}

// Autolinkable is Addressable for an address written *into* a document rather
// than parsed out of one.
//
// A destination inside angle brackets ends at the first space or bracket,
// so an address carrying either is not a link: it is the rest of the line
// becoming content, and the lines after it becoming document. A scan file is
// hostile input (REQ-66 and REQ-69) and a feed's address reaches a release
// note and an issue document, both of which leave the building — so one
// carrying a newline writes attacker-chosen markdown into something somebody
// publishes.
//
// Addressable answers the other half, which is what a reader's machine would
// do if they followed it.
func Autolinkable(address string) error {
	if strings.ContainsAny(address, " \t\r\n<>") {
		return Fault{
			Offending: address,
			Reason: "an address written into a document carries no spaces or angle " +
				"brackets: inside <> it would end at the first of them and the rest " +
				"of the line would become content",
		}
	}
	return Addressable(address)
}
