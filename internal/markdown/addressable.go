package markdown

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
// **The same judgment, not a second one shaped like it.** This stopped at the
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
