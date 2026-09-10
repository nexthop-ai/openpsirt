package markdown

import "fmt"

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
func Addressable(address string) error {
	if address == "" {
		return nil
	}
	scheme, ok := schemeOf(address)
	if ok {
		return nil
	}
	return fmt.Errorf(
		"a link may use http, https, mailto, attachment or issue, and this uses %q",
		scheme)
}
