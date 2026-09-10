// Package publisher is who this deployment says it is when it publishes.
//
// One type, because there were two: a VEX document and an advisory both name
// their publisher, both read it from the same configuration, and each package
// declared its own struct with the same two fields and a byte-identical method
// asking whether they were set. The handler between them converted one to the
// other. Two records of one fact drift, and the drift here would be an
// advisory and a VEX document from the same deployment naming different
// organizations.
package publisher

// Named is who a published document says wrote it.
//
// Configured per deployment rather than tuned by an administrator: it is the
// identity of the organization running this, in the same way the address
// people arrive on is.
type Named struct {
	Name string
	// Namespace is the identifier a reader uses to tell our documents from
	// somebody else's, and it is the field that makes them citable.
	Namespace string
	// Category is what CSAF calls the kind of publisher. A deployment
	// publishing about its own product is a vendor, which is why that is the
	// default and why nothing here works it out from anything. VEX has no such
	// field and ignores it.
	Category string
}

// Stated reports whether enough is configured to name a publisher.
//
// A document with no publisher is not a document — the field is required in
// both formats — so an unconfigured deployment is told that rather than handed
// something that fails validation wherever it is taken next.
func (n Named) Stated() bool { return n.Name != "" && n.Namespace != "" }
