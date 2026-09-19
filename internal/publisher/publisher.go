// Package publisher is the identity this deployment publishes under.
//
// One type for both formats. A VEX document and an advisory name the same
// publisher from the same configuration, and two records of one fact drift —
// here into an advisory and a VEX document from one deployment naming
// different organizations.
package publisher

// Named is the publisher a published document names.
//
// Per deployment rather than tuned by an administrator. It is the identity of
// the organization running this, in the way the address people arrive on is.
type Named struct {
	Name string
	// Namespace is the identifier a reader tells our documents by, and the
	// field that makes them citable.
	Namespace string
	// Category is the kind of publisher, in CSAF's vocabulary. A deployment
	// publishing about its own product is a vendor, which is the default;
	// nothing here derives it. VEX has no such field and ignores it.
	Category string
}

// Stated reports whether enough is configured to name a publisher.
//
// Both formats require the field, so a document with no publisher is not a
// document. An unconfigured deployment is told so rather than handed something
// that fails validation wherever it is taken next.
func (n Named) Stated() bool { return n.Name != "" && n.Namespace != "" }
