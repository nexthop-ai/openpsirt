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
	// Prefix is what a minted advisory identifier opens with, and it is the
	// half of that identifier a reader recognizes the publisher by.
	//
	// Stated rather than derived from the name. A prefix worked out from
	// "Example, Inc." is a string nobody publishes under, and an identifier
	// is the one thing in a document that has to match what the organization
	// already calls its advisories.
	Prefix string
	// Published is where a document this deployment publishes is reachable:
	// the directory an operator serves, ending in a slash.
	//
	// Checked and given its slash where the setting is read, so that
	// everything below here joins a name to it and nothing parses it a second
	// time. A document states its own address and the directory states every
	// file's, and two spellings of one join are two answers to "where is this
	// document" the first time either moves.
	Published string
}

// Stated reports whether enough is configured to name a publisher.
//
// Both formats require the field, so a document with no publisher is not a
// document. An unconfigured deployment is told so rather than handed something
// that fails validation wherever it is taken next.
func (n Named) Stated() bool { return n.Name != "" && n.Namespace != "" }

// Publishes reports whether this deployment knows where its documents are
// reachable.
//
// A document states its own address only where there is one. An address that
// answers nothing is worse than none, because a reader's tooling follows it.
func (n Named) Publishes() bool { return n.Published != "" }

// At is where a file in the published directory is reachable.
//
// The one place a name is joined to the address, for the reason the field
// above gives.
func (n Named) At(path string) string { return n.Published + path }

// Mints reports whether enough is configured to mint an advisory identifier.
//
// Separate from Stated because the two are asked at different moments: a
// document needs a publisher when it is generated, and an identifier is minted
// once, earlier, when somebody starts writing the advisory.
func (n Named) Mints() bool { return n.Prefix != "" }
