package database

// The widths a column is declared at, where both the migration that declares
// one and the store that writes into it can read the same number.
//
// Written out in each place, a bound and the column it protects are two copies
// of one figure, and two copies of a figure are two figures eventually — which
// is how a composed name came to be written into a column sized for one name.

// NameWidth is how many characters a short identifier column holds: a product,
// an issue, a person, a component.
//
// 191 keeps a unique key inside the index limit on older MySQL servers using a
// four-byte character set, which is where the number comes from.
const NameWidth = 191

// ComposedWidth is how many characters a column holds that is written from
// several names at once.
//
// Three of them and their separators, which is the widest thing recorded: what
// an administrative change is about names a product, an issue and a person.
// Derived rather than typed, so that moving a name's width moves this with it.
const ComposedWidth = 3*NameWidth + 20
