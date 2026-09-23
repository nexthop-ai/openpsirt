// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package weakness answers what a weakness identifier is called.
//
// A published advisory cannot state one without the other. CSAF carries a
// weakness as the identifier and the name that goes with it, and a consumer's
// validator checks the pair against the published catalog — so a name invented
// here is the one field in the document guaranteed to be caught. What is held
// about an issue is the identifier alone: a scanner reports "CWE-787" and which
// source said so, and a person recording a flaw types the same.
//
// So the names come from the authority that assigns them, read from the
// published catalog by "make weakness-names" and committed. The version they
// were read from is in the generated file.
//
// This is not the screen's list. The interface names a weakness in a few
// words a reader scans — "Buffer overflow" — and the catalog calls the same one
// "Improper Restriction of Operations within the Bounds of a Memory Buffer".
// Both are right for their reader and only one of them passes a validator, so
// they are two lists rather than one used twice.
package weakness

// Name is what the catalog calls this identifier, and whether it knows it.
//
// Not known is a real answer. The catalog carries categories and views
// alongside weaknesses, identifiers of the same shape that are not what a
// vulnerability is classified as; a scanner may report one, and a newer catalog
// assigns identifiers this one predates. A document leaves such a weakness out
// rather than naming it something, because the whole reason the name is read
// from the catalog is that it cannot be made up.
func Name(id string) (string, bool) {
	name, known := names[id]
	return name, known
}

// Known is how many the catalog assigned, for a check that this was read at all.
func Known() int { return len(names) }

// All is every weakness the catalog assigns, for a check that walks them.
//
// A copy, because a map handed out is a map a caller can write to — and what
// this package answers is what somebody else published.
func All() map[string]string {
	out := make(map[string]string, len(names))
	for id, name := range names {
		out[id] = name
	}
	return out
}
