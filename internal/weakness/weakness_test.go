// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package weakness_test

import (
	"regexp"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/weakness"
)

// identifier is the shape the standard states a weakness under.
var identifier = regexp.MustCompile(`^CWE-[1-9][0-9]{0,5}$`)

func TestTheCatalogWasReadAndEveryNameItGaveIsUsable(t *testing.T) {
	// A generated file nothing looks at is a file that can be empty, or half
	// written, or a fetch that answered with an error page — and the first
	// anybody would hear of it is a document failing validation at a customer.
	if got := weakness.Known(); got < 500 {
		t.Fatalf("the catalog holds %d weaknesses, which is too few to have been read", got)
	}
	if weakness.Version == "" || weakness.Published == "" {
		t.Errorf("the names do not say which catalog they came from: %q of %q",
			weakness.Version, weakness.Published)
	}
}

func TestEveryNameIsStatedUnderAnIdentifierTheStandardAccepts(t *testing.T) {
	// The identifier goes into a field with a stated pattern. One that does
	// not match is a document refused whole, over a weakness nobody was
	// looking at.
	checked := 0
	for id, name := range weakness.All() {
		checked++
		if !identifier.MatchString(id) {
			t.Errorf("%q is not an identifier the standard accepts", id)
		}
		if name == "" {
			t.Errorf("%s has no name, which is the half that cannot be invented", id)
		}
	}
	if checked == 0 {
		t.Fatal("no names were found in the catalog, so this checked nothing")
	}
}

func TestTheNamesAreTheCatalogsRatherThanTheOnesAScreenUses(t *testing.T) {
	// The interface names this one "Buffer overflow", which is right for
	// somebody scanning a list and is not what a validator compares against.
	// Two lists rather than one used twice, and this is the test that says so.
	for _, one := range []struct{ id, want string }{
		{"CWE-119", "Improper Restriction of Operations within the Bounds of a Memory Buffer"},
		{"CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"},
		{"CWE-787", "Out-of-bounds Write"},
	} {
		got, known := weakness.Name(one.id)
		if !known {
			t.Errorf("%s is not in the catalog", one.id)
			continue
		}
		if got != one.want {
			t.Errorf("%s is named %q, want the catalog's %q", one.id, got, one.want)
		}
	}
}

func TestAnIdentifierTheCatalogDoesNotAssignIsNotNamed(t *testing.T) {
	// Categories and views carry identifiers of this shape and are not what a
	// vulnerability is classified as, and a newer catalog assigns numbers this
	// one predates. Both have to come back as not known, because the whole
	// reason the name is read from the catalog is that it cannot be made up.
	//
	// CWE-699 is a view — "Software Development" — and is in the published
	// file this was read from, under a part of it this does not carry.
	for _, id := range []string{"CWE-699", "CWE-999999", "", "CWE-oops"} {
		if name, known := weakness.Name(id); known {
			t.Errorf("%q came back named %q, and it is not a weakness", id, name)
		}
	}
}
