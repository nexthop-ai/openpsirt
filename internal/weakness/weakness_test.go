// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package weakness_test

import (
	"regexp"
	"strings"
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

func TestEveryWeaknessAScreenNamesIsOneTheCatalogNamesToo(t *testing.T) {
	// The screen's name is drawn with the catalog's on hover, and a short
	// name for an identifier the catalog does not assign is a name that was
	// made up.
	offered := weakness.Find("", 1000)
	if len(offered) == 0 {
		t.Fatal("the common list is empty, so this checked nothing")
	}
	for _, one := range offered {
		if one.Short == "" {
			t.Errorf("%s is offered before anything is typed and has no short name", one.ID)
		}
		if one.Name == "" {
			t.Errorf("%s has a short name %q and no name in the catalog", one.ID, one.Short)
		}
	}
}

func TestNothingTypedOffersTheCommonOnesMostCommonFirst(t *testing.T) {
	got := weakness.Find("  ", 3)
	if len(got) != 3 {
		t.Fatalf("offered %d, want the three asked for", len(got))
	}
	for i, want := range []string{"CWE-401", "CWE-362", "CWE-667"} {
		if got[i].ID != want {
			t.Errorf("offered %s at %d, want %s", got[i].ID, i, want)
		}
	}
}

func TestANumberFindsItselfFirstAndThenWhatBeginsWithIt(t *testing.T) {
	for _, typed := range []string{"79", "cwe-79", "CWE79"} {
		got := weakness.Find(typed, 50)
		if len(got) < 2 {
			t.Fatalf("%q found %d, want CWE-79 and the numbers beginning with it", typed, len(got))
		}
		if got[0].ID != "CWE-79" {
			t.Errorf("%q found %s first, want the one typed", typed, got[0].ID)
		}
		for _, one := range got {
			if !strings.HasPrefix(one.ID, "CWE-79") {
				t.Errorf("%q found %s, which does not begin with it", typed, one.ID)
			}
		}
	}
	// A common one ranks ahead of a rarer one that sorts before it by number.
	got := weakness.Find("79", 50)
	if len(got) < 2 || got[1].ID != "CWE-798" {
		t.Errorf("after CWE-79 came %+v, want the common CWE-798 before the rest", got)
	}
}

func TestWordsAreFoundInEitherList(t *testing.T) {
	for _, c := range []struct{ typed, want string }{
		// The screen's name, which the catalog does not use.
		{"buffer overflow", "CWE-119"},
		// The catalog's name, which the screen does not use.
		{"bounds of a MEMORY buffer", "CWE-119"},
		// A word only the screen's name holds and one only the catalog's does.
		{"overflow bounds", "CWE-119"},
	} {
		found := false
		for _, one := range weakness.Find(c.typed, 1000) {
			found = found || one.ID == c.want
		}
		if !found {
			t.Errorf("%q did not find %s", c.typed, c.want)
		}
	}
	if got := weakness.Find("nothing names this at all", 10); len(got) != 0 {
		t.Errorf("words no name holds found %+v", got)
	}
}

func TestASearchStopsAtWhatWasAskedFor(t *testing.T) {
	if got := weakness.Find("improper", 5); len(got) != 5 {
		t.Errorf("found %d, want the five asked for", len(got))
	}
}

func TestAnIdentifierIsNamedAsRecorded(t *testing.T) {
	one := weakness.Of(" cwe-787 ")
	if one.ID != "CWE-787" || one.Name != "Out-of-bounds Write" || one.Short != "Out-of-bounds write" {
		t.Errorf("named %+v", one)
	}
	// A weakness outside the common ones has the catalog's name alone, and one
	// neither list holds has none.
	if rare := weakness.Of("CWE-1321"); rare.Name == "" || rare.Short != "" {
		t.Errorf("a rare weakness is named %+v", rare)
	}
	if other := weakness.Of("NVD-CWE-Other"); other.Name != "" || other.Short != "" {
		t.Errorf("a feed's word for no classification is named %+v", other)
	}
}
