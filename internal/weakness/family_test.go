// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package weakness

import "testing"

func TestOneOverflowNumberedThreeWaysIsOneFamily(t *testing.T) {
	// One overflow, as three tools numbered it, and the reads either side
	// of a buffer that sit under the same class.
	for _, id := range []string{"CWE-788", "CWE-119", "CWE-121", "CWE-122", "CWE-126", "cwe-787", "CWE-125"} {
		if got := Family(id); got != "CWE-119" {
			t.Errorf("%s is in family %s; want CWE-119", id, got)
		}
	}
	if got := Family("CWE-89"); got == "CWE-119" {
		t.Errorf("an SQL injection is in the overflow's family")
	}
	if got := Family("CWE-999999"); got != "CWE-999999" {
		t.Errorf("a weakness the catalog does not place is in family %s; want itself", got)
	}
}

func TestMemorySafetyOutranksStyle(t *testing.T) {
	for id, want := range map[string]Tier{
		"CWE-787":  TierMemory,
		"CWE-416":  TierMemory,
		"CWE-415":  TierMemory,
		"CWE-476":  TierMemory,
		"CWE-89":   TierInjection,
		"CWE-78":   TierInjection,
		"CWE-401":  TierResource,
		"CWE-252":  TierResource,
		"CWE-563":  TierOther,
		"CWE-1164": TierOther,
		"":         TierOther,
	} {
		if got := TierOf(id); got != want {
			t.Errorf("%q is tier %d; want %d", id, got, want)
		}
	}
}

func TestEveryTierNamesAWeaknessTheCatalogHolds(t *testing.T) {
	if len(tiers) == 0 {
		t.Fatal("no tier names anything, so this checked nothing")
	}
	for id := range tiers {
		if _, ok := names[id]; !ok {
			t.Errorf("%s is named by a tier and not held by catalog %s", id, Version)
		}
	}
}

func TestTheHierarchyWasRead(t *testing.T) {
	if len(parents) < 500 || len(classes) < 100 {
		t.Fatalf("the catalog's hierarchy holds %d parents and %d classes, which is too few to be it",
			len(parents), len(classes))
	}
}
