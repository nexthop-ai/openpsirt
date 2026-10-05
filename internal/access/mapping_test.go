// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

func TestTheGroupRolesVariableReadsAsTheMappingsItStates(t *testing.T) {
	got, err := access.ParseGroupRoles(" psirt-leads=admin ; security-team=private-triage+approver; " +
		"kernel=public-triage@Router-OS, switch-os;; everyone=public-read")
	if err != nil {
		t.Fatal(err)
	}
	want := []access.Mapping{
		{Group: "everyone", Grants: "public-read"},
		{Group: "kernel", Grants: "public-triage", Product: "router-os"},
		{Group: "kernel", Grants: "public-triage", Product: "switch-os"},
		{Group: "psirt-leads", Grants: "admin"},
		{Group: "security-team", Grants: "approver"},
		{Group: "security-team", Grants: "private-triage"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("read\n%+v\nwant\n%+v", got, want)
	}
}

func TestAnEmptyGroupRolesVariableMapsNothing(t *testing.T) {
	for _, raw := range []string{"", " ", ";", " ; ; "} {
		got, err := access.ParseGroupRoles(raw)
		if err != nil || len(got) != 0 {
			t.Errorf("%q read as %+v, %v", raw, got, err)
		}
	}
}

func TestAMappingStatedTwiceIsHeldOnce(t *testing.T) {
	got, err := access.ParseGroupRoles("a=public-read; a=public-read+public-read")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("read %+v, want one mapping", got)
	}
}

// Names holding a separator are written percent-encoded, and the spelling a
// file is turned into reads back as the entries it came from.
func TestANameHoldingASeparatorSurvivesBeingSpelledAndRead(t *testing.T) {
	entries := []access.GroupRoles{
		{Group: "sec@example.com", Roles: []string{"audit"}},
		{Group: "cn=x;100%+", Roles: []string{"public-read"}, Products: []string{"a,b@c"}},
	}
	spelled := access.SpellGroupRoles(entries)
	if want := "sec%40example.com=audit; cn%3Dx%3B100%25%2B=public-read@a%2Cb%40c"; spelled != want {
		t.Errorf("spelled %q, want %q", spelled, want)
	}
	got, err := access.ParseGroupRoles(spelled)
	if err != nil {
		t.Fatal(err)
	}
	want := []access.Mapping{
		{Group: "cn=x;100%+", Grants: "public-read", Product: "a,b@c"},
		{Group: "sec@example.com", Grants: "audit"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("read %+v, want %+v", got, want)
	}
}

func TestAGroupRolesEntryThatCannotBeReadIsRefused(t *testing.T) {
	for raw, says := range map[string]string{
		"platform":                                  "names no role",
		"=public-read":                              "names no group",
		"platform=":                                 "is given no role",
		"platform=owner":                            "is not a role",
		"platform=admin@sonic":                      "held over the whole deployment",
		"platform=public-read@":                     "names an empty product",
		"platform=public-read@a,,b":                 "names an empty product",
		"plat%zzform=public-read":                   "does not begin an encoding",
		"platform=public-read@a%2":                  "does not begin an encoding",
		strings.Repeat("g", 192) + "=public-read":   "longer than",
		"g=public-read@" + strings.Repeat("p", 192): "longer than",
		"ok=public-read; bad":                       "entry 2",
	} {
		_, err := access.ParseGroupRoles(raw)
		if err == nil || !strings.Contains(err.Error(), says) {
			t.Errorf("%.40q answered %v, want a refusal saying %q", raw, err, says)
		}
	}
}

func TestAMappingNamesItselfByWhereItIsHeld(t *testing.T) {
	for mapping, want := range map[access.Mapping]string{
		{Group: "g", Grants: "public-read", Product: "sonic"}: "g on sonic",
		{Group: "g", Grants: "public-read"}:                   "g on every product",
		{Group: "g", Grants: "admin"}:                         "g over this deployment",
	} {
		if got := mapping.String(); got != want {
			t.Errorf("%+v named itself %q, want %q", mapping, got, want)
		}
	}
}
