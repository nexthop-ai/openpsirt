// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package signin_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/signin"
)

// An identity carrying a NUL is named as such, part by part, so a sign-in can
// refuse it rather than match a different identity with the character dropped.
func TestAnIdentityCarryingANULSaysWhere(t *testing.T) {
	plain := signin.Identity{Subject: "s", Provider: "p", Username: "u", DisplayName: "d",
		Email: "e@example.com", Groups: []string{"g"}}
	if part, carried := plain.NUL(); carried {
		t.Errorf("an identity with no NUL was said to carry one in its %s", part)
	}
	for want, change := range map[string]func(*signin.Identity){
		"subject":      func(i *signin.Identity) { i.Subject = "s\x00" },
		"provider":     func(i *signin.Identity) { i.Provider = "p\x00" },
		"username":     func(i *signin.Identity) { i.Username = "u\x00" },
		"display name": func(i *signin.Identity) { i.DisplayName = "d\x00" },
		"email":        func(i *signin.Identity) { i.Email = "e\x00@example.com" },
		"groups":       func(i *signin.Identity) { i.Groups = []string{"g", "h\x00"} },
	} {
		carrying := plain
		carrying.Groups = append([]string(nil), plain.Groups...)
		change(&carrying)
		if part, carried := carrying.NUL(); !carried || part != want {
			t.Errorf("a NUL in the %s was reported as %q, %v", want, part, carried)
		}
	}
}
