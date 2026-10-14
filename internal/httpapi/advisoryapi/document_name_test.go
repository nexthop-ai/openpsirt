// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi

import (
	"strings"
	"testing"
)

// The client's file name is stored on every statement a document makes, so it
// is bounded and made safe before any of them is written.
func TestADocumentsFileNameIsBoundedBeforeItIsStored(t *testing.T) {
	for _, each := range []struct{ typed, want string }{
		{"", ""},
		{"  ", ""},
		{"../../etc/acme-vex.json", "acme-vex.json"},
		{"acme\r\nvex.json", "acmevex.json"},
	} {
		if got := documentName(each.typed); got != each.want {
			t.Errorf("documentName(%q) = %q, want %q", each.typed, got, each.want)
		}
	}
	if got := documentName(strings.Repeat("a", 100_000) + ".json"); len(got) > 191 {
		t.Errorf("a long file name was kept as %d bytes", len(got))
	}
}
