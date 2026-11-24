// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// The frozen v0.14.0 upgrade calls these rules, which sit outside every file a
// release record holds by digest, so their outputs are held here as v0.14.0
// gave them.
func TestTheFoldingRulesTheV0140UpgradeReadsStayAsTagged(t *testing.T) {
	for in, want := range map[string]string{
		"  OpenSSL \t": "openssl",
		strings.Repeat("Ü", database.NameWidth+1): strings.Repeat("ü", database.NameWidth),
	} {
		if got := foldedV0130(in); got != want {
			t.Errorf("foldedV0130(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"a\x00b\x1fc": "abc",
		"a\xffb":      "a\xffb",
		"é":           "é",
	} {
		if got := printableV0130(in); got != want {
			t.Errorf("printableV0130(%q) = %q, want %q", in, got, want)
		}
	}
}
