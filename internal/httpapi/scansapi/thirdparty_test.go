// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi

import "testing"

// A declared third-party path is recorded as a path from the top of the
// checkout, the form a lead's path is compared in, however it was typed.
func TestADeclaredThirdPartyPathIsRecordedFromTheTopOfTheCheckout(t *testing.T) {
	stated, err := statedBeside(&analysisParts{ThirdParty: []string{
		"./src/vendor/zlib", "src//vendor/zlib/", " lib/ ", "../outside", "/", ".",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `["lib","outside","src/vendor/zlib"]`; stated.Params.ThirdParty != want {
		t.Errorf("the run declares %s; want %s", stated.Params.ThirdParty, want)
	}
}
