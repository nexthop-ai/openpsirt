// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package upstream_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/upstream"
)

// An upstream is pinned to its host, so an address whose host is not the
// one it names is refused: a user in it, or a password the parser reads as
// a host and port.
func TestAnUpstreamAddressNamesItsHostAlone(t *testing.T) {
	for _, raw := range []string{
		"https://user@csaf.example.test/provider-metadata.json",
		"https://bot:1234/abc@csaf.example.test/provider-metadata.json",
	} {
		if _, err := upstream.Address(raw); !errors.Is(err, upstream.ErrUnusable) {
			t.Errorf("%s answered %v, want it refused", raw, err)
		}
	}
	if _, err := upstream.Address("https://csaf.example.test/.well-known/csaf/provider-metadata.json"); err != nil {
		t.Errorf("a plain address was refused: %v", err)
	}
}
