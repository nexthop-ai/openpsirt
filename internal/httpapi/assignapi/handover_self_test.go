// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

func TestOnlyTheNameTheLookupFindsIsTheCallerThemselves(t *testing.T) {
	// "ſam" folds to "sam" under Unicode case folding and to itself under the
	// lookup's lowering. Read as the caller, it skips the assigner refusal and
	// reaches the lookup, which then answers whether "ſam" has an account.
	const product = 1
	sam := access.NewPerson(7, "sam", false,
		map[int64][]access.Role{product: {access.PublicTriage}}, 7)

	if err := mayHandOver(sam, product, "ſam", ""); err == nil {
		t.Error("a name the lookup does not fold to the caller was read as the caller")
	}
	if err := mayHandOver(sam, product, "  Sam ", ""); err != nil {
		t.Errorf("the caller naming themselves with capitals was refused: %v", err)
	}
}
