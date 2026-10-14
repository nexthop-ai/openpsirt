// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/bound/boundtest"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// A name past the column's width is refused by the store, on every engine:
// PostgreSQL, MySQL and MariaDB would refuse the write as a fault, and SQLite
// would store it.
func TestATeamNamePastTheColumnIsRefusedByTheStore(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		refused := func(err error) bool { return refusal.In(err) }
		boundtest.Edges(t, database.NameWidth, func(n int) error {
			_, err := f.store.DeclareTeam(ctx, fmt.Sprint(n)+strings.Repeat("漢", n-len(fmt.Sprint(n))), "")
			return err
		}, refused)
		boundtest.Edges(t, database.NameWidth, func(n int) error {
			_, err := f.store.DeclareTeam(ctx, fmt.Sprintf("shown-%d", n), strings.Repeat("é", n))
			return err
		}, refused)
	})
}
