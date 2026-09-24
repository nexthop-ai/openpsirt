// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"io"
	"log/slog"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// MigrateTo applies the migrations up to and including a version, which is
// how a test builds the schema a release shipped.
//
// Through the runner a deployment uses, with its lock. A migration registered
// without the library's transaction opens connections of its own, and on
// SQLite, held to one connection, a runner that keeps one for itself waits on
// that migration for ever.
func MigrateTo(t *testing.T, db *database.DB, version int64) {
	t.Helper()
	if err := migrate.UpTo(t.Context(), db, slog.New(slog.NewTextHandler(io.Discard, nil)),
		version); err != nil {
		t.Fatalf("apply the migrations up to %d: %v", version, err)
	}
}
