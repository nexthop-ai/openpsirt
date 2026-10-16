// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// SettleStatistics brings the planner's statistics up to date with every table
// the schema declares, for a measurement taken after a bulk load.
//
// A server refreshes its statistics on its own once about a tenth of a table's
// rows have changed: PostgreSQL through autovacuum, MySQL and MariaDB through
// InnoDB's background statistics. A measurement queries seconds after loading,
// before either has run, and times a plan chosen from an empty table's
// estimates — minutes where the settled plan takes a second. This asks each
// engine what a start asks it.
//
// It then prints the layout of the finding table on a server, which is what
// the plans being timed were chosen over.
func SettleStatistics(t *testing.T, db *database.DB) {
	t.Helper()
	ctx := t.Context()
	started := time.Now()
	analyzed, err := database.AnalyzeEveryTable(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if db.Server.Engine != database.SQLite && analyzed == 0 {
		t.Fatal("no table was analyzed, so no statistics were refreshed")
	}
	t.Logf("statistics refreshed on %s over %d tables in %s", db.Server.Engine, analyzed,
		time.Since(started).Round(time.Millisecond))

	// The layout a plan was chosen over, printed beside the timings that
	// plan produced. Two runs reading different layouts are two different
	// measurements, and this is where that shows.
	l, err := readLayout(ctx, db, measured)
	if errors.Is(err, errNoLayout) {
		return
	}
	if err != nil {
		t.Fatalf("read the layout a measurement runs over: %v", err)
	}
	t.Logf("layout on %s of %s", db.Server.Engine, l)
}
