// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command dbclean drops the test harness's databases on the configured
// servers that no running test binary holds.
//
// It is safe beside running tests: a database is dropped only while this holds
// the lock of the slot it belongs to, and a test binary holds that lock for as
// long as it uses the database.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

func main() {
	if err := dbtest.CleanServers(context.Background(), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
