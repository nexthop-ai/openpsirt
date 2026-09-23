// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command engines prints the database engines the application supports, one
// per line, so that the makefile's checks read the enumeration rather than
// repeating it.
//
// The engine list was written out by hand in three places in the makefile.
// A fifth engine added to the application would not have been grepped for by
// any of them, and a check that looks for nothing reports the same "OK" as one
// that looked and found nothing wrong.
//
// With "servers" it prints the production engines alone, which is what the
// migration lock is exercised on: SQLite is one process and one file, so there
// is no second connection to exclude.
package main

import (
	"fmt"
	"os"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

func main() {
	servers := len(os.Args) > 1 && os.Args[1] == "servers"
	for _, engine := range database.Engines() {
		if servers && !engine.IsProduction() {
			continue
		}
		fmt.Println(engine)
	}
}
