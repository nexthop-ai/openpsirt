// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command engines prints the database engines the application supports, one
// per line, so that the makefile's checks read the enumeration rather than
// repeating it.
//
// With "partial" it prints the engines that commit around every
// data-definition statement, which is where a half-applied migration is run
// again.
package main

import (
	"fmt"
	"os"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// listed is the engines one argument asks for.
func listed(which string) ([]database.Engine, error) {
	var keep func(database.Engine) bool
	switch which {
	case "":
		keep = func(database.Engine) bool { return true }
	case "partial":
		keep = database.Engine.CommitsDataDefinition
	default:
		return nil, fmt.Errorf("engines: %q is not a list this prints; ask for partial or nothing", which)
	}
	var out []database.Engine
	for _, engine := range database.Engines() {
		if keep(engine) {
			out = append(out, engine)
		}
	}
	return out, nil
}

func main() {
	which := ""
	if len(os.Args) > 1 {
		which = os.Args[1]
	}
	engines, err := listed(which)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for _, engine := range engines {
		fmt.Println(engine)
	}
}
