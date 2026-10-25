// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command clangcheckers names the clang static analyzer checkers that apply
// to C and that the weakness table has not looked at.
//
// clang publishes no weakness for its checkers, so the table is held in the
// repository and a new clang release can add a checker it does not know. Run
// against each new release; it fails naming every checker missing, and a
// checker the table holds that this clang lacks is not a failure, because a
// deployment runs more than one release.
//
//	make clang-checkers
package main

import (
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/weakness"
)

// notC are the checker packages for other languages and platforms, for the
// analyzer's own testing, and still in development, none of which a C build
// runs.
var notC = []string{
	"alpha.", "apiModeling.", "cplusplus.", "debug.", "fuchsia.", "nullability.",
	"optin.cplusplus.", "optin.osx.", "osx.", "webkit.",
}

// checkers is every checker a clang's checker list names that applies to C.
func checkers(help string) []string {
	var out []string
	listing := false
	for _, line := range strings.Split(help, "\n") {
		switch {
		case strings.HasPrefix(line, "CHECKERS:"):
			listing = true
			continue
		case !listing || !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   "):
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if slices.ContainsFunc(notC, func(p string) bool { return strings.HasPrefix(name, p) }) {
			continue
		}
		out = append(out, name)
	}
	return out
}

// missing is the checkers among those named that the table does not hold.
func missing(named, held []string) []string {
	var out []string
	for _, c := range named {
		if !slices.Contains(held, c) {
			out = append(out, c)
		}
	}
	return out
}

func main() {
	tool := os.Getenv("CLANG")
	if tool == "" {
		tool = "clang"
	}
	help, err := exec.Command(tool, "-cc1", "-analyzer-checker-help").Output() //nolint:gosec // G204: the clang the person running this named
	if err != nil {
		fmt.Fprintf(os.Stderr, "run %s -cc1 -analyzer-checker-help: %v\n", tool, err)
		os.Exit(1)
	}
	named := checkers(string(help))
	if len(named) == 0 {
		fmt.Fprintln(os.Stderr, "the checker list names no checker, so this checked nothing")
		os.Exit(1)
	}
	if gone := missing(named, weakness.ClangCheckers()); len(gone) > 0 {
		fmt.Fprintln(os.Stderr, "the weakness table has not looked at these checkers:")
		for _, c := range gone {
			fmt.Fprintln(os.Stderr, "  "+c)
		}
		os.Exit(1)
	}
	fmt.Printf("the weakness table has looked at every one of the %d checkers this clang runs on C\n", len(named))
}
