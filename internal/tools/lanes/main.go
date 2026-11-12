// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command lanes prints the packages whose test binaries reach a database, one
// per line: what the server pass of "make test-all" runs.
//
// The two passes differ in the engines they name and in the race detector. A
// test binary holding no SQL connects to no engine, so the server pass runs it
// exactly as the race pass does, without the detector, and adds nothing.
// Every package runs in the race pass; the packages printed here run in the
// server pass as well.
//
// A test binary reaches a database where its dependencies, its tests'
// included, hold database/sql: every driver and the database package rest on
// it, so a test opening a driver directly is found too. The list is read from
// "go list -test" over the packages named on the command line, so a package
// gaining a database is moved without anybody editing a list.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// sqlPackage is what every database driver and the database package import.
const sqlPackage = "database/sql"

// listed is one line per package "go list -test" reports: its import path, a
// tab, and its dependencies separated by spaces. A test binary's main package
// is the one whose path ends in ".test" and carries no variant suffix.
const listed = "{{.ImportPath}}\t{{join .Deps \" \"}}"

// goCommand is the go command make passes in GO, or go from the path where
// none is passed.
func goCommand() string {
	if command := os.Getenv("GO"); command != "" {
		return command
	}
	return "go"
}

func main() {
	packages := os.Args[1:]
	if len(packages) == 0 {
		fmt.Fprintln(os.Stderr, "lanes: no packages named, so there is nothing to divide")
		os.Exit(1)
	}
	var stderr bytes.Buffer
	cmd := exec.Command(goCommand(), append([]string{"list", "-test", "-f", listed}, packages...)...) //nolint:gosec // G204: the go command over this module's packages
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "lanes: go list: %v\n%s", err, stderr.Bytes())
		os.Exit(1)
	}
	picked, examined, err := servers(bytes.NewReader(out))
	if err != nil {
		fmt.Fprintln(os.Stderr, "lanes:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "lanes: %d of %d test binaries reach %s\n", len(picked), examined, sqlPackage)
	for _, p := range picked {
		fmt.Println(p)
	}
}

// servers is every package whose test binary reaches database/sql, sorted, and
// how many test binaries the listing held. A listing holding no test binary,
// or none reaching a database, is refused: either would leave the server pass
// running nothing while reporting green.
func servers(listing io.Reader) (picked []string, examined int, err error) {
	scan := bufio.NewScanner(listing)
	scan.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for scan.Scan() {
		path, deps, ok := strings.Cut(scan.Text(), "\t")
		if !ok {
			return nil, 0, fmt.Errorf("a line of the listing has no tab: %q", scan.Text())
		}
		pkg, isBinary := strings.CutSuffix(path, ".test")
		if !isBinary || strings.Contains(path, " ") {
			continue
		}
		examined++
		for _, dep := range strings.Fields(deps) {
			if dep == sqlPackage {
				picked = append(picked, pkg)
				break
			}
		}
	}
	if err := scan.Err(); err != nil {
		return nil, 0, err
	}
	if examined == 0 {
		return nil, 0, errors.New("the listing held no test binary, so this examined nothing")
	}
	if len(picked) == 0 {
		return nil, examined, fmt.Errorf("none of %d test binaries reaches %s, so the server pass would run nothing", examined, sqlPackage)
	}
	sort.Strings(picked)
	return picked, examined, nil
}
