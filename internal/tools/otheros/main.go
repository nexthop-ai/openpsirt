// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command otheros prints the packages whose compiled files on one operating
// system differ from those on Linux, one per line: what "make vet-other-os"
// type-checks for that system.
//
// Every runner and every other target builds for Linux, so a file a build
// constraint keeps off Linux is compiled by nothing else. A package compiling
// the same files on both systems type-checks the same on both, so vetting it
// again for the other system finds nothing Linux did not.
//
// The packages and their files are read from "go list" under each system, so a
// file gaining a constraint is covered without anybody editing a list, and a
// package whose every file is kept off Linux, which a listing for Linux omits,
// is found in the other system's. A package under node_modules is an npm
// dependency's, never this module's, and is skipped. A name declared in a
// file one system compiles and the other does not reaches the package's
// importers, which are not vetted here, so such a file declaring an exported
// name is refused.
//
//	otheros darwin ./...
package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// listed is one line per package: its import path, its directory, and every
// file vet reads in it, test files included, each field after the first
// separated by a tab.
const listed = "{{.ImportPath}}\t{{.Dir}}\t{{join .GoFiles \" \"}} {{join .CgoFiles \" \"}} {{join .TestGoFiles \" \"}} {{join .XTestGoFiles \" \"}}"

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "otheros: name a GOOS and the packages to compare: otheros darwin ./...")
		os.Exit(1)
	}
	system, packages := os.Args[1], os.Args[2:]
	linux, err := list("linux", packages)
	if err != nil {
		fmt.Fprintln(os.Stderr, "otheros:", err)
		os.Exit(1)
	}
	other, err := list(system, packages)
	if err != nil {
		fmt.Fprintln(os.Stderr, "otheros:", err)
		os.Exit(1)
	}
	picked, examined, err := differing(bytes.NewReader(linux), bytes.NewReader(other), exportedNames)
	if err != nil {
		fmt.Fprintf(os.Stderr, "otheros: %s: %v\n", system, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "otheros: %d of %d packages compile other files on %s than on linux\n", len(picked), examined, system)
	for _, p := range picked {
		fmt.Println(p)
	}
}

// list is "go list" of the packages for one operating system.
func list(system string, packages []string) ([]byte, error) {
	goCommand := os.Getenv("GO")
	if goCommand == "" {
		goCommand = "go"
	}
	var stderr bytes.Buffer
	cmd := exec.Command(goCommand, append([]string{"list", "-e", "-f", listed}, packages...)...) //nolint:gosec // G204: the go command over this module's packages
	cmd.Env = append(os.Environ(), "GOOS="+system)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("GOOS=%s go list: %v\n%s", system, err, stderr.Bytes())
	}
	return out, nil
}

// pkg is one package's line of a listing.
type pkg struct {
	dir   string
	files map[string]bool
}

func parse(listing io.Reader) (map[string]pkg, error) {
	packages := map[string]pkg{}
	scan := bufio.NewScanner(listing)
	scan.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for scan.Scan() {
		fields := strings.SplitN(scan.Text(), "\t", 3)
		if len(fields) != 3 {
			return nil, fmt.Errorf("a line of the listing has %d fields, want 3: %q", len(fields), scan.Text())
		}
		if strings.Contains(fields[0], "/node_modules/") {
			continue
		}
		files := map[string]bool{}
		for _, f := range strings.Fields(fields[2]) {
			files[f] = true
		}
		packages[fields[0]] = pkg{dir: fields[1], files: files}
	}
	return packages, scan.Err()
}

// differing is every package whose files on the other system differ from its
// files on Linux, sorted, and how many packages the other system's listing
// held. A listing holding no package, or no package differing, is refused:
// either leaves the vet checking nothing while reporting green. A file other
// than a test in one list and not the other declaring an exported name, as
// exported reports it, is refused too.
func differing(linux, other io.Reader, exported func(path string) ([]string, error)) (picked []string, examined int, err error) {
	on, err := parse(linux)
	if err != nil {
		return nil, 0, fmt.Errorf("the linux listing: %w", err)
	}
	off, err := parse(other)
	if err != nil {
		return nil, 0, fmt.Errorf("the other listing: %w", err)
	}
	if len(off) == 0 {
		return nil, 0, errors.New("the listing held no package, so this examined nothing")
	}
	var problems []string
	for path, there := range off {
		here := on[path]
		var apart []string
		for f := range there.files {
			if !here.files[f] {
				apart = append(apart, filepath.Join(there.dir, f))
			}
		}
		for f := range here.files {
			if !there.files[f] {
				apart = append(apart, filepath.Join(here.dir, f))
			}
		}
		if len(apart) == 0 {
			continue
		}
		picked = append(picked, path)
		sort.Strings(apart)
		for _, file := range apart {
			// A test file's names reach no importer.
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			names, err := exported(file)
			if err != nil {
				return nil, 0, err
			}
			if len(names) > 0 {
				problems = append(problems, fmt.Sprintf(
					"%s is compiled on one system and not the other and declares %s, which reaches importers no vet compiles for both",
					file, strings.Join(names, ", ")))
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, len(off), errors.New(strings.Join(problems, "\n"))
	}
	if len(picked) == 0 {
		return nil, len(off), fmt.Errorf("none of %d packages compiles other files than on linux, so this vet checks nothing; drop the system from vet-other-os", len(off))
	}
	sort.Strings(picked)
	return picked, len(off), nil
}

// exportedNames is every exported top-level name a Go file declares, methods
// included.
func exportedNames(path string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Name.IsExported() {
				names = append(names, d.Name.Name)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.IsExported() {
						names = append(names, s.Name.Name)
					}
				case *ast.ValueSpec:
					for _, n := range s.Names {
						if n.IsExported() {
							names = append(names, n.Name)
						}
					}
				}
			}
		}
	}
	return names, nil
}
