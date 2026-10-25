// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package build_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/nexthop-ai/openpsirt/"

// imported is every directory of this module that the packages in dirs reach
// through their imports, their tests' included, as make names a directory.
// read returns a directory's Go files by name.
func imported(dirs []string, read func(dir string) map[string]string) (map[string]bool, error) {
	seen := map[string]bool{}
	pending := append([]string(nil), dirs...)
	for len(pending) > 0 {
		dir := pending[0]
		pending = pending[1:]
		if seen[dir] {
			continue
		}
		seen[dir] = true
		for name, text := range read(dir) {
			file, err := parser.ParseFile(token.NewFileSet(), name, text, parser.ImportsOnly)
			if err != nil {
				return nil, err
			}
			for _, spec := range file.Imports {
				path, _ := strconv.Unquote(spec.Path.Value)
				if strings.HasPrefix(path, module) {
					pending = append(pending, "./"+strings.TrimPrefix(path, module)+"/")
				}
			}
		}
	}
	return seen, nil
}

// uncovered is every directory in reached that no entry of sources holds.
func uncovered(reached map[string]bool, sources []string) []string {
	var out []string
	for dir := range reached {
		held := false
		for _, s := range sources {
			if strings.HasSuffix(s, "/") && strings.HasPrefix(dir, s) {
				held = true
				break
			}
		}
		if !held {
			out = append(out, dir)
		}
	}
	sort.Strings(out)
	return out
}

func goFiles(t *testing.T) func(string) map[string]string {
	return func(dir string) map[string]string {
		full := filepath.Join("..", "..", filepath.FromSlash(dir))
		entries, err := os.ReadDir(full)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") {
				body, err := os.ReadFile(filepath.Join(full, e.Name())) //nolint:gosec // this repository's own source
				if err != nil {
					t.Fatal(err)
				}
				out[e.Name()] = string(body)
			}
		}
		return out
	}
}

// makeList is a list the makefile assigns, with any list it names expanded.
func makeList(t *testing.T, name string) []string {
	t.Helper()
	got := regexp.MustCompile(`(?m)^` + name + `\s*:=(.*)$`).FindStringSubmatch(makefileText(t))
	if got == nil {
		t.Fatalf("the makefile declares no %s", name)
	}
	var out []string
	for _, word := range strings.Fields(got[1]) {
		if inner, ok := strings.CutPrefix(word, "$("); ok {
			out = append(out, makeList(t, strings.TrimSuffix(inner, ")"))...)
			continue
		}
		out = append(out, word)
	}
	return out
}

// The macOS and Windows runners start when one of the client's sources moved,
// and the list of those sources holds every package of ours the client
// imports. A package missing from it is a change to the client those runners
// never see.
func TestTheClientSourcesHoldEveryPackageTheClientImports(t *testing.T) {
	packages := makeList(t, "CLIENT_PACKAGES")
	if len(packages) == 0 {
		t.Fatal("CLIENT_PACKAGES is empty, so this checked nothing")
	}
	reached, err := imported(packages, goFiles(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(reached) <= len(packages) {
		t.Fatal("the client imports no package of ours, so this checked nothing")
	}
	for _, dir := range uncovered(reached, makeList(t, "CLIENT_SOURCES")) {
		t.Errorf("the client imports %s and CLIENT_SOURCES does not hold it", dir)
	}
}

// An import the list does not hold is reported, through a test file as well,
// and one it holds is not.
func TestAnImportTheClientSourcesMissIsReported(t *testing.T) {
	files := map[string]map[string]string{
		"./cmd/c/":        {"main.go": `package main; import _ "github.com/nexthop-ai/openpsirt/internal/a"`},
		"./internal/a/":   {"a.go": "package a", "a_test.go": `package a; import _ "github.com/nexthop-ai/openpsirt/internal/b"`},
		"./internal/b/":   {"b.go": `package b; import _ "strings"`},
		"./internal/off/": {"off.go": "package off"},
	}
	reached, err := imported([]string{"./cmd/c/"}, func(dir string) map[string]string { return files[dir] })
	if err != nil {
		t.Fatal(err)
	}
	got := uncovered(reached, []string{"./cmd/c/", "./internal/a/", "go.mod"})
	if strings.Join(got, " ") != "./internal/b/" {
		t.Errorf("uncovered %v; want only ./internal/b/", got)
	}
}
