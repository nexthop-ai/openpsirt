// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Every setting this reads is documented, and everything documented is read.
//
// A setting nobody wrote down is one an operator finds by reading the
// source, which for a deployment they run in production is not an answer.
// The other direction is worse: a documented setting that nothing reads is a
// line somebody follows, sets, restarts for, and gets no change from — and
// there is nothing in the running system to tell them so.
//
// It is the same shape as the checks that hold the design tokens and the API
// reference to the code.
//
// The source is read rather than the package being asked, because the names
// are literals at their call sites: that is what makes them greppable, and a
// list built beside them to satisfy a test is a second list to keep right.

// goSources is every Go file below root that is not a test, skipping the
// directories named. A walk rather than a list, because a list is what a new
// file is left out of; each caller requires the files it knows must be there,
// so a walk that stopped matching fails rather than reading less.
func goSources(t *testing.T, root string, skip ...string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if slices.Contains(skip, filepath.ToSlash(path)) || d.Name() == "testdata" ||
				(strings.HasPrefix(d.Name(), ".") && d.Name() != "." && d.Name() != "..") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			found = append(found, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// requireAmong fails when a file known to be there was not found, which is
// how a walk that silently narrowed shows itself.
func requireAmong(t *testing.T, found []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !slices.Contains(found, w) {
			t.Fatalf("%s was not among the files read, so this checked less than it says", w)
		}
	}
}

// loaderReads is every setting the loader reads, by environment name after
// the prefix: the literal at each call of the reader in this package.
func loaderReads(t *testing.T) map[string]bool {
	t.Helper()
	sources := goSources(t, ".")
	requireAmong(t, sources, "config.go")
	read := regexp.MustCompile(`r\.(?:text|duration|number|boolean)\("([A-Z0-9_]+)"`)
	reads := map[string]bool{}
	for _, path := range sources {
		source, err := os.ReadFile(path) //nolint:gosec // G304: a Go file of this repository, found by the walk above
		if err != nil {
			t.Fatal(err)
		}
		for _, found := range read.FindAllStringSubmatch(string(source), -1) {
			reads[found[1]] = true
		}
	}
	if len(reads) == 0 {
		t.Fatal("no settings were found in the source, so this checked nothing")
	}
	return reads
}

// The table is what the loader reads, in both directions.
//
// A name the loader asks for that the table lacks is read from neither source,
// so a deployment setting it gets nothing. A row the loader never asks for is
// a key a file accepts and nothing reads. And every row has one name in each
// source, neither shared with another row.
func TestTheSettingsTableIsWhatTheLoaderReads(t *testing.T) {
	reads := loaderReads(t)
	if len(settings) == 0 {
		t.Fatal("the table of settings is empty, so this checked nothing")
	}
	envs, files := map[string]bool{}, map[string]bool{}
	for _, one := range settings {
		if envs[one.env] {
			t.Errorf("%s%s is in the table twice", envPrefix, one.env)
		}
		if files[one.file] {
			t.Errorf("%s is in the table twice", one.file)
		}
		envs[one.env], files[one.file] = true, true
		if one.file == "" || strings.Count(one.file, ".") < 1 {
			t.Errorf("%s%s has no key under a table in a file: %q", envPrefix, one.env, one.file)
		}
		if !reads[one.env] {
			t.Errorf("%s%s (%s) is in the table and the loader never reads it", envPrefix, one.env, one.file)
		}
	}
	for name := range reads {
		if !envs[name] {
			t.Errorf("the loader reads %s%s and the table has no row for it, so neither source can set it",
				envPrefix, name)
		}
	}
	// A key is either a setting or a table of them, never both, or a file
	// could not write it.
	for _, one := range settings {
		if section(one.file) {
			t.Errorf("%s is a setting and also a table holding others", one.file)
		}
	}
}

func TestEverySettingIsWrittenDown(t *testing.T) {
	// Where a setting is read: every file in this package.
	reads := loaderReads(t)
	// Where one is named in a message, an API description or a field telling
	// an operator to set it: every file of the program. The harness and the
	// gates are left out, because the names they carry configure a test run
	// rather than a deployment.
	refusals := goSources(t, "../..", "../../internal/tools", "../../internal/dbtest",
		"../../web", "../../node_modules")
	requireAmong(t, refusals, "../../internal/config/config.go", "../../cmd/openpsirt/main.go")

	// A variable named anywhere in the program is one an operator is being
	// told to set, so it is held to the documented set exactly as one that is
	// read here is.
	named := regexp.MustCompile(`OPENPSIRT_([A-Z0-9_]+)`)
	told := 0
	for _, path := range refusals {
		source, err := os.ReadFile(path) //nolint:gosec // G304: a Go file of this repository, found by the walk above
		if err != nil {
			t.Fatal(err)
		}
		for _, found := range named.FindAllStringSubmatch(string(source), -1) {
			reads[found[1]] = true
			told++
		}
	}
	if told == 0 {
		t.Fatal("no variable is named in any refusal, so half of this checked nothing")
	}

	page, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	written := map[string]bool{}
	for _, found := range regexp.MustCompile(`OPENPSIRT_([A-Z0-9_]+)`).
		FindAllStringSubmatch(string(page), -1) {
		written[found[1]] = true
	}

	// Every setting's key in a file is documented beside its variable, in the
	// row of the page's table that describes it, and the page names no key
	// the table does not hold under that variable.
	paired := regexp.MustCompile("(?m)^\\| `OPENPSIRT_([A-Z0-9_]+)` \\| `([a-z0-9_.]+)` \\|")
	keyed := map[string]string{}
	for _, found := range paired.FindAllStringSubmatch(string(page), -1) {
		keyed[found[1]] = found[2]
	}
	if len(keyed) == 0 {
		t.Fatal("no row of the page pairs a variable with its key in a file, so this checked nothing")
	}
	byEnv := map[string]string{}
	for _, one := range settings {
		byEnv[one.env] = one.file
		switch documented, ok := keyed[one.env]; {
		case !ok:
			t.Errorf("%s%s has no row pairing it with its key in a file, %s", envPrefix, one.env, one.file)
		case documented != one.file:
			t.Errorf("%s%s is documented with the key %s and read from %s",
				envPrefix, one.env, documented, one.file)
		}
	}
	for name, documented := range keyed {
		if _, ok := byEnv[name]; !ok {
			t.Errorf("%s%s is documented with the key %s, and no file key is read for it",
				envPrefix, name, documented)
		}
	}

	var missing, invented []string
	for name := range reads {
		if !written[name] {
			missing = append(missing, envPrefix+name)
		}
	}
	for name := range written {
		if !reads[name] {
			invented = append(invented, envPrefix+name)
		}
	}
	sort.Strings(missing)
	sort.Strings(invented)
	if len(missing) > 0 {
		t.Errorf("read and not documented, so an operator would have to find %s in the source:\n  %s",
			plural(len(missing)), strings.Join(missing, "\n  "))
	}
	if len(invented) > 0 {
		t.Errorf("documented and read by nothing, so setting %s changes nothing and says nothing:\n  %s",
			plural(len(invented)), strings.Join(invented, "\n  "))
	}

	// The chart is a third writer of the same contract, and the one on the
	// deployment the design calls the deployment. A name it sets that the
	// process no longer reads is a setting an operator changes to no effect,
	// with nothing anywhere to say so.
	//
	// One direction only: the chart offers the settings a cluster install
	// needs rather than all of them, so asking that it set every name the
	// process reads would fail on every optional one.
	chart, err := os.ReadFile("../../deploy/helm/openpsirt/templates/deployment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, found := range named.FindAllStringSubmatch(string(chart), -1) {
		set[found[1]] = true
	}
	if len(set) == 0 {
		t.Fatal("the chart sets no settings, so this checked nothing")
	}
	var ignored []string
	for name := range set {
		if !reads[name] {
			ignored = append(ignored, envPrefix+name)
		}
	}
	sort.Strings(ignored)
	if len(ignored) > 0 {
		t.Errorf("set by the chart and read by nothing, so a cluster install carries %s and the process ignores it:\n  %s",
			plural(len(ignored)), strings.Join(ignored, "\n  "))
	}
}

func plural(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}
