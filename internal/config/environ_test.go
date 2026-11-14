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

// prefixed matches a variable name carrying the prefix. A name ending in "_"
// is a prefix of a family of names, written in a comment or a message, and
// is not one variable.
var prefixed = regexp.MustCompile(envPrefix + `[A-Z0-9_]*`)

// strays is every variable carrying the prefix that text names and the
// loader would refuse: neither a setting nor one set for something else.
func strays(text string) []string {
	known := make(map[string]bool, len(settings))
	for _, one := range settings {
		known[one.env] = true
	}
	var out []string
	for _, name := range prefixed.FindAllString(text, -1) {
		key := strings.TrimPrefix(name, envPrefix)
		if key == "" || strings.HasSuffix(key, "_") {
			continue
		}
		if !known[key] && !incidental(key, "") && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

func TestAStrayVariableIsFoundAndASettingIsNot(t *testing.T) {
	got := strays("export OPENPSIRT_BASE_URL=x OPENPSIRT_NOT_A_SETTING=y OPENPSIRT_KEY=z; # OPENPSIRT_INGEST_ family")
	if !slices.Equal(got, []string{"OPENPSIRT_NOT_A_SETTING"}) {
		t.Errorf("found %v; want the one name that is no setting", got)
	}
}

// setsVariables reports whether a file in the tree may set or read a
// variable some program in the tree is given: the programs and scripts, the
// interface, the build, the workflows and the chart. A test is left out,
// since a test sets names the loader must refuse.
func setsVariables(path string) bool {
	base := filepath.Base(path)
	switch {
	case strings.HasSuffix(base, "_test.go"), strings.Contains(base, ".test."):
		return false
	case base == "Makefile", base == "Dockerfile", strings.HasPrefix(base, "Dockerfile."):
		return true
	}
	switch filepath.Ext(base) {
	case ".go", ".ts", ".tsx", ".js", ".mjs", ".mk", ".sh", ".yml", ".yaml", ".tpl", ".toml", ".json":
		return true
	}
	return false
}

// TestEveryVariableTheTreeNamesIsReadOrLeftAlone holds every variable
// carrying the prefix that the tree's programs, scripts, build, workflows and
// chart name to a setting or one the loader leaves alone. Any other is
// refused at startup, so a new one stops every server the build or a
// deployment starts before any other test fails.
func TestEveryVariableTheTreeNamesIsReadOrLeftAlone(t *testing.T) {
	root := filepath.Join("..", "..")
	var examined []string
	found := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			// Prose describes refusals and names misspellings on purpose;
			// testdata and installed packages are nobody's settings.
			if path != root && (name == "node_modules" || name == "testdata" || name == "docs" ||
				name == "design-docs" || name == "dist" || name == "vendor" ||
				strings.HasPrefix(name, ".") && name != ".github") {
				return filepath.SkipDir
			}
			return nil
		}
		if !setsVariables(path) {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304: a file of the repository's own tree
		if err != nil {
			return err
		}
		examined = append(examined, filepath.ToSlash(path))
		for _, name := range strays(string(data)) {
			found[name] = append(found[name], filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(examined) == 0 {
		t.Fatal("no file of the tree was read, so this checked nothing")
	}
	// One file of each kind the walk is for, so a walk that narrowed fails.
	requireAmong(t, examined, "../../Makefile", "../../.github/workflows/ci.yml",
		"../../cmd/openpsirt-upload/main.go", "../../web/vite.config.ts")
	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Errorf("%s is named in %s, and the loader refuses it: make it a setting or one the loader leaves alone",
			name, strings.Join(found[name], ", "))
	}
}
