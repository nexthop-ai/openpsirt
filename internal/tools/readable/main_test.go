// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A byte that makes a text tool skip a file is invisible in review and breaks
// whoever greps for the line beside it, and an exit code cannot tell a check
// that found nothing from one that looked at nothing.

func TestWhatCountsAsAnUnreadableByte(t *testing.T) {
	for _, c := range []struct {
		what     string
		body     string
		reported bool
		at       int
	}{
		{"ordinary text", "package p\n\nfunc f() {}\n", false, 0},
		{"a tab, which is how Go indents", "a\tb\n", false, 0},
		{"a carriage return, which is how another machine ends a line", "a\r\nb\n", false, 0},
		{"a NUL", "a\x00b", true, 1},
		{"a vertical tab", "one\ntwo\vthree", true, 2},
		{"a delete", "one\ntwo\nthree\x7f", true, 3},
		{"an escape, which is how a terminal is coloured", "\x1b[31mred", true, 1},
		{"nothing at all", "", false, 0},
		// Multi-byte UTF-8 is text: every continuation byte is at or above
		// 0x80, so a range over bytes must not read one as a control.
		{"a word in another script", "héllo · wörld\n", false, 0},
	} {
		got, line, reported := carrying([]byte(c.body))
		if reported != c.reported {
			t.Errorf("%s: reported=%v (byte %#x), want %v", c.what, reported, got, c.reported)
			continue
		}
		if reported && line != c.at {
			t.Errorf("%s: reported at line %d, want %d", c.what, line, c.at)
		}
	}
}

func TestWhichFilesAreReadAsText(t *testing.T) {
	// Everything but a named binary kind. Both directions: a text file left
	// unread is a file this gate no longer looks at, and a binary read is a
	// gate that fails on every build output.
	for _, c := range []struct {
		path string
		want bool
	}{
		{"internal/access/store.go", true},
		{"web/src/app/App.tsx", true},
		{"design-docs/access.md", true},
		{"Makefile", true},
		{"Dockerfile", true},
		{"LICENSE", true},
		{"internal/sarif/testdata/run.sarif", true},
		{"internal/sbom/testdata/image.cdx.xml", true},
		{"internal/tools/clangcheckers/testdata/leak.c", true},
		{"internal/tools/clangcheckers/testdata/leak.h", true},
		{"internal/uploadclient/testdata/app.plist", true},
		{".gitattributes", true},
		{"web/.prettierignore", true},
		{"a kind nobody has written yet.new", true},
		{"web/public/logo.png", false},
		{"assets/font.woff2", false},
		{"internal/cverecord/testdata/records.json.xz", false},
		{"ASSETS/LOGO.PNG", false},
	} {
		if got := !binary(c.path); got != c.want {
			t.Errorf("%s read as text = %v, want %v", c.path, got, c.want)
		}
	}
}

// commandsIn is the name "go build" gives each command under the directories
// given, which is the directory holding a file of package main.
func commandsIn(dirs ...string) ([]string, error) {
	var names []string
	for _, dir := range dirs {
		sources, err := filepath.Glob(filepath.Join(dir, "*", "*.go"))
		if err != nil {
			return nil, err
		}
		for _, source := range sources {
			body, err := os.ReadFile(source) //nolint:gosec // the repository's own source
			if err != nil {
				return nil, err
			}
			name := filepath.Base(filepath.Dir(source))
			if strings.Contains(string(body), "\npackage main\n") && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	return names, nil
}

// Every file git does not ignore is read, so a command built at the root of
// the checkout is read too unless the ignore list names it.
func TestEveryCommandBuiltAtTheRootIsIgnored(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	names, err := commandsIn(filepath.Join(root, "cmd"), filepath.Join(root, "internal", "tools"))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("no command was found, so this checked nothing")
	}
	ignore, err := os.ReadFile(filepath.Join(root, ".gitignore")) //nolint:gosec // the repository's own ignore list
	if err != nil {
		t.Fatal(err)
	}
	listed := builtIn(string(ignore))
	if len(listed) == 0 {
		t.Fatal(".gitignore lists no build output, so this checked nothing")
	}
	for _, name := range names {
		if !slices.Contains(listed, name) {
			t.Errorf("%s is built at the root as %s, which .gitignore does not name, so make readable reads it", name, name)
		}
	}
	for _, name := range listed {
		if !slices.Contains(names, name) {
			t.Errorf(".gitignore lists %s as build output, and no command is built under that name", name)
		}
	}
}

// builtIn is the names the ignore list's build-output block holds: the run
// of root paths after its heading and the comment beneath it.
func builtIn(ignore string) []string {
	var names []string
	in := false
	for _, line := range strings.Split(ignore, "\n") {
		switch {
		case line == "# Build output":
			in = true
		case !in || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "/"):
			names = append(names, strings.TrimPrefix(line, "/"))
		default:
			in = false
		}
	}
	return names
}
