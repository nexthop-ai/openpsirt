// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// A byte that makes a text tool skip a file is invisible in review and breaks
// whoever greps for the line beside it. This gate had no test, and an exit
// code cannot tell a check that found nothing from one that looked at nothing.

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
		{"internal/webui/dist/.gitkeep", true},
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
