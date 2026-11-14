// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command readable reports source files that a text tool will not read.
//
// One control byte makes grep treat a file as binary, and every text-based
// check then skips it without saying so. A control character in source is
// never deliberate: a separator meant as a character is written as an escape.
// The bytes alone are checked: anything outside tab, newline and carriage
// return names the file.
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/tools/walk"
)

// carrying reports the first offending byte in a file, and where.
func carrying(body []byte) (byte, int, bool) {
	line := 1
	for _, b := range body {
		switch {
		case b == '\n':
			line++
		case b == '\t' || b == '\r':
		case b < 0x20 || b == 0x7f:
			return b, line, true
		}
	}
	return 0, 0, false
}

// binary reports whether this is a file of a kind that is not text.
//
// Every other file is read, so a new text kind is checked from its first
// commit and a new binary kind fails naming the file. By extension, because a
// content sniff reads a text file holding one control byte as binary.
func binary(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
		".woff", ".woff2", ".ttf", ".otf",
		".xz", ".gz", ".zip", ".tar", ".pdf", ".wasm":
		return true
	}
	return false
}

func main() {
	var bad []string
	// Every file git does not ignore, so build output left in the checkout is
	// not read. vendor is a dependency's own source, and the interface is read
	// rather than skipped: a byte that makes a text tool skip a file is not a
	// Go question.
	files, err := walk.Unignored()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	read := 0
	for _, path := range files {
		if binary(path) || strings.HasPrefix(path, "vendor/") {
			continue
		}
		// The path is one git listed in this checkout, never a caller's.
		body, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // listed by git, not supplied
		if errors.Is(err, fs.ErrNotExist) {
			// Deleted in the working tree and not yet committed.
			continue
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		read++
		if b, line, found := carrying(body); found {
			bad = append(bad, fmt.Sprintf(
				"%s:%d: byte 0x%02x, which makes text tools treat this file as binary "+
					"and skip it. Write it as an escape", path, line, b))
		}
	}
	if read == 0 {
		fmt.Fprintln(os.Stderr, "no file was read, so this checked nothing")
		os.Exit(2)
	}
	if len(bad) == 0 {
		fmt.Printf("every source file reads as text, so every text check sees all of it (%d files)\n", read)
		return
	}
	for _, one := range bad {
		fmt.Fprintln(os.Stderr, one)
	}
	fmt.Fprintf(os.Stderr, "\n%d file(s) a text tool will skip without saying so.\n", len(bad))
	os.Exit(1)
}
