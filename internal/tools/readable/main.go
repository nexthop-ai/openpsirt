// Command readable reports source files that a text tool will not read.
//
// A single stray NUL byte in a TypeScript file made grep treat it as binary,
// and every text-based check in this repository skipped it silently: the
// class-collision script, the design-token check, and every audit somebody ran
// by hand. The screen it hid was the busiest one in the interface, and the
// consequence was not a wrong answer but the absence of one — four components
// it draws were reported as reached by nothing at all.
//
// That is the whole class this exists for. A control character in source is
// never deliberate: a separator meant as a character is written as an escape,
// which is what every other file here does. What is checked is the bytes, not
// the meaning — anything outside tab, newline and carriage return, and the
// file is named.
package main

import (
	"fmt"
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

// text reports whether this is a file worth reading as one.
//
// By extension, because the alternative — sniffing the content — is the thing
// that was fooled.
func text(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go", ".ts", ".tsx", ".js", ".mjs", ".css", ".md", ".yaml", ".yml",
		".json", ".sql", ".sh", ".html", ".txt", ".mod", ".sum", ".toml":
		return true
	}
	name := filepath.Base(path)
	return name == "Makefile" || name == "Dockerfile"
}

func main() {
	var bad []string
	// vendor is a dependency's own source, and the interface is walked rather
	// than skipped: a byte that makes a text tool skip a file is not a Go
	// question, and the five Go gates beside this one leave web out.
	read, err := walk.Paths([]string{"vendor"}, func(path string) (bool, error) {
		if !text(path) {
			return false, nil
		}
		// The path comes from the walk over the directory this was started in,
		// never from a caller, and this program reads a repository and prints
		// filenames. Said here rather than as a configured exclusion, which
		// would also cover the next tool written beside it.
		body, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // walked, not supplied
		if err != nil {
			return false, err
		}
		if b, line, found := carrying(body); found {
			bad = append(bad, fmt.Sprintf(
				"%s:%d: byte 0x%02x, which makes text tools treat this file as binary "+
					"and skip it. Write it as an escape", path, line, b))
		}
		return true, nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
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
