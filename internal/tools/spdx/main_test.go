// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/tools/provenance"
)

func TestAFileOpeningWithTheHeaderPasses(t *testing.T) {
	for _, c := range []struct {
		what, file, content string
	}{
		{"go", "a/b.go", "// Copyright Nexthop Systems Inc.\n// SPDX-License-Identifier: Apache-2.0\n\npackage b\n"},
		{"css", "a/b.css", "/* Copyright Nexthop Systems Inc. */\n/* SPDX-License-Identifier: Apache-2.0 */\n\n:root {}\n"},
		{"a makefile", "Makefile", "# Copyright Nexthop Systems Inc.\n# SPDX-License-Identifier: Apache-2.0\n\nall:\n"},
		{"after an interpreter line", "a/run.sh",
			"#!/bin/sh\n\n# Copyright Nexthop Systems Inc.\n# SPDX-License-Identifier: Apache-2.0\n\necho\n"},
		{"after a parser directive", "Dockerfile",
			"# syntax=docker/dockerfile:1\n\n# Copyright Nexthop Systems Inc.\n# SPDX-License-Identifier: Apache-2.0\n\nFROM x\n"},
		{"the whole file", "a/b.ts", "// Copyright Nexthop Systems Inc.\n// SPDX-License-Identifier: Apache-2.0"},
	} {
		t.Run(c.what, func(t *testing.T) {
			if wrong, _ := fault([]byte(c.content), styleOf(c.file), "Apache-2.0"); wrong != "" {
				t.Errorf("reported %q", wrong)
			}
		})
	}
}

func TestAFileWithoutTheHeaderIsReported(t *testing.T) {
	for _, c := range []struct {
		what, content string
		missing       bool
	}{
		{"nothing at all", "package b\n", true},
		{"the header lower down", "package b\n\n// Copyright Nexthop Systems Inc.\n// SPDX-License-Identifier: Apache-2.0\n", false},
		{"another license", "// Copyright Nexthop Systems Inc.\n// SPDX-License-Identifier: MIT\n\npackage b\n", false},
		{"no copyright line", "// SPDX-License-Identifier: Apache-2.0\n\npackage b\n", false},
		{"a comment run on from it", "// Copyright Nexthop Systems Inc.\n// SPDX-License-Identifier: Apache-2.0\n// Package b.\npackage b\n", false},
	} {
		t.Run(c.what, func(t *testing.T) {
			wrong, missing := fault([]byte(c.content), slashes, "Apache-2.0")
			if wrong == "" {
				t.Fatal("was not reported")
			}
			if missing != c.missing {
				t.Errorf("read as missing %v, want %v: %s", missing, c.missing, wrong)
			}
		})
	}
}

func TestAFileCarryingSomebodyElsesWorkStatesTheirTermsToo(t *testing.T) {
	held := []provenance.Entry{
		{Path: "a/ours.go", License: provenance.Ours},
		{Path: "a/same.go", License: "Apache-2.0"},
		{Path: "a/table.go", License: "BSD-2-Clause"},
		{Path: "a/suite_test.go", License: "Apache-2.0 OR BSD-2-Clause"},
	}
	for file, want := range map[string]string{
		"a/ours.go":       "Apache-2.0",
		"a/same.go":       "Apache-2.0",
		"a/table.go":      "Apache-2.0 AND BSD-2-Clause",
		"a/suite_test.go": "Apache-2.0 AND (Apache-2.0 OR BSD-2-Clause)",
		"a/unheld.go":     "Apache-2.0",
	} {
		if got := licenseOf(file, held); got != want {
			t.Errorf("%s states %q, want %q", file, got, want)
		}
	}
}

func TestStampingWritesAHeaderThatPasses(t *testing.T) {
	for _, c := range []struct{ file, content string }{
		{"a/b.go", "package b\n"},
		{"a/b.css", ":root {}\n"},
		{"a/run.sh", "#!/bin/sh\necho\n"},
		{"Dockerfile", "# syntax=docker/dockerfile:1\nFROM x\n"},
	} {
		s := styleOf(c.file)
		out := stamped([]byte(c.content), s, "Apache-2.0")
		if wrong, _ := fault(out, s, "Apache-2.0"); wrong != "" {
			t.Errorf("%s stamped reads %q:\n%s", c.file, wrong, out)
		}
		if !strings.HasSuffix(string(out), c.content[strings.Index(c.content, "\n")+1:]) {
			t.Errorf("%s lost what followed its head:\n%s", c.file, out)
		}
	}
}

func TestOnlySourceIsHeld(t *testing.T) {
	for file, want := range map[string]bool{
		"internal/a/b.go":           true,
		"web/src/a.tsx":             true,
		"web/src/styles/tokens.css": true,
		"Makefile.demo":             true,
		"Dockerfile":                true,
		"README.md":                 false,
		"internal/a/testdata/x.go":  false,
		"web/src/api/schema.d.ts":   false,
		"deploy/helm/x/values.yaml": false,
	} {
		if got, _ := covered(file); got != want {
			t.Errorf("%s held to a header: %v, want %v", file, got, want)
		}
	}
}
