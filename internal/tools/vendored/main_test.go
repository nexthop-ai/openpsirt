// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"strings"
	"testing"
)

// tree is a tree of files for the check to read, by path.
type tree map[string]string

func (t tree) paths() []string {
	var out []string
	for each := range t {
		out = append(out, each)
	}
	return out
}

func (t tree) read(file string) ([]byte, error) {
	content, ok := t[file]
	if !ok {
		return nil, errors.New("no such file")
	}
	return []byte(content), nil
}

var permitted = []string{"Apache-2.0", "BSD-2-Clause", "CC0-1.0", "CC-BY-4.0"}

// faultsFor runs the check over a tree and a list, and returns what it
// reported.
func faultsFor(t *testing.T, files tree, held []entry, notice string) []string {
	t.Helper()
	_, faults := check(files.paths(), files.read, held, notice, permitted)
	return faults
}

func mentions(faults []string, phrase string) bool {
	for _, each := range faults {
		if strings.Contains(each, phrase) {
			return true
		}
	}
	return false
}

// A baseline that passes, which each case below breaks in one way.
func passing() (tree, []entry, string) {
	files := tree{
		"NOTICE":                             "Copyright 2026 Nexthop Systems Inc.",
		"internal/pkg/testdata/taken.json":   `{"dataLicense": "CC-BY-4.0"}`,
		"internal/pkg/testdata/written.json": `{}`,
		"internal/pkg/code.go":               "package pkg\n",
		"internal/x/y.go":                    "package x\n// Copyright (c) Somebody Else\n",
	}
	held := []entry{
		{Path: "internal/pkg/testdata/taken.json", License: "CC-BY-4.0", Source: "https://example.test"},
		{Path: "internal/pkg/testdata/written.json", License: ours, Source: ""},
		{Path: "internal/x/y.go", License: "Apache-2.0", Source: "https://example.test"},
	}
	return files, held, "See internal/pkg/testdata/taken.json and internal/x/y.go."
}

func TestATreeWhoseEveryBorrowedFileIsHeldPasses(t *testing.T) {
	files, held, notice := passing()
	if faults := faultsFor(t, files, held, notice); len(faults) != 0 {
		t.Errorf("a tree with everything held reports %v", faults)
	}
}

func TestAFileSomebodyElseWroteAndNothingHoldsIsReported(t *testing.T) {
	for _, c := range []struct{ what, file, content string }{
		{"a fixture", "internal/pkg/testdata/new.json", "{}"},
		{"a fixture at the top of the tree", "testdata/new.json", "{}"},
		{"a copyright line", "internal/pkg/table.go", "// Copyright 2023 Somebody Else\n"},
		{"a copyright line with a sign", "internal/pkg/table.go", "// Copyright (c) Somebody Else\n"},
		{"a license identifier", "internal/pkg/lib.js", "// SPDX-License-Identifier: MIT\n"},
		{"this license's identifier with nobody's copyright", "internal/pkg/lib.js",
			"// SPDX-License-Identifier: Apache-2.0\n"},
		{"another license beside our copyright", "internal/pkg/lib.go",
			"// Copyright Nexthop Systems Inc.\n// SPDX-License-Identifier: Apache-2.0 AND BSD-2-Clause\n"},
		{"a document's data license", "internal/pkg/doc.json", `{"dataLicense": "CC0-1.0"}`},
		{"a comment saying NOTICE records it", "internal/pkg/suite_test.go", "// `NOTICE` records that.\n"},
	} {
		t.Run(c.what, func(t *testing.T) {
			files, held, notice := passing()
			files[c.file] = c.content
			if faults := faultsFor(t, files, held, notice); !mentions(faults, c.file) {
				t.Errorf("%s nothing holds was not reported: %v", c.file, faults)
			}
		})
	}
}

func TestAFileThatIsOursIsNotAskedAbout(t *testing.T) {
	for _, c := range []struct{ what, file, content string }{
		{"our own copyright", "internal/pkg/header.go", "// Copyright 2026 Nexthop Systems Inc.\n"},
		{"our own header", "internal/pkg/header.go",
			"// Copyright Nexthop Systems Inc.\n// SPDX-License-Identifier: Apache-2.0\n"},
		{"the word in prose", "internal/pkg/doc.go", "// neither the name of the copyright holder\n"},
		{"a markdown file describing a license", "internal/pkg/testdata/README.md", "Copyright 2024 SUSE LLC"},
		{"the license itself", "LICENSE", "Copyright 2026 Somebody"},
		{"a file that is not text", "internal/pkg/blob.bin", "\xff\xfeCopyright 2020 X"},
		{"this program, which spells the marks", "internal/tools/vendored/main.go", "SPDX-License-Identifier:"},
	} {
		t.Run(c.what, func(t *testing.T) {
			files, held, notice := passing()
			files[c.file] = c.content
			if faults := faultsFor(t, files, held, notice); len(faults) != 0 {
				t.Errorf("%s was asked about: %v", c.file, faults)
			}
		})
	}
}

func TestTheListIsHeldToTheTree(t *testing.T) {
	files, held, notice := passing()
	held = append(held, entry{Path: "internal/pkg/testdata/gone.json", License: ours, Source: ""})
	if faults := faultsFor(t, files, held, notice); !mentions(faults, "gone.json is held and is not in the tree") {
		t.Errorf("a held file the tree does not have was not reported: %v", faults)
	}
}

func TestALicenseTheTreeMayNotCarryIsReported(t *testing.T) {
	for _, license := range []string{"GPL-3.0-or-later", "Apache-2.0 AND GPL-2.0-only"} {
		files, held, notice := passing()
		held[0].License = license
		if faults := faultsFor(t, files, held, notice); !mentions(faults, "not a license this tree may carry") {
			t.Errorf("%s was accepted: %v", license, faults)
		}
	}
	// One alternative of an OR is enough.
	files, held, notice := passing()
	held[0].License = "GPL-3.0-or-later OR Apache-2.0"
	if faults := faultsFor(t, files, held, notice); len(faults) != 0 {
		t.Errorf("a choice including a permitted license was refused: %v", faults)
	}
}

func TestAnAttributionLicenseNoticeDoesNotNameIsReported(t *testing.T) {
	files, held, _ := passing()
	if faults := faultsFor(t, files, held, "See internal/x/y.go."); !mentions(faults, "NOTICE does not name it") {
		t.Errorf("an attribution license NOTICE omits was not reported: %v", faults)
	}
	// A longer path ending in this one is a different file.
	if faults := faultsFor(t, files, held, "See internal/x/y.go and internal/x/internal/pkg/testdata/taken.json."); !mentions(faults, "NOTICE does not name it") {
		t.Errorf("NOTICE naming a longer path was read as naming this one: %v", faults)
	}
	// A dedication to the public domain asks nothing, so NOTICE need not say.
	held[0].License = "CC0-1.0"
	if faults := faultsFor(t, files, held, "See internal/x/y.go."); mentions(faults, "NOTICE does not name it") {
		t.Errorf("a license asking nothing was held to NOTICE: %v", faults)
	}
}

func TestABorrowedFileWithNoSourceIsReported(t *testing.T) {
	files, held, notice := passing()
	held[0].Source = ""
	if faults := faultsFor(t, files, held, notice); !mentions(faults, "says nothing about where it came from") {
		t.Errorf("a borrowed file with no source was not reported: %v", faults)
	}
}

func TestWhatNoticeNamesIsHeldAsSomebodyElses(t *testing.T) {
	for _, c := range []struct{ named, want string }{
		{"internal/nothing/here.go", "internal/nothing/here.go, which is not in the tree"},
		{"internal/z/free.go", "internal/z/free.go, and the list does not hold it"},
		{"internal/z/ours.go", "internal/z/ours.go, and the list holds it as ours"},
	} {
		files, held, notice := passing()
		files["internal/z/free.go"] = "package z\n"
		files["internal/z/ours.go"] = "package z\n"
		held = append(held, entry{Path: "internal/z/ours.go", License: ours, Source: ""})
		if faults := faultsFor(t, files, held, notice+" And "+c.named+"."); !mentions(faults, c.want) {
			t.Errorf("NOTICE naming %s: want a fault saying %q, got %v", c.named, c.want, faults)
		}
	}
}

func TestAPathIsReadFromWhereItBegins(t *testing.T) {
	// A directory named partway along a path is not the start of a second.
	got := noticed("See internal/sbom/testdata/x.json, and testdata/y.json.")
	if strings.Join(got, " ") != "internal/sbom/testdata/x.json testdata/y.json" {
		t.Errorf("read %q", got)
	}
}

func TestACheckThatFoundNothingSaysSo(t *testing.T) {
	_, faults := check([]string{"NOTICE"}, tree{"NOTICE": ""}.read, nil, "", permitted)
	if !mentions(faults, "checked nothing") {
		t.Errorf("a tree with nothing to find passed: %v", faults)
	}
	if !mentions(faults, "NOTICE names no file") {
		t.Errorf("a NOTICE naming nothing passed: %v", faults)
	}
}
