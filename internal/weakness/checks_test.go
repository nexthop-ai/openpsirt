// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package weakness_test

import (
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/weakness"
)

func TestARuleOfATaggingNoToolIsClassifiedByItsTable(t *testing.T) {
	for _, c := range []struct {
		rule string
		want []string
	}{
		{"cppcheck/memleak", []string{"CWE-401"}},
		{"cppcheck/nullPointer", []string{"CWE-476"}},
		{"clang/core.NullDereference", []string{"CWE-476"}},
		{"clang/unix.Malloc", []string{"CWE-401", "CWE-415", "CWE-416"}},
		{"clang-tidy/clang-analyzer-unix.Malloc", []string{"CWE-401", "CWE-415", "CWE-416"}},
		// A checker looked at and fitted by no weakness, a clang-tidy check
		// of its own, a tool that tags its rules, a check no table holds and
		// a name with no tool.
		{"clang/core.CallAndMessage", nil},
		{"clang-tidy/bugprone-sizeof-expression", nil},
		{"codeql/cpp/overflow-buffer", nil},
		{"cppcheck/noSuchCheck", nil},
		{"memleak", nil},
	} {
		if got := weakness.OfRule(c.rule); !slices.Equal(got, c.want) {
			t.Errorf("%s is %v; want %v", c.rule, got, c.want)
		}
	}
}

func TestWhatATableAnswersIsTheCallersToChange(t *testing.T) {
	weakness.OfRule("clang/unix.Malloc")[0] = "CWE-1"
	if got := weakness.OfRule("clang/unix.Malloc"); got[0] != "CWE-401" {
		t.Errorf("changing an answer changed the table: %v", got)
	}
}

func TestEveryClangCheckerMapsToAWeaknessTheCatalogNames(t *testing.T) {
	checkers := weakness.ClangCheckers()
	if len(checkers) == 0 {
		t.Fatal("the clang table holds no checker, so this checked nothing")
	}
	for _, c := range checkers {
		for _, cwe := range weakness.OfRule("clang/" + c) {
			if _, ok := weakness.Name(cwe); !ok {
				t.Errorf("%s maps to %s, which the catalog names no weakness", c, cwe)
			}
		}
	}
}

func TestClangCheckersClangTidyRunsAreClangs(t *testing.T) {
	for name, want := range map[string]string{
		"clang-tidy/clang-analyzer-unix.Malloc":          "clang",
		"Clang-Tidy/clang-analyzer-core.NullDereference": "clang",
		"clang/unix.Malloc":                              "clang",
		"clang-tidy/bugprone-use-after-move":             "clang-tidy",
		"cppcheck/nullPointer":                           "cppcheck",
		"CodeQL/cpp/overflow":                            "codeql",
	} {
		if got := weakness.Analyzer(name); got != want {
			t.Errorf("%s is of analyzer %q; want %q", name, got, want)
		}
	}
}
