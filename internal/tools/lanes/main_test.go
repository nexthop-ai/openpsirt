// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

const module = "github.com/nexthop-ai/openpsirt/"

func TestATestBinaryReachingDatabaseSQLIsAServerPackageAndOneNotReachingItIsNot(t *testing.T) {
	listing := strings.Join([]string{
		module + "internal/held\tcontext " + module + "internal/database",
		module + "internal/held [" + module + "internal/held.test]\tdatabase/sql",
		module + "internal/held.test\tcontext database/sql " + module + "internal/held [" + module + "internal/held.test]",
		module + "internal/free\tstrings",
		module + "internal/free.test\tstrings testing " + module + "internal/free",
	}, "\n")
	picked, examined, err := servers(strings.NewReader(listing))
	if err != nil {
		t.Fatal(err)
	}
	if examined != 2 {
		t.Errorf("examined %d test binaries, want the two the listing holds", examined)
	}
	if want := []string{module + "internal/held"}; !slices.Equal(picked, want) {
		t.Errorf("picked %v, want %v", picked, want)
	}
}

func TestAListingWithNoTestBinaryOrNoDatabaseIsRefused(t *testing.T) {
	for name, listing := range map[string]string{
		"no test binary": module + "internal/free\tstrings\n",
		"no database":    module + "internal/free.test\tstrings testing\n",
	} {
		if _, _, err := servers(strings.NewReader(listing)); err == nil {
			t.Errorf("%s: the listing was accepted", name)
		}
	}
}

// The tree divided. Every package of the module is in the race pass, so the
// server pass is the one that can lose a package. A package whose own source
// or tests import a database package directly is the shallow form of reaching
// one, read from the import lists rather than from the dependency graph the
// program reads, and each must be picked. A picked package is one of the
// module's, so the server pass names nothing the race pass does not.
func TestEveryPackageImportingADatabaseRunsInTheServerPass(t *testing.T) {
	out, err := exec.Command("go", "list", "-test", "-f", listed, "../../../...").Output()
	if err != nil {
		t.Fatal(err)
	}
	picked, examined, err := servers(strings.NewReader(string(out)))
	if err != nil {
		t.Fatal(err)
	}
	direct, err := exec.Command("go", "list", "-f",
		"{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}\t{{join .Imports \" \"}} {{join .TestImports \" \"}} {{join .XTestImports \" \"}}\n{{end}}",
		"../../../...").Output()
	if err != nil {
		t.Fatal(err)
	}
	database := regexp.MustCompile(`(^| )(database/sql|` + regexp.QuoteMeta(module) + `internal/(database|dbtest)(/[^ ]*)?)( |$)`)
	var ours []string
	importing := 0
	for line := range strings.SplitSeq(strings.TrimSpace(string(direct)), "\n") {
		pkg, imports, _ := strings.Cut(line, "\t")
		if pkg == "" || strings.Contains(pkg, "/node_modules/") {
			continue
		}
		ours = append(ours, pkg)
		if database.MatchString(imports) {
			importing++
			if !slices.Contains(picked, pkg) {
				t.Errorf("%s imports a database package and is not in the server pass", pkg)
			}
		}
	}
	if len(ours) == 0 || importing == 0 {
		t.Fatalf("listed %d packages, %d importing a database, so this checked nothing", len(ours), importing)
	}
	for _, pkg := range picked {
		if !slices.Contains(ours, pkg) {
			t.Errorf("%s is in the server pass and is not a package of this module", pkg)
		}
	}
	if len(picked) == examined {
		t.Error("every test binary reaches a database, so no package is left to the race pass alone")
	}
	t.Logf("%d of %d test binaries reach a database; %d packages import one directly", len(picked), examined, importing)
}

// Each pass is given its list where the makefile spells it: the race pass
// every package, the server pass what this program prints. Handing the race
// pass the shorter list would leave every other package run by nothing.
func TestTheMakefileGivesTheRacePassEveryPackageAndTheServerPassThisList(t *testing.T) {
	text, err := os.ReadFile("../../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, problem := range wiring(string(text)) {
		t.Error(problem)
	}
}

const wired = `test-all:
	@servers=$$($(GO) run ./internal/tools/lanes $(PACKAGES)) || exit 1; \
	( $(RACE_PASS) -p 2 \
	    $(PACKAGES) ) & \
	( $(SERVERS_PASS) -p 2 \
	    $$servers ) &
`

func TestAPassGivenTheWrongListIsReported(t *testing.T) {
	if got := wiring(wired); len(got) != 0 {
		t.Errorf("a correct makefile was reported: %v", got)
	}
	swapped := strings.NewReplacer("$(PACKAGES) )", "$$servers )", "$$servers )", "$(PACKAGES) )").Replace(wired)
	if got := wiring(swapped); len(got) != 2 {
		t.Errorf("a makefile with the lists swapped was reported %d times, want both passes: %v", len(got), got)
	}
	unassigned := strings.Replace(wired, "./internal/tools/lanes", "./internal/tools/engines", 1)
	if got := wiring(unassigned); len(got) != 1 {
		t.Errorf("a makefile not running this program was reported %d times: %v", len(got), got)
	}
}

// wiring reports each invocation of a pass not given its list on the same or
// the next line, a pass the makefile never invokes, and a makefile never
// assigning the server list from this program.
func wiring(makefile string) []string {
	want := map[string]string{"$(RACE_PASS)": "$(PACKAGES)", "$(SERVERS_PASS)": "$$servers"}
	seen := map[string]int{}
	var problems []string
	lines := strings.Split(makefile, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for pass, list := range want {
			at := strings.Index(line, pass)
			if at < 0 {
				continue
			}
			seen[pass]++
			rest := line[at+len(pass):]
			if i+1 < len(lines) {
				rest += " " + lines[i+1]
			}
			if !strings.Contains(rest, list) {
				problems = append(problems, fmt.Sprintf("line %d runs %s without %s", i+1, pass, list))
			}
		}
	}
	for pass := range want {
		if seen[pass] == 0 {
			problems = append(problems, "the makefile never runs "+pass)
		}
	}
	if !strings.Contains(makefile, "servers=$$($(GO) run ./internal/tools/lanes $(PACKAGES))") {
		problems = append(problems, "the makefile never assigns the server list from this program")
	}
	sort.Strings(problems)
	return problems
}
