// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/build"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/tools/walk"
)

const module = "github.com/nexthop-ai/openpsirt/"

func none(string) ([]string, error) { return nil, nil }

// A package Linux compiles nothing of is missing from its listing and picked
// all the same; an npm dependency's Go package is not this module's.
func TestAPackageCompilingAFileOffLinuxIsPickedAndOneCompilingTheSameFilesIsNot(t *testing.T) {
	linux := strings.Join([]string{
		module + "internal/kept\t/k\tkept.go kept_linux.go  kept_test.go ",
		module + "internal/same\t/s\tsame.go  same_test.go ",
	}, "\n")
	other := strings.Join([]string{
		module + "internal/kept\t/k\tkept.go kept_other.go  kept_test.go ",
		module + "internal/same\t/s\tsame.go  same_test.go ",
		module + "internal/offlinux\t/o\toff_windows.go   ",
		module + "web/node_modules/flatted/golang\t/n\tflatted_windows.go   ",
	}, "\n")
	picked, examined, err := differing(strings.NewReader(linux), strings.NewReader(other), none)
	if err != nil {
		t.Fatal(err)
	}
	if examined != 3 {
		t.Errorf("examined %d packages, want the three of this module the listing holds", examined)
	}
	if want := []string{module + "internal/kept", module + "internal/offlinux"}; !slices.Equal(picked, want) {
		t.Errorf("picked %v, want %v", picked, want)
	}
}

func TestAListingWithNoPackageOrNoneDifferingIsRefused(t *testing.T) {
	same := module + "internal/same\t/s\tsame.go   \n"
	for name, other := range map[string]string{
		"no package":   "",
		"none differs": same,
	} {
		if _, _, err := differing(strings.NewReader(same), strings.NewReader(other), none); err == nil {
			t.Errorf("%s: the listing was accepted", name)
		}
	}
}

func TestAFileOneSystemCompilesDeclaringAnExportedNameIsRefused(t *testing.T) {
	linux := module + "internal/kept\t/k\tkept.go kept_linux.go  kept_linux_test.go \n"
	other := module + "internal/kept\t/k\tkept.go kept_other.go   \n"
	declares := func(path string) ([]string, error) {
		switch filepath.Base(path) {
		case "kept_other.go":
			return []string{"Start"}, nil
		case "kept_linux_test.go":
			return []string{"TestStart"}, nil
		}
		return nil, nil
	}
	_, _, err := differing(strings.NewReader(linux), strings.NewReader(other), declares)
	if err == nil {
		t.Fatal("a file kept off Linux declaring an exported name was accepted")
	}
	if !strings.Contains(err.Error(), "kept_other.go") || strings.Contains(err.Error(), "kept_linux_test.go") {
		t.Errorf("want the source file reported and the test file left alone: %v", err)
	}
}

func TestExportedNamesReadsEveryKindOfTopLevelDeclaration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "names.go")
	source := "package p\n\nfunc Start() {}\nfunc start() {}\ntype Kind int\nvar Held, held = 1, 2\nconst Most = 3\n"
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	names, err := exportedNames(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Start", "Kind", "Held", "Most"}; !slices.Equal(names, want) {
		t.Errorf("names %v, want %v", names, want)
	}
}

// Every file of the module some operating system compiles and Linux does not is
// compiled by one of the systems vet-other-os names, read from its recipe.
// Otherwise the file is type-checked by nothing.
func TestEveryFileKeptOffLinuxIsCompiledByASystemTheVetNames(t *testing.T) {
	text, err := os.ReadFile("../../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	vetted := vettedSystems(string(text))
	if len(vetted) == 0 {
		t.Fatal("vet-other-os names no GOOS, so this checked nothing")
	}
	dist, err := exec.Command("go", "tool", "dist", "list").Output()
	if err != nil {
		t.Fatal(err)
	}
	var systems []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(dist)), "\n") {
		goos, _, _ := strings.Cut(line, "/")
		if goos != "linux" && !slices.Contains(systems, goos) {
			systems = append(systems, goos)
		}
	}
	compiles := func(goos, dir, name string) bool {
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH, ctx.BuildTags = goos, "amd64", nil
		ok, err := ctx.MatchFile(dir, name)
		return err == nil && ok
	}
	// Every file on disk rather than a listing for Linux, which omits a
	// package Linux compiles nothing of.
	t.Chdir("../../..")
	examined, err := walk.Paths([]string{"testdata"}, func(path string) (bool, error) {
		if !strings.HasSuffix(path, ".go") {
			return false, nil
		}
		dir, name := filepath.Split(path)
		if compiles("linux", dir, name) {
			return false, nil
		}
		var compiling []string
		for _, goos := range systems {
			if compiles(goos, dir, name) {
				compiling = append(compiling, goos)
			}
		}
		if len(compiling) == 0 {
			return false, nil
		}
		if !slices.ContainsFunc(compiling, func(goos string) bool { return slices.Contains(vetted, goos) }) {
			t.Errorf("%s is compiled on %v and vet-other-os vets only %v, so nothing type-checks it",
				path, compiling, vetted)
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if examined == 0 {
		t.Fatal("no file of the module is kept off Linux, so this checked nothing")
	}
	t.Logf("%d files kept off Linux, vetted on %v", examined, vetted)
}

func TestVettedSystemsReadsTheRecipeAlone(t *testing.T) {
	makefile := "other:\n\tGOOS=plan9 go build\nvet-other-os:\n\tfor goos in darwin windows; do \\\n\t  GOOS=$$goos\nnext:\n"
	if got, want := vettedSystems(makefile), []string{"darwin", "windows"}; !slices.Equal(got, want) {
		t.Errorf("read %v, want %v", got, want)
	}
}

var systemsLoop = regexp.MustCompile(`for goos in ([a-z0-9 ]+);`)

// vettedSystems is the systems the vet-other-os recipe loops over.
func vettedSystems(makefile string) []string {
	_, recipe, ok := strings.Cut(makefile, "\nvet-other-os:\n")
	if !ok {
		return nil
	}
	var body []string
	for line := range strings.SplitSeq(recipe, "\n") {
		if !strings.HasPrefix(line, "\t") {
			break
		}
		body = append(body, line)
	}
	match := systemsLoop.FindStringSubmatch(strings.Join(body, "\n"))
	if match == nil {
		return nil
	}
	return strings.Fields(match[1])
}
