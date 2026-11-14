// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package walk visits the files of this repository for the gate programs.
//
// "Part of this repository" is decided here, once. Gates that each decide it
// disagree: a generated file in a directory one gate walks and another skips
// fails one and is invisible to the rest. An empty result means both "nothing
// wrong" and "nothing looked at", so a gate reading less of the tree than its
// output implies reports the same "OK" either way.
//
// So the default skip set lives here and each caller names what it adds, with
// the reason at the call site, which is where a reader looks for it.
//
// The walk is rooted at the working directory and takes no root argument:
// a program that walks wherever it is pointed is a shape worth not having,
// and the analysis gate wants the no-path-argument form.
package walk

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// Skipped is the directories no gate reads.
//
//   - .git holds the history rather than the tree, and .demo and .vite hold
//     what a local run wrote. .claude is a local tool's working directory,
//     whose worktrees are whole copies of this checkout: read, every gate
//     reports each finding once per copy. A dot-prefixed directory is not
//     skipped as a class: .github is the workflows, which are checked.
//   - node_modules is somebody else's code.
//   - dist, site and bin are output: what is in them was built from what is
//     checked, so reading them checks the same thing twice and fails on
//     generated code nobody wrote.
//
// A fresh slice each time, because callers append their own names to it and a
// shared backing array would let one caller's extra reach another's walk.
func Skipped() []string {
	return []string{".git", ".demo", ".vite", ".claude", "node_modules", "dist", "site", "bin"}
}

// Sources visits every file under the working directory whose name ends in
// suffix, in lexical order, with its contents.
//
// The path is relative and carries no "./" prefix, because that is what a
// gate prints and what a person pastes back into an editor.
func Sources(suffix string, visit func(path string, body []byte) error) (int, error) {
	return Only(suffix, nil, visit)
}

// Only is Sources with further directories skipped, named at the call site.
func Only(suffix string, extra []string, visit func(path string, body []byte) error) (int, error) {
	read := 0
	err := each(extra, func(path string) error {
		if !strings.HasSuffix(path, suffix) {
			return nil
		}
		body, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // walked, not supplied
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		read++
		return visit(path, body)
	})
	if err != nil {
		return 0, err
	}
	return read, sawSomething(read, "files ending "+suffix)
}

// Paths visits every file under the working directory, by path alone, for a
// gate that decides from the name whether to read it at all.
//
// It reports how many the caller kept, not how many it was shown. A count of
// visits is held above zero by any file at all — a license, a readme — so
// counted that way the refusal below never fires for a gate that reads one
// kind of file, which is the answer-that-means-two-things this package exists
// to remove.
func Paths(extra []string, visit func(path string) (bool, error)) (int, error) {
	kept := 0
	err := each(extra, func(path string) error {
		took, err := visit(path)
		if took {
			kept++
		}
		return err
	})
	if err != nil {
		return 0, err
	}
	return kept, sawSomething(kept, "files")
}

// Tracked is every file git tracks in the working directory's checkout,
// less those under a skipped directory, for a gate whose set of files is the
// committed tree. Each file's content is read from the working tree.
func Tracked() ([]string, error) {
	return listed("tracked files", "ls-files", "-z")
}

// Unignored is Tracked with the files git would add beside them: every file
// on disk that no ignore rule covers, for a gate reading the change about to
// be committed. Build output is ignored, so it is not read.
func Unignored() ([]string, error) {
	return listed("files git does not ignore", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
}

func listed(what string, args ...string) ([]string, error) {
	out, err := exec.Command("git", args...).Output() //nolint:gosec // G204: arguments fixed by its callers in this file
	if err != nil {
		return nil, fmt.Errorf("listing the tree: %w", err)
	}
	files := trackedIn(out, Skipped())
	return files, sawSomething(len(files), what)
}

// trackedIn reads git's NUL-separated listing, once per path, dropping an
// empty entry, a listed directory and a path with a directory named in skip.
func trackedIn(listed []byte, skip []string) []string {
	var tracked []string
	for _, each := range bytes.Split(listed, []byte{0}) {
		path := string(each)
		// A directory git lists as a whole is a nested repository, which holds
		// no file to read; an unmerged path is listed once per stage.
		if path == "" || strings.HasSuffix(path, "/") || slices.Contains(tracked, path) {
			continue
		}
		dirs := strings.Split(path, "/")
		if slices.ContainsFunc(dirs[:len(dirs)-1], func(dir string) bool { return slices.Contains(skip, dir) }) {
			continue
		}
		tracked = append(tracked, path)
	}
	return tracked
}

func each(extra []string, visit func(path string) error) error {
	skip := append(Skipped(), extra...)
	return filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != "." && slices.Contains(skip, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		return visit(path)
	})
}

// sawSomething refuses a walk that reached nothing.
//
// A gate reports the same "OK" whether it found nothing wrong or looked at
// nothing at all, and the second is what a skip list one directory too wide
// produces — or running the gate from a directory that is not the repository.
// The distinction has to be made here, because no caller can make it from an
// empty result.
func sawSomething(count int, what string) error {
	if count == 0 {
		return fmt.Errorf("the walk reached no %s, so this checked nothing: "+
			"run it from the repository root", what)
	}
	return nil
}
