// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package released is the record each tagged release keeps of its migrations:
// which files it shipped, their digests, and the schema they build on each
// engine.
//
// A database a release built has applied exactly those files, so what they do
// is fixed from the tag on. The record is what holds them there. It is written
// once, on the commit that is tagged, and read by the tests that hold the tree
// to it and by the check the release workflow runs before it publishes.
package released

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Engines is every engine a release's schema is recorded on.
var Engines = []string{"mariadb", "mysql", "postgres", "sqlite"}

// Files is the name of the list of a release's files and their digests.
const Files = "files.txt"

// Schema is the name of what a release's migrations build on one engine.
func Schema(engine string) string { return "schema-" + engine + ".txt" }

// Record is one release's migrations as it tagged them.
type Record struct {
	// Version is the tag, as v0.2.0.
	Version string
	// Last is the highest migration the release carried.
	Last int64
	// Digests is each file the release shipped for its migrations, and the
	// digest of the file below its license header.
	Digests map[string]string
}

var release = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(-rc\.\d+)?$`)

// Base is the release a tag names. A release candidate is checked against
// the record of the release it precedes, since a database it built applies
// the same migrations.
func Base(tag string) (string, error) {
	m := release.FindStringSubmatch(tag)
	if m == nil {
		return "", fmt.Errorf("%q is not a release tag: one reads as v0.3.0, or v0.3.0-rc.1", tag)
	}
	return "v" + m[1] + "." + m[2] + "." + m[3], nil
}

// Code is the prefix a release's table declarations carry: v030 for v0.3.0.
func Code(version string) (string, error) {
	base, err := Base(version)
	if err != nil {
		return "", err
	}
	return "v" + strings.ReplaceAll(strings.TrimPrefix(base, "v"), ".", ""), nil
}

// order is a release's version as numbers, for sorting.
func order(version string) [3]int {
	m := release.FindStringSubmatch(version)
	var out [3]int
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out
}

// Digest is the digest of a migration file below its license header. The
// header is the comment block the file opens with, and a blank line ends it:
// the header was added to files v0.1.0 shipped without one, and what a
// migration does is below it.
func Digest(content []byte) (string, error) {
	if !bytes.HasPrefix(content, []byte("// Copyright")) {
		return "", errors.New("it does not open with the license header")
	}
	_, body, found := bytes.Cut(content, []byte("\n\n"))
	if !found {
		return "", errors.New("nothing follows its license header")
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

// Number is the migration a file is, or zero where it is not one.
func Number(name string) int64 {
	digits, _, ok := strings.Cut(name, "_")
	if !ok {
		return 0
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// Owned is the files of a migrations directory that belong to one release:
// the migrations numbered after the previous release's last up to its own,
// and the table declarations carrying its code.
func Owned(names []string, previous, last int64, code string) []string {
	var out []string
	for _, name := range names {
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if n := Number(name); n > previous && n <= last {
			out = append(out, name)
			continue
		}
		if strings.HasPrefix(name, code+"_") {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// Read reads one release's record.
func Read(root, version string) (*Record, error) {
	content, err := os.ReadFile(filepath.Join(root, version, Files)) //nolint:gosec // G304: a record in this repository, named by a release tag checked above it
	if err != nil {
		return nil, err
	}
	r := &Record{Version: version, Digests: map[string]string{}}
	lines := bufio.NewScanner(bytes.NewReader(content))
	for n := 1; lines.Scan(); n++ {
		line := strings.TrimSpace(lines.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "last "):
			if r.Last, err = strconv.ParseInt(strings.TrimPrefix(line, "last "), 10, 64); err != nil {
				return nil, fmt.Errorf("%s line %d: %w", version, n, err)
			}
		default:
			digest, name, ok := strings.Cut(line, "  ")
			if !ok || len(digest) != sha256.Size*2 {
				return nil, fmt.Errorf("%s line %d is neither a digest and a file nor the last migration", version, n)
			}
			r.Digests[name] = digest
		}
	}
	if err := lines.Err(); err != nil {
		return nil, err
	}
	if r.Last == 0 {
		return nil, fmt.Errorf("%s names no last migration", version)
	}
	return r, nil
}

// All is every release frozen under root, oldest first.
func All(root string) ([]*Record, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []*Record
	for _, entry := range entries {
		if !entry.IsDir() || !release.MatchString(entry.Name()) {
			continue
		}
		// A release whose schema is written and whose files are not yet is
		// being frozen, and holds nothing until it is.
		r, err := Read(root, entry.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b *Record) int {
		oa, ob := order(a.Version), order(b.Version)
		return slices.Compare(oa[:], ob[:])
	})
	return out, nil
}

// previous is the last migration of the release recorded before version, or
// zero where there is none.
func previous(records []*Record, version string) int64 {
	var last int64
	for _, r := range records {
		ov, or := order(version), order(r.Version)
		if slices.Compare(or[:], ov[:]) < 0 {
			last = r.Last
		}
	}
	return last
}

// migrationNames lists the files of a migrations directory.
func migrationNames(migrations string) ([]string, error) {
	entries, err := os.ReadDir(migrations)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, entry := range entries {
		if !entry.IsDir() {
			out = append(out, entry.Name())
		}
	}
	return out, nil
}

// Held is what is wrong with a tree against one release's record: a file the
// release owns that it did not list, one it listed that is gone, and one that
// is not the file it tagged. Empty is a tree that still ships what the release
// shipped.
func Held(root, migrations string, r *Record) ([]string, error) {
	records, err := All(root)
	if err != nil {
		return nil, err
	}
	code, err := Code(r.Version)
	if err != nil {
		return nil, err
	}
	names, err := migrationNames(migrations)
	if err != nil {
		return nil, err
	}
	var faults []string
	owned := Owned(names, previous(records, r.Version), r.Last, code)
	for _, name := range owned {
		want, listed := r.Digests[name]
		if !listed {
			faults = append(faults, fmt.Sprintf("%s belongs to %s and the release did not ship it", name, r.Version))
			continue
		}
		content, err := os.ReadFile(filepath.Join(migrations, name)) //nolint:gosec // G304: a file the migrations directory listed
		if err != nil {
			return nil, err
		}
		got, err := Digest(content)
		if err != nil {
			faults = append(faults, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if got != want {
			faults = append(faults, fmt.Sprintf("%s is not the file %s shipped; a change to its schema goes in a later migration",
				name, r.Version))
		}
	}
	for name := range r.Digests {
		if !slices.Contains(owned, name) {
			faults = append(faults, fmt.Sprintf("%s shipped %s and it is not here", r.Version, name))
		}
	}
	slices.Sort(faults)
	return faults, nil
}
