// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package released

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Check is what is wrong with tagging a release from this tree. The release
// has to have been frozen: a record of its files, each file still the one
// recorded, the schema it builds recorded on every engine, and no migration in
// the tree past its last — one there would ship without anything holding it.
func Check(root, migrations, tag string) ([]string, error) {
	version, err := Base(tag)
	if err != nil {
		return nil, err
	}
	r, err := Read(root, version)
	if errors.Is(err, os.ErrNotExist) {
		return []string{fmt.Sprintf("%s has no record of its migrations: run make release-freeze VERSION=%s "+
			"on a branch from the head of main, and land it before the tag", version, version)}, nil
	}
	if err != nil {
		return nil, err
	}
	faults, err := Held(root, migrations, r)
	if err != nil {
		return nil, err
	}
	for _, engine := range Engines {
		info, err := os.Stat(filepath.Join(root, version, Schema(engine)))
		if err != nil || info.Size() == 0 {
			faults = append(faults, fmt.Sprintf("%s has no record of the schema it builds on %s", version, engine))
		}
	}
	names, err := migrationNames(migrations)
	if err != nil {
		return nil, err
	}
	records, err := All(root)
	if err != nil {
		return nil, err
	}
	codes := map[string]bool{}
	for _, each := range records {
		code, err := Code(each.Version)
		if err != nil {
			return nil, err
		}
		codes[code] = true
	}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		if n := Number(name); n > r.Last {
			faults = append(faults, fmt.Sprintf("%s is past %s's last migration, %d, and nothing holds it: "+
				"if %s is not tagged yet, freeze it again; once it is, the migration belongs to the next release",
				name, version, r.Last, version))
		}
		if m := declaration.FindStringSubmatch(name); m != nil && !codes[m[1]] {
			faults = append(faults, fmt.Sprintf("%s declares tables for a release nothing froze", name))
		}
	}
	return faults, nil
}

// declaration is the name of a file holding a release's table declarations,
// and the code of the release it is for.
var declaration = regexp.MustCompile(`^(v\d+)_[a-z_]+\.go$`)

// Freeze writes the record of a release's files: every migration past the
// previous release's last, and every declaration carrying its code. The
// schema each engine builds is written beside it first, by a test, because
// only a test has the engines.
//
// A release that changes no schema has a record listing no files, with the
// previous release's last migration as its own. It is still a record: the
// check refuses a tag with none, and a release that ships nothing new still
// ships the schema before it.
func Freeze(root, migrations, tag string) (*Record, error) {
	version, err := Base(tag)
	if err != nil {
		return nil, err
	}
	code, err := Code(version)
	if err != nil {
		return nil, err
	}
	records, err := All(root)
	if err != nil {
		return nil, err
	}
	names, err := migrationNames(migrations)
	if err != nil {
		return nil, err
	}
	var last int64
	for _, name := range names {
		if n := Number(name); n > last && !strings.HasSuffix(name, "_test.go") {
			last = n
		}
	}
	before := previous(records, version)
	if last < before {
		return nil, fmt.Errorf("the last migration here is %d, behind %d, the last of the release before %s",
			last, before, version)
	}
	r := &Record{Version: version, Last: last, Digests: map[string]string{}}
	var b strings.Builder
	fmt.Fprintf(&b, "# The migrations %s tagged, and the digest of each file below its license header.\n", version)
	fmt.Fprintf(&b, "last %d\n", last)
	for _, name := range Owned(names, before, last, code) {
		content, err := os.ReadFile(filepath.Join(migrations, name)) //nolint:gosec // G304: a file the migrations directory listed
		if err != nil {
			return nil, err
		}
		digest, err := Digest(content)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		r.Digests[name] = digest
		fmt.Fprintf(&b, "%s  %s\n", digest, name)
	}
	if err := os.MkdirAll(filepath.Join(root, version), 0o750); err != nil {
		return nil, err
	}
	return r, os.WriteFile(filepath.Join(root, version, Files), []byte(b.String()), 0o600)
}
