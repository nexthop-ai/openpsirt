// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sync"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate/released"
)

// The sources of every migration in this package.
//
// Embedded so that a database somebody built earlier can be recognized as
// still built by these. Below 1.0 a schema change edits what declares the
// thing rather than adding a migration beside it, so the set of migration
// names says nothing about whether a database matches the
// schema this build expects — the version stays where it was and the tables
// are wrong. Only the content distinguishes them.
//
//go:embed *.go
var sources embed.FS

var (
	fingerprintOnce sync.Once
	fingerprint     string
	fingerprintErr  error
)

// Fingerprint identifies this migration set by what it contains.
//
// The same bytes give the same value on every machine and every run: the files
// are read in name order and hashed with their names, so adding, removing or
// editing one changes it. It is not a version — nothing orders two of these —
// and nothing about the running application depends on it. It exists for the
// test harness, which keeps a migrated database between runs and needs to know
// whether the migrations that built it are the ones in hand.
func Fingerprint() (string, error) {
	fingerprintOnce.Do(func() {
		names, err := fs.Glob(sources, "*.go")
		if err != nil {
			fingerprintErr = err
			return
		}
		// Glob answers in lexical order, which is what makes the hash the same
		// on two machines; sorting again would only hide it if that changed.
		sum := sha256.New()
		for _, name := range names {
			content, err := sources.ReadFile(name)
			if err != nil {
				fingerprintErr = fmt.Errorf("read %s: %w", name, err)
				return
			}
			_, _ = fmt.Fprintf(sum, "%s\x00%d\x00", name, len(content))
			_, _ = sum.Write(content)
		}
		fingerprint = hex.EncodeToString(sum.Sum(nil))
	})
	return fingerprint, fingerprintErr
}

var (
	expectedOnce sync.Once
	expected     int64
	expectedErr  error
)

// Expected is the highest migration version this build carries.
//
// Read from the embedded sources rather than from the migration library, which
// holds the registered set in package-level state with no way to ask it. The
// number in a migration's file name is its version — that is the library's own
// rule, and the registration in each file's init is keyed on it — so the two
// cannot disagree without the file being misnamed, which nothing else would
// accept either.
//
// It exists for this: a deployment that applies migrations separately needs to
// know whether the database is behind the binary, and "behind" needs a number
// on both sides: the applied version is one, and this is the other.
func Expected() (int64, error) {
	expectedOnce.Do(func() {
		names, err := fs.Glob(sources, "*.go")
		if err != nil {
			expectedErr = err
			return
		}
		expected, expectedErr = highestOf(names)
	})
	return expected, expectedErr
}

// highestOf is the highest migration among the embedded file names, by the
// rule the release records read, so the two cannot disagree over a test file
// the embedding includes.
func highestOf(names []string) (int64, error) {
	highest := released.Highest(names)
	if highest == 0 {
		return 0, fmt.Errorf("this build carries no migrations")
	}
	return highest, nil
}
