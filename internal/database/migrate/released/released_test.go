// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package released

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const header = "// Copyright Nexthop Systems Inc.\n// SPDX-License-Identifier: Apache-2.0\n\n"

// tree is a migrations directory and a record directory in a temporary place:
// two releases' migrations, v0.1.0's frozen, and v0.2.0's migration and
// declaration not yet.
func tree(t *testing.T) (root, migrations string) {
	t.Helper()
	base := t.TempDir()
	root, migrations = filepath.Join(base, "released"), filepath.Join(base, "migrations")
	for _, dir := range []string{root, migrations} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		"00001_first.go":  "package migrations\n\n// one\n",
		"00002_second.go": "package migrations\n\n// two\n",
		"00003_v020.go":   "package migrations\n\n// three\n",
		"v020_finding.go": "package migrations\n\n// declared\n",
		"apply.go":        "package migrations\n\n// shared\n",
		"v020_test.go":    "package migrations\n",
	} {
		write(t, filepath.Join(migrations, name), header+body)
	}
	frozen(t, root, migrations, "v0.1.0", 2)
	return root, migrations
}

// frozen records a release the way make release-freeze does, with a schema
// on every engine and the files through its last migration.
func frozen(t *testing.T, root, migrations, version string, last int64) {
	t.Helper()
	names, err := migrationNames(migrations)
	if err != nil {
		t.Fatal(err)
	}
	code, err := Code(version)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("# a release\nlast " + strconv.FormatInt(last, 10) + "\n")
	for _, name := range Owned(names, 0, last, code) {
		content, err := os.ReadFile(filepath.Join(migrations, name)) //nolint:gosec // G304: a file this test wrote
		if err != nil {
			t.Fatal(err)
		}
		digest, err := Digest(content)
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(digest + "  " + name + "\n")
	}
	if err := os.MkdirAll(filepath.Join(root, version), 0o750); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, version, Files), b.String())
	for _, engine := range Engines {
		write(t, filepath.Join(root, version, Schema(engine)), "column t.c int\n")
	}
}

// atV010 takes v0.2.0's files out of the tree, leaving it as v0.1.0 tagged it.
func atV010(t *testing.T, migrations string) {
	t.Helper()
	for _, name := range []string{"00003_v020.go", "v020_finding.go"} {
		if err := os.Remove(filepath.Join(migrations, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil { //nolint:gosec // G703: a path under this test's temporary directory
		t.Fatal(err)
	}
}

func check(t *testing.T, root, migrations, tag string) []string {
	t.Helper()
	faults, err := Check(root, migrations, tag)
	if err != nil {
		t.Fatal(err)
	}
	return faults
}

// A release whose record matches the tree may be tagged, and so may its
// release candidate.
func TestAFrozenReleaseMayBeTagged(t *testing.T) {
	root, migrations := tree(t)
	atV010(t, migrations)
	for _, tag := range []string{"v0.1.0", "v0.1.0-rc.2"} {
		if faults := check(t, root, migrations, tag); len(faults) != 0 {
			t.Errorf("%s was refused: %v", tag, faults)
		}
	}
}

// A release nobody froze is refused, naming the command that freezes it.
func TestAReleaseNobodyFrozeIsRefused(t *testing.T) {
	root, migrations := tree(t)
	faults := check(t, root, migrations, "v0.2.0")
	if len(faults) != 1 || !strings.Contains(faults[0], "make release-freeze VERSION=v0.2.0") {
		t.Errorf("an unfrozen release answered %v", faults)
	}
}

// A migration past the release's last would ship with nothing holding it.
func TestAMigrationPastTheLastFrozenIsRefused(t *testing.T) {
	root, migrations := tree(t)
	if err := os.Remove(filepath.Join(migrations, "v020_finding.go")); err != nil {
		t.Fatal(err)
	}
	faults := check(t, root, migrations, "v0.1.0")
	if len(faults) != 1 || !strings.Contains(faults[0], "00003_v020.go is past v0.1.0's last migration") {
		t.Errorf("a migration past the frozen last answered %v", faults)
	}
}

// Declarations for a release nobody froze would ship with nothing holding
// them.
func TestADeclarationForAnUnfrozenReleaseIsRefused(t *testing.T) {
	root, migrations := tree(t)
	if err := os.Remove(filepath.Join(migrations, "00003_v020.go")); err != nil {
		t.Fatal(err)
	}
	faults := check(t, root, migrations, "v0.1.0")
	if len(faults) != 1 || !strings.Contains(faults[0], "v020_finding.go declares tables for a release nothing froze") {
		t.Errorf("a declaration for an unfrozen release answered %v", faults)
	}
}

// A file edited after it was frozen is stale.
func TestAFileEditedAfterTheFreezeIsRefused(t *testing.T) {
	root, migrations := tree(t)
	atV010(t, migrations)
	write(t, filepath.Join(migrations, "00002_second.go"), header+"package migrations\n\n// edited\n")
	faults := check(t, root, migrations, "v0.1.0")
	if len(faults) != 1 || !strings.Contains(faults[0], "00002_second.go is not the file v0.1.0 froze") {
		t.Errorf("an edited file answered %v", faults)
	}
}

// A release recorded without the schema one engine builds is incomplete.
func TestAReleaseMissingAnEngineIsRefused(t *testing.T) {
	root, migrations := tree(t)
	atV010(t, migrations)
	if err := os.Remove(filepath.Join(root, "v0.1.0", Schema("mysql"))); err != nil {
		t.Fatal(err)
	}
	faults := check(t, root, migrations, "v0.1.0")
	if len(faults) != 1 || !strings.Contains(faults[0], "on mysql") {
		t.Errorf("a record missing an engine answered %v", faults)
	}
}

// A tag that is not a release is refused before anything is read.
func TestATagThatIsNoReleaseIsRefused(t *testing.T) {
	root, migrations := tree(t)
	for _, tag := range []string{"v0.2.0-4-gabc1234", "0.2.0", "v0.2"} {
		if _, err := Check(root, migrations, tag); err == nil {
			t.Errorf("%q was read as a release", tag)
		}
	}
}

// Freezing records the release's migration and its declarations, from past
// the previous release's last, and what it records is what the check accepts.
// The schema is written first, as make release-freeze writes it, so the
// release's directory is already there when its files are recorded.
func TestFreezingRecordsWhatTheReleaseOwns(t *testing.T) {
	root, migrations := tree(t)
	if err := os.MkdirAll(filepath.Join(root, "v0.2.0"), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, engine := range Engines {
		write(t, filepath.Join(root, "v0.2.0", Schema(engine)), "column t.c int\n")
	}
	r, err := Freeze(root, migrations, "v0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for name := range r.Digests {
		names = append(names, name)
	}
	slices.Sort(names)
	if r.Last != 3 || !slices.Equal(names, []string{"00003_v020.go", "v020_finding.go"}) {
		t.Errorf("froze through %d: %v", r.Last, names)
	}
	if faults := check(t, root, migrations, "v0.2.0"); len(faults) != 0 {
		t.Errorf("the release just frozen was refused: %v", faults)
	}
	back, err := Read(root, "v0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if back.Last != r.Last || len(back.Digests) != len(r.Digests) {
		t.Errorf("read back as %+v, froze %+v", back, r)
	}
}

// A release that changes no schema is frozen with no files of its own, and
// may be tagged: a bug-fix release ships the schema of the release before it.
func TestAReleaseWithNoMigrationOfItsOwnIsFrozenEmpty(t *testing.T) {
	root, migrations := tree(t)
	atV010(t, migrations)
	if err := os.MkdirAll(filepath.Join(root, "v0.1.1"), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, engine := range Engines {
		write(t, filepath.Join(root, "v0.1.1", Schema(engine)), "column t.c int\n")
	}
	r, err := Freeze(root, migrations, "v0.1.1")
	if err != nil {
		t.Fatalf("a release with no migration of its own was refused: %v", err)
	}
	if r.Last != 2 || len(r.Digests) != 0 {
		t.Errorf("froze through %d with %v", r.Last, r.Digests)
	}
	if faults := check(t, root, migrations, "v0.1.1"); len(faults) != 0 {
		t.Errorf("the release just frozen was refused: %v", faults)
	}
}

// A file named for the release after its freeze is one it did not ship: a
// second migration in its range, or a declaration carrying its code.
func TestAFileTheReleaseDidNotShipIsRefused(t *testing.T) {
	for _, name := range []string{"00002_another.go", "v010_extra.go"} {
		root, migrations := tree(t)
		atV010(t, migrations)
		write(t, filepath.Join(migrations, name), header+"package migrations\n\n// later\n")
		faults := check(t, root, migrations, "v0.1.0")
		if len(faults) != 1 || !strings.Contains(faults[0], name+" belongs to v0.1.0 and the release did not ship it") {
			t.Errorf("%s, added after the freeze, answered %v", name, faults)
		}
	}
}

// A file the record lists that the tree no longer has is gone from what the
// release shipped.
func TestAFileTheReleaseShippedAndIsGoneIsRefused(t *testing.T) {
	root, migrations := tree(t)
	atV010(t, migrations)
	if err := os.Remove(filepath.Join(migrations, "00001_first.go")); err != nil {
		t.Fatal(err)
	}
	faults := check(t, root, migrations, "v0.1.0")
	if len(faults) != 1 || !strings.Contains(faults[0], "v0.1.0 shipped 00001_first.go and it is not here") {
		t.Errorf("a shipped file removed answered %v", faults)
	}
}

// A release's code is one digit per part, so a version with a part past nine
// is refused rather than given a code another release already reads as.
func TestAReleaseCodeNamesOneReleaseOnly(t *testing.T) {
	for tag, want := range map[string]string{"v0.3.0": "v030", "v1.2.9-rc.1": "v129"} {
		if got, err := Code(tag); err != nil || got != want {
			t.Errorf("%s has code %q (%v), want %q", tag, got, err, want)
		}
	}
	for _, tag := range []string{"v0.1.10", "v0.11.0", "v10.0.0"} {
		if got, err := Code(tag); err == nil {
			t.Errorf("%s was given the code %q, which another release also reads as", tag, got)
		}
	}
}

// The last migration in the tree is the tree's, whichever release owns it, so
// freezing a release older than one already recorded is refused rather than
// claiming the newer one's migration, and says the release cannot be cut.
func TestFreezingAReleaseOlderThanOneRecordedIsRefused(t *testing.T) {
	root, migrations := tree(t)
	frozen(t, root, migrations, "v0.2.0", 3)
	if _, err := Freeze(root, migrations, "v0.1.1"); err == nil ||
		!strings.Contains(err.Error(), "older than v0.2.0") || !strings.Contains(err.Error(), "cannot be cut") {
		t.Errorf("v0.1.1 after v0.2.0 answered %v", err)
	}
}

// A tree whose last migration is behind the release before is not the tree
// the release is cut from.
func TestFreezingATreeBehindThePreviousReleaseIsRefused(t *testing.T) {
	root, migrations := tree(t)
	for _, name := range []string{"00002_second.go", "00003_v020.go"} {
		if err := os.Remove(filepath.Join(migrations, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Freeze(root, migrations, "v0.2.0"); err == nil ||
		!strings.Contains(err.Error(), "behind 2") {
		t.Errorf("a tree behind the previous release answered %v", err)
	}
}

// A schema record that is there and empty says nothing was described, which
// is no more a record than a missing one.
func TestAReleaseWithAnEmptySchemaIsRefused(t *testing.T) {
	root, migrations := tree(t)
	atV010(t, migrations)
	write(t, filepath.Join(root, "v0.1.0", Schema("mysql")), "")
	faults := check(t, root, migrations, "v0.1.0")
	if len(faults) != 1 || !strings.Contains(faults[0], "on mysql") {
		t.Errorf("an empty schema record answered %v", faults)
	}
}

// A digest is taken of what follows the license header, so a file without
// the header, or with nothing after it, has none.
func TestADigestNeedsTheHeaderAndABody(t *testing.T) {
	for what, content := range map[string]string{
		"no header":        "package migrations\n\n// one\n",
		"nothing after it": "// Copyright Nexthop Systems Inc.\n// SPDX-License-Identifier: Apache-2.0\n",
	} {
		if _, err := Digest([]byte(content)); err == nil {
			t.Errorf("%s: a digest was taken", what)
		}
	}
	if _, err := Digest([]byte(header + "package migrations\n")); err != nil {
		t.Errorf("a file with its header and a body: %v", err)
	}
}

// A record line that is neither the last migration nor a digest and a file is
// refused, naming the line, rather than skipped.
func TestAMalformedRecordLineIsRefused(t *testing.T) {
	root, _ := tree(t)
	write(t, filepath.Join(root, "v0.1.0", Files), "last 2\nabc123  00001_first.go\n")
	if _, err := Read(root, "v0.1.0"); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("a short digest answered %v", err)
	}
}

// A release whose migrations were replaced by a baseline holds none of the
// files it shipped and refuses one that reappears, numbered or named as its
// own, and the release after it is still held to its own.
func TestABaselineReleaseHoldsNoFilesAndTheNextIsStillHeld(t *testing.T) {
	root, migrations := tree(t)
	for _, name := range []string{"00001_first.go", "00002_second.go"} {
		if err := os.Remove(filepath.Join(migrations, name)); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(migrations, "00002_baseline.go"), header+"package migrations\n\n// made at once\n")
	write(t, filepath.Join(root, "v0.1.0", Files), "# a baseline\nbaseline\nlast 2\n")
	if _, err := Freeze(root, migrations, "v0.2.0"); err != nil {
		t.Fatal(err)
	}
	for _, engine := range Engines {
		write(t, filepath.Join(root, "v0.2.0", Schema(engine)), "column t.c int\n")
	}
	baseline, err := Read(root, "v0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if faults, err := Held(root, migrations, baseline); err != nil || len(faults) != 0 {
		t.Errorf("the baseline release was held to files: %v %v", faults, err)
	}
	for _, name := range []string{"00001_misnumbered.go", "v010_table.go"} {
		path := filepath.Join(migrations, name)
		write(t, path, header+"package migrations\n")
		if faults, err := Held(root, migrations, baseline); err != nil || len(faults) != 1 {
			t.Errorf("%s, a file the baseline replaced, answered %v %v", name, faults, err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if faults := check(t, root, migrations, "v0.2.0"); len(faults) != 0 {
		t.Errorf("the release after the baseline was refused: %v", faults)
	}
	write(t, filepath.Join(migrations, "00003_v020.go"), header+"package migrations\n\n// edited\n")
	if faults := check(t, root, migrations, "v0.2.0"); len(faults) != 1 {
		t.Errorf("an edit to the release after a baseline answered %v", faults)
	}
}

// A baseline record that lists a file is refused: the files a baseline
// replaced are gone from the tree.
func TestABaselineRecordListingAFileIsRefused(t *testing.T) {
	root, _ := tree(t)
	content, err := os.ReadFile(filepath.Join(root, "v0.1.0", Files)) //nolint:gosec // G304: a record this test wrote
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "v0.1.0", Files), "baseline\n"+string(content))
	if _, err := Read(root, "v0.1.0"); err == nil || !strings.Contains(err.Error(), "baseline") {
		t.Errorf("a baseline listing files answered %v", err)
	}
}
