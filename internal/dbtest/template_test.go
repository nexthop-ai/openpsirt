// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A kept template is what every binary after the first reads, so a kept file
// is used as it stands and nothing is migrated. A file under the name that
// does not open like a database is not trusted: it is migrated again and
// replaced.
func TestAKeptTemplateIsReadAndAnUnreadableOneReplaced(t *testing.T) {
	dir := t.TempDir()
	name, err := templateName()
	if err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(dir, name)

	marked := sqliteHeader + "kept by an earlier binary"
	if err := os.WriteFile(kept, []byte(marked), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := sharedTemplate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != marked {
		t.Errorf("a kept template was not the one read: %d bytes", len(got))
	}

	if err := os.WriteFile(kept, []byte("half a file"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = sharedTemplate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), sqliteHeader) || len(got) < 4096 {
		t.Errorf("an unreadable template was returned rather than migrated again: %d bytes", len(got))
	}
	replaced, err := os.ReadFile(kept) //nolint:gosec // G304: a file this test named inside its own directory
	if err != nil {
		t.Fatal(err)
	}
	if string(replaced) != string(got) {
		t.Error("the migrated template was not kept for the next binary")
	}
}
