// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/refusaltest"
)

// Every package here that declares a refusal mapper checks it: a lost
// connection and an unclassified error are faults in each, and each is in the
// table its package passes them through. The checks run inside each package,
// because only a mapper's own package can call it, so a package with a mapper
// and no checks would leave its mappers unread.
func TestEveryPackageWithARefusalMapperChecksIt(t *testing.T) {
	holding := 0
	err := filepath.WalkDir(".", func(dir string, entry fs.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return err
		}
		declared, err := refusaltest.DeclaredIn(os.DirFS(dir))
		if err != nil || len(declared) == 0 {
			return err
		}
		holding++
		checks, err := os.ReadFile(filepath.Join(dir, "refusals_test.go")) //nolint:gosec // G304: a path in this tree
		if err != nil || !strings.Contains(string(checks), "refusaltest.CoversEveryMapper") {
			t.Errorf("%s declares %v and does not check them in its refusals_test.go", dir, declared)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if holding == 0 {
		t.Fatal("no package declaring a refusal mapper was found, so this checked nothing")
	}
}
