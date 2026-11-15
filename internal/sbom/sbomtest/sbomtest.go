// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package sbomtest reads the full-size inventory fixture for tests and
// measurements in any package.
package sbomtest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// fullSize is the fixture as read, once per binary. Every caller only reads
// the result, and decompressing and reading it is most of what a test of it
// costs.
var fullSize struct {
	once sync.Once
	doc  *sbom.Document
	err  error
}

// FullSizeImage is the full-size fixture, a public switch operating-system
// image, as the inventory reader reads it with the default limits. A test is
// skipped where xz is not installed.
//
// Kept compressed in the repository: the shape is what matters and twenty
// megabytes of it in every checkout is not.
func FullSizeImage(t testing.TB) *sbom.Document {
	t.Helper()
	if _, err := exec.LookPath("xz"); err != nil {
		t.Skip("xz is not available, so the full-size fixture cannot be read here")
	}
	fullSize.once.Do(func() {
		fullSize.doc, fullSize.err = decompressAndRead(t.TempDir())
	})
	if fullSize.err != nil {
		t.Fatal(fullSize.err)
	}
	return fullSize.doc
}

// fixture is the compressed fixture's path, found from this file rather than
// from the working directory, which is the package of whichever test asks.
func fixture() (string, error) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("the fixture's directory cannot be found")
	}
	return filepath.Join(filepath.Dir(here), "..", "testdata", "switch-image.cdx.json.xz"), nil
}

// decompressAndRead decompresses the fixture into dir and reads it.
func decompressAndRead(dir string) (*sbom.Document, error) {
	compressed, err := fixture()
	if err != nil {
		return nil, err
	}
	// Opened relative to a directory the test made, so the name cannot reach
	// outside it however this file is later edited.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	const name = "switch-image.cdx.json"
	out, err := root.Create(name)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("xz", "--decompress", "--stdout", compressed) //nolint:gosec // G204: this file's own fixture
	cmd.Stdout = out
	runErr := cmd.Run()
	if err := out.Close(); err != nil {
		return nil, err
	}
	if runErr != nil {
		return nil, fmt.Errorf("decompress the fixture: %w", runErr)
	}

	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	doc, err := sbom.Read(f, sbom.Limits{})
	if err != nil {
		return nil, fmt.Errorf("read the fixture: %w", err)
	}
	return doc, nil
}
