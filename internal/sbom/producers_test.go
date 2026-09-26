// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// producerFixtures are real documents from producers the other fixtures do
// not cover, each kept for a shape the reader has to take. README.md says
// where each came from and why.
var producerFixtures = []struct {
	file       string
	components int
	root       string
	// unidentified is how many components carry neither a package identifier
	// nor a CPE, which is what no scanner can match.
	unidentified int
	// distros is how many components' identifiers say which distribution
	// release they were built for, however the identifier spells it.
	distros int
}{
	{file: "tern-photon-image.spdx.json", components: 37, root: "photon", unidentified: 37},
	{file: "sbom-tool-linux.spdx.json", components: 234, root: "SBOM Tool Main Build (YAML)"},
	{file: "apko-wolfi-image.spdx.json", components: 119,
		root:         "sha256:1dc2f617fc4430893004717cace9029b854e1dfb78b3a71220be6f2eb20a4c7f",
		unidentified: 32, distros: 31},
	{file: "oe-linked.spdx.json", components: 1, unidentified: 1},
	{file: "sbom-tool-hello.spdx3.json", components: 0, root: "hello"},
	{file: "maven-dropwizard.cdx.json", components: 167, root: "dropwizard-parent"},
	{file: "saasbom-services.cdx.json", components: 0, root: "Acme Cloud Example"},
	{file: "trivy-ubuntu.cdx.json", components: 102, root: "ubuntu:latest",
		unidentified: 1, distros: 101},
	{file: "snyk-juice-shop.cdx.json", components: 1004, root: "juice-shop"},
	{file: "scout-python-image.spdx.json.xz", components: 142, root: "sbom", distros: 122},
	{file: "github-dependency-graph.spdx.json.xz", components: 545,
		root: "com.github.grafana/loki"},
}

func TestEachProducersOutputReadsAsItsShapeSays(t *testing.T) {
	for _, f := range producerFixtures {
		t.Run(f.file, func(t *testing.T) {
			body := fixtureBytes(t, f.file)
			doc, err := sbom.Read(bytes.NewReader(body), sbom.DefaultLimits())
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			unidentified, distros := 0, 0
			for _, c := range doc.Components {
				if c.Purl == "" && c.CPE == "" {
					unidentified++
				}
				if graph.PartsOfPurl(c.Purl).Distro != "" {
					distros++
				}
			}
			if len(doc.Components) != f.components || doc.Root.Name != f.root ||
				unidentified != f.unidentified || distros != f.distros {
				t.Errorf("read %d components under %q, %d unidentified, %d with a distribution; "+
					"want %d under %q, %d, %d", len(doc.Components), doc.Root.Name,
					unidentified, distros, f.components, f.root, f.unidentified, f.distros)
			}
		})
	}
}

// fixtureBytes is one fixture's contents, decompressed where it is kept
// compressed. A compressed fixture is skipped where xz is missing, as the
// full-size one is.
func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.OpenInRoot("testdata", name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if !strings.HasSuffix(name, ".xz") {
		body, err := io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	if _, err := exec.LookPath("xz"); err != nil {
		t.Skip("xz is not installed, so the compressed fixture cannot be read")
	}
	cmd := exec.Command("xz", "--decompress", "--stdout")
	cmd.Stdin = f
	body, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return body
}
