// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

func TestAComponentsNameAndVersionArriveWithoutControlCharacters(t *testing.T) {
	// A name or a version is joined into keys with control characters as
	// separators, so one carrying a separator reads back as another
	// component, or as two version pairs sharing one key.
	library := `{"bom-ref": "a", "name": "libc", "version": "2.41", "purl": "pkg:deb/debian/libc6@2.41"}`
	cases := map[string]string{
		"CycloneDX": strings.Replace(minimal, library,
			`{"bom-ref": "a", "name": "lib\u001ec", "version": "2.\u000041",
			  "purl": "pkg:deb/debian/libc6@2.41?upstream=glibc%40a%00b"}`, 1),
		"SPDX 2": strings.Replace(strings.Replace(minimalSPDX, `"name": "libc"`, `"name": "lib\u001fc"`, 1),
			`"versionInfo": "2.41"`, `"versionInfo": "2.\u001e41"`, 1),
		"SPDX 3": strings.Replace(strings.Replace(minimalSPDX3, `"name": "libc"`, `"name": "lib\u0007c"`, 1),
			`"software_packageVersion": "2.41"`, `"software_packageVersion": "2.\u001f41"`, 1),
	}
	for format, body := range cases {
		t.Run(format, func(t *testing.T) {
			if body == minimal || body == minimalSPDX || body == minimalSPDX3 {
				t.Fatal("the fixture's component moved")
			}
			doc := read(t, body)
			if len(doc.Components) != 1 {
				t.Fatalf("read %d components", len(doc.Components))
			}
			got := doc.Components[0]
			if got.Name != "libc" || got.Version != "2.41" {
				t.Errorf("read %q at %q", got.Name, got.Version)
			}
			if format == "CycloneDX" && (got.UpstreamName != "glibc" || got.UpstreamVersion != "ab") {
				t.Errorf("built from %q at %q", got.UpstreamName, got.UpstreamVersion)
			}
		})
	}

	nothing := strings.Replace(minimal, `"name": "libc"`, `"name": "\u001e\u001f"`, 1)
	if _, err := sbom.Read(strings.NewReader(nothing), sbom.Limits{}); err == nil {
		t.Error("a component named by control characters alone was read")
	}
}
