package sbom_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

func TestWhatWeStoredCanBeScanned(t *testing.T) {
	// The scanner is fed from the graph rather than from the file a build
	// sent, because that file is not kept. Whatever survives this round trip
	// is what can ever be matched against a vulnerability database.
	held := []graph.Described{
		{Name: "libc6", Version: "2.41", Purl: "pkg:deb/debian/libc6@2.41",
			CPE: "cpe:2.3:a:gnu:glibc:2.41:*:*:*:*:*:*:*"},
		{Name: "frr", Version: "10.5.4-sonic-0", Purl: "pkg:deb/sonic/frr@10.5.4-sonic-0",
			UpstreamName: "frr", UpstreamVersion: "10.5.4"},
	}

	var out bytes.Buffer
	if err := sbom.WriteInventory(&out, held); err != nil {
		t.Fatalf("write: %v", err)
	}

	// It has to read back as the format a scanner accepts, which our own
	// reader is the nearest thing to hand for checking.
	doc, err := sbom.Read(bytes.NewReader(out.Bytes()), sbom.Limits{})
	if err != nil {
		t.Fatalf("what we wrote does not read back: %v", err)
	}
	if len(doc.Components) != 2 {
		t.Errorf("read back %d components, wrote 2", len(doc.Components))
	}
	// It names no product of its own. The product is not a package any
	// database has heard of, and including it invites a match on a name that
	// happens to collide.
	if doc.RootDeclared {
		t.Error("an inventory for scanning named a product of its own")
	}

	var written struct {
		BomFormat  string `json:"bomFormat"`
		Components []struct {
			BomRef  string `json:"bom-ref"`
			Name    string `json:"name"`
			Version string `json:"version"`
			Purl    string `json:"purl"`
			CPE     string `json:"cpe"`
		} `json:"components"`
	}
	if err := json.Unmarshal(out.Bytes(), &written); err != nil {
		t.Fatal(err)
	}
	if written.BomFormat != "CycloneDX" || len(written.Components) != 2 {
		t.Fatalf("wrote %d components in %q", len(written.Components), written.BomFormat)
	}

	// Sorted, so two runs over the same inventory produce the same bytes and a
	// scanner's own caching is not defeated by our ordering.
	if written.Components[0].Name != "frr" {
		t.Errorf("written in %q order", written.Components[0].Name)
	}
	// Both identifier schemes survive: one of them is what matches components
	// a package identifier alone would miss.
	for _, c := range written.Components {
		if c.Name == "libc6" && c.CPE == "" {
			t.Error("the platform enumeration was dropped on the way to the scanner")
		}
		if c.Purl == "" {
			t.Errorf("%s went to the scanner with no package identifier", c.Name)
		}
		if c.BomRef == "" {
			t.Errorf("%s went to the scanner with nothing to match it back by", c.Name)
		}
	}
}
