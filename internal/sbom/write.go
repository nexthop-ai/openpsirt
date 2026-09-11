package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// WriteInventory writes what a variant contains, in the form a scanner reads.
//
// The scanner is fed from what we stored rather than from the file a build
// sent, because that file is not kept: a nightly scan is superseded the next
// night and its documents go. Re-scanning a year-old release against today's
// vulnerability data has to work from the inventory, which means whatever was
// not stored cannot be scanned — that is why a component's second identifier
// scheme is captured at ingest rather than when a scanner first wants it.
//
// Only what identifies a component is written. A scanner matches on identity,
// not on structure; the structure is ours, and it is what turns one reported
// issue into the places it occupies.
//
// The product itself is left out. It is not a package any database has heard
// of, and including it invites a match on a name that happens to collide.
func WriteInventory(w io.Writer, components []graph.Described) error {
	sorted := make([]graph.Described, len(components))
	copy(sorted, components)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].Version < sorted[j].Version
	})

	type written struct {
		BomRef  string `json:"bom-ref"`
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Purl    string `json:"purl,omitempty"`
		CPE     string `json:"cpe,omitempty"`
	}

	out := struct {
		BomFormat   string    `json:"bomFormat"`
		SpecVersion string    `json:"specVersion"`
		Version     int       `json:"version"`
		Components  []written `json:"components"`
	}{BomFormat: cyclonedxName, SpecVersion: "1.6", Version: 1}

	for _, c := range sorted {
		out.Components = append(out.Components, written{
			// Our own identity, so that what comes back can be matched to what
			// went in without depending on a name being unique.
			BomRef: c.Identity(), Type: "library",
			Name: c.Name, Version: c.Version, Purl: c.Purl, CPE: c.CPE,
		})
	}

	if err := json.NewEncoder(w).Encode(out); err != nil {
		return fmt.Errorf("write the inventory for scanning: %w", err)
	}
	return nil
}
