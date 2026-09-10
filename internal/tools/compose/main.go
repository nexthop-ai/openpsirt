// Command compose joins several CycloneDX inventories into one that has a
// graph.
//
// The problem it solves. Cataloging a directory finds every package in an
// image and says almost nothing about how they are arranged: the distribution
// packages carry their own dependencies, and the modules inside a compiled
// binary arrive flat — with nothing above them, not even the module that *is*
// the binary. Cataloging one binary produces the opposite: a proper graph, and
// no knowledge of the image around it.
//
// So the image is cataloged as its parts, and this puts them back together.
// Nothing is inferred. Each input says what it found and how it was arranged;
// what is added here is one edge per input's top-level components to the image
// itself, which is what "this image contains that" already means.
//
// The result matters because a finding has to be able to say where it lives. A
// vulnerability in a module of the bundled scanner is real either way; only the
// graph says it is in the scanner rather than in the thing being scanned.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
)

// document is as much of CycloneDX as composing needs. Everything else in an
// input is carried through untouched on the components themselves.
type document struct {
	Schema       string          `json:"$schema,omitempty"`
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber,omitempty"`
	Version      int             `json:"version"`
	Metadata     *metadata       `json:"metadata,omitempty"`
	Components   []component     `json:"components,omitempty"`
	Dependencies []dependency    `json:"dependencies,omitempty"`
	Rest         json.RawMessage `json:"-"`
}

type metadata struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Tools     any        `json:"tools,omitempty"`
	Component *component `json:"component,omitempty"`
}

// component keeps the fields composing reads and preserves the rest verbatim,
// so nothing a producer said is lost on the way through.
type component struct {
	Ref     string `json:"bom-ref,omitempty"`
	Type    string `json:"type,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Purl    string `json:"purl,omitempty"`

	other map[string]json.RawMessage
}

func (c *component) UnmarshalJSON(data []byte) error {
	type plain component
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*c = component(p)
	if err := json.Unmarshal(data, &c.other); err != nil {
		return err
	}
	for _, known := range []string{"bom-ref", "type", "name", "version", "purl"} {
		delete(c.other, known)
	}
	return nil
}

func (c component) MarshalJSON() ([]byte, error) {
	out := map[string]json.RawMessage{}
	for k, v := range c.other {
		out[k] = v
	}
	set := func(key string, value string) {
		if value == "" {
			return
		}
		raw, _ := json.Marshal(value)
		out[key] = raw
	}
	set("bom-ref", c.Ref)
	set("type", c.Type)
	set("name", c.Name)
	set("version", c.Version)
	set("purl", c.Purl)
	return json.Marshal(out)
}

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// identity is what makes the same component in two inputs one component here.
//
// The package identifier where there is one, because that is what every
// producer agrees on and what a scanner matches against. Otherwise the name and
// version, which is what is left. Never the reference the file used: those are
// per-document and two catalogs of the same binary give the same module two of
// them.
func identity(c component) string {
	if c.Purl != "" {
		// Everything after the first "?" is the producer's qualifiers, and
		// syft puts a per-scan package identity there. Two catalogs of one
		// module differ only in that, so it is cut.
		if i := strings.IndexByte(c.Purl, '?'); i > 0 {
			return c.Purl[:i]
		}
		return c.Purl
	}
	return c.Name + "@" + c.Version
}

func main() {
	name := flag.String("name", "", "what the composed inventory is of")
	version := flag.String("version", "", "the version of that thing")
	out := flag.String("out", "", "where to write the result")
	flag.Parse()
	if *name == "" || *out == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: compose -name NAME [-version V] -out FILE INPUT...")
		os.Exit(2)
	}
	if err := run(*name, *version, *out, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "compose:", err)
		os.Exit(1)
	}
}

func run(name, version, out string, inputs []string) error {
	here := os.DirFS(".")
	docs := make([]document, 0, len(inputs))
	for _, path := range inputs {
		body, err := fs.ReadFile(here, strings.TrimPrefix(path, "/"))
		if err != nil {
			return err
		}
		var doc document
		if err := json.Unmarshal(body, &doc); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		docs = append(docs, doc)
	}

	composed, err := compose(name, version, docs)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(composed, "", "  ")
	if err != nil {
		return err
	}
	// Readable only by whoever ran this, which is what the analysis gate
	// allows a program to write and is the right default for one.
	//
	// **The mode travels with the file**, and that is the part worth knowing:
	// a container build copying this into an image carries 0600 along, into an
	// image whose process runs as somebody else — so the document describing
	// what that image contains could not be read from inside it. Widening it
	// belongs to whoever ships it, beside the decision to ship it, and the
	// Dockerfile does exactly that.
	return os.WriteFile(out, append(body, '\n'), 0o600)
}

// compose merges the documents under one root.
func compose(name, version string, docs []document) (*document, error) {
	if len(docs) == 0 {
		return nil, fmt.Errorf("nothing to compose")
	}

	root := component{Ref: "root", Type: "container", Name: name, Version: version}
	composed := &document{
		BOMFormat: "CycloneDX", SpecVersion: docs[0].SpecVersion, Version: 1,
		Metadata: &metadata{Timestamp: docs[0].metaTimestamp(), Component: &root},
	}
	if composed.SpecVersion == "" {
		composed.SpecVersion = "1.6"
	}

	// One entry per distinct component, and one reference per identity, so a
	// module two binaries both link appears once with both parents.
	byIdentity := map[string]string{}
	var components []component
	edges := map[string]map[string]bool{}
	var top []string

	for _, doc := range docs {
		// What this document calls a thing, mapped to what the composed one
		// does. The root of an input is not carried over: it describes the
		// part rather than the whole, and the whole is the root here.
		local := map[string]string{}
		for _, c := range doc.Components {
			// The name this document used, taken before anything is rewritten.
			// Recording it afterwards maps the new reference to itself and
			// leaves every edge in the input pointing at nothing — which reads
			// as a document that placed none of its components, the exact
			// failure this command exists to repair.
			was := c.Ref
			id := identity(c)
			ref, seen := byIdentity[id]
			if !seen {
				ref = id
				byIdentity[id] = ref
				c.Ref = ref
				components = append(components, c)
			}
			if was != "" {
				local[was] = ref
			}
			local[id] = ref
		}

		// Which of this document's components nothing in it places. Those are
		// what the image contains directly as far as this input can say —
		// which for a cataloged binary is its main module, and for a cataloged
		// filesystem is every package no other package pulls in.
		placed := map[string]bool{}
		for _, dep := range doc.Dependencies {
			for _, child := range dep.DependsOn {
				if ref, known := local[child]; known {
					placed[ref] = true
				}
			}
		}
		for _, dep := range doc.Dependencies {
			parent, known := local[dep.Ref]
			if !known {
				// An edge from the input's own root. Its children are what
				// that part contains, and the part is the image here.
				continue
			}
			for _, child := range dep.DependsOn {
				ref, known := local[child]
				if !known {
					continue
				}
				if edges[parent] == nil {
					edges[parent] = map[string]bool{}
				}
				edges[parent][ref] = true
			}
		}
		for _, c := range doc.Components {
			ref := byIdentity[identity(c)]
			if !placed[ref] {
				top = append(top, ref)
			}
		}
	}

	// The root contains everything nothing else placed.
	sort.Strings(top)
	seen := map[string]bool{}
	var children []string
	for _, ref := range top {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		children = append(children, ref)
	}

	sort.Slice(components, func(i, j int) bool { return components[i].Ref < components[j].Ref })
	composed.Components = components
	composed.Dependencies = append(composed.Dependencies,
		dependency{Ref: root.Ref, DependsOn: children})

	parents := make([]string, 0, len(edges))
	for parent := range edges {
		parents = append(parents, parent)
	}
	sort.Strings(parents)
	for _, parent := range parents {
		kids := make([]string, 0, len(edges[parent]))
		for child := range edges[parent] {
			kids = append(kids, child)
		}
		sort.Strings(kids)
		composed.Dependencies = append(composed.Dependencies,
			dependency{Ref: parent, DependsOn: kids})
	}
	return composed, nil
}

func (d document) metaTimestamp() string {
	if d.Metadata == nil {
		return ""
	}
	return d.Metadata.Timestamp
}
