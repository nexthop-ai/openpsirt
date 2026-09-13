package sbom_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// read parses a document written inline in a test.
func read(t *testing.T, body string) *sbom.Document {
	t.Helper()
	doc, err := sbom.Read(strings.NewReader(body), sbom.Limits{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return doc
}

// refuses parses a document that should not be accepted, and returns why.
func refuses(t *testing.T, body string) string {
	t.Helper()
	doc, err := sbom.Read(strings.NewReader(body), sbom.Limits{})
	if err == nil {
		t.Fatalf("expected a refusal, got a document with %d components", len(doc.Components))
	}
	return err.Error()
}

// fixture reads one of the recorded producer documents.
func fixture(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.OpenInRoot("testdata", name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// edges renders the graph as parent -> child, by name, for comparison.
func edges(doc *sbom.Document) []string {
	var out []string
	for _, d := range doc.Dependencies {
		out = append(out, d.Parent.Name+" -> "+d.Child.Name)
	}
	return out
}

// minimal is the smallest document that says enough to be read.
const minimal = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6",
  "metadata": {"component": {"bom-ref": "root", "name": "product", "version": "1.0"}},
  "components": [{"bom-ref": "a", "name": "libc", "version": "2.41", "purl": "pkg:deb/debian/libc6@2.41"}],
  "dependencies": [{"ref": "root", "dependsOn": ["a"]}]
}`

func TestReadsAnAggregateImageDocument(t *testing.T) {
	doc, err := sbom.Read(fixture(t, "image.cdx.json"), sbom.Limits{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if doc.Root.Name != "sonic-broadcom.bin" {
		t.Errorf("root is %q", doc.Root.Name)
	}
	if want := "urn:uuid:1c9f4b6a-6a2e-5a0d-9b4a-2f1c7d3e8a55"; doc.Serial != want {
		t.Errorf("serial is %q, want %q", doc.Serial, want)
	}
	if want := time.Date(2026, 8, 14, 9, 12, 33, 0, time.UTC); !doc.BuiltAt.Equal(want) {
		t.Errorf("built at %v, want %v", doc.BuiltAt, want)
	}
	if len(doc.Components) != 6 {
		t.Errorf("read %d components, want 6", len(doc.Components))
	}

	// A shared library reached from three places is one component with three
	// edges, not three copies of it.
	var into int
	for _, d := range doc.Dependencies {
		if d.Child.Name == "libc6" {
			into++
		}
	}
	if into != 3 {
		t.Errorf("libc6 is reached by %d edges, want 3", into)
	}

	// A component the producer could not place stays unplaced rather than
	// being attached to the root on the assumption that it must be somewhere.
	if doc.Unrooted != 1 {
		t.Errorf("%d components sit under nothing, want 1 (paramiko)", doc.Unrooted)
	}
}

func TestTheOtherIdentifierSchemeIsKeptWithoutMovingIdentity(t *testing.T) {
	// A package identifier is what identity is derived from. The platform
	// enumeration is what the national vulnerability database keys on, and a
	// scanner given one matches things a package identifier alone misses — so
	// it is worth keeping, and a scan file is not kept to be re-read later.
	//
	// It must not reach identity. Deriving identity from both would move the
	// identity of every component that carries the second one, which takes
	// every triage decision attached to it along.
	doc, err := sbom.Read(fixture(t, "image.cdx.json"), sbom.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range doc.Components {
		if c.Name != "libc6" {
			continue
		}
		found = true
		if c.CPE == "" {
			t.Error("the platform enumeration was dropped")
		}
		without := c
		without.CPE = ""
		if c.Identity() != without.Identity() {
			t.Error("the platform enumeration reached identity")
		}
	}
	if !found {
		t.Fatal("the component carrying one is missing")
	}
}

func TestPedigreeSuppliesUpstreamIdentity(t *testing.T) {
	doc, err := sbom.Read(fixture(t, "image.cdx.json"), sbom.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Components {
		if c.Name != "frr" {
			continue
		}
		if c.Version != "10.5.4-sonic-0" {
			t.Errorf("shipped version is %q", c.Version)
		}
		if c.UpstreamName != "frr" || c.UpstreamVersion != "10.5.4" {
			t.Errorf("upstream is %q %q, want frr 10.5.4", c.UpstreamName, c.UpstreamVersion)
		}
		return
	}
	t.Fatal("the forked component is missing")
}

func TestReadsAGoModuleDocument(t *testing.T) {
	doc, err := sbom.Read(fixture(t, "gomod-app.cdx.json"), sbom.Limits{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if doc.Root.Name != "github.com/nexthop-ai/openpsirt" {
		t.Errorf("root is %q", doc.Root.Name)
	}
	// This producer's identifiers are not its package identifiers — the two
	// differ by build platform and by the entry point. Edges resolve through
	// the identifiers, so a reader that matched on package identifier instead
	// would find no edge at all.
	if len(doc.Dependencies) == 0 {
		t.Fatal("no edges resolved")
	}
	// Modules hold the packages they are made of. That nesting is the only
	// structure this producer states for them, so losing it would leave every
	// package sitting under nothing.
	var nested int
	for _, d := range doc.Dependencies {
		if strings.HasPrefix(d.Child.Purl, "pkg:golang/") && strings.Contains(d.Child.Purl, "type=package") {
			nested++
		}
	}
	if nested == 0 {
		t.Error("nested packages produced no containment edges")
	}
}

func TestADocumentNamingNoComponentOfItsOwnIsFiledAgainstItsTarget(t *testing.T) {
	// The format requires only a format and a version, so a document that
	// names no component of its own is ordinary. It was filed against a
	// declared product, stream and variant, and that is what it is about —
	// standing in costs nothing, because what a root says about itself is
	// excluded from identity and expiry either way.
	doc, err := sbom.Read(fixture(t, "build-fragment.cdx.json"), sbom.Limits{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if doc.RootDeclared {
		t.Error("a document that named no component of its own says it did")
	}
	if len(doc.Components) != 1 {
		t.Fatalf("read %d components, want 1", len(doc.Components))
	}

	target := graph.Described{Name: "sonic", Version: "master"}
	snap := doc.Snapshot(target)
	if snap.Root.Identity() != target.Identity() {
		t.Error("the target did not stand in as the root")
	}

	// A document that does name one keeps it.
	rooted, err := sbom.Read(fixture(t, "image.cdx.json"), sbom.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !rooted.RootDeclared {
		t.Fatal("a document that named a component of its own says it did not")
	}
	if rooted.Snapshot(target).Root.Name != "sonic-broadcom.bin" {
		t.Error("the target displaced a root the document named")
	}
}

func TestTheFilesOwnIdentifiersNeverReachIdentity(t *testing.T) {
	// The proof that a producer renumbering its own identifiers changes
	// nothing we store. Every identifier in the document is replaced; the
	// components, their identities and the graph between them must be
	// unchanged.
	original, err := os.ReadFile(filepath.Join("testdata", "image.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(original, &doc); err != nil {
		t.Fatal(err)
	}

	renamed := map[string]string{}
	rename := func(ref string) string {
		if _, ok := renamed[ref]; !ok {
			renamed[ref] = fmt.Sprintf("urn:cdx:shuffled:%d", len(renamed))
		}
		return renamed[ref]
	}
	root := doc["metadata"].(map[string]any)["component"].(map[string]any)
	root["bom-ref"] = rename(root["bom-ref"].(string))
	for _, c := range doc["components"].([]any) {
		comp := c.(map[string]any)
		comp["bom-ref"] = rename(comp["bom-ref"].(string))
	}
	for _, d := range doc["dependencies"].([]any) {
		dep := d.(map[string]any)
		dep["ref"] = rename(dep["ref"].(string))
		on := dep["dependsOn"].([]any)
		for i, child := range on {
			on[i] = rename(child.(string))
		}
	}
	shuffled, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	before := read(t, string(original))
	after := read(t, string(shuffled))

	if before.Root.Identity() != after.Root.Identity() {
		t.Error("the root's identity moved with the file's identifiers")
	}
	if len(before.Components) != len(after.Components) {
		t.Fatalf("component count changed: %d then %d", len(before.Components), len(after.Components))
	}
	for i := range before.Components {
		if before.Components[i].Identity() != after.Components[i].Identity() {
			t.Errorf("component %d changed identity", i)
		}
	}
	b, a := strings.Join(edges(before), "\n"), strings.Join(edges(after), "\n")
	if b != a {
		t.Errorf("the graph changed:\n%s\n---\n%s", b, a)
	}
}

func TestAnEdgeNamingAnUndescribedComponentIsDroppedAndCounted(t *testing.T) {
	// Inventing the missing component would report a dependency on something
	// nobody declared. Refusing the document would throw away tens of
	// thousands of good components over one edge, and producers differ in how
	// completely they state a graph.
	doc := read(t, strings.Replace(minimal, `"dependsOn": ["a"]`, `"dependsOn": ["a", "ghost"]`, 1))
	if doc.DanglingEdges != 1 {
		t.Errorf("%d edges went nowhere, want 1", doc.DanglingEdges)
	}
	if len(doc.Dependencies) != 1 {
		t.Errorf("kept %d edges, want the one that resolved", len(doc.Dependencies))
	}
}

func TestTwoComponentsSharingAnIdentifierAreRefused(t *testing.T) {
	// Every edge naming that identifier would be a coin toss between them.
	why := refuses(t, strings.Replace(minimal,
		`{"bom-ref": "a", "name": "libc", "version": "2.41", "purl": "pkg:deb/debian/libc6@2.41"}`,
		`{"bom-ref": "a", "name": "libc", "version": "2.41", "purl": "pkg:deb/debian/libc6@2.41"},
		 {"bom-ref": "a", "name": "zlib", "version": "1.3", "purl": "pkg:deb/debian/zlib1g@1.3"}`, 1))
	if !strings.Contains(why, "ambiguous") {
		t.Errorf("refusal does not say why it matters: %s", why)
	}
}

func TestAComponentWithoutAVersionIsKeptAndCounted(t *testing.T) {
	// The format requires a type and a name and nothing else. What a component
	// with no version costs is matching, not tracking — and it ships either
	// way, so it is better visible than discarded along with the rest of the
	// document.
	doc := read(t, strings.Replace(minimal, `"version": "2.41", `, "", 1))
	if len(doc.Components) != 1 || doc.Unversioned != 1 {
		t.Errorf("read %d components, %d of them stating no version", len(doc.Components), doc.Unversioned)
	}
}

func TestAComponentWithoutANameIsRefused(t *testing.T) {
	// Nothing can identify it, so nothing can track it.
	why := refuses(t, strings.Replace(minimal, `"name": "libc", `, "", 1))
	if !strings.Contains(why, "no name") || !strings.Contains(why, "cannot be tracked") {
		t.Errorf("refusal does not name the fault or what it costs: %s", why)
	}
}

func TestAComponentUnderNothingIsOrdinary(t *testing.T) {
	// A producer emits the edges it can derive and records what it could not.
	// Refusing the file would reject a legitimate scan.
	doc := read(t, strings.Replace(minimal, `"dependencies": [{"ref": "root", "dependsOn": ["a"]}]`,
		`"dependencies": []`, 1))
	if len(doc.Components) != 1 || doc.Unrooted != 1 {
		t.Errorf("read %d components, %d of them under nothing", len(doc.Components), doc.Unrooted)
	}
}

func TestAnEdgeBetweenTwoNamesForOneComponentIsDropped(t *testing.T) {
	// The producer could not have known: its two identifiers differ. Identity
	// comes from content, which is what makes them the same component and the
	// edge between them meaningless.
	doc := read(t, strings.Replace(minimal,
		`"components": [{"bom-ref": "a", "name": "libc", "version": "2.41", "purl": "pkg:deb/debian/libc6@2.41"}]`,
		`"components": [{"bom-ref": "a", "name": "libc", "version": "2.41", "purl": "pkg:deb/debian/libc6@2.41"},
		  {"bom-ref": "b", "name": "libc", "version": "2.41", "purl": "pkg:deb/debian/libc6@2.41"}]`, 1))
	doc2 := read(t, strings.Replace(strings.Replace(minimal,
		`"components": [{"bom-ref": "a", "name": "libc", "version": "2.41", "purl": "pkg:deb/debian/libc6@2.41"}]`,
		`"components": [{"bom-ref": "a", "name": "libc", "version": "2.41", "purl": "pkg:deb/debian/libc6@2.41"},
		  {"bom-ref": "b", "name": "libc", "version": "2.41", "purl": "pkg:deb/debian/libc6@2.41"}]`, 1),
		`"dependsOn": ["a"]`, `"dependsOn": ["a"]}, {"ref": "a", "dependsOn": ["b"]`, 1))

	if len(doc.Components) != 1 {
		t.Errorf("two names for one component read as %d components", len(doc.Components))
	}
	if doc2.SelfReferences != 1 {
		t.Errorf("%d edges dropped for joining a component to itself, want 1", doc2.SelfReferences)
	}
	for _, d := range doc2.Dependencies {
		if d.Parent.Identity() == d.Child.Identity() {
			t.Error("an edge joins a component to itself")
		}
	}
}

func TestSomethingThatIsNotThisFormatIsRefused(t *testing.T) {
	why := refuses(t, `{"bomFormat": "SPDX", "specVersion": "2.3"}`)
	if !strings.Contains(why, "CycloneDX") {
		t.Errorf("refusal does not say what was expected: %s", why)
	}
	why = refuses(t, strings.Replace(minimal, `"specVersion": "1.6"`, `"specVersion": "2.0"`, 1))
	if !strings.Contains(why, "2.0") {
		t.Errorf("refusal does not name the version: %s", why)
	}
}

func TestAnOversizeDocumentIsRefusedAsOversize(t *testing.T) {
	// Not as a malformed one. Whoever reads the message has to know whether to
	// look at their file or at their limits.
	_, err := sbom.Read(strings.NewReader(minimal), sbom.Limits{MaxBytes: 64})
	if err == nil {
		t.Fatal("an oversize document was accepted")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("refusal reads as something else: %v", err)
	}
}

func TestMoreComponentsThanAllowedAreRefused(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"bomFormat": "CycloneDX", "specVersion": "1.6",
	 "metadata": {"component": {"bom-ref": "root", "name": "p", "version": "1"}}, "components": [`)
	for i := range 50 {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"bom-ref": "c%d", "name": "c%d", "version": "1"}`, i, i)
	}
	b.WriteString("]}")

	if _, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxComponents: 10}); err == nil {
		t.Fatal("a document past the component limit was accepted")
	} else if !strings.Contains(err.Error(), "component limit") {
		t.Errorf("refusal does not name the limit: %v", err)
	}
	if _, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxComponents: 100}); err != nil {
		t.Errorf("a document inside the limit was refused: %v", err)
	}
}

func TestDeeperNestingThanAllowedIsRefused(t *testing.T) {
	// A document nested far enough to exhaust the process has to fail as a
	// refusal rather than as a crash, including where the nesting sits in a
	// part of the document nothing reads.
	var b strings.Builder
	b.WriteString(`{"bomFormat": "CycloneDX", "specVersion": "1.6", "properties": `)
	const deep = 400
	for range deep {
		b.WriteString("[")
	}
	for range deep {
		b.WriteString("]")
	}
	b.WriteString(`, "metadata": {"component": {"name": "p", "version": "1"}}}`)

	if _, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxDepth: 16}); err == nil {
		t.Fatal("a document past the nesting limit was accepted")
	} else if !strings.Contains(err.Error(), "nests deeper") {
		t.Errorf("refusal does not name the limit: %v", err)
	}
}

func TestMoreEdgesThanAllowedAreRefused(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"bomFormat": "CycloneDX", "specVersion": "1.6",
	 "metadata": {"component": {"bom-ref": "root", "name": "p", "version": "1"}},
	 "components": [{"bom-ref": "a", "name": "a", "version": "1"}],
	 "dependencies": [{"ref": "root", "dependsOn": [`)
	for i := range 40 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"a"`)
	}
	b.WriteString(`]}]}`)

	if _, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxEdges: 10}); err == nil {
		t.Fatal("a document past the dependency limit was accepted")
	} else if !strings.Contains(err.Error(), "dependency limit") {
		t.Errorf("refusal does not name the limit: %v", err)
	}
}

func TestTheHeaderReadsWithoutTheContents(t *testing.T) {
	// What an arriving scan is judged on — when it was built, what it is, and
	// the identity that joins it to anything produced from it — is answered
	// without parsing components, whatever order the producer wrote its keys
	// in.
	head, err := sbom.ReadHeader(fixture(t, "image.cdx.json"), sbom.Limits{})
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if head.Root.Name != "sonic-broadcom.bin" || head.Serial == "" || head.BuiltAt.IsZero() {
		t.Errorf("header is %+v", head)
	}

	// The recorded producer writes its keys in sorted order, which puts the
	// components before the metadata.
	sorted := `{"bomFormat": "CycloneDX", "components": [{"bom-ref": "a", "name": "libc", "version": "2.41"}],
	 "metadata": {"component": {"name": "p", "version": "9"}, "timestamp": "2026-01-02T03:04:05Z"},
	 "serialNumber": "urn:uuid:9", "specVersion": "1.6"}`
	head, err = sbom.ReadHeader(strings.NewReader(sorted), sbom.Limits{})
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if head.Root.Version != "9" || head.Serial != "urn:uuid:9" {
		t.Errorf("header is %+v", head)
	}
	if want := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC); !head.BuiltAt.Equal(want) {
		t.Errorf("built at %v, want %v", head.BuiltAt, want)
	}
}

func TestAnUnreadableBuildTimeIsRefused(t *testing.T) {
	// The build time orders scans against each other. A value nobody can read
	// is not a scan we can place.
	why := refuses(t, strings.Replace(minimal, `"metadata": {`, `"metadata": {"timestamp": "last tuesday", `, 1))
	if !strings.Contains(why, "is not a time") {
		t.Errorf("refusal does not say what is wrong: %s", why)
	}
}

func TestTheSnapshotCarriesWhatTheGraphStores(t *testing.T) {
	doc, err := sbom.Read(fixture(t, "image.cdx.json"), sbom.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	snap := doc.Snapshot(graph.Described{Name: "stand-in"})
	if snap.Root.Identity() != doc.Root.Identity() {
		t.Error("the snapshot is about something else")
	}
	if len(snap.Components) != len(doc.Components) || len(snap.Dependencies) != len(doc.Dependencies) {
		t.Error("the snapshot and the document disagree")
	}
	// Every edge has to name a component the snapshot lists, or the graph
	// refuses to apply it.
	listed := map[string]bool{snap.Root.Identity(): true}
	for _, c := range snap.Components {
		listed[c.Identity()] = true
	}
	for _, d := range snap.Dependencies {
		if !listed[d.Parent.Identity()] || !listed[d.Child.Identity()] {
			t.Errorf("edge %s -> %s names something the snapshot does not list", d.Parent.Name, d.Child.Name)
		}
	}
}

func TestRepeatingOneComponentDoesNotEvadeTheLimit(t *testing.T) {
	// The bound has to count what the document states, not what survives
	// deduplication. Counting survivors means a file of one component repeated
	// is unbounded: every copy is read and held, and the count that was
	// supposed to stop it never moves.
	var b strings.Builder
	b.WriteString(`{"bomFormat": "CycloneDX", "specVersion": "1.6",
	 "metadata": {"component": {"name": "p", "version": "1"}}, "components": [`)
	for i := range 200 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"name": "same", "version": "1", "purl": "pkg:deb/debian/same@1"}`)
	}
	b.WriteString("]}")

	_, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxComponents: 20})
	if err == nil {
		t.Fatal("a document repeating one component past the limit was accepted")
	}
	if !strings.Contains(err.Error(), "component limit") {
		t.Errorf("refusal does not name the limit: %v", err)
	}
}

func TestOneHugeDependencyListIsRefusedWhileItIsRead(t *testing.T) {
	// Collecting the whole list and checking afterwards means the memory is
	// already spent by the time the bound is consulted, which is the thing the
	// bound exists to prevent. A single component can name as many
	// dependencies as it likes.
	var b strings.Builder
	b.WriteString(`{"bomFormat": "CycloneDX", "specVersion": "1.6",
	 "metadata": {"component": {"bom-ref": "root", "name": "p", "version": "1"}},
	 "components": [{"bom-ref": "a", "name": "a", "version": "1"}],
	 "dependencies": [{"ref": "root", "dependsOn": [`)
	for i := range 500 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"a"`)
	}
	b.WriteString(`]}]}`)

	_, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxEdges: 50})
	if err == nil {
		t.Fatal("a single dependency list past the limit was accepted")
	}
	if !strings.Contains(err.Error(), "dependency limit") {
		t.Errorf("refusal does not name the limit: %v", err)
	}
}

func TestReadsTheRevisionEveryShippedInventoryStates(t *testing.T) {
	// The reader checks the major version and accepts any minor revision,
	// which is deliberate: a revision of the format adds fields rather than
	// moving the ones read. What that leaves is a revision accepted by
	// construction rather than by evidence, and the one every inventory this
	// deployment ships now states was exactly that — the producer moved to
	// 1.7 while every fixture here said 1.6.
	//
	// So this is the same document the image carries and the demo ingests,
	// read through the same reader, asserting the parts a revision could move:
	// the root, the components, the edges, and the identifiers the graph is
	// built from.
	doc, err := sbom.Read(fixture(t, "openpsirt-image.cdx.json"), sbom.Limits{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if doc.Root.Name != "openpsirt-image" {
		t.Errorf("root is %q", doc.Root.Name)
	}
	if len(doc.Components) != 347 {
		t.Errorf("%d components, want 347", len(doc.Components))
	}
	if len(doc.Dependencies) == 0 {
		t.Fatal("no edges resolved, so the document describes a pile rather than a graph")
	}
	// Every component the graph is keyed on has to arrive with something to
	// key it on. A revision that moved where the package identifier sits would
	// leave these empty and the reader would report a document that parsed.
	var identified int
	for _, c := range doc.Components {
		if c.Purl != "" {
			identified++
		}
	}
	if identified < len(doc.Components)-1 {
		t.Errorf("%d of %d components carry a package identifier",
			identified, len(doc.Components))
	}
}

// The component bound is charged on the header-only read too.
//
// It was charged where a component is recorded, and that returns at once when
// only the header is wanted — so a document putting its components inside the
// root component's own nested array was walked in full, binding every one of
// them, with nothing but the byte limit saying how many there could be. That
// read happens synchronously inside the upload request, so it is a process
// somebody fills from outside with a build key, and the same document read
// whole is refused at the limit.
func TestTheComponentBoundHoldsWhenOnlyTheHeaderIsWanted(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"bomFormat": "CycloneDX", "specVersion": "1.6",
	 "metadata": {"component": {"bom-ref": "root", "name": "p", "version": "1",
	  "components": [`)
	for i := range 50 {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"bom-ref": "n%d", "name": "n%d", "version": "1"}`, i, i)
	}
	b.WriteString(`]}}}`)

	if _, err := sbom.ReadHeader(strings.NewReader(b.String()),
		sbom.Limits{MaxComponents: 10}); err == nil {
		t.Fatal("a header-only read walked a document past the component limit")
	} else if !strings.Contains(err.Error(), "component limit") {
		t.Errorf("refusal does not name the limit: %v", err)
	}
	if _, err := sbom.ReadHeader(strings.NewReader(b.String()),
		sbom.Limits{MaxComponents: 100}); err != nil {
		t.Errorf("a document inside the limit was refused: %v", err)
	}
}

func TestWhoSuppliedAComponentIsKeptWithoutMovingIdentity(t *testing.T) {
	// A bare name is not enough for a dependency of a dependency, and a
	// producer often says who supplied it — one real image states it for 759
	// of the 6,866 components it describes. It was read and dropped.
	//
	// It must not reach identity. Two producers describing one component name
	// its supplier differently or not at all, so an identity that moved with it
	// would take every triage decision attached along with it.
	doc, err := sbom.Read(strings.NewReader(`{
		"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
		"metadata":{"component":{"bom-ref":"root","name":"image","version":"1"}},
		"components":[
			{"bom-ref":"a","name":"stated","version":"1.0",
			 "purl":"pkg:deb/debian/stated@1.0","supplier":{"name":"Debian"}},
			{"bom-ref":"b","name":"published","version":"1.0",
			 "purl":"pkg:deb/debian/published@1.0","publisher":"Somebody"},
			{"bom-ref":"c","name":"both","version":"1.0",
			 "purl":"pkg:deb/debian/both@1.0","supplier":{"name":"Debian"},
			 "publisher":"Somebody else"},
			{"bom-ref":"d","name":"silent","version":"1.0",
			 "purl":"pkg:deb/debian/silent@1.0"}
		],
		"dependencies":[{"ref":"root","dependsOn":["a","b","c","d"]}]
	}`), sbom.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	said := map[string]string{}
	for _, c := range doc.Components {
		said[c.Name] = c.Supplier
	}
	if said["stated"] != "Debian" {
		t.Errorf("the supplier is %q, want Debian", said["stated"])
	}
	// The weaker field where it is the only one.
	if said["published"] != "Somebody" {
		t.Errorf("with only a publisher the supplier is %q, want Somebody", said["published"])
	}
	// And the supplier wins where a producer states both.
	if said["both"] != "Debian" {
		t.Errorf("stating both, the supplier is %q, want the supplier", said["both"])
	}
	// Absent is absent rather than a placeholder.
	if said["silent"] != "" {
		t.Errorf("a component stating nothing has supplier %q", said["silent"])
	}

	for _, c := range doc.Components {
		if c.Name != "stated" {
			continue
		}
		without := c
		without.Supplier = ""
		if c.Identity() != without.Identity() {
			t.Error("the supplier reached identity")
		}
	}
}
