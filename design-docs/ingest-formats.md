# Inventory formats

The formats read, where each states each fact, the root, and which
relationships make the graph.

Satisfies REQ-05, REQ-08, REQ-76.

## Contents

- [The formats read](#the-formats-read)
- [Format spellings](#format-spellings)
- [The root](#the-root)
- [Limits](#limits)

## The formats read

CycloneDX encoded as JSON or XML, and SPDX 2.x and 3.x as JSON (REQ-05): three
vocabularies sharing one reader. A vocabulary knows which keys its format uses
and what they mean; deduplication, edge resolution and where a bound is
charged are the reader's.

| Rule | Reason |
|---|---|
| The document chooses the reader, never the request | A format parameter is one a build sets wrong, and the refusal is then about the parameter instead of the file |
| A top-level key is read by the format that owns it, before the document has necessarily declared its format | The declaration has no guaranteed position: a producer sorting its keys puts SPDX's packages ahead of `spdxVersion` |
| The formats claim no key in common, and a test asserts it | A key claimed twice makes routing a coin toss |
| Which vocabulary read each key is recorded, and a document that used two is refused | A handler writes before anything checked the format, and both formats state an identity, so a file carrying both is stored under whichever came last, an identity decided by key order |
| A document declaring no format is refused | A fragment or a hand-edited file whose keys look familiar. The declaration exists so nothing guesses |
| Half a declaration is no declaration | CycloneDX states format and version in two keys, and an unstated version is one this was not written against |
| A major version is read only where it was written against, refused by name where it is read | A file never going to be read is dropped before the rest is walked |
| SPDX 2.2 and 2.3 are one vocabulary | The later revision adds nothing this reads |

### SPDX 3.x

A third vocabulary sharing no key path with 2.x: a context and one flat graph
of typed elements, packages, files, relationships, people, tools, licenses and
the document's own record, in no stated order.

| Difference | Rule |
|---|---|
| An element states its type in a field that may follow the fields it governs | An element is read into one neutral shape and interpreted when it closes, holding one element at a time |
| The header is inside the contents | The document's creation record is one entry of the same array, so the header pass walks the whole graph and builds nothing from it |
| A document carries several creation records | The one the document points at is the document's. Where it points at none, none stands in and the upload is dated on arrival, because an imported document's time does not move between builds and every later scan would be refused as not newer |
| A file carries several document elements | The file's own is the one no other names in its imports, and its identifier, creation record and roots are the document's. Several the imports leave unsettled are refused, because the last read is an accident of order |
| An inventory element belongs to an imported document | Where an import names it, the imported document names it as a root, or every root it names is the imported document's and none the file's own. It names none of the build's roots |
| A creation record may be written in place as an object | On the document, its time is the document's. On another element it dates nothing unless it carries an identifier, and then it is the record every reference to that identifier names. Its version is checked as a referred-to record's is |
| One relationship states a list of ends | The edge bound is charged per end, as each is read |
| An element's type is known only once it is read | Every entry is charged against the component bound on the way in. A path hands that charge back and takes the file bound; a relationship hands it back for the edge bound its ends took, and one stating no end keeps its component charge |
| Identifiers are absolute | Nothing depends on their shape. Every one but the document's own resolves the document to itself and is discarded |
| A path and a package may not share an identifier | Checked where a package is bound and where a path is recorded, since either may come first |
| The version is stated in the context and in every creation record, and either serves | A producer need not emit the first |

### CycloneDX encoded as XML

A second walk over the same reader, never a fourth vocabulary: its Maven
plugin, the likeliest source, writes both encodings by default. Everything a
fact means once read (which of two suppliers wins, how licenses combine, what a
patch claims, where a bound is charged) is the JSON reader's, and a test holds
the plugin's two encodings of one build to one build.

| Where XML differs | Spelling |
|---|---|
| A component's identifier within the file, and its kind | The attributes `bom-ref` and `type` |
| The document's identity | The `serialNumber` attribute of the top-level element |
| What a component depends on | A `dependency` element nested inside its own, each naming one by its `ref` attribute |

| Rule | Reason |
|---|---|
| The encoding is told from the first character after layout and, in XML, a byte-order mark: a brace or an angle bracket | The content type a pipeline sends is its HTTP client's default |
| The declaration is the top-level element's namespace, `http://cyclonedx.org/schema/bom/1.6` | It states format and revision at once and cannot arrive late. Any other namespace is refused by name, SPDX's RDF encoding among them, found once in 41 public inventories |
| An element in another namespace is walked past | It is an extension. Version 1.1 stated dependencies through one, so a 1.1 document reads with its components and no edges |
| A document type declaration is refused where it is met | It is where XML defines entities, through which a document makes its reader fetch a file or URL or expand to gigabytes. No producer writes one, and a reader never accepting one is not exposed by a later change to the decoder |
| UTF-8 only; another declared encoding is refused | Every producer seen writes UTF-8 |
| The same bounds, charged at the same points, depth per element including unread ones | |
| A dependency nested in a nested dependency is an edge from the one it is nested in | The schema nests the element without saying where it stops. How deep is the depth bound's business |
| A NUL is refused, where the JSON reader drops one | XML forbids the character, written or by reference, and JSON allows it |
| An element's text is trimmed | Layout is not the value |
| The decoder's complaints are bounded like anything else quoted | They quote the document; passed on whole, a 1 MiB element name returned a refusal of about that size |

## Format spellings

The internal shape is the graph's own, the same from every format.

| Fact | CycloneDX | SPDX 2.x | SPDX 3.x |
|---|---|---|---|
| The document's identity | `serialNumber` | `documentNamespace` | the document element's identifier |
| When the producer made it | `metadata.timestamp` | `creationInfo.created` | the creation record the document points at |
| What it is about | the component under `metadata`, inline | an identifier pointing at a package | identifiers on the document or inventory element, and `describes` |
| What ships | `components` | `packages` | entries typed as a package |
| A component's identity in the file | `bom-ref` | `SPDXID` | `spdxId` |
| The version | `version` | `versionInfo` | `software_packageVersion` |
| Package identifier and database key | fields of the component | external references, by type | a field of the package, or external identifiers by type |
| Structure | `dependencies`, and nesting | relationships, either way round | relationships, one way round |
| A dependency's scope | a component's `scope` | the relationship type: build, development, runtime, optional, test | a `scope` on the relationship |
| What it was built from | a pedigree describing the ancestor | a relationship to another package | the same, as `ancestorOf` or `descendantOf` |
| What a carried patch resolves | a patch in the pedigree, naming the vulnerability | cannot be stated | cannot be stated |
| A container image | `type` of `container` | `primaryPackagePurpose` of `CONTAINER` | `software_primaryPurpose` of `container` |

| Rule | Reason |
|---|---|
| A container image is read from the format only where the component carries no package identifier | The identifier's type decides where there is one. An image is identified by its name (REQ-08, `design-docs/data-model.md` § Container images) |
| Only the first ancestor supplies upstream identity | Anything further back is history, and a scanner matches against the fork point |
| The first of each identifier stands | One real producer emits eight spellings of one database key, differing in a hyphen, and nothing says which an advisory used |
| SPDX's `NOASSERTION` and `NONE` are read as no value | Taken literally a package's version is `NOASSERTION`, which a person reads as a version and a scanner tries to match |
| `BUILD_DEPENDENCY_OF`, `DEV_DEPENDENCY_OF`, `RUNTIME_DEPENDENCY_OF` and `OPTIONAL_DEPENDENCY_OF` are edges carrying the producer's word; `TEST_DEPENDENCY_OF` places nothing | The word's meaning is `design-docs/findings-components.md` § Declared dependency scope |
| A component reached only by those four has a consumer, so its occurrence identity is a consumer's and a decision keyed on the component alone does not cover it | A database that took SPDX 2 inventories under an earlier build is recreated, never migrated (REQ-76) |

### Structural relationships

A relationship is an edge where it says one component is part of another in the
sense the graph is walked, the question a CycloneDX `dependsOn` answers.

| SPDX 2.x | Types |
|---|---|
| An edge | `CONTAINS`, `CONTAINED_BY`, `DEPENDS_ON`, `DEPENDENCY_OF`, `DYNAMIC_LINK`, `STATIC_LINK`, `HAS_PREREQUISITE`, `PREREQUISITE_FOR`, `RUNTIME_DEPENDENCY_OF`, `OPTIONAL_DEPENDENCY_OF`, `PROVIDED_DEPENDENCY_OF`, `BUILD_DEPENDENCY_OF`, `DEV_DEPENDENCY_OF` |
| What the document is about | `DESCRIBES` and `DESCRIBED_BY`, between the document and a package |
| What a component was derived from | `ANCESTOR_OF` and `DESCENDANT_OF` |
| Nothing | Everything else |

| SPDX 3.x | Types |
|---|---|
| An edge | `contains`, `dependsOn`, `hasDynamicLink`, `hasStaticLink`, `hasPrerequisite`, `hasOptionalComponent`, `hasOptionalDependency`, `hasProvidedDependency` |
| What the document is about | `describes` |
| What a component was derived from | `ancestorOf`, `descendantOf` |
| Nothing | Everything else |

| Rule | Reason |
|---|---|
| A type stated either way round is the same edge | The graph has one shape |
| A build tool, a development tool and a test dependency place nothing | They describe the build, not the product. The component is still held and counted as under nothing, as CycloneDX build tooling under `formulation` is |
| A derivation fills an upstream nothing else stated and never replaces one | It is a pointer to something the document also describes, weaker than a pedigree |
| A derivation is charged against the claim bound | An unbounded array of them is the edge hazard under another name |

### Lifecycle scopes

The third version annotates a relationship with a phase: build, design,
development, runtime, test or other. The specification never says one means the
target does not ship.

| Scope | Read as |
|---|---|
| `test` | Places nothing. The target is held and counted as under nothing, as `TEST_DEPENDENCY_OF` is |
| Everything else | Places its target under the element the relationship is stated from |

`build` is not "does not ship": a crate or module linked into a binary is a
build-phase dependency inside what ships. § Limits says what the reading costs.

### Files are not components

| Rule | Reason |
|---|---|
| A file is never held as a component | Nothing matches a vulnerability against a path, and a real image catalogs five files per package |
| File identifiers are kept, and an edge naming one is dropped and counted apart from other dropped edges | 91 of the fixture's 125 relationships run from a package to its files. Uncounted, the graph reads as holed, and a count meant to say the derivation changed moves with how much file detail the producer emits |
| Files have a bound of their own, set by measurement | A real scan catalogs 4,964 files against 89 packages and 21,643 against 480, 45 to 56 per package, so a switch operating system's 6,866 packages bring over 300,000 files. Charged against the component ceiling of 100,000, a real inventory is refused; raised to fit, the component bound bounds nothing. A path costs 133 bytes to hold, a component 766 |

## The root

| Rule | Reason |
|---|---|
| The root is resolved once the document closes | One format states it inline; the other points at a package that may not have been read |
| A document pointing at several things has no single root, and the tracked unit stands in, as for a document naming none | Picking one states a hierarchy the producer did not |
| Roots are counted by what the pointers resolve to | A producer filling both the list and the relationship names one component twice, and counting statements would leave the document with none |
| The root is stored by name alone | A package identifier carries the version, which moves every build, and the root's identity moving takes every edge with it |
| The declared root's package identifier is kept on the scan as a fact about the document, beside its serial and what it was made of, never as an identity | It is what a published advisory offers a reader to match a release against |
| It is read off the document, never off the resolved graph, and a root carrying no package identifier keeps nothing | An identifier helps only if it appears on both sides, and the tracked unit standing in is ours |

## Limits

| Limit | Detail |
|---|---|
| A lifecycle scope is read the way that keeps a component | Keeping too much adds triage somebody sees; dropping too much removes a finding nobody learns of. The format's example 11 states its three dependencies unscoped in the second version and as `build` in the third, so read as not shipping, that document loses every component |
| The third SPDX version is read against the specification's documents and no producer's output | Nothing ingested here emits it, and the bundled scanner emits 2.3 and tag-value. The fixtures are hand-written and small, so which shapes real producers use is unknown |
