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

CycloneDX as JSON or XML, and SPDX 2.x and 3.x as JSON (REQ-05): three
vocabularies over one reader. A vocabulary knows its keys; deduplication, edge
resolution and bound charging are the reader's.

| Rule | Reason |
|---|---|
| The document chooses the reader, never the request | A format parameter is one a build sets wrong |
| A top-level key is read by the format owning it, before the format is declared | A producer sorting keys puts SPDX's packages ahead of `spdxVersion` |
| The formats share no key, and a test asserts it | |
| Which vocabulary read each key is recorded, and a document using two is refused | Both state an identity, so the stored one would depend on key order |
| A document declaring no format is refused | |
| Half a declaration is none | CycloneDX states format and version in two keys |
| A major version is read only where written against, refused by name where read | The rest is never walked |
| SPDX 2.2 and 2.3 are one vocabulary | 2.3 adds nothing read |

### SPDX 3.x

A context and one flat graph of typed elements in no stated order, sharing no
key path with 2.x.

| Difference | Rule |
|---|---|
| An element's type may follow the fields it governs | Each element is read into a neutral shape and interpreted when it closes |
| The header is inside the contents | The header pass walks the graph and builds nothing |
| Several creation records | The one the document points at is its own; with none, the upload is dated on arrival, since an imported document's time never moves |
| Several document elements | The file's own is the one no import names, and its identifier, creation record and roots are the document's; several left unsettled are refused |
| An inventory element of an imported document | One an import names, the imported document names as root, or whose roots are all the imported document's; it names none of the build's roots |
| A creation record written in place | On the document it dates the document; elsewhere it dates nothing unless it carries an identifier, and then every reference to it names it; its version is checked as a referred record's |
| One relationship, many ends | The edge bound is charged per end |
| Type known only after reading | Every entry charges the component bound on the way in; a path hands it back for the file bound, a relationship for the edge bound its ends took, and one with no end keeps it |
| Identifiers are absolute | All but the document's own resolve and are discarded |
| A path and a package sharing an identifier | Refused, checked where either is recorded |
| The version in the context or in any creation record | Either serves |

### CycloneDX encoded as XML

A second walk over the same reader: the Maven plugin writes both encodings by
default, and what a fact means once read is the JSON reader's. A test holds the
plugin's two encodings of one build to one build.

| XML spelling | Of |
|---|---|
| The attributes `bom-ref` and `type` | A component's in-file identifier and kind |
| `serialNumber` on the top-level element | The document's identity |
| A `dependency` element nested in its component, naming one by `ref` | What a component depends on |

| Rule | Reason |
|---|---|
| The encoding is told from the first character after layout and any byte-order mark | A pipeline's content type is its client's default |
| The declaration is the top-level namespace, `http://cyclonedx.org/schema/bom/1.6`; any other is refused by name | SPDX's RDF encoding turned up once in 41 public inventories |
| An element in another namespace is walked past | It is an extension, so a 1.1 document reads without its edges |
| A document type declaration is refused where met | It is how XML fetches files or expands to gigabytes, and no producer writes one |
| UTF-8 only | Every producer seen writes it |
| Size, depth, components, edges, licenses and claims are charged at the JSON walk's points, through the same functions; depth per element, unread ones included | |
| A dependency nested in a nested dependency is an edge from its parent | Depth is the depth bound's business |
| A NUL is refused | XML forbids it |
| Element text is trimmed | |
| The decoder's complaints are bounded | A 1 MiB element name came back as a refusal that size |

## Format spellings

| Fact | CycloneDX | SPDX 2.x | SPDX 3.x |
|---|---|---|---|
| Document identity | `serialNumber` | `documentNamespace` | the document element's identifier |
| When made | `metadata.timestamp` | `creationInfo.created` | the creation record the document points at |
| What it is about | the component under `metadata` | an identifier pointing at a package | identifiers on the document or inventory element, and `describes` |
| What ships | `components` | `packages` | entries typed as a package |
| In-file identity | `bom-ref` | `SPDXID` | `spdxId` |
| Version | `version` | `versionInfo` | `software_packageVersion` |
| Package identifier and database key | component fields | external references by type | a package field, or external identifiers by type |
| Structure | `dependencies`, and nesting | relationships, either way round | relationships, one way round |
| Dependency scope | `scope` | the relationship type | `scope` on the relationship |
| Built from | a pedigree | a relationship to another package | `ancestorOf` or `descendantOf` |
| What a carried patch resolves | a pedigree patch naming the vulnerability | cannot be stated | cannot be stated |
| Container image | `type` `container` | `primaryPackagePurpose` `CONTAINER` | `software_primaryPurpose` `container` |

| Rule | Reason |
|---|---|
| A container image is read from the format only where no package identifier decides it; an image is identified by name (REQ-08, `design-docs/data-model.md` § Container images) | |
| Only the first ancestor supplies upstream identity | A scanner matches the fork point |
| The first of each identifier stands | One producer emits eight spellings of one database key |
| `NOASSERTION` and `NONE` are no value | Otherwise a scanner matches the word as a version |
| SPDX 2's `BUILD_`, `DEV_`, `RUNTIME_` and `OPTIONAL_DEPENDENCY_OF` are edges keeping the producer's word; `TEST_DEPENDENCY_OF` places nothing | What the word means is `design-docs/findings-components.md` § Declared dependency scope |
| A component reached only by those four has a consumer, so a decision keyed on the component alone does not cover it; an older database is recreated (REQ-76) | |

### Structural relationships

An edge is a relationship saying one component is part of another, as
CycloneDX `dependsOn` does.

| SPDX 2.x | Types |
|---|---|
| Edge | `CONTAINS`, `CONTAINED_BY`, `DEPENDS_ON`, `DEPENDENCY_OF`, `DYNAMIC_LINK`, `STATIC_LINK`, `HAS_PREREQUISITE`, `PREREQUISITE_FOR`, `RUNTIME_DEPENDENCY_OF`, `OPTIONAL_DEPENDENCY_OF`, `PROVIDED_DEPENDENCY_OF`, `BUILD_DEPENDENCY_OF`, `DEV_DEPENDENCY_OF` |
| What the document is about | `DESCRIBES`, `DESCRIBED_BY` |
| Derived from | `ANCESTOR_OF`, `DESCENDANT_OF` |
| Nothing | Everything else |

| SPDX 3.x | Types |
|---|---|
| Edge | `contains`, `dependsOn`, `hasDynamicLink`, `hasStaticLink`, `hasPrerequisite`, `hasOptionalComponent`, `hasOptionalDependency`, `hasProvidedDependency` |
| What the document is about | `describes` |
| Derived from | `ancestorOf`, `descendantOf` |
| Nothing | Everything else |

| Rule | Reason |
|---|---|
| Either direction is one edge | |
| A build tool, development tool or test dependency places nothing; the component is held under nothing | As CycloneDX `formulation` tooling |
| A derivation fills an upstream nothing else stated, never replacing one | It only points at something the document describes |
| A derivation charges the claim bound | |

### Lifecycle scopes

| SPDX 3 scope | Read as |
|---|---|
| `test` | Places nothing; the target is held under nothing |
| build, design, development, runtime, other | Places its target under the relationship's source |

`build` ships: a crate linked into a binary is a build-phase dependency.

### Files are not components

| Rule | Reason |
|---|---|
| A file is never held as a component | Nothing matches a path, and an image catalogs five files per package |
| An edge naming a file is dropped and counted apart | 91 of the fixture's 125 relationships run to files, so mixed in, the count tracks file detail |
| Files have their own bound | 4,964 files against 89 packages and 21,643 against 480 put a 6,866-package switch image over 300,000 files, past the 100,000 component ceiling; a path costs 133 bytes held, a component 766 |

## The root

| Rule | Reason |
|---|---|
| Resolved once the document closes | SPDX may point at a package not yet read |
| A document pointing at several things has no single root, and the tracked unit stands in, as for none | Picking one invents a hierarchy |
| Roots are counted by what the pointers resolve to | A producer filling list and relationship names one root twice |
| Stored by name alone | Its version moves every build and would move every edge |
| The declared root's package identifier is kept on the scan as a fact, beside serial and composition, never as identity | An advisory reader matches a release by it |
| Read off the document; a root with no package identifier keeps nothing | An identifier we invent matches nothing |

## Limits

| Limit | Detail |
|---|---|
| A lifecycle scope is read the way that keeps a component | Too much adds visible triage; too little hides findings. The format's example 11 states as `build` in version 3 what version 2 states unscoped, so reading `build` as not shipping loses every component |
| SPDX 3 is read against the specification alone | Nothing ingested emits it, the bundled scanner emits 2.3 and tag-value, and the fixtures are small and hand-written |
