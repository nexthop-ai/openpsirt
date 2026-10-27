# Inventory parsing

How an inventory is read: the header pass, the bounds, identifiers and edges,
what is tolerated and refused, and the check on unread fields.

Satisfies REQ-08, REQ-16, REQ-66, REQ-69.

## Contents

- [Parsing](#parsing)
- [Bounds](#bounds)
- [Identifiers and edges](#identifiers-and-edges)
- [Tolerated and refused](#tolerated-and-refused)
- [Unread fields](#unread-fields)
- [Limits](#limits)

## Parsing

A scan file is hostile input (REQ-66, REQ-69): read as a stream, and bounded in
every dimension a producer controls.

| Rule | Reason |
|---|---|
| The header is read by a pass that skips the contents, and the arrival decision turns on it alone | On the largest producer, parsing a file about to be refused is most of the cost of taking it. The reference producer sorts its keys, putting tens of thousands of components ahead of the metadata, and walking past a value is still far cheaper than building from it |
| The document is walked, never decoded whole | Decoding has no settable depth limit, so a file nested far enough would be found by running out of memory |
| Reading is all or nothing | A partial inventory is indistinguishable from a product that shrank, and acting on one closes findings that are still somebody's problem. This concerns a failed parse, not producer variation |
| What a refusal quotes from the file is bounded in length | An error is one of the few places a scan file's contents reach a person |

## Bounds

Each is settable per read: document size, component count, file count, edge
count, claim count, nesting depth, and documents per scan.

| Rule | Reason |
|---|---|
| Edges have a bound of their own | A thousand components can declare a million edges |
| Nesting is bounded everywhere, inside the parts nothing reads included | |
| A document of exactly the size bound is read: the reader asks for one byte past the bound before refusing | The end of the file is told apart from more of it |
| An oversized document is refused as oversized, a third party's VEX document included | Truncated, it fails as malformed, which sends its reader to their build instead of to the limit, and the digest covers only the part that fitted |
| The component bound is charged where a component is read, never where one is recorded | The header pass records nothing, so charged at recording, a document nesting its components inside the root component is walked in full inside the upload request. A bound holding on one of two paths through the parser is routed around |
| The header pass holds nothing it walked past | It runs inside the upload request, so what it holds is held per concurrent upload |
| A suppression document's product identifiers are charged against the component bound | One claim names any number of products, so a single statement listing millions of identifiers is inside the claim bound |
| A CycloneDX document's license entries are charged against ten times the component bound, with a refusal of their own | Each is kept, so one component could otherwise hold as many as the byte bound allows. A real component states one to three, the real switch images under one on average, and the claim bound would refuse a large image that makes no claim, naming the wrong setting |
| The claim bound is spent across a scan's documents, never per document | A scan carries as many documents as a build attaches; passed whole to each, fifty documents hold fifty times the limit |
| The claim bound counts the claims a document returns | A CSAF vulnerability returns one claim per status its products are listed under, so counting vulnerabilities lets one document overspend what the scan's other documents have left |
| How many documents arrive with one scan is bounded | Without it every per-document bound is multiplied by a number nothing decides |
| The bounds are configuration, never constants | A defaults function every deployment runs unchanged is a constant with extra steps |
| The bounds are set from what reading costs, never from what a document looks like | An edge holds about half a kilobyte of heap while read and a component about 1.3 KB, so two million edges and a quarter of a million components, several times the largest real producer, accept a document taking about 1.3 GB and kill the background reader after the upload was answered 202. The budget is about 250 MB for one document, the server's share of the pod beside the scanner's process in the same cgroup, and a test measures the per-unit cost with a wide bound |

## Identifiers and edges

| Rule | Reason |
|---|---|
| The file's own identifiers resolve edges and are then discarded (REQ-08) | They are the producer's, and nothing makes them stable between builds or consistent between producers. A test replaces every identifier in a real document and asserts the components, identities and graph are unchanged |
| The graph is stored as the nodes and edges the document states (REQ-16) | |
| Nesting becomes an edge | A component containing components is the producer stating what is assembled from what, and for some producers the only structure stated |
| Two components sharing one identifier are refused | Every edge naming it would be a coin toss |
| An edge whose ends resolve to one component is dropped and counted | Content-derived identity can find two identifiers describing one component, which the producer could not have known; stored, it is a component depending on itself |
| Two things a document states twice are resolved once it has closed: who supplied a component, which two of the three vocabularies state two ways, and what it was built from | Key order is the producer's choice, and which field wins must not be |

## Tolerated and refused

The specifications require very little, and a valid sparse document is not a
broken one. Each count below should be stable build to build, so a change says
the producer changed.

| Tolerated | Behavior |
|---|---|
| The document names no component of its own | What the scan was filed against stands in. The root is excluded from identity and expiry anyway |
| A component states no version | Kept and counted: it ships either way, and what it costs is matching. Counted once over the deduplicated inventory, so a document naming one unversioned component in ten relationships counts one, and where a second description states a version the combination is what is counted and stored |
| An edge names something the document never describes | Dropped and counted. The missing component is not invented |
| An edge names a file rather than a package | Dropped and counted separately (`design-docs/ingest-formats.md` § Files are not components) |
| An edge end is the format's word for nothing | Read as nothing. Read literally, it adds an identifier nothing describes to the count of holes in the graph |
| A relationship naming what a build is about, stated by anything other than the document | Left out. Taken as a root claim, any element could re-parent the whole inventory under itself |
| The third SPDX version's version written as `SPDX-3.0.1` | Read as `3.0.1`, the bare version the format states. A fourth major version with the prefix is still refused |
| A control character in a component's name, version, package identifier or what it was built from, written or escaped | Dropped before the component is identified. Keys join names and versions with control characters as separators, so one carrying a separator reads as another component. A name of control characters alone is a component with no name |
| Unread fields | Ignored. A producer carrying more than is read is the ordinary case |

| Refused | Reason |
|---|---|
| Neither format, or a major version not written against | A reader that guesses eventually guesses wrong on a file that looks close enough |
| Keys from two formats | The last handler has written over the other's answer, and nothing says which half the producer meant. The same holds for a suppression document |
| Half of one format's declaration | An unstated version is a version this was not written against |
| A file and a component sharing one identifier | The edge resolves to the component and invents a dependency nobody stated |
| A component with no name | It cannot be identified, so it cannot be tracked |
| Two components sharing one identifier | Every edge naming it is ambiguous |
| A build time nothing can read | The build time orders scans against each other |
| Past any bound | A broken or hostile file fails rather than exhausting the process |
| Anything but whitespace after the top-level value, in an inventory, a suppression document or an advisory; in an XML inventory, anything but layout and comments after the top-level element | Two documents written one after the other read as the first, and the missing second reads as a product that shrank |
| A document type declaration in an XML inventory | `design-docs/ingest-formats.md` § CycloneDX encoded as XML |

## Unread fields

A field considered and left alone and a field nobody noticed look identical in
the code, so every key path the recorded documents contain is written down as
acted on or deliberately left alone.

| Rule | Reason |
|---|---|
| A recorded document holding a path the list does not have fails the check | |
| A path the reader acts on that no recorded document contains fails the check | It is a branch nothing exercises |
| The check covers the recorded documents, never what is accepted | The reader ignores anything it does not recognize |
| A fixture is the inventory this deployment's own image ships, read through the same reader, asserting the root, the component count, the edges and the package identifiers | Every minor revision within a major version parses by construction, so a reference producer moving to a newer revision would otherwise leave the image's own inventory untested. Each key path it brings is one more to decide about |

## Limits

| Limit | Detail |
|---|---|
| Every minor revision within a major version is accepted by construction | The reader checks the major version only. The fixture of the image's own inventory is the evidence for the revision it states, and nothing else |
