# Inventory parsing

How an inventory is read: the header pass, the bounds, identifiers and edges,
what is tolerated and refused, and the check on unread fields.

Satisfies REQ-08, REQ-09, REQ-16, REQ-66, REQ-69.

## Contents

- [Parsing](#parsing)
- [Bounds](#bounds)
- [Identifiers and edges](#identifiers-and-edges)
- [Tolerated and refused](#tolerated-and-refused)
- [Unread fields](#unread-fields)
- [Limits](#limits)

## Parsing

A scan file is hostile input (REQ-66, REQ-69), read as a stream and bounded in
every dimension a producer controls.

| Rule | Reason |
|---|---|
| The arrival decision reads only a header pass that skips the contents | Parsing a file about to be refused is most of the cost on the largest producer, whose sorted keys put the components first |
| The document is walked, never decoded whole | Decoding has no settable depth limit |
| Reading is all or nothing | A partial inventory reads as a product that shrank, and closes live findings |
| What a refusal quotes from the file is bounded in length | An error is where a scan file's contents reach a person |

## Bounds

Settable per read: document size, components, files, edges, claims, nesting
depth, and documents per scan. Each is configuration, never a constant.

| Rule | Reason |
|---|---|
| Bounds are sized and tested against the largest real input (REQ-09), and set from what reading costs | An edge holds about half a kilobyte while read and a component about 1.3 KB, so round numbers several times the largest producer (two million edges, a quarter of a million components) accept 1.3 GB, past what the chart ships as a limit, and kill the background reader after the 202. The budget is about 250 MB a document, the server's share of a pod it shares with the scanner; a test measures per-unit cost |
| Edges have their own bound | A thousand components can declare a million edges |
| Nesting is bounded everywhere, unread parts included | |
| A document of exactly the size bound is read; the reader asks one byte past it before refusing | |
| An oversized document, a third party's VEX included, is refused as oversized | Truncated, it fails as malformed and its digest covers only part |
| The component bound is charged where a component is read, never where recorded | The header pass records nothing, so components nested in the root would be walked unbounded inside the request |
| The header pass holds nothing it walked past | It runs per concurrent upload |
| A suppression document's product identifiers count against the component bound | One claim can name millions of products |
| CycloneDX license entries count against ten times the component bound, with their own refusal | Each is kept; a real component states one to three, the switch images under one on average |
| The claim bound is spent across a scan's documents | Per document, fifty documents hold fifty times the limit |
| The claim bound counts claims returned | A CSAF vulnerability returns one claim per status |
| Documents per scan are bounded | Otherwise every per-document bound multiplies |

## Identifiers and edges

| Rule | Reason |
|---|---|
| The file's identifiers resolve edges and are discarded (REQ-08) | A test replaces every one in a real document and finds components, identities and graph unchanged |
| The graph is stored as nodes and edges, walked when asked, never flattened (REQ-16) | |
| Nesting becomes an edge | For some producers it is the only structure stated |
| Two components sharing one identifier are refused | |
| An edge whose ends resolve to one component is dropped and counted | Content identity can merge two identifiers the producer could not know were one |
| Facts stated twice (supplier, what a component was built from) are resolved once the document closes | Key order is the producer's choice |

## Tolerated and refused

Each count below is stable build to build, so a change says the producer
changed.

| Tolerated | Behavior |
|---|---|
| The document names no component of its own | What the scan was filed against stands in |
| A component states no version | Kept and counted once over the deduplicated inventory; where another description states one, the combination is counted and stored |
| An edge names something never described | Dropped and counted; nothing is invented |
| An edge names a file | Dropped and counted apart (`design-docs/ingest-formats.md` § Files are not components) |
| An edge end is the format's word for nothing | Read as nothing |
| A relationship naming what the build is about, stated by anything but the document | Left out; otherwise any element could re-parent the inventory |
| An SPDX 3 version written `SPDX-3.0.1` | Read as `3.0.1`; a fourth major version is still refused |
| A control character in a name, version, package identifier or what a component was built from, written or escaped | Dropped before identity, since keys join on control characters. A name of control characters alone is no name |
| Unread fields | Ignored |

| Refused | Reason |
|---|---|
| Neither format, or an unread major version | A guessing reader eventually guesses wrong |
| Keys from two formats, in an inventory or a suppression document | One handler has overwritten the other |
| Half a format declaration | |
| A file and a component sharing an identifier | It invents a dependency |
| A component with no name | It cannot be tracked |
| Two components sharing an identifier | |
| An unreadable build time | It orders scans |
| Past any bound | |
| Anything but whitespace after the top-level value (in XML, anything but layout and comments after the top-level element), in an inventory, suppression document or advisory | Two concatenated documents read as the first |
| A document type declaration in XML | `design-docs/ingest-formats.md` § CycloneDX encoded as XML |

## Unread fields

Every key path the recorded documents contain is listed as acted on or
deliberately left alone.

| Rule | Reason |
|---|---|
| A recorded document holding an unlisted path fails the check | A considered field and an unnoticed one look the same in code |
| A path the reader acts on that no recorded document holds fails the check | Nothing exercises it |
| A fixture is this deployment's own image inventory, asserting root, component count, edges and package identifiers | The reader checks only the major version, so any minor revision parses by construction; the fixture is the evidence for the one the image states |

## Limits

| Limit | Detail |
|---|---|
| The check covers recorded documents, never what is accepted | The reader ignores what it does not recognize |
