# The CSAF document

The CSAF 2.0 document generated for one advisory, from what is already held.
Nothing is sent anywhere.

Satisfies REQ-19, REQ-25, REQ-37, REQ-39, REQ-76.

The advisory, its agreement, its issuances and its publisher are in
`design-docs/remediation-advisories.md`.

## Contents

- [Format and identity](#format-and-identity)
- [Release statuses](#release-statuses)
- [Document contents](#document-contents)
- [Weakness names](#weakness-names)
- [Product identification](#product-identification)
- [Not built](#not-built)
- [Limits](#limits)

## Format and identity

| Rule | Reason |
|---|---|
| CSAF 2.0, moved to 2.1 once 2.1 is an OASIS standard | 2.0 is the standard and ISO/IEC 20153 consumers validate against; a draft version risks refusal |
| Only for a flaw in what this deployment ships; a third-party issue is refused by name | |
| The tracking identifier is the advisory's minted identifier | An issue's identifier claims authority over the issue, which a coordinator holds |
| One entry per issue; a vendor branch holding a product branch per product covered, every status naming releases of its product | |
| Releases are named by branch or tag and variant together, all named in the product tree | |
| Every list is ordered here, never by the engine | The same facts give the same bytes |
| Every date is a date and a time | A validator with format assertions refuses a bare day, which a schema check without them passes |
| Every object's keys are in alphabetical order, imposed on the bytes as generated and kept | The standard's optional sorting test reads every depth. The framework's schema link, a key the standard does not define, is left off this route |
| A settled digest taken with a bare day or unsorted keys does not match again | REQ-76 covers it |
| The version is the last number the revision history states | Counted apart they disagree once issued, which a validator compares |
| The profile declared is worked out from what the document carries | A missing profile-mandatory element fails that profile's tests |
| Always a security advisory, never the VEX profile; known not affected, its flag and impact are allowed in it, and a document stating only that states it for every release | A category switching between editions drops out of readers filtering on it, this deployment's supplier reader included |
| The security-advisory profile is the product tree, the vulnerabilities, and notes and a status on each | Document-level notes and references belong to the informational advisory; gating on them hid unwritten-up flaws from tooling filtering for security advisories |

## Release statuses

| Rule | Reason |
|---|---|
| A document about an undisclosed flaw travels no further, whatever its editorial state; the distribution label carries this | Reaching a disclosure date discloses nothing (REQ-37) |
| One undisclosed occurrence of an issue in its product embargoes the issue there | |
| A reader who may not read undisclosed work in that product is refused the listing, the advisory by name and its document together | A listing beside a refused document says undisclosed work exists |
| A release that fixed the flaw is named fixed, never omitted; somebody saying so fills the list (REQ-19) | Omission reads as never shipped, and no scan reports a recorded flaw |
| A release whose every open occurrence stands under approved, live decisions with one outcome states it, through the query the VEX document uses: not applicable or a wrong match, with its reason, is known not affected; already fixed is fixed; will not fix is known affected, no fix planned | |
| A release partly covered stays known affected | The release is the finest grain |
| Where decisions at a release differ, the earliest speaks, reason and mitigation from that one | |
| Decisions are read at the visibility of their findings, at what the reader may see | |
| A finding taken back as invalid is left out | That build never shipped the flaw |
| A superseded closure is never a fix; a release whose only closures are superseded, with nothing open, is known affected | The flaw came along with the version |
| A release can be marked affected whatever its decisions say | A decision reaches every build whose versions match (REQ-25), including a variant with the code compiled in |
| Beside each release the preparer sees the builds its decision was made on; a release of a variant none of them is, reached only by lookup, is flagged | Another branch or tag of the same variant is the same configuration. A decision recording no build is shown as not recorded and flags nothing |

## Document contents

Everything is already held. A field the record cannot answer is left out.

| Element | Filled by | Reason |
|---|---|---|
| References | The issue's write-up and every other address a report points at, once each, then this document's own address | On the document, which the profile requires. The own address only where the deployment says where documents are reachable, built by the directory's naming rule |
| Scores | The version 3 rating, scored from its vector, for every release the flaw is or was in; none for known not affected | The score object holds versions 2 and 3, so a flaw rated under 4 alone states none |
| Score order | The ratings a report stated, newest first, then the vector of a flaw assessed here | |
| Vector | The base vector inside the one held | Other metrics are accepted unchecked; a validator refuses a metric name or value the specification does not define |
| Acknowledgments | The credit the reporter asked to be named by, alone | A name given for replies is not for publishing |
| Remediations | For releases still carrying the flaw, details naming the fixed releases in product-tree order; none for known not affected. A release wholly under decisions not to fix takes `no_fix_planned`, with a `mitigation` of what stops the flaw where named, and is offered no fixed release | A vendor fix is for the affected product. Release names are never ordered by age, and a vendor fix beside "no fix planned" contradicts it |
| Planned work | Never stated | A commitment published is a dated promise to a customer |
| Flags | One per reason of the decisions behind known not affected, naming its releases | The decision's five reasons are the standard's five labels |
| Impact | What stops the flaw, one statement per mitigation; absent where none was named | The reasoning is never published: it is a triager's argument to a second person |
| Distribution | RED while anything covered is held back, WHITE otherwise | The labels are the standard's four |

An address a report supplied passes the rule for an address stored beside a
decision (`design-docs/text.md` § Link schemes), and a custom application
scheme is dropped.

## Weakness names

A weakness is stated as its identifier and the catalog's name, which a
validator compares as a pair.

| Rule | Reason |
|---|---|
| Names come from the published catalog, fetched and committed | A transcription error is a document refused at a customer months later |
| Never a screen's short names | "Buffer overflow" fails a validator where the catalog's full name passes |
| One weakness, the one the data calls the root cause: a feed's primary, or the first a person recording a flaw names | |
| An identifier the catalog does not assign states nothing | Categories and views share the shape, and a newer catalog outruns an older one |
| The catalog version is recorded, never gated against what it publishes today | It is not pinned, so a drift check fails builds for no change here |

## Product identification

Each release is named by what its own inventory called it: the product
identification helper carries the package identifier the build declared for the
component, where it declared one.

| Rule | Reason |
|---|---|
| The identifier the build declared, never one minted here | A reader matches on what the build wrote; an invented identifier makes them miss |
| Read from the scan, never the root component | The root is stored by name alone, since its identifier carries a moving version |
| Absent where the document named no component of its own, or its root has no package identifier | The tracked unit standing in is ours |

## Not built

| Not built | What exists |
|---|---|
| A note stating a version 4 score with no version 3 rating: version, base score, severity and vector | A flaw rated under version 4 alone is published with no score; CSAF 2.1 gains a field |

## Limits

| Rule | Reason |
|---|---|
| Only a decision made where a build was in hand records one | A decision from before builds were kept, or made with no build on screen, records none; the advisory says so and flags nothing, since a guess would name every variant holding the code |
