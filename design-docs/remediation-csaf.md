# The CSAF document

The CSAF 2.0 document generated for one advisory, from what is already held.
Nothing is sent anywhere.

Satisfies REQ-19, REQ-25, REQ-37, REQ-39, REQ-76.

The advisory, its agreement and its issuances are in
`design-docs/remediation-advisories.md`; the publisher it names is there too,
under § Publisher identity.

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
| Written as CSAF 2.0, and moved to 2.1 once 2.1 is an OASIS standard | 2.0 is the OASIS standard and ISO/IEC 20153, the version consumers' validators check; 2.1 is a committee draft, and a document claiming it risks refusal by those consumers |
| Only for a flaw in what this deployment ships | A scanner's issue against a third-party component is refused by name, never answered with a document that looks the same and means something else |
| The tracking identifier is the advisory's minted identifier | A document naming an issue's identifier as its own claims to be the authority on that issue, which a coordinator is and this deployment is not |
| One entry per issue, and one branch per product | The tree carries a vendor branch holding a product branch per product covered, and every status names releases of the product the issue was covered in |
| Releases are named by branch or tag and variant together, every one a status refers to named in the product tree | |
| Every list is ordered here, never by the engine | Two documents from the same facts are the same bytes |
| Every date stated is a date and a time | The standard defines each so, and a validator run with format assertions refuses a bare day, a document a customer's tooling drops silently. A schema check without them passes it |
| Every object's keys are written in alphabetical order, imposed on the bytes as generated and as kept | The standard's optional sorting test reads every key at every depth. The framework's schema link is left off the route answering with the document, since the standard defines no such key |
| A settled digest taken while a date was a bare day, or before keys were sorted, does not match again | REQ-76 covers it |
| The document's version is the last number its revision history states | Counted apart, the two disagree once an advisory has been issued, which a validator compares; they agree by accident for an unpublished document |
| The profile declared is worked out from what the document carries | Declared unconditionally, a document missing a profile-mandatory element fails that profile's tests and is dropped |
| An advisory is always a security advisory, never the VEX profile, whatever it states | A category switching between editions drops out of every reader filtering on it, this deployment's supplier reader included; VEX output is the separate per-build document. Known not affected, its flag and its impact are allowed in a security advisory, and a document whose only status is known not affected states one for every release it names |
| The security-advisory profile is the product tree, the vulnerabilities, and notes and a status on each | The standard's own list. Notes and references on the document belong to the informational advisory, for a document with no vulnerabilities; gating on them declared a base document for every unwritten-up flaw, which tooling filtering for security advisories skips |

## Release statuses

| Rule | Reason |
|---|---|
| A document about an undisclosed flaw travels no further, whatever its editorial state | Reaching a disclosure date discloses nothing (REQ-37), so neither does generating a document. The distribution label carries this; the tracking status says where the document is in its life |
| The label is decided from every occurrence of each issue in its product: one undisclosed occurrence embargoes the issue there | Whichever occurrence was recorded first or the reader sees |
| A reader who may not read undisclosed work in that product is not shown the advisory: listing, opening by name and generating refuse together | A listing admitting it beside a refusing document says undisclosed work exists |
| A release that fixed the flaw is named fixed, never omitted | Omission reads as a release that never shipped it. Somebody saying so fills that list (REQ-19), because for a recorded flaw no scan will |
| A release whose every open occurrence stands under approved, live decisions with one outcome states what they say, through the query the VEX document uses | Not applicable or a wrong match, with its reason, is known not affected; already fixed is fixed; will not fix stays known affected and says no fix is planned |
| A release partly covered stays known affected | The document has no finer grain than the release |
| Where the decisions at a release differ, the earliest speaks, its reason and mitigation read off that one decision | It has stood longest, as in the VEX document |
| A decision is read at the visibilities the findings are, at what the document's reader may see | A decision carries the visibility of the finding it was made about |
| A finding taken back as invalid is left out | Narrowing a flaw's builds closes a build's finding so, and that build never shipped it; named fixed, it reads as a release to upgrade to |
| A superseded closure is never a fix | The version moved and the flaw came along, so the superseding row speaks. A release whose only closures are superseded, with nothing open, is known affected |
| A release can be marked affected whatever its decisions say | A decision reaches every build whose versions match (REQ-25), so one made on a variant with the code compiled out covers one with it compiled in |
| The person preparing the advisory sees, beside each release, the builds its decision was made on, and a release of a variant none of them is, reached only by lookup, is flagged | Another branch or tag of a variant the decision was made on is the same configuration and is not flagged, or nearly every release would be. A decision recording no build is shown as not recorded and flags nothing |

## Document contents

Everything is already held and nothing is derived. A field the standard defines
and the record cannot answer is left out.

| Element | Filled by | Reason |
|---|---|---|
| References | The issue's write-up and everywhere else a report points, each address once, then the address this document is published at | On the document, not the vulnerability: the document is about one flaw, and the profile requires the document's. Its own address is stated only where the deployment says where documents are reachable, because tooling follows a self reference, and it is built by the rule the directory names the file by |
| Scores | The version 3 rating, scored here from its vector, for every release the flaw is or was in; none for a release known not affected | A stored number and vector that disagree say nothing about which was meant. The score object has fields for versions 2 and 3, so a flaw rated under 3 and 4 states 3, and one rated under 4 alone states none |
| Score order | The ratings a report stated, newest first, then the vector a flaw assessed here was given | |
| Vector | The base vector inside the one held | Metrics outside the base set are accepted and not checked, and a validator refuses a metric the specification does not define |
| Acknowledgments | The credit the reporter asked to be named by, alone | A name given so somebody can reply is not given for publishing, and "anonymous" is a real answer |
| Remediations | For releases still carrying the flaw, the details naming the fixed releases by their product-tree names in product-tree order. A release known not affected is in neither. A release whose every open occurrence stands under approved decisions not to fix takes `no_fix_planned`, with a `mitigation` carrying what stops the flaw where named, never the reasoning, and is not offered the fixed releases | The standard defines a vendor fix as one for the affected product, so pointed at fixed releases the customer who must act gets none. Not the earliest fixed release, which would order release names. Beside "no fix planned", a vendor fix reads as a contradiction; moving lines is the reader's call |
| Planned work | Never stated | A commitment is one build's internal plan, and published it is a promise to a customer about a date |
| Flags | The reason of the decision a release known not affected stands under, one flag per reason naming its releases | The five reasons a decision records are the standard's five flag labels |
| Impact | What stops the flaw, from the same decision, one statement per mitigation naming its releases; absent where none was named | The mitigation is what a holder can act on. The reasoning is never read into a document: it is a triager's argument to a second person here |
| Distribution | RED while anything covered is held back, WHITE otherwise | Handing a document about an unannounced flaw to somebody who may pass it on is the disclosure the embargo holds, at any editorial point. The labels are the standard's four, so a disclosed document is WHITE, not the protocol's renamed word |

An address a report supplied passes the rule an address stored beside a
decision passes (`design-docs/text.md` § Link schemes), and a custom application
scheme is dropped, because it leaves the deployment into tooling that follows
it.

## Weakness names

A weakness is stated as its identifier and the catalog's own name for it,
because a consumer's validator compares the pair.

| Rule | Reason |
|---|---|
| The names come from the published catalog, fetched and committed | A thousand names unchecked by eye go wrong quietly: one transcription error is a document refused at a customer months later. The reserved-word list is asked, never typed, for the same reason |
| Never the names a screen uses | A screen says "Buffer overflow"; the catalog says "Improper Restriction of Operations within the Bounds of a Memory Buffer", and only that passes a validator |
| One weakness: the one the data calls the root cause | The standard carries one and an issue is often classified as several. A feed says which is primary, and a person recording a flaw names theirs first |
| An identifier the catalog does not assign states nothing | Categories and views share the shape and are not classifications, and a newer catalog assigns numbers an older one predates |
| The catalog version is recorded and not gated against what it publishes today | The reserved-word engines are pinned in CI and this authority is not, so a drift check fails a build for a reason no change here caused |

## Product identification

Each release is named by what its own inventory called it: the product
identification helper carries the package identifier the build declared for
the component the document is about, where it declared one.

| Rule | Reason |
|---|---|
| The identifier the build declared, never one minted here | A reader holding the image matches on what the build wrote into its inventory; a plausible identifier nobody outside has seen makes them miss |
| Read from the scan, never from the root component | The root is stored by name alone, since a package identifier carries the version and the root's identity moving takes every edge with it. What the document declared is kept beside the serial and what the inventory was made of |
| Absent where the document named no component of its own, or its declared root carries no package identifier | The tracked unit stands in for the root, and it is ours, not the producer's |

## Not built

| Not built | What exists |
|---|---|
| A version 4 score with no version 3 rating beside it, stated in a note giving the version, base score, severity and vector | A flaw rated under version 4 alone is published with no score. Tooling would not read a score from prose either; CSAF 2.1 gains a field |

## Limits

| Rule | Reason |
|---|---|
| Only a decision made where a build was in hand records one | A decision from before builds were kept, or made with no build on screen, records none; the advisory says so and flags nothing, because a guess from where the occurrence sat names every variant holding the same code, the case the flag is for |
