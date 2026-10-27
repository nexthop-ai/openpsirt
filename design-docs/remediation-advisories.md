# Advisories

The advisory as a record of its own, its editorial state, the agreement it
goes out under, the record of each issuance, and the publisher it names.

Satisfies REQ-19, REQ-24, REQ-28, REQ-37, REQ-39, REQ-42.

The document generated for an advisory is in
`design-docs/remediation-csaf.md`; where it is written for a web server, in
`design-docs/remediation-directory.md`; where this deployment serves it, in
`design-docs/publishing.md`.

## Contents

- [Publication](#publication)
- [The advisory](#the-advisory)
- [Editorial state](#editorial-state)
- [Editions and agreement](#editions-and-agreement)
- [Issuance records](#issuance-records)
- [Publisher identity](#publisher-identity)
- [Not built](#not-built)
- [Limits](#limits)

## Publication

Two destinations are built: the static directory somebody else's web server
serves, and, where the deployment publishes, the documents it serves itself
beside a VEX document per issue and per branch or tag. Nothing is sent
anywhere, and no adapter to anybody's platform exists; the rules below are
what one would be, because the shape it would publish in is what makes the
content right.

Publication covers a flaw in this deployment's own product (REQ-39). A known
CVE in a shipped third-party component is dependency hygiene a consumer reads
from the inventory.

| Rule | Reason |
|---|---|
| A pluggable output with several adapters, never one integration | Routes differ by product: an open-source project uses its forge's advisory system, an appliance vendor its own site |
| The triage record is ours, the published advisory the platform's | Neither copies or syncs the other |
| CSAF is the adapter that matters for commercial products | Nearly free from what is held: VEX is a CSAF profile, and the dismissal vocabulary is aligned to it |
| A forge's advisory system is one adapter | Draft privately, request an identifier, publish, and use its temporary private fork for fix work under embargo. It applies to nothing hosted elsewhere |
| Publishing aggregates: one advisory covers a product and a version range, never a path | A reader asks "am I affected", and the answer is a version |
| Optional and configured per deployment | Nobody needs an account anywhere to use this |

## The advisory

An advisory is a record of its own, under an identifier this deployment mints,
naming the issues it covers and the products each is covered in.

| Rule | Reason |
|---|---|
| Keyed on itself, never on a product and an issue | The standard carries vulnerabilities as an array and means the tracking identifier to be the publisher's own name for the document; a product-and-issue key cannot express a document about two and hands out somebody else's name |
| The identifier is minted here: a year and a number under a prefix the deployment configures | It is the name a reader cites and a revision keeps, so it belongs to the document, not to whichever issue was first |
| An advisory issued before v0.2.0 keeps the name it went out under, numbered in year zero | No advisory minted from the prefix reaches it |
| An advisory names many issues across many products | Several embargoed flaws released together are one document on one date, which is coordinated release. One issue in two products is two entries, because the releases differ |
| An issue is named once per product | The pair is what a status is stated about; named twice, a reader gets two answers about one release and the document is refused |
| Only a flaw recorded here, refused when added | A scanner's issue against a third-party component is dependency hygiene; refused at adding, the refusal names the issue somebody chose |
| An advisory with no issues generates nothing | The standard requires one, and a document about nothing drafts nothing |
| Read whole or not at all: somebody who may not see every issue it covers is told it does not exist, as for a name nobody minted | A document with a product left out reads as a complete statement about a product it says nothing of, and a row saying one went out is as much a disclosure |
| One covering nothing is its minter's alone, as is one whose issues were all taken off | Covering nothing it passes every narrowing, and its title is typed prose that becomes the document's |
| What went out is read at what it named: the report of what went out, the documents a directory serves, one advisory's issuances, whether it changed since, its editorial status and a document's revision history are shown only to a reader who may see what every issuance named and every flaw it covers now | Otherwise told it does not exist, so emptying or re-pointing an advisory after it went out discloses nothing |
| An issue taken off leaves its record, and naming it again revives that record | Who removed a flaw is a question a deleted row does not answer; reviving keeps the pair unique |
| A flaw recorded from a code finding is fixed in a build where a person closed it there; its page offers each build its code finding is no longer detected on, from the first run that did not see it | The code finding's absence is the evidence and the closure the statement (`design-docs/analysis.md` § Fixed in) |
| The flaws offered for a product are every one recorded there, open or fixed, with how many of each are still open | An advisory is usually written after the fix lands. The list is what naming one accepts: recorded by a person, at a visibility the reader sees, in a product they triage |

An advisory is rare and deliberate: single or low double digits a year, for a
flaw recorded here, an embargo reaching its date, or an inherited issue severe
enough to speak about before the next release cut. The trigger is a non-public
issue becoming public. Inherited issues otherwise reach the release note and
the disposition register, read at upgrade time.

## Editorial state

Where a document is in its life, read from what people did about it.

| Status | Reached by |
|---|---|
| `final` | An agreement stands on what it says now, whether or not it has gone out |
| `interim` | It has gone out, and no agreement stands on what it says now |
| `draft` | Neither |

| Rule | Reason |
|---|---|
| The agreement is asked before the issuance | A document is generated before it is published, so the bytes sent must say what they are; in the other order the file that goes out says draft |
| How far a document may travel is its distribution label, from whether anything it covers is still held back; the editorial state says only whether it is the publisher's settled word | A document about disclosed flaws can be unfinished, and one about an embargoed flaw ready to go |

## Editions and agreement

An edition is what an advisory says at a point. It carries the title; what it
covered then is recovered from when each flaw was named on it and taken off.

| Rule | Reason |
|---|---|
| An agreement names an edition | A second person reads particular words; one naming the advisory would stand after the words were rewritten, with nothing reporting it (REQ-24, REQ-28) |
| Retitling, naming a flaw, taking one off, and marking a release affected or clearing the mark each open a new edition | Each changes what the document says: a fourth flaw added under an agreement to three is one nobody read. Asking for a mark already standing opens nothing |
| An agreement records what each release stood at when given | A decision approved or lapsing afterwards moves a status and the agreement stands, since the decision had its own second person. The screen says "changed since approval" against every standing agreement, and whether the document differs from what last went out is asked of the settled digest |
| Opening an edition takes back every agreement on the one it replaced | The record still says a second person once agreed, and to which edition |
| Changing what an advisory says needs a triage role on every product it covers: retitling, agreeing, taking an agreement back, naming or removing a flaw, and recording that it went out | It is one document about all of them |
| The roles that may agree are the triage pair, never the approver role a decision takes | Agreeing is a statement about every product covered, which the triage roles are held per product for |
| Neither the person who started the advisory nor the author of the standing edition may agree to it, with no override | Whoever started it chose the name a reader cites and usually the flaws |
| The author of the standing edition is everybody who wrote an edition back to the one that set its title | A change to coverage opens an edition carrying the title forward, written by whoever changed it; asked of that edition alone, the title's author could agree to their own words |
| Taking an agreement back is open to anybody who may change the advisory, takes back every standing agreement, and needs no agreement of its own | It stops the document going out, not one person's opinion |
| An advisory goes out once an agreement stands on what it says, whether or not its flaws are public | An advisory about an embargoed flaw sent to a coordinating body is coordinated disclosure, and the distribution label keeps it safe |
| An issuance names the edition that went out | The advisory moves on; a record of March's document read through it would answer with June's title |
| Who agrees to the standing edition is named, by sign-in identity | A count says whether it may go out, not who vouched for it |

## Issuance records

An issuance records when a document went out, by whom, and a digest of what
went out. An advisory's is keyed on the advisory, so one revision of a document
covering two issues is one record; a VEX document's on the build and the kind of
document its identifier names, so each kind numbers its own revisions. Without
it a second document could carry no revision history and no incremented
version, both of which CSAF validators check.

| Rule | Reason |
|---|---|
| It is a fact about a moment | What was published on a date cannot be worked out again once a release is added, a decision revised or a fix landed |
| The document is kept as the bytes that went out | It is the only copy. Regenerated, a directory serves a different document dated as unmoved, by an edit that withdrew the agreement that let it go |
| Everything volatile in those bytes is dated when it left | A file written again by a later pass is the same file, and a reader fetches again by what moved |
| The version and history are read inside the write recording the issuance | Read outside, a second issuance committing between leaves a number missing from the history, which a validator reports |
| The moment it went out is read inside that write too | A retried attempt keeps the moment its predecessor started, dating the second revision before the first and every later history backwards. The same holds for a VEX document |
| The digest is taken from the document generated here | A caller's digest is of whatever they say; both sides of the comparison come from one place |
| The next document is one past what has gone out, and its last history entry is the document in hand, which says it has not gone out | |
| A revision is of the advisory, never of a flaw | An advisory covering two flaws going out once is one issuance |
| Recording that a VEX document went out asks for the triage role on the product, and no further agreement | Each statement it carries had its second person when the decision was approved |
| The public document is what is recorded, never the preview | The preview carries unannounced work, and recording it says this deployment published that work |
| Whether a document moved since it last went out is answered beside it, for an advisory and a VEX document alike | The settled digest of what would be generated now against the last issuance's. No answer where nothing has gone out, or where no publisher is configured and nothing can be generated |

### The two hashes

| Hash | Over | Answers |
|---|---|---|
| The settled digest | What the document says: the title, the product tree and the vulnerabilities | Whether what is published is still what this would generate |
| The delivered checksum | The bytes as published, every volatile field included | Whether the file a reader fetched arrived intact |

| Rule | Reason |
|---|---|
| The settled digest leaves out the assembly moment, the generator, the version, the revision history and the tracking status | They move on generation or because of issuance, and the tracking status follows the agreement, not the words |
| The address the document states for itself is outside the digest | It is where the file sits; inside, a deployment starting a directory would see every past issuance as differing, which reads as an instruction to re-issue all of them |
| The settled digest is taken as an issuance is recorded; the delivered checksum by the directory writer, over the file it writes | |

## Publisher identity

One record for every format: a VEX document and an advisory both read their
publisher from the same configuration.

| Rule | Reason |
|---|---|
| The publisher is deployment configuration, never an administrator's setting | It is the identity of the organization running this |
| A name and a namespace are both required | A document naming no publisher is not a CSAF document |
| Generating or recording a document with no publisher configured answers 409; any other failure is a fault | The missing publisher is the store's own refusal, matched by identity. Reading what has gone out needs no publisher, so its failures are faults wherever none is configured |
| The CSAF category is one of the six the standard names, refused at startup otherwise | It reaches the document verbatim, so a typo yields advisories failing validation wherever they are taken |
| The VEX document ignores the category | A deployment publishing about its own product is a vendor, which is what the format wants told |

## Not built

| Not built | What exists |
|---|---|
| Every adapter sending an advisory to somebody's platform (§ Publication) | Files written where an operator pointed, for their own web server (`design-docs/remediation-directory.md`), and the documents this deployment serves itself (`design-docs/publishing.md`) |
| Document-level notes of the deployment's own | An edition carries the title and each issuance a typed revision summary; everything else a reader acts on is assembled from the flaws the advisory covers |

## Limits

| Rule | Reason |
|---|---|
| A deployment with one person publishes no advisory | That person started it, may not agree to it, and nothing overrides that: the control working |
