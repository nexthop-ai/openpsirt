# Advisories

The advisory as a record of its own, its editorial state, the agreement it goes
out under, the record of each issuance, and the publisher it names.

Satisfies REQ-19, REQ-24, REQ-28, REQ-37, REQ-39, REQ-42.

The document generated for an advisory is in `design-docs/remediation-csaf.md`;
the files written for a web server, in `design-docs/remediation-directory.md`;
the documents this deployment serves, in `design-docs/publishing.md`.

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

Two destinations are built: the static provider directory, and the documents
this deployment serves where it publishes. Nothing is sent anywhere. Publication
covers a flaw in this deployment's own product (REQ-39); a CVE in a shipped
third-party component is dependency hygiene read from the inventory.

The rules an adapter to somebody's platform would follow:

| Rule | Reason |
|---|---|
| A pluggable output with several adapters | An open-source project uses its forge's advisory system, an appliance vendor its own site |
| The triage record is ours, the published advisory the platform's; neither syncs the other | |
| CSAF is the adapter that matters for commercial products | VEX is a CSAF profile, and the dismissal vocabulary is aligned to it |
| A forge's advisory system is one adapter: draft privately, request an identifier, publish, and fix under embargo in its temporary private fork | |
| One advisory covers a product and a version range, never a path | A reader asks "am I affected", and the answer is a version |
| Optional and configured per deployment | Nobody needs an account anywhere |

## The advisory

A record of its own, under an identifier this deployment mints, naming the
issues it covers and the products each is covered in. Advisories are single or
low double digits a year: a flaw recorded here, an embargo reaching its date, or
an inherited issue severe enough to speak about before the next release. Other
inherited issues reach the release note and the disposition register.

| Rule | Reason |
|---|---|
| Keyed on itself, never on a product and an issue | The standard carries vulnerabilities as an array and means the tracking identifier as the publisher's own name |
| The identifier is a year and a number under a prefix the deployment configures | It is the name a reader cites and a revision keeps |
| An advisory issued before v0.2.0 keeps its name, numbered in year zero | No minted name reaches it |
| Many issues across many products | Embargoed flaws released together are one document; one issue in two products is two entries |
| An issue is named once per product | Named twice, the document is refused |
| Only a flaw recorded here, refused when added, naming the issue | |
| An advisory with no issues generates nothing | The standard requires one |
| Read whole or not at all: a reader who may not see every issue it covers is told it does not exist | A document missing a product reads as complete, and a row saying one went out discloses as much |
| One covering nothing, or whose issues were all taken off, is its minter's alone | It passes every narrowing, and its title is typed prose |
| Everything about what went out (the report of issuances, the files a directory serves, one advisory's issuances, whether it changed since, its editorial status, a revision history) is shown only to a reader who may see what every issuance named and every flaw it covers now | Emptying or re-pointing an advisory after it went out discloses nothing |
| An issue taken off leaves its record, and naming it again revives it | Who removed a flaw stays answerable, and the pair stays unique |
| A flaw recorded from a code finding is fixed in a build where a person closed it there; its page offers each build its code finding is no longer detected on, from the first run not seeing it (`design-docs/analysis.md` § Fixed in) | |
| The flaws offered for a product are every one recorded there, open or fixed, with how many are open: recorded by a person, at a visibility the reader sees, in a product they triage | An advisory is usually written after the fix |

## Editorial state

| Status | Reached by |
|---|---|
| `final` | An agreement stands on what it says now, gone out or not |
| `interim` | It has gone out, and no agreement stands on what it says now |
| `draft` | Neither |

| Rule | Reason |
|---|---|
| The agreement is asked before the issuance | The bytes sent must say what they are |
| How far a document travels is its distribution label, from whether anything it covers is held back; the editorial state is independent | A disclosed document can be unfinished, and an embargoed one ready |

## Editions and agreement

An edition is what an advisory says at a point. It carries the title; what it
covered then is recovered from when each flaw was named and taken off.

| Rule | Reason |
|---|---|
| An agreement names an edition | Naming the advisory, it would survive a rewrite (REQ-24, REQ-28) |
| Retitling, naming or removing a flaw, and marking a release affected or clearing the mark each open an edition; asking for a mark already standing opens nothing | Each changes what the document says |
| An agreement records what each release stood at when given | A decision approved or lapsing later moves a status and the agreement stands; the screen says "changed since approval" against it, and difference from what went out is asked of the settled digest |
| Opening an edition takes back every agreement on the one replaced | The record keeps which edition was agreed |
| Every change to what an advisory says, agreeing, taking agreement back, and recording that it went out need a triage role on every product it covers | It is one document about all of them |
| The triage pair may agree, never the approver role a decision takes | Agreeing speaks for every product covered |
| Neither the advisory's starter nor the standing edition's author may agree, with no override | The starter chose the cited name and usually the flaws |
| The standing edition's author is everybody who wrote an edition back to the one that set its title | Otherwise the title's author agrees to their own words |
| Taking agreement back is anybody's who may change the advisory, takes back every standing agreement, and needs no agreement | It stops the document going out |
| An advisory goes out once an agreement stands, whether or not its flaws are public | Sending an embargoed flaw to a coordinating body is coordinated disclosure; the label keeps it safe |
| An issuance names the edition that went out | Otherwise March's record reads June's title |
| Who agrees to the standing edition is named, by sign-in identity | A count says it may go out, not who vouched |

## Issuance records

An issuance records when a document went out, by whom, and a digest of it. An
advisory's is keyed on the advisory, so a revision covering two issues is one
record; a VEX document's on its build and kind, so each kind numbers its own
revisions. CSAF validators check the revision history and version it yields.

| Rule | Reason |
|---|---|
| The document is kept as the bytes that went out | It is the only copy of a moment that cannot be worked out again |
| Everything volatile in those bytes is dated when it left | A later pass writes the same file |
| The version, the history and the moment it went out are read inside the write recording it, for an advisory and a VEX document alike | Outside, a concurrent issuance leaves a gap a validator reports, and a retry dates the second revision before the first |
| The digest is of the document generated here, never a caller's | |
| The next document is one past what went out, and its last history entry says it has not gone out | |
| A revision is of the advisory, never of a flaw | Two flaws going out once are one issuance |
| Recording that a VEX document went out needs the triage role on the product, and no further agreement | Each statement had its second person at approval |
| The public document is recorded, never the preview | The preview carries unannounced work |
| Whether a document moved since it last went out is answered beside it, for both kinds, from the settled digest | No answer where nothing went out or no publisher is configured |

### The two hashes

| Hash | Over | Answers |
|---|---|---|
| The settled digest | The title, the product tree and the vulnerabilities | Whether what is published is what this would generate |
| The delivered checksum | The bytes as published | Whether a fetched file arrived intact |

| Rule | Reason |
|---|---|
| The settled digest leaves out the assembly moment, generator, version, revision history and tracking status | They move on generation or issuance, and the tracking status follows the agreement |
| The document's own address is outside the digest | Inside, starting a directory would mark every past issuance changed |
| The settled digest is taken at issuance; the delivered checksum by the directory writer | |

## Publisher identity

One record for every format, read from configuration by the VEX document and
the advisory alike.

| Rule | Reason |
|---|---|
| Deployment configuration, never an administrator's setting | It is the identity of the organization running this |
| A name and a namespace are required | A document naming no publisher is not CSAF |
| Generating or recording with no publisher answers 409; any other failure is a fault | The missing publisher is the store's own refusal, matched by identity. Reading what went out needs no publisher |
| The CSAF category is one of the standard's six, refused at startup otherwise | It reaches the document verbatim |
| The VEX document ignores the category | A deployment publishing about its own product is a vendor |

## Not built

| Not built | What exists |
|---|---|
| Every adapter sending an advisory to somebody's platform | The provider directory (`design-docs/remediation-directory.md`) and the served documents (`design-docs/publishing.md`) |
| Document-level notes of the deployment's own | An edition's title and each issuance's typed revision summary; the rest is assembled from the flaws covered |

## Limits

| Rule | Reason |
|---|---|
| A deployment with one person publishes no advisory | That person started it and may not agree to it |
