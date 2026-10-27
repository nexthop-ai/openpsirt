# The VEX document

The OpenVEX document of one build, one product, branch or tag, and variant:
approved `not-applicable`, `mismatched` and `already-fixed` decisions (REQ-39),
`wont-fix` decisions saying what a holder can do instead, and the patches the
build declares.

Satisfies REQ-11, REQ-18, REQ-31, REQ-37, REQ-39.

Its issuances are in `design-docs/remediation-advisories.md` § Issuance
records; the per-issue and per-branch documents this deployment serves are in
`design-docs/publishing.md`.

## Contents

- [Document kinds](#document-kinds)
- [Statements](#statements)
- [Supplier statements](#supplier-statements)
- [Agreement across occurrences](#agreement-across-occurrences)
- [Statements about one occurrence](#statements-about-one-occurrence)
- [Identity and revisions](#identity-and-revisions)
- [Limits](#limits)

## Document kinds

A customer running their own scanner against a shipped image asks "which of
these are you not affected by" more often than for an advisory. The document
puts this deployment's dismissals in writing in front of every customer, which
is why those decisions need two people.

The kind is chosen when a document is generated.

| Kind | Carries |
|---|---|
| Ours | What this deployment agreed to, and the patches the build declares. The default |
| With suppliers | Ours, and beside it what a supplier states about its own product, in the supplier's name, where the statement closed every occurrence of a component in the build |

| Rule | Reason |
|---|---|
| OpenVEX, never the CSAF profile | It is the format this deployment reads, so one deployment's output is another's input |
| Each kind is a document of its own, with its own identifier and revisions | A toggle on one document has statements vanish and return at a generator's choice, reading as a retraction nobody made |
| Ours is the default | Putting a supplier's word under this deployment's name is a deliberate choice, and configuring a supplier is not that choice |

## Statements

| Rule | Reason |
|---|---|
| Approved decisions only, beside the build's own patches and, in the document carrying them, suppliers' statements | A proposal is one person's opinion, and this is the deployment's word to a customer |
| A patch the build declares is stated `fixed` | The build's word on its own patches is applied without a decision here (REQ-11); the finding is closed as patched, and a customer's scanner still matches the upstream version |
| A patch is stated only while it stands: the component still ships, no occurrence of a component of that name and package identifier is open against the issue, and the build still declares it | A build dropping the patch drops the statement before any scan reopens the finding |
| The impact statement carries what stops the flaw, never the reasoning | The reasoning is a triager's argument to a second person; published, it is this deployment's review of itself in front of every customer |
| Where no mitigation was named the field is absent | Only one recognized reason asks for one, and silence says less wrongly than the wrong text |
| An outcome with no status of its own fails the document as a fault | Each outcome maps to one status by name, and the outcomes a covering read selects are one list a test holds to the statuses. The only safe default on a published document is silence |
| A deferral is absent | Exported as not affected it claims an assessment that was only postponed; silence already reads as affected |
| A decision not to fix is published as affected, and only where it names what to do instead | It is the truth: the flaw is there and staying, and nothing else tells a customer about a third-party component. The format requires an action on an affected statement, so a decision offering none falls through to silence |
| The mitigation's field depends on the status | On a not-affected decision it is why, beside the machine-read category; on a will-not-fix one, what to do instead. An affected statement carrying a not-affected justification says both |
| Public findings only | Asking for undisclosed ones is a preview for somebody who may read them, refused for anybody who may not |
| A statement is about the build with the component beneath, or about the consumer where stated occurrence by occurrence | What somebody has is the image |
| The build is named by the package identifier its inventory gave its root, or by its names where it gave none | A scanner matches the product against the root, and a deployment loading both reads a statement about the root as the build's own claim |
| A component with no package identifier is named by the name the build calls it | A silent omission reads in this format as "no claim" |
| Every statement carries the other names its issue answers to, the primary not repeated among them (REQ-18) | A customer holds identifiers under the names their own scanner's database uses |
| An issue that is also a flaw of ours undisclosed anywhere carries no other names in a document of disclosed work; a preview including undisclosed work keeps them | One of them is the flaw's minted name, which is the flaw (REQ-37) |
| Ordered here, never by the engine | Two documents from the same state are byte-for-byte identical |
| A build with more statements than one document carries is refused, naming the build and the number, never truncated | There is no second request, so a document stopping at a ceiling says "nothing is claimed" about everything past it to every customer. The ceiling is well above anything real |

## Supplier statements

| Rule | Reason |
|---|---|
| Stated only while it stands, under the guard a patch stands under: the component still ships, no occurrence of that name and package identifier is open against the issue, the statement that closed it is not set aside, and nothing has been recorded at the occurrence since | An occurrence the build later patched is stated fixed |
| Stated `not_affected`, with the supplier's justification where the format defines it, and an impact statement naming the publisher, the document and the product | A customer sees whose judgment it is. A justification the format does not define is left out, and the impact statement satisfies the format without one |
| Only a statement that said not affected is passed on | An upstream's statement that a component is fixed closes occurrences too (`design-docs/upstream.md`) and says nothing of being unaffected |
| A component two suppliers' statements closed occurrences of is stated by neither | Each spoke for their own product, and the format names the component once |
| An agreed decision and a supplier's statement never speak about one issue in one component | A decision is stated only of a component with an occurrence open, a supplier's statement only of one with none |

## Agreement across occurrences

A statement about the build is made only where every open occurrence agrees,
and agrees the same way; an advisory asks the same of each release through the
same query. A dismissal agreed at one occurrence of a component sitting at
several, published about the component, is a machine-readable "not affected"
about something affected.

| Rule | Reason |
|---|---|
| Where occurrences were decided in separate sittings, the earliest decision speaks | It has stood longest and a reader can check it against the record. Grouping on the words and moment emits one decision twice |
| The earliest decision is picked first, by identifier, and then its words are read | A minimum per column composes a statement from two decisions: with "component_not_present" and "inline_mitigations_already_exist / bound to the management VLAN" both standing, it would say the component is absent while describing the control protecting it |
| Occurrences dismissed for different reasons are no statement about the component | Each is stated about its own occurrence, where § Statements about one occurrence holds there |

## Statements about one occurrence

Where a component's occurrences disagree, each occurrence a decision covers is
stated on its own: the consumer pulling the component in is the product and the
component is beneath it. "libnl inside libswsscommon 1.0.0: not affected".

| Rule | Reason |
|---|---|
| An occurrence is stated only where every open occurrence of the component beneath its consumer, at any depth, is decided the same way | A reader applies a statement about a product to everything beneath it, a supplier's statement included (REQ-31) |
| The earliest decision among those occurrences speaks | As for a whole component |
| A consumer whose package identifier names no version names no product | A product at no version is every release of it, and a reader applies it nowhere |
| An occurrence the build holds directly is never stated alone | Its only product would be the build, applied across the whole build |
| One statement per consumer, however many occurrences beneath it agree | A deeper occurrence is also stated about its own consumer, where the rule holds there |
| Only from an agreed decision, never from a patch the build declares | A patch is stated about a whole component; a fix the build states beneath one product closes only occurrences beneath it, so with another occurrence open the fix is not published |

## Identity and revisions

| Rule | Reason |
|---|---|
| The document carrying suppliers' statements is named for the build and its kind; ours keeps its name | It is a second document |
| The identifier names the build and nothing that moves | A reader tells a revision from a second document by whether it matches |
| The build is named by the stored names | A name people type matches without regard to capitals, so one build asked for two ways carries one name |
| The version is one past what has gone out, stated before it goes out | The bytes sent carry the number they will be known by |
| The document to send is the one recording answers with | Recording numbers and dates it inside the write taking the ordinal, keeps it and hands it back; generated before, somebody else recording between leaves it one behind its own record |
| Each revision that went out is readable by its version | The kept bytes are what a customer holds |
| Two generations with nothing published between are one revision | A change nobody published is a revision no reader holds |
| The moment the document was assembled sits in its own field | The format carries it there, and an identifier is an identity |

## Limits

| Rule | Reason |
|---|---|
| A dismissal covering part of a group is never published as covering all of it | A statement about a group speaks for the whole group |
