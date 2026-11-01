# The VEX document

The OpenVEX document of one build (a product, branch or tag, and variant):
approved `not-applicable`, `mismatched` and `already-fixed` decisions (REQ-39),
`wont-fix` decisions saying what a holder can do instead, and the patches the
build declares.

Satisfies REQ-11, REQ-18, REQ-31, REQ-37, REQ-39.

Its issuances are in `design-docs/remediation-advisories.md` § Issuance
records; the documents this deployment serves per issue and per branch, in
`design-docs/publishing.md`.

## Contents

- [Document kinds](#document-kinds)
- [Statements](#statements)
- [Supplier statements](#supplier-statements)
- [Agreement across occurrences](#agreement-across-occurrences)
- [Statements about one occurrence](#statements-about-one-occurrence)
- [Reads](#reads)
- [Identity and revisions](#identity-and-revisions)
- [Limits](#limits)

## Document kinds

A customer scanning a shipped image asks which issues it is not affected by
more often than for an advisory, and this document answers in front of every
customer, which is why its dismissals need two people. The kind is chosen when
a document is generated.

| Kind | Carries |
|---|---|
| Ours, the default | What this deployment agreed to, and the patches the build declares |
| With suppliers | Ours, and what a supplier states about its own product, in its name, where the statement closed every occurrence of a component in the build |

| Rule | Reason |
|---|---|
| OpenVEX, never the CSAF profile | It is the format this deployment reads |
| Each kind is its own document, with its own identifier and revisions | A toggle reads as retractions nobody made |
| Ours is the default | Configuring a supplier is not choosing to publish its word |

## Statements

| Rule | Reason |
|---|---|
| Approved decisions only, beside the build's patches and, in that kind, suppliers' statements | A proposal is one person's opinion |
| A patch the build declares is stated `fixed` (REQ-11) | A customer's scanner still matches the upstream version |
| A patch is stated only while the component still ships, no occurrence of its name and package identifier is open against the issue, and the build still declares it | Dropping the patch drops the statement before a scan reopens the finding |
| The impact statement carries what stops the flaw, never the reasoning, and is absent where no mitigation was named | The reasoning is a triager's argument to a second person |
| An outcome with no status of its own fails the document as a fault | Each outcome maps to one status by name, and a test holds the covering read's outcomes to them; the safe default is silence |
| A deferral is absent | Silence already reads as affected |
| A decision not to fix is stated affected, only where it names what to do instead | Nothing else tells a customer, and the format requires an action |
| The mitigation's field follows the status: why on not affected, what to do on affected | |
| Public findings only; undisclosed ones are a preview for a reader who may see them | |
| A statement is about the build with the component beneath, or about the consumer when stated by occurrence | What somebody has is the image |
| The build is named by the package identifier its inventory gave its root, else by its names | A scanner matches the product against the root |
| A component with no package identifier is named as the build calls it | An omission reads as "no claim" |
| Every statement carries its issue's other names, without repeating the primary (REQ-18) | A customer's scanner uses its own database's names |
| An issue that is also a flaw of ours undisclosed anywhere carries no other names in a document of disclosed work; a preview keeps them | One is the flaw's minted name (REQ-37) |
| Ordered here, never by the engine | The same state gives the same bytes |
| A build with more statements than one document carries is refused, naming the build and the number, never truncated | A truncated document claims nothing about the rest. The ceiling is well above anything real |

## Supplier statements

| Rule | Reason |
|---|---|
| Stated only while it stands, under a patch's guard: the component ships, no occurrence of its name and package identifier is open, the closing statement is not set aside, and nothing has been recorded at the occurrence since | An occurrence later patched is stated fixed |
| Stated `not_affected`, with the supplier's justification where the format defines one, and an impact statement naming the publisher, the document and the product | A customer sees whose judgment it is |
| Only a statement saying not affected is passed on | An upstream's fixed statement closes occurrences (`design-docs/upstream.md`) without saying unaffected |
| A component two suppliers' statements closed is stated by neither | The format names the component once |
| An agreed decision and a supplier's statement never speak about one issue in one component | A decision needs an open occurrence, a supplier statement none |

## Agreement across occurrences

A statement about the build is made only where every open occurrence agrees the
same way; an advisory asks the same of each release, through the same query.

| Rule | Reason |
|---|---|
| Across separate sittings, the earliest decision speaks | It is the one a reader can check; grouping on words and moment emits one decision twice |
| The earliest is picked by identifier, then its words are read | A minimum per column composes "component_not_present" with another decision's "bound to the management VLAN" |
| Occurrences dismissed for different reasons are no statement about the component | Each is stated about its own occurrence where § Statements about one occurrence holds |

## Statements about one occurrence

Where a component's occurrences disagree, each decided occurrence is stated on
its own, the consumer pulling it in as the product: "libnl inside
libswsscommon 1.0.0: not affected".

| Rule | Reason |
|---|---|
| Only where every open occurrence beneath the consumer, at any depth, is decided the same way | A reader applies a statement to everything beneath its product (REQ-31) |
| The earliest decision speaks | |
| A consumer whose package identifier names no version names no product | A reader applies it nowhere |
| An occurrence the build holds directly is never stated alone | Its product would be the whole build |
| One statement per consumer; a deeper occurrence is also stated about its own consumer where the rule holds | |
| Only from an agreed decision, never from a declared patch | A patch is stated about a whole component, and is not published while another occurrence is open |

## Reads

The document of a build and the statements published about it
(`design-docs/publishing.md`) read through the same statements. The runs behind
these rules are in `design-docs/remediation-measurements.md` § VEX document
reads and § A long-lived product.

| Rule | Reason |
|---|---|
| The issues a covering decision exists for in the product, at an occurrence the build holds open, are read first, and only their findings after | Most of a build's open findings are undecided, and a product decides issues across every build it had |
| A statement about the build is grouped in two levels: each issue at each component, then each name and stated package identifier | The stated identifier is asked once per component |
| In a statement read as one query, a component's stated package identifier is asked of each row with its keys bound, never joined | Joined, an engine with no statistics reads the build's graph once per finding |
| In a statement read as one query, the open image version is asked of each open node with its keys bound | An image keeps every version it was rebuilt at; read through all of them, each row costs the image's history |
| A statement occurrence by occurrence reads the same issues first | |
| The patches and suppliers' statements are read as sets and grouped in the application: the build's closed findings, what closed them, the findings of their issues, the open nodes and image versions of their components, and the components' names | Asked per row or per group inside one statement, every engine picks a plan reading the build's findings or graph once per closed finding on the statistics a bulk load leaves |
| Each of those statements reads one table by constants, and joins another only by its primary key | A primary key lookup is the one plan every engine picks whatever its statistics say |
| The findings of the closed issues are read once: open and closed for the suppliers' statements, serving both the open check and the latest row at each occurrence; the open ones for the patches | Read twice, the suppliers' statements take 202 ms against 119 ms on SQLite, analyzed |
| The findings of the closed issues are read at every visibility, whatever the document is read at | An undisclosed occurrence still open holds back a disclosed statement |

## Identity and revisions

| Rule | Reason |
|---|---|
| The suppliers kind is named for the build and its kind; ours keeps its name | |
| The identifier names the build and nothing that moves | A reader tells a revision from a new document by it |
| The build is named by its stored names | A typed name matches regardless of capitals |
| The version is one past what has gone out, stated before it goes out | |
| The document to send is the one recording returns, numbered and dated inside that write | Generated earlier, a concurrent record leaves it one behind |
| Each revision that went out is readable by its version, from its kept bytes | |
| Two generations with nothing published between are one revision | |
| The assembly moment sits in its own field | An identifier is an identity |

## Limits

| Rule | Reason |
|---|---|
| A dismissal covering part of a group is never published as covering all of it | A statement speaks for its whole group |
