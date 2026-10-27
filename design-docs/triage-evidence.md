# Evidence

What publishers say about a finding, which of it closes findings here, and
decisions other products made at the same occurrence.

Satisfies REQ-11, REQ-31, REQ-84.

## Contents

- [Evidence from publishers](#evidence-from-publishers)
- [Statement display and filters](#statement-display-and-filters)
- [Decided elsewhere](#decided-elsewhere)

## Evidence from publishers

Three kinds of document arrive (REQ-31): a publisher's VEX statement set, a
supplier's advisory about its own products, and a trusted upstream's VEX
document (`design-docs/upstream.md`). The layer is named "what publishers say",
on screen and in the field. The screen shows what the build claims, what the
publisher says, and what we decided, as three statements.

| Rule | Reason |
|---|---|
| An empty panel says there is nothing, and why | Empty reads as nobody having an opinion |
| A statement's reasoning is stored once, cut to a build claim's bound (`design-docs/findings-closure.md` § Build-declared claims) | |
| Its file name is made safe and bounded as an attachment's | Every statement carries it |
| A supplier's statement about its own product closes the finding where that product occupies the occurrence (REQ-31), applied by the run after the build's patches and the CVE record | § Supplier statements applied |
| A trusted upstream's statement closes it at that component and version (REQ-84; `design-docs/upstream.md` § Statements applied) | |
| Every other statement is shown and offered as a prefill, and closes nothing | A statement applies only to what it speaks for |

### Supplier statements applied

The supplier's product is what the statement names a component as shipping
inside: an OpenVEX statement's product with subcomponents, or the platform a
CSAF relationship composes it into; failing both, and failing a package
identifier, what the statement names. A statement naming a package alone, or
recorded before the product was read, closes nothing.

| Rule | Reason |
|---|---|
| It closes a finding where every route up from the occurrence runs through the product: the consumer is the product, or beneath it where the root reaches it no other way. Worked out per product from the edges, two passes each | |
| An occurrence reached both through and outside the product stays open, marked answered through it: no deadline, in no late count, no notice, no duplicate report routed, counted answered | One row stands for both routes |
| About a component inside the product, it closes that component's findings of the issue only | |
| Naming the product alone, it closes the issue's findings on everything beneath | |
| A finding on the product itself stays evidence, a cycle included | A package identifier cannot tell the supplier's build from a rebuild |
| A statement naming an ecosystem's package alone closes nothing | |
| The product is matched exactly at the stated version; a version change reopens; no version stays evidence | |
| Matched by the statement's package identifier or the component's name, never by what it was built from; a generic identifier is matched against identifier and name, namespace compared as for a source-tree claim | A fork carries the supplier's name as its source |
| Only `not_affected` closes, whatever the justification; "will not be fixed" stays a prefilled will-not-fix | |
| The product must be a component of the build | A distribution's platform is in no build |
| The build's patch and the CVE record are asked first | |
| An occurrence somebody marked affected, by a decision standing at its versions, stays open; where the statement already closed it, the finding shows it, it can be decided, and the next run opens it again. Only the latest row at the occurrence counts | Disagreeing with a supplier hides nothing, so needs no second person |
| A run no longer reading the statement there reopens: set aside, revised away, another product version, or a route outside | A statement uploaded between scans applies at the next |
| A version moving to one the statement covers closes the row before as disclaimed | Nothing was fixed |
| An occurrence closed for any other reason keeps no partial-route answer | |
| The closed row names the statement; a revision saying the same moves the row to it | |
| Among several statements, one answering every route beats one answering some, and the oldest a newer | The answer is stable between runs |

### Statements about the build

A statement whose product is a build's root speaks for the producer (REQ-11):
sent with the inventory it is the build's claim when read, and uploaded alone the
run records it as a claim taken from that statement. Both apply alike
(`design-docs/findings-closure.md` § Build-declared claims).

| Rule | Reason |
|---|---|
| The root is matched by the package identifier the latest inventory gave it, at the stated version; no version or no identifier places nothing | |
| A root another build of the product shares names neither; sent with each inventory, statements are told apart by upload | Variants share the identifier |
| Of an inventory claim and a statement claim at one occurrence, the more recently said stands; each upload restates the build's claims, a later repeat says it again, the same document twice says nothing | |
| A statement claim closes when the statement is set aside or revised away, or the root moves, kept in step by the run before the build's claims are read | A scan restates only its own claims |
| The claim names its statement | |
| A statement about a component inside the build, uploaded alone, is its supplier's (§ Supplier statements applied) | |
| The same statement sent with the inventory is the build's claim beneath that component (`design-docs/ingest.md` § Build-declared suppressions) | As a supplier's, each build's upload would set aside the last |

### Evidence placement

| Rule | Reason |
|---|---|
| A statement naming the product its component ships inside, where this product ships that product, is evidence where the product sits above the component, at any version; at another release it still closes nothing | Shown on every component of the name, it speaks where the supplier did not |
| Naming a product this product does not ship, asked by name across its builds, it is evidence by package | |
| Naming a product alone, it is evidence on the product and beneath | |
| The publisher and status filter finds a placed statement only through findings the run answered with it | Placing every list row is a walk per row |

## Statement display and filters

The status is already in the scanner's fix state; the document adds reasoning a
triager otherwise types from memory. 1,113 of 1,125 no-fix findings on a real
image are distribution packages, which distributions publish statements about.
This is a security team's statement about one package, and does not contradict
rejecting the absence of a fix as a signal.

| Rule | Reason |
|---|---|
| A distribution declining to fix (Debian's `no-dsa`, Ubuntu's `ignored`, Red Hat's will-not-fix) prefills a will-not-fix, never `not-applicable`; undecided offers nothing | Each means affected and minor |
| Statements are resolved once into distinct pairs by `UNION`, and the list joins that | As a correlated `EXISTS` per finding the filter ran past five minutes on 281,884 findings and 1,854 statements |
| The issue identifier is folded on write | A function on the indexed side defeats the index |
| Only standing statements narrow; a superseded row stays readable | |
| A later upload sets aside its own kind: a set replaces the set, an advisory the advisory of its name (`design-docs/ingest.md` § Supplier advisories) | |
| The same bytes again change nothing | Supersession notifies holders of approvals citing it |
| Shown against the package named, type and namespace compared, never the version | A short name such as `parser` is many packages |
| The version a statement was made about is stored and shown beside it | A supplier names the fixing version; some state it only as a branch |
| A source-tree claim shows however named | Bare name and generic identifier are one claim |

## Decided elsewhere

An approved decision about the same issue at the same occurrence in another
product, shown as a fourth block of evidence. An occurrence has no product in
its identity, so two products shipping a library under one consumer share it.

| Rule | Reason |
|---|---|
| Evidence, never an outcome, and applied to nothing here (REQ-31) | What ships around a component differs |
| Offered as a reasoning prefill, never its outcome | |
| Narrowed by what the subject may read | Otherwise it leaks an embargoed decision in an unseen product |
| Approved decisions only, at most a handful | |
