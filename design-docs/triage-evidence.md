# Evidence

What publishers say about a finding, which of it closes findings here, and
decisions other products made at the same occurrence.

Satisfies REQ-11, REQ-31, REQ-84.

## Contents

- [Evidence from publishers](#evidence-from-publishers)
- [Statement display and filters](#statement-display-and-filters)
- [Decided elsewhere](#decided-elsewhere)
- [Limits](#limits)

## Evidence from publishers

Three kinds of document arrive, and the layer is named for what it holds
(REQ-31): a publisher's VEX statement set, a supplier's security advisory about
its own products, and a VEX document an upstream this product trusts publishes
(`design-docs/upstream.md`). The screen says "what publishers say" and the field
is named the same, since a name from one format is wrong about the other.

It is a third layer, beside a build's claims and the decisions made here. The
screen shows what the build claims, what the distribution says, and what we
decided, as three statements.

| Rule | Reason |
|---|---|
| An empty panel says there is nothing, and why | Empty reads as "nobody has an opinion" where no document was uploaded |
| A statement's reasoning is stored once however many components it names, cut to the bound a build's claim is cut to (`design-docs/findings-closure.md` § Build-declared claims) | |
| Its file name is made safe and bounded as an attachment's is | Every statement in the document carries it |
| A supplier's statement about its own product closes the finding at the occurrences that product occupies (REQ-31), applied by the run beside the build's own patches and the CVE record | § Supplier statements applied |
| An upstream's statement holding for anybody shipping the component closes it at that component and version (REQ-84) | `design-docs/upstream.md` § Statements applied |
| Every other statement is shown and offered as a prefill, and closes nothing | A statement is applied only to what it speaks for |

### Supplier statements applied

The supplier's product is what a statement names a component as shipping inside:
the product of an OpenVEX statement with subcomponents, or the platform a CSAF
relationship composes the component into. Where a statement names no such
product and no package identifier, the product is what it names. A statement
naming a package alone, and one recorded before the product was read, name no
supplier's product and close nothing.

| Rule | Reason |
|---|---|
| A statement closes a finding where every route up the tree from its occurrence runs through the supplier's product: the consumer is the product, or sits beneath it where the root reaches it no other way. Worked out per product from the build's edges, two passes each | Every route to an occurrence runs through its consumer |
| An occurrence reached through the product and outside it stays open, marked answered through the product, and is not work: no deadline, in no late count, no notice, no duplicate report routed to it, counted as answered | One row stands for both routes. Closed, it hides the unanswered route; unmarked, it hides the supplier's answer |
| A statement about a component inside the product closes its issue's findings on that component alone | Another component under the product with the same issue is not answered |
| A statement naming the product alone closes its issue's findings on anything beneath the product | The supplier is speaking about everything they shipped |
| A finding on the product itself stays evidence, including one a cycle puts beneath itself | A statement naming a package cannot tell the supplier's build from a rebuild of its source |
| A statement naming an ecosystem's package alone closes nothing | A distribution's identifier is shared by its own build and a rebuild of its source |
| The product is matched exactly, at the version the statement names; a version change reopens the finding; a statement naming no version stays evidence | A statement about one release says nothing about the next, and one naming none speaks for every release past and future |
| The product is matched by the package identifier the statement names, or the component's own name, never by what the component was built from. A generic identifier is matched against the component's identifier and name, with its namespace compared as a source-tree claim compares one | A fork carries the supplier's name as its source, and a build of the supplier's source is not the supplier's product |
| Only `not_affected` closes, whatever its justification | Each justification is the supplier speaking about its own product. "Will not be fixed" is affected and minor, and stays a prefilled will-not-fix |
| The product must be a component of the build | A distribution names a platform no build here contains, so its statements close nothing |
| The build's own patch and the CVE record are asked first | Both say the code is not vulnerable here, the stronger answer |
| An occurrence marked affected by a decision standing at its versions stays open | Disagreeing with a supplier is the ordinary route and needs no second person, hiding nothing |
| A closed occurrence is shown on the finding and can be decided about; the next run then opens it again | Only the latest row at the occurrence is: a run records a new row rather than reopening, so an earlier closed row speaks for nothing |
| A run no longer reading the statement there opens the finding again: the statement set aside or revised away, the product at another version, or the occurrence reachable outside it | A statement uploaded between scans is applied by the next scan |
| A version moving to one the statement speaks for closes the row before it as disclaimed | Nothing was fixed, so it is no upgrade |
| An occurrence closed for any other reason keeps no partial-route answer | What closed it is the reason a register reads |
| The closed row names the statement, and a revision saying the same moves the row to it | What closed it stays readable after supersession |
| Among several statements, one answering every route stands over one answering some, and the oldest over a newer | The answer does not move between runs |

### Statements about the build

A statement whose product is a build's root speaks for the build's producer
however it arrived (REQ-11). Sent with the inventory, it is recorded as the
build's claim when the scan is read; uploaded on its own, the run records it as
a claim of the build taken from that statement. Both apply alike
(`design-docs/findings-closure.md` § Build-declared claims).

| Rule | Reason |
|---|---|
| The root is matched by the package identifier the build's latest inventory gave it, at the version the statement names; no version, or a root with no identifier, places nothing and the statement stays evidence | A statement about one release says nothing about the next |
| A root another build of the product also holds names neither build; sent with each inventory, statements are told apart by the upload they arrive in | Two variants of one release commonly share the identifier |
| Where a claim sent with the inventory and one taken from a statement cover one occurrence, the more recently said stands | A revision uploaded alone replaces the inventory's, and a later upload the revision. Each upload restates every claim the build still sends, and a later document repeating a statement says it again; the same document twice says nothing new |
| A claim taken from a statement closes when the statement is set aside or revised away, or the root moves version; the run keeps it in step before the build's claims are read | A scan restates the claims it sent, never these |
| The claim names the statement it came from | Whose document it is stays readable |
| A statement about a component inside the build, uploaded alone, is that component's supplier's | § Supplier statements applied |
| The same statement sent with the inventory is the build's claim, applied beneath that component | The build is speaking. A supplier's statement is replaced by the publisher's next document across the product, and every build sends one by the same author, so each would set aside the last. `design-docs/ingest.md` § Build-declared suppressions |

### Evidence placement

| Rule | Reason |
|---|---|
| A statement naming the product its component ships inside, where this product ships that product, is evidence where the product is above the component in the build, at any version; a statement about one release of the product is still the supplier's word where another sits, and closes nothing there | Shown against every component of the name, it speaks where the supplier never spoke |
| A statement naming a product this product does not ship is evidence by package; whether a product ships is asked by name across this product's builds | A distribution's platform is no component of any build |
| A statement naming a product alone is evidence on the product and beneath it | It is about the product and what was shipped inside |
| The list's publisher and status filter reaches a statement placed by its product only through findings the run answered with it; a placed statement the run does not apply, of another status, or naming no version, is evidence on the finding and not found by the filter | A component and issue pair cannot say where a component sits, and placing every list row is a walk per row |

## Statement display and filters

What the document adds is the reasoning: the status is already in the scanner's
fix state, and the reasoning is what a triager otherwise types from memory and
an approver cannot check. Statements filter by what was said and who said it:
1,113 of 1,125 no-fix findings on a real image are distribution packages, about
which distributions publish machine-readable statements.

This does not contradict rejecting abandonment as a signal: that rejected the
absence of a fix, true of nearly everything; this is the presence of a security
team's statement about that issue in that package.

| Rule | Reason |
|---|---|
| A distribution declining to fix is affected: Debian's `no-dsa`, Ubuntu's `ignored` and Red Hat's will-not-fix prefill a will-not-fix, never `not-applicable`; a publisher that has not decided offers nothing | Each means affected and judged minor |
| The statements are resolved once into the pairs they name, distinct by `UNION`, and the list joins that | Far fewer statements than findings, and a join cannot multiply a finding. As a correlated `EXISTS` over three subqueries per finding, the filter did not return within five minutes on 281,884 findings and 1,854 statements, and held a core after the request was abandoned |
| The issue's identifier is folded on write | A published identifier arrives in any case and a statement folded; a function on the indexed side is an index nobody uses |
| Only what stands narrows; a superseded row stays readable | An approval granted on it remains explicable |
| A later upload sets aside its document's own kind: a statement set replaces the publisher's set; an advisory replaces the advisory of its name (`design-docs/ingest.md` § Supplier advisories) | A set is a whole answer; an advisory is one announcement among hundreds |
| The same bytes again change nothing | A superseded claim notifies everyone holding an approved decision citing it, and re-syncing a publisher's directory is ordinary |
| A statement is shown against the package it names, comparing type and namespace, never the version | A component is called by its short name, and two registries hold different packages under one: a scoped npm package's statement otherwise appears on every `parser` |
| The version a statement was made about is shown beside what it said, stored rather than read back from the identifier | A supplier's advisory names the fixing version, so a status alone says the opposite; a publisher stating products without identifiers states the version as its product's branch |
| A claim against a source tree is shown however named | A bare name and a generic package identifier are one claim to the matching rules, and the evidence must show what already suppressed the finding |

## Decided elsewhere

An approved decision about the same issue at the same occurrence in another
product, shown on the finding as a fourth block of evidence. An occurrence's
identity is a consumer and a component with no product, so it is recognized
across variants and across products: two products shipping the same library
under the same consumer hold the same code in the same position.

| Rule | Reason |
|---|---|
| Evidence, never an outcome | Another team's decision is about their product, and what ships around a component differs |
| Offered as a prefill for the reasoning; the outcome is not carried | Reading another argument is for judging whether it holds here |
| Narrowed by what the subject may read | An occurrence spans products, so without the subject the join hands over an embargoed decision's reasoning, approver and existence in a product the reader cannot see |
| Approved decisions only, at most a handful | A proposal is nobody's conclusion, and twenty products would put twenty blocks on a screen |
| Applied to nothing here (REQ-31) | A statement is applied only to what it speaks for |

## Limits

| Limit | Detail |
|---|---|
| A statement closes only what its author speaks for | A supplier for its product, an upstream for its component, a build for itself; everything else is evidence |
