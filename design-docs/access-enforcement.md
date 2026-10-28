# Access enforcement

Where each access check sits, the order it runs in, and refusals that disclose
nothing.

Satisfies REQ-29, REQ-42, REQ-43.

## Contents

- [Refusals disclose nothing](#refusals-disclose-nothing)
- [Enforcement sites](#enforcement-sites)
- [Store methods with no subject](#store-methods-with-no-subject)
- [Decisions about an issue](#decisions-about-an-issue)
- [Limits](#limits)

## Refusals disclose nothing

A product somebody holds nothing on is invisible: not listed, not counted, and
reported as not declared, the answer a name nobody declared gets. A pipeline key
is held to the same. The lookup and the check happen together, because resolving
a name first leaks the difference.

| Name in a request | Rule |
|---|---|
| A person | Every route decides whether the caller may act before resolving the person, or any account reads a staff directory. A route open to any credential answers a name nobody holds as a name whose work the caller cannot see: an empty list |
| An issue at an occurrence | One resolver serves every such route: resolve the name, then ask whether the subject may read a finding of it in this product, and answer a failure of either "no open finding is recorded there". The identifier carries no sequence to walk or count |
| A list of issues | The resolver's list form, one statement per batch. A name filed only where the caller may not read it gets the words of a name nobody filed |
| A component | A graph read taking a component name refuses before resolving it, or the inventory reads back one guess at a time, versions and ecosystems included |

A test walks every route carrying an identity and asserts that a held and an
unheld name answer alike, for every kind of credential, one holding nothing
included.

## Enforcement sites

| Decided | Where | Reason |
|---|---|---|
| Who is asking | One middleware, before any route | A handler that forgets answers for everybody |
| Whether they are anybody at all | The same middleware | An unrecognized caller learns nothing of its body |
| Whether they may reach this product | The data layer, on the query | A new endpoint cannot skip it |
| Whether they may do this at all | The handler | Declaring a product is administration whatever the query |
| Whether a header from an untrusted source was a mistake | Logged, never answered | The operator's only signal of a wrong address family |

| Rule | Reason |
|---|---|
| Everything outside the unauthenticated surfaces (`design-docs/api.md` § Unauthenticated surfaces) is authenticated, named as a list and never by path prefix | A prefix leaves open what lies outside it, framework routes included |
| A query without a subject is a fault: reading the subject from a request with nobody attached fails | Absence read as "nobody" hides the bug until a query reads it as "everybody" |
| A pipeline is refused a read, the receipts of the builds it may upload to excepted | An empty answer reads as an empty list |
| Every read of findings in one product or build first asks which visibilities the subject reads there; none is a refusal, whether the product is unseen or seen with nothing read | A pipeline key and an administrator granted no reading are both refused. A read about one issue widens the question by a case the subject was brought into |
| The refusal sits in the store read as well as at the edge, and the zero subject counts as a non-person | A handler check is the one somebody forgets |
| A non-person is refused; a person holding nothing gets an empty list | Both checks stay, and the layers agree |
| A read is narrowed to the products somebody holds anything on, and within those to the visibilities read in each, as one call; nothing calls the visibility half bare | Where a product is already pinned, a named pairing states that the first half was done |

| Read | Answer to a subject that reads nothing there |
|---|---|
| Findings, occurrences, runs, promised upgrades, carried patches, received VEX, readiness, standing, what each release holds, the release trend, the labels in use | Refused |
| What each run opened and closed | Refused, for an empty list of runs as well |
| The receipts list | The receipts, with no counts of what each run changed |

## Store methods with no subject

A store method takes no subject only for one of three reasons:

1. A background pass answering to nobody.
2. A private helper reading rows a narrowed query already selected.
3. A question whose answer does not vary by who asks, such as whether a finding is suppressed.

The exported methods of the finding, triage and graph stores that query without
a subject are named, with their reason, in a list `make subjected` holds them to
(`design-docs/build.md` § Make targets). Querying through a helper of the same
package counts as querying.

| Read | Rule |
|---|---|
| What an assignment rule would catch; the words in use on a product | Take a subject, since both read findings product-wide |
| A product's assignment rules, the response windows and the products each is limited to, an upload's receipt and kept documents | The store decides what the subject reaches: the rules for whoever triages the product, a window narrowed to products the reader may know exist, the builds a key may upload to. The sweeps applying rules and watching windows read as the deployment |
| The administration trail | Refuses a subject holding neither administration nor the audit permission, the deployment itself excepted. A refusal, since an empty page claims nobody changed anything |
| Whether somebody may read; whether they may triage | One question each, asked in one place on the subject |
| Whether any row of a group is undisclosed | The private rows counted and compared with zero |
| Whether any row's detail stays inside the deployment | The rows that are not public, counted. An outbound message asks it before naming an issue |
| A visibility column | Compared for equality, never ordered, and a test fails an ordering over one anywhere in the source |

| Question | Asked at |
|---|---|
| An act on one finding: a decision, a label, giving work to somebody else or taking what they hold | The finding's own visibility |
| Approving somebody else's decision | Reading at the decision's visibility with the approver capability or triage there; the capability alone at internal visibility |
| An act about the product: an assignment rule, a rating, a scan sent by hand, an incident, taking unowned work | Triage at any visibility, narrowed further wherever there is a finding |
| Taking unowned work, handing back your own | Rows at a visibility they read, and a disclosed row of their own whatever they read |
| Reading or publishing a VEX document, and what has gone out | Public reading to read, public triage to publish |
| A release note between two builds | Public reading at both; undisclosed work only where asked for and read |
| An advisory, draft or issued | Every issue it covers at a visibility read in that issue's product |
| A list, count or export spanning products | Per product and per visibility; the assignment carry reaches the work list alone |

## Decisions about an issue

A rating of an issue belongs to one product and reaches every build of it
(REQ-29). Asked anywhere, it would move deadlines and the minimum severity in a
product the person cannot see; held deployment-wide, one rating would stand for
every product and a second team could record none.

| Act | Asks for |
|---|---|
| Recording a rating | Triage on the product named in the request |
| Taking one back | Triage on the product the rating belongs to |
| Agreeing to a milder one | That, or the approver capability, on the product the rating belongs to |

| Rule | Reason |
|---|---|
| Each act also asks whether the subject may read a finding of the issue in that product, at its visibility | A role names a right, never the issues it reaches |
| An issue at no build anywhere is exempt | There is no finding to disclose |
| A refusal is spelled as an unused name; an unreadable claim is left out of a list | |
| The product is resolved and the role checked before the issue name is looked at | A name nobody used and an undisclosed flaw answer alike (REQ-42) |
| Agreeing and withdrawing check that the caller holds the role somewhere before resolving the rating, and the product-specific check after | The rating's identifier is the only name; the second check answers as a missing rating |
| A mention of somebody who cannot read the finding is accepted, nobody is told, and the author is told it reached nobody | Refusing loses the paragraph. A name nobody holds and an unreadable holder answer alike |
| The names typed are resolved, never looked for in a page of the picker | |
| A notification that fails reports the names it did not reach: the one it failed on and every one after, or all of them where who may be told could not be read | The words are kept either way |
| Nobody is offered for being an administrator; one who wants to be mentionable grants themselves a read role | A mention would tell them undisclosed work exists |
| Somebody who has left is not offered | |
| The picker is a staff directory for one product, deliberately: anybody reading findings there lists who else holds a read role on it | The smallest set that makes mentioning work |
| What somebody is told asks for reading it, at the finding's visibility | A notification is stored as written, so nothing downstream repairs it |

### Notes on an issue

A note records no decision and follows the rule of the rating beside it
(REQ-29, REQ-43).

| Rule | Reason |
|---|---|
| Reading asks whether the reader may read a finding of the issue in that product, answering otherwise as an unused name | |
| Writing asks for triage on that product, at the same visibility | |
| A collaborator brought into one case reads and writes on that issue | |
| One undisclosed occurrence in the product makes the whole thread undisclosed | A note is one thread; the stricter direction is safe |
| Only the author may change one | An edit by anybody is a forgery with a timestamp |
| A mention reaches only people who may read what it is about | The query the editor's picker uses |

## Limits

| Limit | Detail |
|---|---|
| A fault is logged, never described | The framework serializes an attached error, which would hand over the query text and a connection's address and user |
