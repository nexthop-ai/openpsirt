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
reported as not declared, the answer a name nobody declared gets. A pipeline
key is held to the same, so a stolen build credential reads nothing of the
catalog. The lookup and the check happen together, because resolving a name
first leaks the difference however the second half is written.

| Name in a request | Rule |
|---|---|
| A person | Every route decides whether the caller may act before it resolves the person, or any account reads a directory of the organization. A route open to any credential answers a name nobody holds as a name whose work the caller cannot see: an empty list |
| An issue at an occurrence | One resolver does both steps for every such route: resolve the name, then ask whether this subject may read a finding of it in this product. A failure of either answers "no open finding is recorded there". The identifier carries no sequence, so names cannot be walked or counted |
| A list of issues | The list form of the same resolver, one statement per batch. A name filed only where the caller may not read a finding of it in this product gets the words a name nobody filed gets |
| A component | A graph read taking a component name refuses before resolving it. Otherwise a subject who may not read findings in the product reads the build's inventory, versions and ecosystems included, one guess at a time |

A test walks every route carrying an identity and asserts that a held and an
unheld name answer alike, for every kind of credential, one holding nothing
included.

## Enforcement sites

| Decided | Where | Reason |
|---|---|---|
| Who is asking | One middleware, before any route | A handler that forgets to ask answers for everybody, invisibly |
| Whether they are anybody at all | The same middleware | An unrecognized caller does not learn whether their body was well formed |
| Whether they may reach this product | The data layer, on the query | A check beside the query cannot be skipped by adding an endpoint |
| Whether they may do this at all | The handler | Declaring a product is administration whatever the query looks like |
| Whether a header from an untrusted source was a mistake | Logged, never answered | The caller learns nothing; an operator who trusted one address family and is reached from the other has no other way to find out |

Everything outside the unauthenticated surfaces
(`design-docs/api.md` § Unauthenticated surfaces) is authenticated, named as a
list and never guarded by a path prefix: a prefix leaves open everything outside
it, the routes the framework registers itself included.

| Rule | Reason |
|---|---|
| A query without a subject is a fault, never a denial: reading the subject from a request with nobody attached fails | Absence read as "nobody" hides the bug until a query reads it as "everybody" |
| A pipeline is refused a read, never shown an empty one, the receipts of the builds it may upload to excepted | "Here is nothing" invites a caller to believe the list is empty |
| Every read of findings in one product or one build first asks which visibilities the subject reads there; none is a refusal | Whether it cannot see the product or sees it and reads nothing: a pipeline key, an administrator granted no reading. A read about one issue asks the same, widened by a case the subject was brought into |
| The refusal is in the store read, as well as at the edge | A store answering a non-person with an empty result leaves the invariant to a handler. The zero subject is a non-person and is refused alike |
| A credential that is not a person is refused; a person holding nothing gets an empty list | An empty list is the correct narrowed answer. Both checks stay, and the layers say the same thing |
| A read is narrowed twice: to the products somebody holds anything on, and within those to the visibilities they read in each | The visibility half is written per product and admits nothing elsewhere; the product half states that bound outright. The pair is one call, and nothing calls the visibility half bare. Where a product is already pinned, a named pairing states that the first half was done |

| Read | Answer to a subject that reads nothing there |
|---|---|
| Findings, occurrences, runs, promised upgrades, carried patches, received VEX, readiness, standing, what each release holds, the release trend, the labels in use | Refused |
| What each run opened and closed | Refused, for an empty list of runs as well |
| The receipts list | The receipts, with no counts of what each run changed; the counts are a report on findings |

## Store methods with no subject

Visibility is enforced in the data layer with a subject. A method takes none
only for one of three reasons:

1. A background pass answering to nobody, the deployment looking at itself.
2. A private helper reading rows a narrowed query already selected.
3. A question whose answer does not vary by who asks, such as whether a finding is suppressed.

The exported methods of the finding, triage and graph stores that query without
a subject are each named, with their reason, in a list `make subjected` holds
them to (`design-docs/build.md` § Make targets). A method querying through a
helper of its own package counts as querying.

| Read | Rule |
|---|---|
| What an assignment rule would catch, and the words in use on a product | Take a subject: both read findings across the whole product |
| A product's assignment rules, the response windows and the products each is limited to, an upload's receipt and the documents it kept | Read with the subject, and the store decides what it reaches: the rules for whoever triages the product, a window narrowed to the products the reader may know exist, the builds a key may upload to. The sweeps applying rules and watching windows read as the deployment |
| The administration trail | Each reader takes a subject and refuses one holding neither administration nor the audit permission. A refusal, because a deployment where nobody changed anything is a different statement. A row names who was brought into which case, undisclosed ones included |
| Whether somebody may read, and whether they may triage | One question each, asked in one place on the subject. Two, because triage implies reading and reading does not imply triage |
| Whether any row of a group is undisclosed | One aggregate: the private rows counted and compared with zero |
| Whether any row's detail stays inside the deployment | One aggregate: the rows that are not public. An outbound message asks it before naming an issue, so an internal row withholds detail as an undisclosed one does |
| A visibility column | Compared for equality and never ordered, because the smallest word of a group answers only while the words happen to sort that way. A test fails an ordering over a visibility column anywhere in the source |

| Question | Asked at |
|---|---|
| An act on one finding: a decision, a label, giving work to somebody else or taking what they hold | The finding's own visibility |
| Approving somebody else's decision | Reading at the decision's visibility with the approver capability or triage there; the capability alone at internal visibility. The session answer says which visibilities |
| An act about the product: an assignment rule, a rating, a scan sent by hand, an incident, taking unowned work | Triage at any visibility; the finding-level question narrows further wherever there is a finding |
| Taking unowned work, handing back your own | Rows at a visibility they read, and a disclosed row of their own whatever they read, since the assignment carried it |
| Reading or publishing a VEX document, and what has gone out | Public reading to read, public triage to publish. A row saying a document went out is as much a disclosure as the document |
| A release note between two builds | Public reading at both. Undisclosed work is added only where asked for and read |
| An advisory, draft or issued | Every issue it covers at a visibility read in that issue's product |
| A list, count or export spanning products | Per product and per visibility, by the grants on each. The assignment carry reaches the work list alone |

## Decisions about an issue

A rating of an issue belongs to one product and reaches every build of it
(REQ-29).

| Act | Asks for |
|---|---|
| Recording a rating | Triage on the product named in the request |
| Taking one back | Triage on the product the rating belongs to |
| Agreeing to a milder one | That, or the approver capability, on the product the rating belongs to |

A rating sets deadlines and can push a finding below the product's minimum
severity, so it is held per product: asked anywhere, it moves both in a product
the person cannot see, and held deployment-wide, one rating stands for every
product and a second team may record none of its own.

| Rule | Reason |
|---|---|
| Each act also asks whether the subject may read a finding of the issue in that product, at its visibility | A role names a right, never the issues it reaches; "public knowledge" is true of a CVE and false of an identifier this deployment minted |
| An issue at no build anywhere is exempt | There is no finding for a rating to disclose |
| A refusal is spelled as an unused name, and an unreadable claim is left out of a list | |
| The product is resolved and the role checked before the issue name is looked at | A name nobody used and an undisclosed flaw answer alike (REQ-42) |
| Agreeing and withdrawing check that the caller holds the role somewhere before resolving the rating, and the product-specific check after it | The rating's identifier is the only name in the request. The second check answers in the words a missing rating gets |
| Mentioning somebody who cannot read the finding is accepted; nobody is told, and the author is told it reached nobody | Refusing the write loses the paragraph to fix a word. A name nobody holds and one held by somebody who may not read answer alike |
| The names typed are resolved, never looked for in a page of the picker | The picker narrows by what is typed and takes a page; a mention has names in hand |
| A notification that fails reports the names it did not reach: the one it failed on and every one after, or all of them where who may be told could not be read | The words are kept either way; a failure answered as success tells the author somebody was told |
| Nobody is offered for being an administrator | Administering is not reading; a mention would tell them undisclosed work exists in a product they may not open. One who wants to be mentionable grants themselves a read role |
| Somebody who has left is not offered | They will never see it |
| The picker is a staff directory for one product, deliberately | Anybody who reads findings there can list who else holds a read role on it; it is the smallest set that makes mentioning work, bounded to one product |
| What somebody is told asks for reading it, at the finding's visibility | A notification names the issue, component and build and is stored as written, so nothing downstream can repair it |

### Notes on an issue

A note records no decision and follows the rule of the rating beside it: the
product, and the issue's visibility in it (REQ-29, REQ-43).

| Rule | Reason |
|---|---|
| Reading asks whether the reader may read a finding of the issue in that product | A product held nothing on answers as an issue that is not there, in an unused name's words |
| Writing asks for triage on that product, at the same visibility | Saying something on the record is part of arguing about the work |
| A collaborator brought into one case reads and writes on that issue | The note is inside the pair they were brought in on |
| One undisclosed occurrence in the product makes the whole thread undisclosed | A note is one thread for the issue; the stricter direction is the safe one |
| Only the author may change one | An edit anybody could make is a forgery with a timestamp |
| A mention reaches only people who may read what it is about | The same query the editor's picker uses |

## Limits

| Limit | Detail |
|---|---|
| A fault is logged, never described | The framework serializes an error passed with the message, which would hand the caller the query text and, for a connection failure, the address and user |
