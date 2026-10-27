# Access

Who a request is, the roles and visibilities it reads under, and the subjects a
credential resolves to.

Satisfies REQ-14, REQ-42, REQ-43, REQ-44, REQ-56, REQ-63.

The rest of the area: refusals and where each check sits
(`design-docs/access-enforcement.md`), assignment and teams
(`design-docs/access-assignment.md`), how roles are granted and accounts end
(`design-docs/access-grants.md`), sign-in and sessions
(`design-docs/access-signin.md`), embargoes and case grants
(`design-docs/access-disclosure.md`), and the administration trail and secrets
(`design-docs/access-trail.md`).

## Contents

- [Authentication and authorization](#authentication-and-authorization)
- [Roles](#roles)
- [Internal visibility](#internal-visibility)
- [Breadth of view](#breadth-of-view)
- [The upward tree](#the-upward-tree)
- [Subject kinds](#subject-kinds)
- [Anybody at all](#anybody-at-all)
- [Limits](#limits)

## Authentication and authorization

Authenticating says who somebody is, never whether they should be here.

| Rule | Reason |
|---|---|
| No path creates an account | Access is granted in advance or not at all; the first person to reach a fresh deployment gains nothing by being first |
| Somebody unknown and somebody known but granted nothing get the same refusal | A difference tells an outsider whether a name is real |
| Public and private mean disclosed and undisclosed, never readable and unreadable | Every request is authenticated either way, so a mistake exposes something to a colleague rather than to the internet |
| Anything unrecognized reads as not disclosed | A column added later would otherwise make every older row visible |
| A deployment that cannot tell who is asking serves nobody | Up and refusing is visible; up and answering everybody is not |
| Stating administration or auditing is conditional on the value read; a write that matched nothing is taken again whole | Two administrators granting the same thing at once would both record a move. The retry reads what the other left, and records nothing where nothing moved |
| The trail records a move from the value the write was conditioned on | A separate earlier read can see a value another administrator replaces first |
| Recording somebody says nothing about administration unless the request states it | Granting, taking away and saying nothing stay three requests. Two requests at once lose neither, and a failed read never withdraws administration |
| Recording somebody already recorded sets the display name where one is stated, clears it where stated empty, and leaves it where not mentioned | The display name is the label read instead of the identity. A rename leaves a row in the administration trail |

## Roles

| Kind | Roles |
|---|---|
| Read and triage, per visibility | `public-read`, `private-read`, `internal-read`, `public-triage`, `private-triage`, `internal-triage` |
| Capabilities | `assigner`, `approver` |
| Global | `admin`, and the audit permission (`design-docs/access-grants.md` § The audit permission) |

| Rule | Reason |
|---|---|
| Each visibility is its own grant, and no role reaches a visibility it does not name | Somebody working private reports is not handed every public finding, and private reading does not read internal work or the reverse |
| Triage implies reading at the same visibility | Nobody decides about what they cannot see |
| A capability grants no visibility, and grants something on its own | What an approver reaches is bounded by what they read, and somebody granted exactly the right to approve can approve |
| An administrator is not every role (REQ-42) | Administration is people, roles, credentials, settings and the catalog. Reading and triage are granted per product, an administrator's included, so one account cannot propose and approve a decision, and a read-only auditor is expressible |
| Knowing a product exists is administration; what is open against it is not | An administrator holding no role sees the products they administer with nothing open against them |
| Admin is a property of the person, never a grant against a product | A grant with no product needs a uniqueness rule over a nullable column, which each engine enforces differently |
| The `reporting` role is retired, and a test asserts the refusal | What it would gate is breadth of view, which narrowing already expresses (`design-docs/access-grants.md` § Statistics and the audit permission) |

The background passes ask as **the deployment itself**: a subject no credential
resolves to, holding no role. It reads every product and triages, approves and
decides in none, so a narrowing by a reading rule lets every row through for it
and one by a rule about acting lets none. The demo's administrator grants itself
roles while seeding.

## Internal visibility

The third visibility, for material never disclosed in its own right:
unconfirmed results nobody has judged, such as an analyzer's code findings
(REQ-14).

| Visibility | Holds | Read under | Triaged under |
|---|---|---|---|
| Public | Disclosed work | `public-read` | `public-triage` |
| Private | Work not yet disclosed, which a disclosure opens | `private-read` | `private-triage` |
| Internal | Unconfirmed results, never disclosed | `internal-read` | `internal-triage` |

| Rule | Reason |
|---|---|
| Disclosure never applies to it | It carries no disclosure date, and nothing about it is published |
| Its roles are granted like every read and triage role: per product, across every product, or from a group mapping | Analyzer noise and embargoed cases are worked by different people, and neither is handed the other's material |
| `internal-read` alone lists the product, with nothing open against it but internal findings | It is a read role, so a capability granted beside it reaches something |
| The anonymous subject reads no internal work | § Anybody at all |
| A case reaches public and private work only | A case is one issue somebody intends to disclose. A personal token keeps a case's write half only where it carries `public-triage` or `private-triage`. A code finding included in a flaw's disclosure stays internal, and the case reaches it and the decisions at its occurrence as one of the flaw's readers (`design-docs/analysis.md` § Disclosure inclusion) |
| A code finding included in its flaw's disclosure is read whole by everybody who read it before, and with the decisions at its occurrence by the flaw's readers while the flaw is undisclosed | Inclusion adds readers. Taking it out of disclosure takes back only the readers the inclusion added (`design-docs/analysis.md` § Disclosure inclusion) |
| A code finding collaborator is granted one code finding recorded as a flaw while its flaw is undisclosed, and reads its evidence alone | It is no grant of a list, a build's tree or an inventory. Its flaw's disclosure ends it, included or not (`design-docs/analysis.md` § Code finding collaborators) |
| `internal-triage` triages nothing about a product as a whole: an assignment rule, assignment, a rating, an incident, a response window, an inventory upload | Each is about what the builds ship, which internal triage reads none of |
| Approving at internal visibility needs internal reading and the approver capability | Internal triage alone agrees to nothing (`design-docs/analysis.md` § Code finding triage). The session answer states it per visibility |
| A message leaving the deployment carries no detail of a row that is not public | Internal rows are withheld as undisclosed ones are. "Any row not public" is asked apart from "any row undisclosed", which is about disclosure alone |

No consumer of vulnerability findings reads analysis results: the findings
lists, reports, exports, published documents and the interface's screens read
none, and the code finding screens read code findings
(`design-docs/kinds.md` § Consumers). Sending an analyzer run asks for
`internal-triage` on the product, since every result opens internal.

## Breadth of view

One of three, with no flag switching between them (REQ-43). All three are built.

| Grant | Sees |
|---|---|
| Reading on a product | Every finding in it, at that visibility |
| A capability held without a read role | Only what that person, or a team they are on, is assigned. An assignment carries visibility of what was assigned |
| A collaborator on a case | That one issue (`design-docs/access-disclosure.md` § Case collaborators) |

A right to write implies the read it acts on. An approver or assigner holding no
read role is expressible, and an assignment gives it content.

| Rule | Reason |
|---|---|
| An assignment carries its row: a disclosed one to anybody, an undisclosed one only to a reader of undisclosed work there | The "what am I dealing with" list answers for somebody who reads nothing, and the product stays one they may not know exists. The findings list, the tree and the product's other screens answer questions about a product, which one held row does not open |
| Assigning asks about the level, never the row | Before an assignment the recipient cannot see the row by construction. Work goes only to somebody reading every visibility it carries in that product; for a team, to one member reading all of them |
| The notification keeps its own check | A different check at a different moment; a channel that leaks only when another rule is wrong goes unnoticed |
| The narrowing is no switch an administrator turns | It is what not granting reading means. Nobody holds reading and is narrowed anyway |
| Administering the catalog is not reading it, for the set that narrows findings | Which products somebody may know exist and which products' findings they read are two rules. An administrator holding only a capability on a product reads no finding in it |
| What a flaw recorded in another product wrote onto a shared issue is withheld from a reader who may not read that record: its summary, names and addresses. Its rating is never written there | The issue row is shared by every product holding the issue (`design-docs/findings-flaws.md` § Recorded words on a shared issue; `design-docs/findings-severity.md` § The rating in force) |
| The report endpoints add no check | Every query narrows in the data layer, so narrowing the subject narrows every trend, rate, bar and total |

## The upward tree

For a person holding no reading on the product, the dependency tree is the
inventory they were not granted, so it cannot be drawn with rows hidden: a
container's count would say how much sits under it. They get the chains their
own findings sit on (REQ-56), from each finding's component up to the build
root, with counts narrowed to match. Descending a node is the question they may
not ask.

| Rule | Reason |
|---|---|
| No reading is asked for and none is implied | The population is their own work and their teams', as an assignment carries it. A finding that became undisclosed after it was handed over drops out of the tree |
| A node counts their work, never the build's, merged by path | A tree is paths: one library under two containers is two places |
| Where they hold work on more components than the tree assembles, it says so | A count quietly short is worse than one with a caveat |
| Drawn as it is, never opened | There is nothing under the chains to expand |

## Subject kinds

What a request may do is decided in one place, never in each handler.

| Asker | Credential | May do |
|---|---|---|
| A person | A session cookie, or a username a trusted proxy asserts on every request | What their roles allow |
| A person's own script | A token they minted | A narrowed view of what they may do (`design-docs/access-grants.md` § Personal tokens) |
| A pipeline | An API key | Send scans and analyzer runs, and read back what became of its own |
| Anybody at all | None, and none is looked at | Read the security documents of the products that publish (§ Anybody at all) |

A pipeline reads no finding, triages nothing and reports nothing, which keeps
the visibility rules out of a build server's reach.

| Rule | Reason |
|---|---|
| Creating a credential asks for a session (REQ-44) | A credential may not mint another. Recording a person, creating a key and unbinding a provider identifier are refused to a delegated subject: each would outlive the token, and whoever next arrives under an unbound username is taken to be its holder |
| A key's scope is constraints: the product always, release and variant each pinned or not | Every constraint present must match |
| A mismatch is refused, never redirected | A product-wide key cannot imply a release, so an upload states its whole build |
| A key reads back the receipts of the builds it may upload to and nothing else, every sender's included | Likewise the documents sent there and what each upload changed. An upload is answered before its documents are read, and the pipeline is the party that can fix its producer. A rotated or second key re-sending the same bytes is answered with the other sender's scan. Narrowed in the query, since a count taken before filtering says how many other builds exist |
| A key reads back the receipts of the analyzer runs sent to the builds it may upload to | A receipt counts the code findings a run opened and saw and names none. A person reads them where they read internal findings in the product (`design-docs/analysis.md` § Receipts) |
| The secret is generated here, stored hashed, shown once | A store that can hand back what it holds gives up every key with a copy of the database. It is no password, so nothing slows a guesser |
| A key's name is stored folded and matched exactly; other capitals are refused as taken, and a name of only spaces as naming nothing | An administrator types it to make the key and to withdraw it |
| A key's name is unique among the keys in force | A withdrawn key's name may be reused. A receipt credits the key's row, never its name, and withdrawing by name reaches the key in force |
| Pipeline keys and personal tokens carry distinct fixed prefixes | Resolution dispatches on the prefix, and a secret scanner recognizes a leaked credential |

## Anybody at all

The subject the published documents are read as (REQ-63). It is built per
request by the surface serving them, from the products publishing at that
moment, and by the pass writing them; no credential, header or cookie resolves
to it.

| Rule | Reason |
|---|---|
| It reads disclosed work in a publishing product, and nothing else | Every list, count and lookup narrowed by the two reading questions narrows it alike, so a product that does not publish is not listed, counted or named |
| It is nobody: no role, case, team or deployment-wide permission | It triages, approves and decides nothing |
| Three reads are open to it: the documents published, the advisories that went out, and disclosed findings, decisions and patches in a publishing product | The first two ask for it by name; the third is what the publishing pass reads through it. Every read asking for a person refuses it |
| It reads no code finding, a disclosed one included | Every code finding read, lists, counts and groups included, refuses it before narrowing by visibility; a code finding is no security document a product publishes |
| Which products publish takes no subject | It builds this subject, and is the same for everybody |
| A signed-in person never reads the published documents through it | Their own grants answer through the API. The store of published documents refuses anybody but this subject and the deployment itself |

`design-docs/publishing.md` says what is read and served.

## Limits

| Limit | Detail |
|---|---|
| A key is honored from anywhere | It holds a credential; where it connects from says nothing about whether it is genuine |
| The stored key digest is matched by SQL equality on the whole digest | The equality is the comparison; a constant-time compare over the row it selected cannot fail, so there is none |
| A person holding triage may send a scan | Re-uploading a build by hand is triage work |
| A pipeline sees the product it may send to | Otherwise an upload to its own product could not be told from one to a product that is not there |
