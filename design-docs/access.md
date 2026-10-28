# Access

Who a request is, the roles and visibilities it reads under, and the subjects a
credential resolves to.

Satisfies REQ-14, REQ-42, REQ-43, REQ-44, REQ-56, REQ-63.

The rest of the area: `design-docs/access-enforcement.md` (refusals and where
each check sits), `design-docs/access-assignment.md`,
`design-docs/access-grants.md` (granting roles, accounts ending),
`design-docs/access-signin.md`, `design-docs/access-disclosure.md` and
`design-docs/access-trail.md`.

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
| No path creates an account | Access is granted in advance; the first person to reach a fresh deployment gains nothing |
| Somebody unknown and somebody granted nothing get the same refusal | A difference says whether a name is real |
| Public and private mean disclosed and undisclosed | Every request is authenticated either way |
| Anything unrecognized reads as not disclosed | A column added later would make every older row visible |
| A deployment that cannot tell who is asking serves nobody | Failing closed is visible |
| Stating administration or auditing is a write conditioned on the value read; one that matched nothing is taken again whole | Two administrators granting at once would both record a move. The trail's record is `design-docs/access-trail.md` § The administration trail |
| Recording somebody says nothing about administration unless the request states it | Granting, withdrawing and saying nothing stay three requests, and a failed read never withdraws it |
| Recording somebody already recorded sets the display name where stated, clears it where stated empty, and leaves it where not mentioned | A rename leaves a trail row |

## Roles

| Kind | Roles |
|---|---|
| Read and triage, per visibility | `public-read`, `private-read`, `internal-read`, `public-triage`, `private-triage`, `internal-triage` |
| Capabilities | `assigner`, `approver` |
| Global | `admin`, and the audit permission (`design-docs/access-grants.md` § The audit permission) |

| Rule | Reason |
|---|---|
| Each visibility is its own grant, and no role reaches a visibility it does not name | Private work and analyzer noise go to different people |
| Triage implies reading at the same visibility | Nobody decides about what they cannot see |
| A capability grants no visibility, and grants something on its own | Somebody granted exactly the right to approve can approve what they read |
| An administrator is not every role (REQ-42) | Administration is people, roles, credentials, settings and the catalog. Reading and triage are granted per product to administrators too, so one account cannot propose and approve, and a read-only auditor is expressible |
| Knowing a product exists is administration; what is open against it is not | |
| Admin is a property of the person, never a grant against a product | A unique key over a nullable product behaves differently on each engine |
| The `reporting` role is retired, and a test asserts its refusal | Breadth of view already expresses it (`design-docs/access-grants.md` § Statistics and the audit permission) |

The background passes ask as **the deployment itself**: a subject no credential
resolves to, holding no role. A narrowing by a reading rule lets every row
through for it, and one by a rule about acting lets none. The demo's
administrator grants itself roles while seeding.

## Internal visibility

The third visibility, for unconfirmed results never disclosed in their own right,
such as an analyzer's code findings (REQ-14).

| Visibility | Holds | Read under | Triaged under |
|---|---|---|---|
| Public | Disclosed work | `public-read` | `public-triage` |
| Private | Work not yet disclosed, which a disclosure opens | `private-read` | `private-triage` |
| Internal | Unconfirmed results, never disclosed | `internal-read` | `internal-triage` |

| Rule | Reason |
|---|---|
| Disclosure never applies to it | It has no disclosure date and nothing of it is published |
| Its roles are granted like every read and triage role: per product, across every product, or from a group mapping | |
| `internal-read` alone lists the product, with nothing open but internal findings | A capability beside it then reaches something |
| The anonymous subject reads no internal work | § Anybody at all |
| A case reaches public and private work only | A personal token keeps a case's write half only where it carries `public-triage` or `private-triage`. A code finding included in a flaw's disclosure stays internal; the case reaches it and the decisions at its occurrence as one of the flaw's readers (`design-docs/analysis-flaws.md` § Disclosure inclusion) |
| A code finding included in its flaw's disclosure is read whole by everybody who read it before, and with the decisions at its occurrence by the flaw's readers while the flaw is undisclosed | Inclusion adds readers; taking it out takes back only those (`design-docs/analysis-flaws.md` § Disclosure inclusion) |
| A code finding collaborator is granted one code finding recorded as a flaw while its flaw is undisclosed, and reads its evidence alone | No list, tree or inventory; the flaw's disclosure ends it, included or not (`design-docs/analysis-flaws.md` § Code finding collaborators) |
| `internal-triage` triages nothing about a product as a whole: an assignment rule, assignment, a rating, an incident, a response window, an inventory upload | Each is about what the builds ship |
| Approving at internal visibility needs internal reading and the approver capability; the session answer states it per visibility | Internal triage alone agrees to nothing (`design-docs/analysis-triage.md` § Code finding triage) |
| A message leaving the deployment carries no detail of a row that is not public | "Any row not public" is asked apart from "any row undisclosed" |
| A person sends an analyzer run where they hold `internal-triage` on the product; a pipeline sends under its key's scope | Every result opens internal |

No consumer of vulnerability findings reads analysis results: the findings
lists, reports, exports, published documents and screens read none, and the code
finding screens read code findings (`design-docs/kinds.md` § Consumers).

## Breadth of view

One of three, with no flag between them (REQ-43). All three are built.

| Grant | Sees |
|---|---|
| Reading on a product | Every finding in it, at that visibility |
| A capability without a read role | Only what that person, or a team they are on, is assigned |
| A collaborator on a case | That one issue (`design-docs/access-disclosure.md` § Case collaborators) |

| Rule | Reason |
|---|---|
| An assignment carries its row: a disclosed one to anybody, an undisclosed one only to a reader of undisclosed work there | It opens the "what am I dealing with" list, never the product's findings list, tree or other screens, and the product stays one they may not know exists |
| Assigning asks about the level, never the row: work goes only to somebody reading every visibility it carries in that product, or for a team to one member reading all of them | Before the assignment the recipient cannot see the row |
| The notification keeps its own check | A different check at a different moment |
| The narrowing is no switch an administrator turns | It is what not granting reading means |
| Administering the catalog is not reading it: an administrator holding a capability on a product is narrowed exactly as a non-administrator holding the same grant | Which products somebody may know exist and whose findings they read are two rules |
| What a flaw recorded in another product wrote onto a shared issue (summary, names, addresses) is withheld from a reader who may not read that record; its rating is never written there | `design-docs/findings-flaws.md` § Recorded words on a shared issue; `design-docs/findings-severity.md` § The rating in force |
| The report endpoints add no check | The data layer narrows every trend, rate, bar and total |

## The upward tree

For a person holding no reading on the product, the tree is the inventory they
were not granted, and a hidden row still shows in its container's count. They
get the chains their own findings sit on (REQ-56), from each component up to the
build root, with counts narrowed to match; descending a node is refused.

| Rule | Reason |
|---|---|
| The population is their own work and their teams', as an assignment carries it | A finding that became undisclosed after it was handed over drops out |
| A node counts their work, merged by path | One library under two containers is two places |
| Where they hold work on more components than the tree assembles, it says so | Its counts then fall short |
| Drawn whole, never opened | Nothing lies under the chains |

## Subject kinds

What a request may do is decided in one place.

| Asker | Credential | May do |
|---|---|---|
| A person | A session cookie, or a username a trusted proxy asserts on every request | What their roles allow |
| A person's own script | A token they minted | A narrowed view of that (`design-docs/access-grants.md` § Personal tokens) |
| A pipeline | An API key | Send scans and analyzer runs, and read back what became of them; never read a finding, triage or report |
| Anybody at all | None, and none is looked at | Read the security documents of the publishing products (§ Anybody at all) |

| Rule | Reason |
|---|---|
| Creating a credential asks for a session (REQ-44): recording a person, creating a key and unbinding a provider identifier are refused to a delegated subject | Each outlives the token, and whoever next arrives under an unbound username is taken to be its holder |
| A key's scope is constraints: the product always, release and variant each pinned or not, every one present matching | |
| A mismatch is refused, never redirected | An upload states its whole build |
| A key reads back the receipts, documents and inventory changes of the builds it may upload to, whichever key sent them, and nothing else | The pipeline can fix its producer, and a rotated or second key re-sending bytes gets the other sender's scan. Narrowed in the query, since a count before filtering says how many builds exist |
| A key reads back the receipts of analyzer runs sent to those builds; a person reads them where they read internal findings in the product | A receipt counts code findings and names none (`design-docs/analysis.md` § Receipts) |
| The secret is generated here, stored hashed, shown once | A readable store gives up every key with the database |
| A key's name is stored folded and matched exactly; other capitals are refused as taken, and only spaces as naming nothing | It is typed to make and to withdraw the key |
| A key's name is unique among keys in force; a receipt credits the key's row | A withdrawn key's name may be reused, and withdrawing by name reaches the key in force |
| Pipeline keys and personal tokens carry distinct fixed prefixes | Resolution dispatches on the prefix, and secret scanners recognize a leak |

## Anybody at all

The subject the published documents are read as (REQ-63), built per request by
the serving surface from the products publishing then, and by the pass writing
them. No credential, header or cookie resolves to it.

| Rule | Reason |
|---|---|
| It reads disclosed work in a publishing product, and nothing else | A non-publishing product is not listed, counted or named |
| It holds no role, case, team or deployment-wide permission | It triages, approves and decides nothing |
| Three reads are open to it: the published documents and the advisories that went out, each asking for it by name, and disclosed findings, decisions and patches in a publishing product, which the publishing pass reads through it | Every read asking for a person refuses it |
| Every code finding read, lists, counts and groups included, refuses it before narrowing by visibility | A code finding is no published security document, disclosed or not |
| Which products publish takes no subject | It is configuration, the same for everybody |
| The store of published documents refuses anybody but this subject and the deployment itself | A signed-in person reads through the API under their own grants |

`design-docs/publishing.md` says what is served.

## Limits

| Limit | Detail |
|---|---|
| A key is honored from anywhere | Where it connects from says nothing about whether it is genuine |
| A key digest is matched by SQL equality on the whole digest, with no constant-time compare | The compare would run over a row equality already selected |
| A person holding triage may send a scan | Re-uploading by hand is triage work |
| A pipeline sees the product it may send to | Otherwise its upload reads like one to a product not there |
