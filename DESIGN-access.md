# Access

Subject resolution, roles, visibility enforcement and disclosure control.

Satisfies REQ-22, REQ-29, REQ-34, REQ-37, REQ-38, REQ-41, REQ-42, REQ-43,
REQ-44, REQ-45, REQ-56, REQ-59, REQ-68, REQ-69's server half.

## Contents

- [Authentication and authorization](#authentication-and-authorization)
- [Roles](#roles)
- [Breadth of view](#breadth-of-view)
- [The upward tree](#the-upward-tree)
- [Refusals disclose nothing](#refusals-disclose-nothing)
- [Assignment](#assignment)
- [Departure](#departure)
- [No statistics role](#no-statistics-role)
- [Somebody who has left](#somebody-who-has-left)
- [Teams](#teams)
- [Routing rules](#routing-rules)
- [Store methods with no subject](#store-methods-with-no-subject)
- [Judgments about an issue](#judgments-about-an-issue)
- [Subject kinds](#subject-kinds)
- [Provider sign-in](#provider-sign-in)
- [Outbound provider fetches](#outbound-provider-fetches)
- [Trusted-header sign-in](#trusted-header-sign-in)
- [Name and identifier](#name-and-identifier)
- [Sessions and request forgery](#sessions-and-request-forgery)
- [Role assignment modes](#role-assignment-modes)
- [The grant grid](#the-grant-grid)
- [Personal tokens](#personal-tokens)
- [Where each check is made](#where-each-check-is-made)
- [Browser headers](#browser-headers)
- [Sign-in return addresses](#sign-in-return-addresses)
- [The administration trail](#the-administration-trail)
- [Secrets and logs](#secrets-and-logs)
- [Disclosure](#disclosure)
- [Extending a disclosure date](#extending-a-disclosure-date)
- [Case collaborators](#case-collaborators)
- [Mail addresses](#mail-addresses)
- [Absent holders](#absent-holders)
- [Limits](#limits)

## Authentication and authorization

Authenticating establishes who somebody is. It says nothing about whether they
should be here.

| Rule | Reason |
|---|---|
| No path creates an account | Access is granted in advance or not at all. The first person to reach a fresh deployment gains nothing by being first, which is a well-known way for self-hosted software to be taken over by whoever finds the URL |
| Somebody unknown and somebody known but granted nothing are refused with the same answer | Distinguishing them tells an outsider whether a name is real |
| Public and private mean disclosed, not readable | Every request is authenticated either way, so a mistake in these rules exposes something to a colleague rather than to the internet |
| Anything unrecognized reads as not disclosed | A column added later would otherwise default every row that predates it to visible |
| A deployment that cannot tell who is asking serves nobody | Failing closed means an unconfigured deployment is up and refusing, which is visible, rather than up and answering everybody |

## Roles

| Kind | Roles |
|---|---|
| Read and triage, per visibility | `public-read`, `private-read`, `public-triage`, `private-triage` |
| Capabilities | `assigner`, `approver` |
| Global | `admin` |

**Triage implies reading at the same visibility.** Nobody decides about what they
cannot see, and a deployment forced to grant both would eventually grant one and
wonder why nothing worked.

**A capability grants no visibility**, so what an approver reaches is bounded by
what they may read. The converse also holds: **a capability has to grant
something.** Approving asked for the triage role, which made the approver
capability do nothing at all — somebody granted exactly the right to approve
could approve nothing.

**An administrator is not every role** (REQ-42). Administration is people, roles,
credentials, settings and the catalog. Reading and triaging a product are granted
per product like anybody else's, and an administrator who wants them grants them
to themselves, so the grant sits in the same record as everybody else's.

It read the other way and nothing said so. The cost was **separation of duties**:
one account proposed a decision and approved it, re-rated severities and read
every embargo, so the second person a dismissal asks for was optional for whoever
held admin. It also made a read-only auditor impossible to express.

**Knowing a product exists is administration; what is open against it is not.** An
administrator holding no role sees the products they administer with nothing open
against them, which is what a first sign-in looks like.

Two things had been leaning on "an administrator sees everything": the background
passes that report on the tool ask as **the deployment itself**, a subject
nothing resolves a credential to and which holds no role; and the demo's
administrator grants itself roles as part of seeding.

| Rule | Reason |
|---|---|
| Creating a credential asks for a session (REQ-44) | A credential may not mint another. That held for a personal token issuing a token, and was got around by what an administrator's token could make instead: a person, an administrator even, and a pipeline key, both outliving the token and neither bounded by it. Recording a person and creating a key are the two acts refused to a delegated subject |
| Admin is a property of the person rather than a grant against a product | Modeling it as a grant means a row whose product is absent, and a uniqueness rule over a nullable column behaves differently on each of the four engines |
| The `reporting` role is retired rather than defined | What such a role would gate is breadth of view, and statistics are what breadth looks like once aggregated. It gated nothing: one use outside tests, and a field in the session answer no screen read. A test asserts the refusal rather than its absence from a list |

## Breadth of view

One of three things, with no flag switching between them (REQ-43). All three are
built.

| Grant | Sees |
|---|---|
| Reading on a product | Every finding in it, at that visibility. The ordinary grant |
| A capability held without a read role | Only what that person, or a team they are on, is assigned. An assignment is itself a grant: it carries visibility of what was assigned |
| A collaborator on a case | That one issue. Described under [case collaborators](#case-collaborators) |

There is no "triage without reading": **a right to write implies the read it acts
on.** What is expressible and meaningless is an approver or an assigner holding
no read role, which an assignment gives content to.

| Rule | Reason |
|---|---|
| An assignment carries the row it was made about, at the visibility the holder may read it at | The "what am I dealing with" list answers for somebody who reads nothing, and the product it sits in stays one they may not know exists. The findings list, the dependency tree and the product's other screens answer a question about a product, and holding one row in it is not an answer to that |
| Assigning asks about the level, not the row | Whether they can already see the row is the wrong question — before the assignment they cannot, by construction. What is checked is that an undisclosed finding goes only to somebody who may read undisclosed work in that product. For a team it asks whether at least one member can |
| The notification's own check stays beside it | A different check at a different moment. A channel that leaks only when another rule is wrong is a channel nobody notices is leaking |
| The narrowing is not a switch an administrator turns on | It is what not granting reading already meant. There is no fourth state where somebody holds reading and is narrowed anyway |
| The report endpoints need no check added | Every query carries a subject and narrows in the data layer, so narrowing the subject narrows every trend, rate, bar and total with it. A check bolted onto a report is the per-handler enforcement this area exists to avoid |

## The upward tree

The part of the narrowing that is not a filter.

The dependency tree is a structure rooted at the build. For a person holding no
reading on the product, that structure is the inventory of what the product
contains — the breadth they were not granted — so it cannot be drawn with rows
hidden: a container's count would still say how much sits under it.

What they get is **the chains their own findings sit on** (REQ-56): from each
finding's component up to the build root, with per-node counts narrowed to match.
The chain upward is what makes a finding judgeable, and every node on it sits
above something they were already given. Descending a node is the question they
may not ask.

| Rule | Reason |
|---|---|
| No reading is asked for and none is implied | The population is what they hold — their own name and their teams' — at the visibility they may read it at. An undisclosed finding that became undisclosed after it was handed over drops out of the tree rather than arriving through it |
| A node counts their work, never the build's | Merged by path rather than by component, because a tree is paths: the same library under two containers is two places somebody is looking at |
| Where somebody holds work on more components than the tree assembles, it says so | The counts then under-report, and a number quietly short is worse than one with a caveat |
| Drawn as it is, not opened | What is drawn is the chains, and there is nothing under them to expand |

## Refusals disclose nothing

**A product somebody holds nothing on is invisible**, not merely unreadable: not
listed, not counted, and reported as not declared — the same answer a name nobody
ever declared gets. The lookup and the check happen together, because resolving a
name first and authorizing afterwards leaks the difference however carefully the
second half is written.

The same applies to a pipeline. A stolen build credential must not become a
reader of the shipping catalog.

**Nobody learns who has an account.** Every route resolves the person *after*
deciding whether the caller may act at all. Resolving first and refusing after
answers "does this person have an account here" for anybody signed in, which is a
directory of the organization readable by every account.

A route open to any credential satisfies the rule the other way: there is no
earlier check to hide behind, so a name nobody holds answers exactly as a name
somebody holds whose work the caller cannot see — an empty list.

That shape was found in three places, so it is no longer checked one route at a
time: **a test walks every route carrying an identity** and asserts that both
spellings answer alike, for every kind of credential including one holding
nothing.

**Nobody learns which issues exist either.** Every route shaped "this issue, at
this place" resolved the name first and checked what it reached second. On two of
them the second check was not a refusal at all: a fix target answered an empty
list and an assignment answered "done" while writing nothing, so those two
**disclosed by succeeding**.

**One resolver does both steps**, and every such route goes through it: resolve
the name, then ask whether this person may read a finding of it in this product,
and answer a failure of either as "no open finding is recorded there". Written
once rather than checked at each route, because the leak is the *ordering*. The
identifier carries no sequence, so the names cannot be walked or counted even
before a route is asked.

## Assignment

Deciding who deals with something is a different act from deciding what it is, so
it asks for a different right (REQ-34).

| Act | Right |
|---|---|
| Taking work nobody owns; handing back your own | Triage |
| Giving work to somebody else; taking what they are holding | Assigner |
| Moving everything one person holds | Administration. That is about a person rather than a finding, and it spans every product at once |

The first row keeps the ordinary case working: findings arriving under an
already-assigned component start unowned, so if starting on something needed
somebody else's attention first, working the queue would be a full-time job for
whoever held the assigner right.

Taking work off a colleague is the act the assigner right names, and doing it to
yourself is still doing it.

| Rule | Reason |
|---|---|
| Assigner is held alongside triage, not instead of it | The role widens what a triager may do with work; on its own it assigns nothing, because handing around findings in a product you may not argue about is not a narrower version of triaging it. Enforced at the endpoint and again at the store, with the session answer carrying the same conjunction so an interface does not draw a control that always fails |
| Who may *be* assigned is visibility, not a grant of its own | |
| A finding is assigned for a whole group at once | One issue in one component, however many places. Assigning one place and not another is not something anybody means to do |
| Handing something back is the same operation as giving it out | With nobody as the recipient |
| Nobody-assigned is a state to be asked about, not an absence | Work that nobody owns is what falls between people, so it is listed across every product somebody can see — that is exactly what hides when every screen shows one product |
| Assigning covers what is there now | Findings arriving under the same component tomorrow start unassigned and appear in that list |

## Departure

Nothing tells this software somebody has gone. Membership is read at sign-in and
a person who has left never signs in again, so it is an action an administrator
takes rather than something discovered.

Until it is taken, their work is in no list at all: not in the shared one because
it is assigned, and not in anybody's own because they are not here.

| Operation | Meaning |
|---|---|
| Releasing | Nobody is dealing with it, and it goes back where it can be picked up. The honest answer when who takes it on has not been decided |
| Handing over | Says who is dealing with it now |

Only an administrator does either; a person hands back their own by assigning it
to nobody.

**Two triggers happen on their own:** withdrawing somebody's last role on a
product hands back what they were dealing with *there*, and only there; and
deactivating an account hands back everything it held, everywhere.

## No statistics role

Not built, and not planned. Asked for as "counts and trends without reading the
findings behind them".

**`public-read` on the products somebody should see already is that role.**
Every report endpoint runs as the subject asking and answers only what that
subject may see (REQ-43), so a person granted disclosed reading on two products
gets the numbers for two products and nothing else.

| | |
|---|---|
| What a numbers-only role would cost | A second visibility mode threaded through the whole reporting layer: every aggregate, every figure that opens the list it counts, and every export |
| What it would protect | A product's name, which REQ-42 already treats as a secret — a product somebody holds nothing on is invisible rather than merely unreadable |
| Why that is not enough | The protection is already there, and the mode would be a second way of expressing it that can disagree with the first |

The `reporting` role was retired for the same reason (REQ-42), and a read-only
auditor is granted with what already exists.

## Somebody who has left

REQ-45: nothing detects a departure. A provider never tells us an account was
disabled, and somebody who has left never signs in again — so without this the
account stays live, holding whatever it held.

Recorded by an administrator, as a date on the person.

| Rule | Reason |
|---|---|
| A date, not a flag | "When" is the whole of what an audit asks after a departure, and a boolean cannot answer it |
| Never a deletion | The record names them as the proposer of judgments and the approver of others, and an assignment used to point at them. Deleting the row would either break those or rewrite what happened |
| Their roles are left where they are | What somebody held is part of why the record reads as it does, and bringing them back should not mean reconstructing it from memory. What stops them is the date |
| Read once, where every way in already passes | A session, a personal token and a group-bound sign-in all resolve by identity. A second spelling of the check is a second rule to keep in step with the first |
| Sessions are ended rather than left to expire | Roles are re-read at sign-in, so withdrawing one takes effect then. This is what makes leaving immediate instead |
| Everything they held is handed back | Work held by somebody who is gone is work nobody is doing, and it does not look like it |
| Deactivating somebody who has already left succeeds and moves nothing | An administrator clicking again, or two of them acting at once, is the ordinary case — and the date is when they left, not when it was last asserted |
| An administrator may not deactivate themselves | It leaves nobody able to undo it, and the bootstrap account is often the one doing it |
| Coming back does not return their work | Somebody else may have picked it up, and reassigning it would take it off them silently |

## Teams

**Built.** A team is a named set of people, managed here. It holds work and
**grants nothing**: no role, no visibility, no capability.

**Managing a team is administration, and routing to one is not.** An assigner
holds their right per product; a team is deployment-wide. So an assigner may
hand work to a team and may not create one, retire one, or decide who is on it —
those are deployment acts, and a per-product right cannot authorize one.

| | |
|---|---|
| Why an assigner can route to a team but not populate it | The two rights are at different grains. Letting a per-product assigner add somebody to a team would let them change who receives work in every other product that routes to it |
| Why the split is not made finer now | A role between the two — team administration, per team — is possible and buys nothing yet. Decide it against evidence of the burden rather than in advance |

**Who is on a team is listed for an administrator; anybody else sees the
names.** Routing work needs the name and not the membership, and the membership
of a team is a fact about people.

A provider group is the wrong unit twice over: role assignment is one mode for
the whole deployment, so a deployment in direct mode has no groups at all; and
what makes people leave the other mode is discovering that their groups do not
map to how the team actually divides work.

**Keeping roles out of a team is what lets one carry mixed clearance.** A kernel
team where two members may read undisclosed work and four may not is the ordinary
arrangement. A team that granted anything would make routing work to it an access
decision, and a queue could then only be built out of people who all see the same
things.

**Assignment points at a party**: a person or a team, in the column it already
has. Not a second column beside the first, because "who holds this" stays one
question and every filter, count, digest line, reminder and handover asks it
once. Two columns are right in nine places and forgotten in the tenth.

A discriminator beside the identifier is the same defect in a subtler shape —
person 4 and team 4 would match the same condition — so a person and a team draw
their assignable name from one place, and a person's is made with the person and
lives as long as they do. Whoever a request resolves to carries what counts as
theirs: their own name and every team they are on, read once.

Naming a person and a team in one request is refused rather than resolved by a
precedence rule nobody would remember.

| Rule | Reason |
|---|---|
| Team names are answered to anybody, membership to an administrator | Routing work to a team means naming one; who is on a team is the same question as who is here |
| A team assignment is a queue, not a holding | Work routed to a team is unheld until a person takes it, and taking it is the ordinary act of picking up unowned work — triage alone, no dispatch right. *Filling* the queue is dispatching. The alternative marks rows as held by the team, and hundreds then read as owned while nobody has looked at them |
| Routing asks that at least one member may read it, not every member | Asked at the strictest visibility any open place carries, so one undisclosed place among fifty makes the whole undisclosed for this purpose. Requiring every member turns routing pressure into access pressure; requiring nobody leaves work showing as held in every administrative view and sitting in nobody's list |
| The queue is narrowed per viewer, counts included | A badge reading "Kernel team · 14" shown to everybody says two embargoed items exist. Asserted by a matrix test rather than assumed from the row query being right |
| Retiring a team keeps its row and does not free its name | Work already routed has to keep resolving to something a screen can name. Declaring that name again brings the team back, because declaring is idempotent everywhere else and the alternative was a refusal citing a team the person asking cannot see |

## Routing rules

A rule matches on **component identity as well as a place in the tree**. The
upstream name is the key that matters: one rule naming a source package catches
every binary package built from it. A kernel is one source package appearing at
many places under many consumers, so a subtree rule would need a line per place
and would still miss tomorrow's.

**Either key may be a pattern, and `*` is the only metacharacter.** A rule that
can only name one package exactly is a rule somebody writes forty of. Nothing
else is special, because package names are full of dots, plus signs and dashes.
What SQL treats as special is escaped rather than passed through: `%` and `_`
appear in real package names.

**What a rule would catch is shown before it is saved.** The form answers,
recording nothing: which components it names, how many pieces of work sit at
them, and how many of those nobody holds. Only the last is what it would place,
and both numbers are shown because the gap between them is the thing worth
knowing.

| Rule | Reason |
|---|---|
| The preview asks exactly what the sweep asks, sharing the predicate | A preview that disagreed with the rule would be a confident wrong answer about the one thing nobody can otherwise see. It does not account for the rules already there, so it is named for what it *matches* rather than what it will place |
| The preview is narrowed like every other count (REQ-42, REQ-43) | Read unnarrowed, the gap between the preview and the same person's findings list is exactly the amount of undisclosed work. Somebody who may see nothing is told nothing rather than zero |
| A rule places only work nobody holds | A human assignment always wins. A rule able to override one would perform the assigner's act continuously on behalf of whoever wrote it, with nobody holding the right at the moment it happened |
| Not holding a place is re-checked at the moment of the write | The batch reads which findings a rule matches and then writes them by identifier; an assignment landing between the two is somebody's |
| Rules are ordered, first match wins, and the finding records which rule placed it | An unwritten precedence rule is forgettable, and "where did this come from" is asked months later |
| The order is settled | The ordinal is one past the highest under ordinary isolation, so two rules created at the same moment take the same number. Ties break by identifier rather than letting two rules swap places between batches |
| Writing a rule asks for the assigner right | Reading the rules asks only for triage, because knowing where work goes is part of working it |
| A rule pointing at a retired team places nothing | Rather than placing work into a queue nothing can be picked up from. Retiring a rule leaves what it placed |

**A rule matches without regard to capitals and asks the engine to fold.** It is
the one place that does: everywhere a person types a name it is normalized on the
way in, but a component name is whatever a producer's inventory called it and the
spelling is worth keeping, so there is no normalized copy to compare against.

**Turning a rule on is a bulk write.** One rule naming a source package sweeps
thousands of existing unowned issues across every place each sits at, so the
bound is counted on rows written rather than on the request. The sweep is queued
work in bounded batches, and a batch that fills its bound queues itself again
rather than looping in the worker.

**A batch is full when it has read a batch's worth, not when it has written
one.** The page is bounded on rows read and the write re-checks the holder at the
moment it writes, so an assignment made inside that window leaves a row already
theirs. Counting writes and calling a short batch the end of the estate stopped
the sweep at the first such assignment, silently, with the job recorded as having
succeeded. For the same reason a rule's share of a batch is what the batch has
left to *read*: measured in writes, the room one rule lost to a human assignment
was handed to the next rule down.

## Store methods with no subject

Visibility is enforced in the data layer with a subject. A handful of methods
genuinely take none, so the rule is stated with its exceptions — a method with no
subject is exactly what a leak looks like from the outside.

1. A background pass that answers to nobody, where the deployment is looking at
   itself and there is no person to narrow by.
2. A private helper reading rows a narrowed query already selected.
3. A question whose answer does not vary by who is asking. Whether a finding is
   suppressed is the same fact for everybody.

Anything else takes a subject. Two did not and should have: what a routing rule
would catch, and which words are in use on a product. Both read findings, both
answered for the whole product, and both were reached straight from a request.

**Whether somebody may read, and whether they may argue, are one question each,
asked in one place.** The reading rule lived on the subject from the start; the
writing rule was written out byte for byte in two packages and open-coded at six
more sites. They stay two questions rather than one: triage implies reading and
reading does not imply triage, so a single answer would have to be qualified at
every call site.

## Judgments about an issue

A rating of an issue is a claim about the issue, true wherever it appears
(REQ-29), so there is no product to hold a role on. What stood in that gap was
"is signed in", which is not an authorization rule.

**These ask for the role anywhere.** Recording a rating and taking one back ask
for triage on some product; agreeing to a milder one asks for that or the
approver capability. A rating sets the deadline and can push a finding below the
line a product triages at, in every product at once.

**The role anywhere is not the whole of it: the issue has to be one the person
may be told about.** "Anywhere" answers which right is asked for, not which
issues it may be exercised on, and on its own it reads "an issue is public
knowledge" — true of a CVE and false of an identifier this deployment minted. So
each act also asks whether the subject may read a finding of that issue
somewhere, at its visibility. An issue that sits at no build here is exempt. A
refusal is spelled as an unused name, and an unreadable claim is left out of a
list rather than refused.

**A mention that reached nobody is reported as such.** Mentioning somebody who
cannot read the finding is accepted, nobody is told, and whoever wrote it is told
that much — refusing the write loses the paragraph to fix a word. Why it did not
land stays unsaid: a name nobody holds and a name held by somebody who may not
read this answer alike.

**What somebody is told asks for reading it.** A notification names the issue,
the component and the build, and is stored as written, so there is no visibility
filter downstream that could repair it. The check is at the visibility of the
finding, not of the product.

## Subject kinds

What a request may do is decided in one place, not in each handler that remembers
to ask.

| Asker | Credential | May do |
|---|---|---|
| A person | A session cookie, or a username a trusted proxy asserts on every request | What their roles allow |
| A person's own script | A token they minted | A narrowed view of what they may do |
| A pipeline | An API key | Send scans, and read back what became of its own |

**A pipeline may send and nothing else** — no reading findings, no triage, no
reporting. A build server has no business holding a person's permissions, and
this keeps the visibility rules out of its reach rather than relying on them
being applied correctly to it.

| Rule | Reason |
|---|---|
| A key's scope is constraints, not a path | The product is always required; release and variant are independent, and either, both or neither may be pinned. Every constraint present must match |
| A mismatch is refused rather than redirected | A product-wide key cannot imply which release an upload is for, so the upload always states its full target |
| A key reads back its own receipts and nothing else | An upload is answered before its documents are read, and the party who can fix a producer emitting unreadable files is the pipeline that ran it. Narrowed in the query rather than on the page after it is read: a count taken before filtering says how many builds somebody else runs |
| The secret is generated here, never chosen, stored hashed, shown once | A credential store that can hand back what it holds gives up every pipeline's key along with a copy of the database. It is not a password: there is nothing to slow a guesser down |

## Provider sign-in

Two adapters behind one interface. One speaks OpenID Connect, for an identity
provider. The other speaks plain OAuth 2.0, for a forge that issues no identity
token and publishes no discovery document, so the account has to be asked about.

**The exchange happens here and the browser gets a session of this
deployment's.** A provider's token is never handed to a page: one of them is
opaque and this API could not check it, so a browser holding one would mean a
second way to authenticate, verified by a second path, readable by anything that
got into the page.

What has to survive the round trip — the value the provider echoes back, the one
tying its answer to this request, and the proof-key secret — is left with the
browser where no script can read it. The alternative is a table of half-finished
sign-ins, which has to be swept and which anybody can fill.

| Check | Prevents |
|---|---|
| The echoed value is compared **before** anything is exchanged | Somebody handing a signed-in person a callback of their own making and having the session come back as theirs |
| The proof key is sent as a digest and kept as the secret it hashes | An authorization code taken in flight being exchanged by whoever took it |
| The identity token must carry the value tying it to this sign-in | It belonging to a different one |
| An identity token naming no subject is refused | Quietly reducing that deployment to matching by name |
| A provider's stated address is used only where the provider says it verified it | An authorization waiting under somebody's work address being redeemable by anybody willing to claim it |

## Outbound provider fetches

Discovery, the key fetches that follow it, the exchange of an authorization code,
and the calls made to a forge go through a client that talks to **the configured
host and nowhere else**, does not follow a redirect, and does not connect to an
address inside this network.

**One client, in one place, for every fetch out of this process.** It was written
twice and forgotten a third time: the sign-in fetches had it, the
upstream-currency asker had a bare client with a timeout and nothing else, and
the token exchange — the one call carrying a client secret — fell back to the
library's default client, which has no timeout and follows ten redirects.

The exchange matters more than the rest: it carries the client secret and the
authorization code, it happens on every sign-in rather than once at startup, and
it re-resolves the issuer's name each time.

| Rule | Reason |
|---|---|
| Pinning the fetch is not enough | A document fetched from the right host can name endpoints on another one, turning every sign-in into a redirect of the issuer's choosing. The endpoints a provider publishes are checked against the issuer's own host when the adapter is built, and a provider that would misdirect people stops the process |
| The address check runs after the name resolves and before the connection is made | Checked earlier it would see a name rather than an address and refuse everything; resolving separately and then connecting leaves a window in which the name resolves to something else the second time |
| The return address is stated in configuration, not taken from the request | Otherwise it is whatever a caller claimed the host was. A deployment that configured a provider without stating its address does not start |
| An answer read back from a provider is bounded | A profile is a few hundred bytes; a body that never ends is a sign-in that allocates until the process dies |

## Trusted-header sign-in

A reverse proxy authenticates and passes the username on, which lets a deployment
run with no provider at all.

**Two guardrails, both deliberate acts:** naming the header, and naming the
sources it is honored from. Trusting it unconditionally would let anybody who can
reach the process directly be anybody at all, administrator included, because
reaching the container bypasses the proxy. **A half-configuration stops the
process.**

It can report membership too, in a second header. This extends no trust that was
not already extended: anybody able to forge the group header could forge the
username header and claim to be an administrator outright. Both the header name
and the separator are configured, because neither is standardized.

## Name and identifier

An administrator grants access to a person they can name. A provider reports a
username and its own identifier. **Only the second is stable.**

- **The username is redeemed once.** The first successful sign-in pins the
  provider's identifier to the authorization waiting under that name.
- **From then on the identifier decides**, and the username is followed as a
  label.

| Failure closed | How |
|---|---|
| A username moves | People rename themselves at work, and a forge login can be renamed and the name then registered by somebody else. The newcomer's identifier does not match what was pinned, so they are refused, while the original holder is still recognized under their new name |
| A username is only unique within its provider | A deployment with two providers would otherwise treat `alice` at each as one person. Every lookup is scoped to the provider, including the one on the identifier — providers do not coordinate, and plenty issue small numbers |

Pinning at first use is what lets authorization stay in advance: an administrator
cannot know an identifier before somebody has arrived.

## Sessions and request forgery

A session is **stored, not held in a process**, so it works whichever replica
answers and deleting the row cuts access off at once.

**A session holds no roles.** It establishes who is asking; what they may reach
is read at the moment they ask, so a role withdrawn takes effect on their next
request rather than at their next sign-in. The token is stored hashed and the
cookie cannot be read by script. The session lifetime is exactly the window in
which somebody who moved out of a team still holds what the team gave them.

A browser's credential arrives whoever asked for the request, which is what makes
forgery possible, and it is true of both browser paths.

| Arriving by | Proof required |
|---|---|
| A session | A value bound to that session, which this deployment's pages read and echo. A page from another origin cannot read it |
| A proxy's header | Where the request came from. There is no session to hold a value, and a browser will not let a page misstate its own origin |

Origin is checked for both, because it costs nothing and still holds when the
echoed value has leaked. Requests carrying a key or a token are exempt: nothing
sends those automatically. Safe methods are named as a list, so a method nobody
thought of is guarded rather than exempt by having been forgotten.

## Role assignment modes

Either an administrator assigns roles or provider groups derive them. **Never
both.** A hybrid needs a precedence rule for somebody holding one role from a
team and another directly, and that rule is forgettable — it is how a stale direct
grant outlives somebody's removal from the team it was shadowing.

**A derived role is a statement about current membership.** Membership is read at
sign-in and never again: no provider reports a departure, and polling every active
user against a rate-limited API is worse than the drift it would close. Every
derived grant is **replaced wholesale at each sign-in** rather than merged, so a
group somebody left takes its roles with it.

The window in which a withdrawn role still applies is therefore the session
lifetime. The deliberate case is handled at once by ending their sessions.

| Rule | Reason |
|---|---|
| Missing or unreadable membership yields no roles, never unrestricted | That failure would otherwise be silent and total |
| The mapping is the authorization | Somebody arriving for the first time in a mapped group is admitted and recorded then. An administrator made the mapping before anybody arrived. What is never true is somebody being admitted because a provider vouched for them and nothing else |
| Switching modes is reversible | Turning group binding on marks assignments **inactive rather than deleting** them, and turning it off makes them active again. An inactive row grants nothing and is never counted as access — not in a query, not in a report, not in a review |
| Derived grants are cleared on the way out | They are a cache of what a provider said at somebody's last sign-in |
| What makes a grant unique includes where it came from | An assignment set aside and a live derived grant for the same role on the same product can exist at once |
| Granting a role and reading one are different shapes (REQ-61) | A grant is written with which product and which role, and read back with two more the writer cannot decide: whether it is in force, and whether an administrator assigned it or a group derived it. A request refused the right to grant a role would otherwise be answered with its own claim that the role was granted and in force |

**Somebody named in configuration keeps administration**, applied at **every**
startup rather than the first. That makes it the way back in: lose administrative
access, add yourself, restart. It survives re-derivation from groups, because a
sign-in that stripped it would take the recovery path away at the moment it is
needed. It remains a pre-authorization and not a bypass.

**A deployment may not start unable to administer itself.** In group-bound mode
that means at least one group mapped to administration, or somebody named in
configuration. The only route back from locking yourself out is editing the
database by hand.

## The grant grid

Products down and capabilities across (REQ-42), one checkbox per pair. It
replaced a run of chips shaped "product · role" beside a form of three controls,
because two ordinary questions were unanswerable: "who can approve on this
product" meant reading every chip on every person's row, and "what does this
person hold" meant reading a list as long as products times capabilities, in no
order.

| Feature | Reason |
|---|---|
| The row across the top is every product at once | Checked where they hold that capability everywhere, partial where they hold it somewhere, and pressing it grants or withdraws only the difference. Granting a reviewer the same capability on eight products was twenty-four gestures, and the chips gave no way to tell "on all eight" from "on six of eight" |
| A role derived from a group is drawn and cannot be changed here | It is withdrawn by changing the group, so the box is disabled and says so rather than accepting a click the next sign-in would undo. Where the deployment takes its roles from groups, the grid is not offered |
| A capability granted where nothing is readable is marked as it is granted | Approver and assigner are bounded by what their holder may read. That was already said after the fact, on the row; the cell says it where somebody is about to do it |

## Personal tokens

Anything the interface does not offer cannot be automated, and the usual result
is somebody driving a browser session with a script or reusing a pipeline's key
for work it was never scoped for.

| Rule | Reason |
|---|---|
| A live reference to its owner, never a snapshot | What it reaches is read from what they hold at the moment it is used, so a role withdrawn cuts the token at the same instant — including one withdrawn because a group membership went away, which is the case with nothing else to notice it |
| It may not mint or withdraw another | Minting resolves through the owner, so a token that could mint would ask for a wider one and be given it, making every limit exactly one request deep |
| Narrowing intersects | A token pinned to a product its owner cannot read reaches nothing rather than being granted it. Administration is dropped by narrowing entirely, because a token narrowed to one product that still administered everything would not be narrowed |
| Expiry is not optional, with a maximum an administrator sets | A credential that never runs out is one nobody ever revokes. Revoking marks rather than deletes, so what used it stays answerable |

**Every credential says which kind it is.** Pipeline keys and personal tokens
carry distinct fixed prefixes, so resolution dispatches on the prefix rather than
trying each store in turn. A credential that ends up somewhere public is also
recognizable as one: secret scanners match fixed prefixes, and a bare run of
base64 matches nothing.

## Where each check is made

| Decided | Where | Reason |
|---|---|---|
| Who is asking | One middleware, before any route | A handler that forgets to ask answers for everybody, and the forgetting is invisible |
| Whether they are anybody at all | The same middleware | An unrecognized caller does not learn whether their body was well-formed |
| Whether they may reach this product | The data layer, on the query | A check beside the query cannot be skipped by adding another endpoint |
| Whether they may do this at all | The handler | Declaring a product is administration whatever the query looks like |
| Whether a header from an untrusted source was a mistake | Logged, never answered | The caller is told no more than anybody else. An operator who trusted one address family and is reached from the other has no other way to find out |

**A query without a subject is a fault, not a denial.** Reading who is asking from
a request's context **fails** when nobody is attached — it is a bug in this
program. Treating absence as "nobody, so show nothing" hides that until somebody
writes the query that treats absence as "everybody": one of those is a blank
screen and the other is a disclosure.

**A pipeline is refused a read rather than shown an empty one**, receipts for its
own uploads excepted. "Here is nothing" and "you cannot ask" are different
statements, and the first invites a caller to believe the list is empty.

**Everything except the probes is authenticated, named as a list** rather than
guarded by a path prefix. A prefix leaves everything outside it open by default,
and the framework registers routes of its own — the API document and its schemas
were served to anybody who asked, including the running version the endpoint
reporting it is authenticated to withhold.

**A read is narrowed twice**: to the products somebody holds anything on, and
within those to what has been disclosed to them. **Forgetting the first is
silent** — the visibility half alone admits every disclosed finding in the
deployment, in products the asker holds nothing on, which reads as working
because the numbers are plausible.

The pair is one call. Where a product is already pinned — a build's readiness, one
product's releases — a set membership would say less, so those have their own name
for the pairing, which states that the first half was done. **Nothing calls the
visibility half bare.**

## Browser headers

Every response carries the headers that turn off what nothing here needs
(REQ-69): no content-type sniffing, no framing by any page, referrers kept to
this origin, and a content security policy permitting only what the bundled
interface ships — its own scripts, styles and fonts, `data:` images, and requests
to itself. Inline styles are the one concession, because the chart library writes
them.

Set **before any handler**, on the API's answers as well as the page's, so a
route added later cannot lack them and a JSON body opened in a browser is still
covered. It is the second line behind the markdown sanitizer.

| Rule | Reason |
|---|---|
| The page's own inline script is allowed by its hash and nothing wider | The document said the interface had no inline script, which stopped being true when the page grew one — the snippet reading the chosen theme before the first paint. The browser refused it silently, the bundle applied the theme a moment later, and the flash the snippet exists to prevent happened on every load |
| The hash is taken from what is served, not written down beside it | A hash maintained by hand drifts the first time a build step touches the snippet. `'unsafe-inline'` would have been the one-line fix and allows *every* inline script, including one smuggled past the sanitizer |
| `base-uri` permits nothing and `form-action` permits this origin | A `<base>` element rewrites what every relative address resolves to without violating any fetch directive, and a form's action is not a fetch |
| A download filename is made safe where the header is written | Two exports name the file after the product, and a product's name is checked for being usable as an identifier rather than inside a quoted header field, where a quote ends the field early and a carriage return ends the header. The check that has to hold is the one at the header, because it covers every export including one added later |

## Sign-in return addresses

A sign-in may carry the address it began at, so somebody whose session ended
halfway through writing lands back on the screen they were on. Losing the words is
prevented in the browser; losing the *place* is prevented here.

| Rule | Reason |
|---|---|
| The address never leaves this deployment | Kept in the same cookie that already holds what a sign-in has to remember, so nothing a provider echoes back can decide where somebody ends up |
| It is a path here or it is discarded | Kept only when it starts with a single `/`, does not start with `//` or `/\`, which browsers read as protocol-relative, and parses with no scheme and no host of its own. This is the whole of the defense |
| Checked on the way in and again on the way out | The cookie is the browser's own, so somebody may edit it. A person redirecting themselves gains nothing, but an address that left here is an address this deployment sent |
| Discarded rather than refused | Turning a bad address into a failed sign-in would punish the person for a link somebody else wrote |

## The administration trail

An administrative change is recorded — who, what, before, after, and when
(REQ-22): settings, role grants and withdrawals, end-of-life dates, the triage
floor, credentials, accounts and teams. An administrator reads it beside the
triage record, because it is the same question one layer up.

| Rule | Reason |
|---|---|
| Both values are kept, and absent is not empty | "Who raised the floor to critical" is half of what somebody asks; the other half is what it was. A value nobody had set is an *absent* before rather than an empty one |
| Recorded where the actor is known, which is the request | A setting write knows a name and a value and nothing about who is asking. The cost is that a new administrative route can forget, so a test walks the routes and asserts each leaves a row |
| A failure to record is not a failure of the change | The change has already happened; an error would invite a retry that makes it twice |

Three levers silently rewrite what this tool reports: changing the deadline policy
recomputes every open finding's deadline, raising the triage floor removes
deadlines below it, and an end-of-life date removes them past it. **For a tool
whose entire output is evidence, that is the evidence itself being movable.**

## Secrets and logs

Connection strings are redacted, and credentials and tokens are never written at
any level (REQ-68). Not a level to be turned down in production: a token at debug
is a token in whatever collects the logs, read by everybody who can read those
and kept for longer than the token's own life.

The case that actually happens is a database URL with a password in it, printed
once at startup by something helpful. **It is redacted where it is formatted, not
where it is logged**, so a second caller that logs the same value cannot
reintroduce it.

The rule is written down rather than left as a habit because the failure is
invisible: nothing breaks, no test fails, and the leak lives in a system nobody
thinks of as holding secrets.

## Disclosure

Public and private mean disclosed and not disclosed, so an undisclosed finding is
one somebody intends to disclose eventually. **All of this is built.**

A private finding carries a disclosure date, defaulting to ninety days after the
report was received (REQ-37). A public finding has none. The point of having one
is that it gives the embargo an end somebody outside could hold this deployment
to.

**Reaching the date discloses nothing. It escalates.** Publishing embargoed detail
because a timer expired is the wrong default in both directions: if the fix is
not ready, disclosing anyway is a decision a person makes, and automatic
publication eventually publishes something nobody was ready for.

**What is approaching disclosure is surfaced before the date** (REQ-38), on a
list ordered soonest first and as a notice at a lead time somebody sets. The date
arriving is the last moment to act rather than the first useful warning.

**That list is itself a disclosure.** A product somebody may not read undisclosed
work in contributes nothing to their copy of it — not a row and not a count,
because a count says as much as a row.

The date arriving tells administrators, and whoever holds the finding where they
may still read undisclosed work in that product. A condition rather than an
event: it stands while the date is past and nothing has been decided.

## Extending a disclosure date

Needs a reason, and past a threshold that is a setting — thirty days by default —
a second person (REQ-38). The same shape as a deferral, because it is the same
act: keeping risk hidden for longer.

| Rule | Reason |
|---|---|
| A reason is required always, however short | One with no reason is a record saying somebody moved it and nothing else |
| The threshold is measured against everything the embargo has already moved by | Measured per request, the exception swallows the rule three weeks at a time. Only extensions that took effect count |
| An extension that needs agreement moves nothing until it has it | An embargo running on while somebody thought about it would be the extension taking effect on one person's say-so with a queue entry as decoration |
| The person who asked may not be the one who agrees | That is the control the threshold exists to reach |
| A date only ever moves later | Bringing one forward is disclosing sooner, which is a different act |
| Every request is kept, granted or not, oldest first, with why and by whom | One extension is a judgment and six is a policy nobody wrote down, and the difference is invisible if each replaces the last |

**There is somewhere to be the second person.** A request over the threshold
could be read on the finding it belongs to and nowhere else, so the only way to
find one was to already know it existed. The requests waiting appear on the review
queue as their own list rather than as claims: what is agreed to here is not a
claim about code.

That list is a disclosure too, so it is narrowed in the query. **A request of your
own is shown and marked** and cannot be agreed to — hiding it would leave somebody
hunting for what is holding their case up. That is the opposite of the review
queue's rule: there an entry is work the reader might do, and here it is a state
of the case.

## Case collaborators

Everybody holding private triage on a product used to see every embargoed finding
in it, and there was no smaller unit than the product.

**A collaborator is granted one issue in one product** (REQ-43). They see that
issue everywhere it sits in that product and nothing else — not the rest of the
embargo list, not a count of it.

The case is the kernel engineer who normally sees only public findings and is
needed on one embargoed kernel flaw. Coordinated disclosure practice is built on
case-level lists: three named people know before disclosure, not everyone holding
private access.

| Rule | Reason |
|---|---|
| Approval stays with the pool that already held it | Two collaborators could otherwise satisfy the two people a dismissal asks for with nobody accountable for the product. Proposing, revising and reaffirming ask a question naming the issue; agreeing asks one that does not |
| The grant is asked wherever a row is read, not only where a list is narrowed | A grant that shows a row in a list and refuses it when opened is a grant with no content. The list narrowing asked it and three reads by identifier did not, so a collaborator saw their case among the decisions and could open none of them |
| Asked once the row is in hand | It needs the issue, which a bare product-and-visibility rule cannot see. That is the opposite order from a name somebody typed, and safe for the same reason it is necessary: the row is already established as existing |
| Adding somebody is an access change | It lands in the administration trail, tells them at once in the area inside the application, and the finding shows how many collaborators it has. It stops meaning anything at disclosure |
| Whoever reads the case manages its list, rather than an administrator | Knowing who is needed on a case is knowing the case, and routing it through somebody who does not read it makes them the bottleneck on every embargo |

**The product-wide question keeps answering no, and that is the whole of the
safety.** Every list, count, report and export narrows by whether somebody reads
the product at a visibility, so a case grant that widened *that* would hand
somebody the embargo list of a product they were let into one finding of. The
grant is asked by a second question put beside the first at every read about one
named issue.

A collaborator does not get the findings list. They reach the case through the
notification the grant sends — the one message that names an undisclosed issue on
purpose, because it goes to the person who has just been given that issue.

## Mail addresses

A person's record carries a mail address, and it is optional. Somebody without
one is told nothing outside the application and keeps the area inside it.

**Two sources, one field.** An administrator sets it with the rest of the record,
and a sign-in provider fills in one nobody set. Which it came from is kept, so a
provider may refresh what a provider gave and may never overwrite what somebody
here decided. Written the other way round, an administrator correcting a wrong
address would watch the next sign-in put it back.

Neither source alone is enough. A provider covers the ordinary case for nothing
and covers nothing at all on the trusted-header path, and it has nothing to offer
until a first sign-in — which is exactly the person the absence condition is
about. Recording every address by hand asks somebody to type what the provider
already knows.

**A provider's address is taken only where the provider says it checked it.** An
address nobody checked is whatever the account holder typed, and mail sent to it
is mail sent wherever they said. For one forge that means asking for the
addresses it has confirmed rather than reading the public profile.

**Failing to record an address does not fail a sign-in.** Arriving is what was
asked for; refusing it because a column did not fill would lock people out.

## Absent holders

An administrator is told when somebody has not signed in for a configured period
and still holds assigned work (REQ-45): "X has not signed in for two weeks and
has six items assigned". A condition rather than an event, because what is wrong
is that nothing has happened.

Nothing tells this software somebody has left, membership is only read at
sign-in, and a person who has gone never signs in again, so the software can only
notice the absence and say so.

## Limits

- **A rule naming a component whose name carries a letter outside ASCII matches
  on the three servers and not on SQLite**, whose fold is ASCII-only. SQLite is
  for development and testing, so no deployment is affected, but a rule proved
  locally can behave differently in production. Making it agree everywhere means
  storing a folded name beside the spelling, which is a schema change.
- **The batch-fullness rule is reasoned rather than pinned by a test.** The
  divergence needs a write landing between the read and the write of the same
  batch, and a test here runs one thing at a time. What is pinned is that a sweep
  spanning several batches routes everything it matches.
- **Trusted-header sign-in has no stable identifier of its own.** It asserts a
  username on every request and there is nothing else to match on. The proxy is
  the authority there.
- **Proxies that deliver identity in a signed token are not supported by that
  path**, because reading a header cannot verify a signature. Such deployments
  configure a provider instead.
- **A saved filter is not a permission.** It lived in this package because it
  hangs off a person, which is the wrong reason. What it cost was that the triage
  vocabulary a filter can prepare was defined a second time inside the package
  about permissions, which is the last place somebody looks for it.
- **A key is honored from anywhere.** It holds a credential rather than being
  vouched for by position; where it connects from says nothing about whether it is
  genuine.
- **The stored key digest is compared again in constant time.** Finding a row by
  digest is not by itself a statement that two secrets match.
- **A person holding triage may send a scan.** Somebody re-uploading a build by
  hand is doing triage work.
- **A pipeline sees the product it may send to.** Pretending otherwise would make
  an upload to its own product indistinguishable from one to a product that is not
  there.
- **A fault is logged rather than described.** The framework serializes an error
  passed alongside the message, so handing it one hands the caller the query text
  and, for a connection failure, the address and user it tried.
- **Naming every address as a trusted source is refused.** It reaches the same
  place as naming none, through the setting that is supposed to be the guard.
- **Granting a role somebody already holds succeeds.** An administrator scripting
  grants should not have to check first.
