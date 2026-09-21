# The HTTP API

The one surface. Everything a person or a pipeline can do goes through it, and
the web interface is a client of it.

Satisfies REQ-61, REQ-62, REQ-63, REQ-64, REQ-65, REQ-66, REQ-67.

## Contents

- [No private half](#no-private-half)
- [Document generation](#document-generation)
- [Unauthenticated surfaces](#unauthenticated-surfaces)
- [Operation descriptions](#operation-descriptions)
- [Status codes](#status-codes)
- [Refusal shape](#refusal-shape)
- [Paging](#paging)
- [Sorting and filtering](#sorting-and-filtering)
- [Issue-keyed and cross-product reads](#issue-keyed-and-cross-product-reads)
- [Path version](#path-version)
- [Declared privileges](#declared-privileges)
- [Representation](#representation)
- [Addresses and labels](#addresses-and-labels)
- [File organization](#file-organization)
- [Limits](#limits)

## No private half

No endpoints are reserved for the web interface. The interface uploads a scan
through the same endpoint a build pipeline uses; that upload path is a testing
convenience, not a second contract.

A private half is how an API stops being honest: the endpoints a browser needs
get built quickly because only internal code calls them, the public ones become
the second-class copy, and the interface acquires abilities nobody else has —
a security boundary nobody designed.

## Document generation

The OpenAPI document is produced from the route definitions rather than
maintained beside them. The published document is checked in, and the build fails
when the committed copy has drifted.

Without that check, regenerating is a step somebody skips, and a hand-kept
document is wrong the first time somebody is in a hurry — silently.

| Rule | |
|---|---|
| A closed vocabulary is the domain's list, not a literal beside the route | Retyped at the route, a word added to the domain is accepted by the store and refused by every route that takes it, and each retyping is free to carry a different membership. The list comes from the package that owns the vocabulary, so the document and the store cannot disagree about what a word is |
| A subset is a named rule in the domain package | Some routes take fewer words than the vocabulary has: one decision at a time offers what a person may propose there, and a bulk claim offers less again. Shortening the list at the route makes what is left out an accident; naming the subset where the vocabulary lives makes it a statement, with the reason beside it |
| Every word in the built document is checked against the list that owns it | A test walks the document the server builds from its own registrations and requires each enumerated word to be one the domain holds. Asked of a hand-kept list it would only check that two copies match; asked of the domain it checks that the document is true |

## Unauthenticated surfaces

The application serves no documentation of its own, leaving no unauthenticated
route that reads domain data: no product, finding, issue, person or credential
is readable without a credential.

Sign-in is not nothing. It reads and writes the deployment's own sign-in key,
the session it is creating and the account row a first arrival needs — its own
machinery, and nothing beyond it. A route added under that prefix is checked
against that rather than assumed harmless.

Four surfaces answer without a credential. The list is written out rather than
inferred from a rule, so adding a route never adds an exception.

| Surface | Answers |
|---|---|
| `/healthz`, `/readyz` | Whether the process is up and whether it can reach its database |
| `/v1/sign-in` | The providers an operator configured. A sign-in page draws a button per provider and cannot ask for that list while holding nothing |
| `/v1/sign-in/…` | Redirects to a provider, or refuses. What it reads and writes is its own: the sign-in key, the session, and the account a first arrival needs. A route added here is checked against that rather than assumed harmless |
| The interface | The built assets. They contain no data; everything drawn in them is fetched with a credential |

## Operation descriptions

| Rule | Detail |
|---|---|
| A summary is an imperative verb and the thing it acts on | In the words the domain uses. Somebody scanning thirty operations has to find theirs in a second |
| The first sentence states what the operation does | Opening with the argument leaves the endpoint's answer unsaid |
| A description states what the operation takes, what comes back, and what is not obvious | An upload that answers before parsing, a field required only for one outcome, an approval a later edit withdraws |
| Reasoning is excluded | It lives in this document and in `REQUIREMENTS.md`. Requirement identifiers name a file no caller has |
| Every parameter carries its own description | A required query parameter documented as nothing is a parameter somebody guesses at |

## Status codes

| Code | Meaning |
|---|---|
| 201 | Something now exists, and its identifier is in the answer |
| 202 | Accepted, not yet done. Only an upload, which answers before it has been read |
| 204 | Done, with nothing worth saying |
| 404 | The thing is not there, **or** is not yours. Deliberately the same answer |
| 409 | The request conflicts with the state of what it names: a scan older than the one held, a role granted the wrong way for this deployment's mode, an approval by the person who made the claim |
| 422 | Understood, and cannot be stored as written |

Not found and not yours are one answer. A product somebody holds nothing on is
invisible rather than unreadable: not listed, not counted, and reported as not
declared — the answer a name nobody ever declared gets. The same applies to a
decision identifier, a person and a credential.

Anything else is an oracle: if "you may not see that" and "that does not exist"
differ, somebody holding one product learns the name of every other by guessing.

The sentences are kept in one place, so spellings cannot multiply and describe
the wrong thing.

A store's refusal that no handler has an arm for is an oracle too. It falls
through to the fault answer, so the route says 500 where a stranger is told
404, and the pair says the build is there — one name at a time, with the
fault's own text naming which of product, stream and variant is undeclared.
Every store refusal is typed and every handler that can meet one answers it the
way a name that reaches nothing is answered.

The reach that meets them is a case collaborator: they hold nothing on the
product and may open exactly one finding, so every product-wide read refuses
them, and each of those refusals has to look like a stranger's.

| A refusal answers | |
|---|---|
| 404 | A name that reaches nothing, including one that reaches something they may not have |
| 403 or 422 | An act they may not do on something already shown to them |

The second is the one two routes answer differently if nothing holds them
together: handing work to somebody else needs a right, and 404 against 422
about the identical condition is what that looks like.

A streamed answer is refused before its first byte. Once the status has gone,
the only place left to say anything is the file, which then reports that the
export stopped early behind a 200.

## Refusal shape

`application/problem+json`, for everything, including the handlers in front of
the router — the credential check and the sign-in callbacks, which are ordinary
handlers rather than operations because a redirect arriving from a provider is
not an API call. Answering `text/plain` there makes a client parsing the
documented error model read a refusal as a transport fault.

A refusal states where to look. Each fault travels as its own detail carrying
the line and the offending text. This is an API shape decision rather than a
presentation one: an interface can only point at the problem if the answer says
where it is.

A store's own sentence and a failed query are distinguished by the engine's
error types, asked in one place, rather than by the message text. Answered
alike as a 422 with the message in it, a broken database reaches the caller as
a bad request carrying the statement text and, for a connection failure, the
address and user it tried. Where the type cannot decide, the error is treated
as a refusal.

A 404 is never built from an error's own text. It asserts that a name reaches
nothing, and the body then publishes whatever the error carried — for a store
read, the driver's message. Built that way over a reader returning the driver's
error unwrapped, a connection failure reaches an authenticated caller as "that
product does not exist" with the database host, port and driver in the detail.
A gate checks it.

The one exception is named in place: the catalog's own not-declared error is
composed from the names the caller supplied and fixed words, and a pipeline
whose upload was refused has to be told which of the product, the branch and
the variant it was. That arm is reached only once the sentinel has been tested.

A read that could not be made is a fault rather than a 404. The split is one
helper rather than a judgment made per route: made per route, it is made
differently per route.

A process with no database answers with one sentence. Every handler guards
against it, because a nil pointer inside one is worse than a refusal, and each
guard writing its own wording reads as that many different conditions. It says
nothing about what the caller asked for, because the caller did not cause it
and cannot fix it.

## Paging

`limit` and `offset`, with a total, wherever a caller reads a second page. A
list that takes a limit and no offset cannot be read past its ceiling at all
through the API, and a screen shows the ceiling's worth and reports it as the
list.

Some lists take a limit and no offset on purpose, and the limit is there to
refuse an absurd request rather than to cut a page.

| A limit alone | |
|---|---|
| What it is for | A list a screen draws whole: a standing short list, a picker's page, what sits at the top of one build's tree |
| What makes it correct | The ceiling is above anything the list can hold, so nobody is looking at a page |
| What ends it | The list growing past the ceiling on a real deployment. It gains an offset then, and the screen gains the control to use it |

Four of them take an offset: what is running out of time, what is approaching
disclosure, the disclosure-date movements waiting for a second person, and the deferrals that
keep repeating. Each grows with the estate, and each answers with a total as
well — a caller holding a full page cannot otherwise tell a clipped page from
the whole list, and a screen then prints the length of its own page as the
figure.

The three that keep a limit alone are the pickers: who holds something, who may
be mentioned, and what sits at the top of one build's tree. Each is a list
somebody scrolls once.

The bound is stated twice:

| Layer | Behavior | Reason |
|---|---|---|
| The API | Declares the ceiling on the parameter and refuses anything larger, naming the bound | That is what a caller should get |
| The store | Clamps | It defends itself against a caller that is not the API — a background pass, a test, a second surface — and has nobody to explain a refusal to |

The clamp is one function. Page sizes are named constants rather than literals: a
list somebody reads and pages through, a list read in bulk, a whole build's
register, a component's worth of findings, a chart's points, a picker. A test
walks the document and fails a declared limit that is not one of them.

Ceilings vary by list. Which list allows what is a judgment about each list.

| Rule | |
|---|---|
| A capped listing carries the whole-answer count | A caller cannot tell a clipped page from a complete answer otherwise, and a reader recounting its own page states a figure about the page under a heading about the whole. Without the count a tile says 200 over a list of 462 |
| A figure counted over the whole answer is returned beside the rows, not recomputed from them | Coverage reports how many builds there are, how many have gone quiet, how many have never been scanned and how many are out of support, each counted before the page is cut |
| A bound declared for a listing bounds the whole listing | Applied to the people alone, it appends every team there is after them |
| What a request asked for and could not be acted on comes back | A note naming more people than one act may tell reaches some of them, and the rest go unmentioned in the response and anywhere else |

## Sorting and filtering

Filters are named fields with fixed meanings, bound as parameters.

A filter over an open set says so. The kind of package is read out of the
identifier a producer wrote, so the set is whatever producers emit and the
parameter carries any string: one nothing carries matches nothing. Named as
eight kinds and offered as eight, most of an image whose packages are `apk` or
`rpm` cannot be narrowed to at all, while the server answers either correctly.

Sorting is permitted (REQ-66). A value in a query can be bound as a parameter
and a column name cannot, so a sort column arriving from a query string becomes
part of the statement.

| Rule | |
|---|---|
| Six keys, each selecting an expression stored beside it | The key a caller sends is a lookup and never the value |
| The fix-bundle list has six of its own | A bundle is one upstream bump rather than a finding: it has an issue count and a build count a finding has not, and no age of its own. One allowlist covering both would offer each list keys that mean nothing there, so it has a second — read the same way, with the same direction word, and offered by the same generated enum |
| Nothing else reaches the statement | No derivation from the parameter, no mapping that falls through, no default that is the parameter |
| The direction is one of two words written here | Not a word that arrived |
| A key that misses answers in the list's own order | An unknown sort is a mistake about a list, not a reason not to show it |
| The issue table is joined only where the chosen order needs it | The ordinary page still reads one covering index |
| A narrowing that cannot be applied answers nothing, never everything | "Assigned to me" from a credential that holds no party names nobody. Dropping the condition hands the caller every finding there is while the screen goes on showing the filter as on, so a filter asking for a set nothing is in answers with nothing |
| A filter with three answers is a word, not a flag | Origin is one: a screen offering "Scanner" as a flag can only send the absence of "entered by hand", so choosing it filters nothing |
| A repeated value is one value | A set of one word sent twice otherwise reads as both kinds and no narrowing, which silently puts tags back into a list somebody asked to see branches of |

This also prevents a sort exposing a column the caller was never meant to order
by.

## Issue-keyed and cross-product reads

One page answers for an issue (REQ-64): every product, build and component it
sits at, with how far it has been decided in each.

| Rule | Reason |
|---|---|
| One row per build and component, not per place | The same component in two builds is two things shipped; sixty places of it in one build is one piece of work with a count |
| How far it is decided uses the findings list's own expression | Two screens with two definitions of "decided" come to disagree in front of somebody |
| No new visibility rule, but the narrowing is in the query | A page spanning products is where filtering afterwards gets forgotten, and the count leaks even when no row is shown |
| The search box lands here, with no product picked | An issue by name spans products by construction. Which of the two searches it is is decided by asking the server, not by the shape of the text |

The findings list spans products too, at `/v1/findings` with no product in the
path: one row per product, issue and component, with the same filters, sort
allowlist and paging.

Every product's own triage line applies per row from that product's own column
rather than from one number chosen for the page. `severity` raises the line for
the whole page and never lowers it below what a product decided; `below_floor`
turns every line off.

The filters belonging to one product's builds are not offered across products
rather than answered from whichever build sorted first: `beneath` walks one
build's edges, and `differs` and `across_variants` are statements about a
selection of builds. Everything else is one struct shared by both endpoints.

`across_variants` compares a row with the other builds of the branch that row
sits on. `only` keeps what no other variant of that branch holds and is refused
unless the selection names a variant; `every` keeps what every build of that
branch holds and needs none.

Still per product: the dependency tree, the inventories, and the list of work
nobody owns.

## Path version

`/v1` is the shape the API will have. Below 1.0 it is not a compatibility
promise (REQ-76), and a change to a shape is an edit rather than a second
version standing beside the first.

## Declared privileges

Each operation carries a structured statement of what it asks of a caller
(REQ-62).

| Field | Holds |
|---|---|
| Scope | The deployment, a product, yourself, any signed-in person, any recognized credential, or answered without one |
| Roles | Any one of which is sufficient |
| Note | Only where a rule is not a role |

The line in the description is rendered from that same value rather than written
beside it. Two hand-written copies disagree within a month, and a wrong
permission is worse than the silence it replaced.

A declaration states which of two kinds of rule it is:

| Kind | Behavior |
|---|---|
| Gate | Refuses a caller holding none of its roles |
| Narrowed | Answers everybody; the roles decide what is in the answer. A stranger gets an empty list or a count of zero |

Read as a gate, a narrowed operation looks like one whose check is missing; read
as narrowed, a gate hides a real hole.

Every gate is swept. A test walks the document the server builds and asks each
gated operation as somebody holding none of its roles; a 2xx fails it.

A gate refuses an operation declaring neither scope nor roles. An endpoint added
without one is not broken, it is undocumented.

"Any signed-in person" and "any recognized credential" are two scopes, because
a pipeline's key is not somebody. An operation declaring the second and then
refusing every credential that is not a person makes the reference, the
extension a client generator reads and an access review all state a rule the
code contradicts. The word cannot be redefined instead: two operations really
do mean any credential — a key reads back the scans it sent, and the receipts
for them.

The part of a requirement that is about the subject alone is enforced before any
handler runs, which is what makes the handler's own check the second statement
of a rule rather than the only statement of one the document contradicts. A role
on a product needs the product resolved and stays in the handler.

The privileges page keeps only what a per-endpoint line cannot carry: what each
role means, how roles are granted, what a declaration is and is not, and that
seeing is never changing. Two rules in it are not roles and cannot be granted:
visibility narrows every answer, and the proposer of a claim may never approve
it.

## Representation

Text written by people comes back as markdown, as the only representation. There
is no markup representation and no parameter requesting one.

A caller receives the source and renders it themselves. The server has already
refused what its policy forbids at submission (REQ-67), so the text is known-good
under the rules in force when it was written; rules written since are the
renderer's to apply. The rules are in `DESIGN-text.md`.

## Addresses and labels

A product, a person and a team each answer to two strings: the one that
addresses it, and the one somebody declared to read. They are different
wherever a display name is more than a recapitalization.

| Rule | Reason |
|---|---|
| A field a write resolves carries the address | It is what the lookup matches. A listing publishing the label there cannot undo what it listed |
| The label goes beside it, never in place of it | A screen still shows what a person reads. Two fields is the only arrangement where both are true |
| The label is absent where it repeats the address | So that "no display name" and "the same again" do not read alike |
| A name in a path is the address | Folding only lowercases and trims, so a label matches no row |

What publishing the label in the address's field costs. A collaborator on an
embargoed case listed under their display name in a field called `identity`
cannot be taken off, because the removal route resolves that field. A role on a
product declared `acme-router` and displayed `Acme Router`, listed as the
label, is sent back by the withdraw beside it and matches nothing.

Every listing carries both fields: the collaborators, the roles, the
credentials, the bindings, the tokens and the routing rules.

## File organization

One file per subject, where a subject is a noun somebody acts on rather than a
count of lines. The catalog is three — declaring what exists, stating policy on
it, and reading it — because stating policy is the group that silently rewrites
what the tool reports and was the hardest of the three to find inside a
five-hundred-line registration. Keys left the people endpoints for the same
reason: a different noun, a different lifetime, and the one act here that hands
out a new way in.

The package's authorization primitives sit beside the declarations they
enforce. A declaration in one file and the primitive enforcing it in another
with nothing to do with it is what makes the privilege ladder hard to audit.

### Deliberate omissions

Recorded because the conclusion is the deliverable.

| Left alone | Why |
|---|---|
| `findings.go` | The findings list, its filter mapping, and the narrowing, paging and single-build types every other list embeds. Cutting it would separate the filter struct from the one function that reads it |
| The two-build `locate` closures in the report handlers | The shared part is four lines over different response shapes. A helper whose body is an argument list is harder to read than the repetition |

## Limits

| Limit | Detail |
|---|---|
| Half the declaration is the check and half is not | The scope — an administrator, the caller's own credential, any recognized one, none — is a fact about the subject alone, so it is enforced from the declaration before any handler runs. A role on a product needs the product resolved and stays a line in the handler, where a check narrower than the operation declares disagrees with it and nothing fails. Enforcing the role half centrally would answer 403 before the handler and tell a guesser the thing exists; enforcing neither leaves every administrator gate resting on one line nobody sweeps |
| The gate sweep is a floor, not a proof | A refusal for the wrong reason passes it, and it says nothing about what a narrowed operation puts in its answer. It walks both gated scopes and counts them apart, because a sweep over one of them skips the administrator gates |
| A note states something the scope does not, or is omitted | A note saying the opposite of the value beside it is worse than none: an operation answered without a credential can declare that it requires one |
| Paging is `limit` and `offset`, with a total | A cursor is better under concurrent writes and worse for jumping to a page. The total is separate from the page because somebody deciding whether to start work needs to know how much there is |
| A list answers with an object, not an array | An array at the top level has nowhere to put the total |
| Names in paths, identifiers in bodies | A product, stream and variant are what somebody typing a request knows and what a pipeline has in its configuration. A decision is numbered because it has no name |
| A place in a path is the identity the findings list gave out | A caller free to compose one would be choosing which decisions apply where |
| Comment density in this layer is low by design | It is a registration and a mapping: the operation is declared, a store is called, its answer becomes a body. What is worth explaining about a rule belongs where the rule is enforced |
