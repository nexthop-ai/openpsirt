# The HTTP API

The one surface. Everything a person or a pipeline can do goes through it, and
the web interface is a client of it.

Satisfies REQ-40, REQ-61, REQ-62, REQ-63, REQ-64, REQ-65, REQ-66, REQ-67.

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

## Unauthenticated surfaces

The application serves no documentation of its own, leaving **no unauthenticated
route that reads anything from the database**. Four surfaces answer without a
credential. The list is written out rather than inferred from a rule, so adding a
route never adds an exception.

| Surface | Answers |
|---|---|
| `/healthz`, `/readyz` | Whether the process is up and whether it can reach its database |
| `/v1/sign-in` | The providers an operator configured. A sign-in page draws a button per provider and cannot ask for that list while holding nothing |
| `/v1/sign-in/…` | Redirects to a provider, or refuses. Nothing under it reads anything, so a route added here by mistake leaks a redirect rather than data |
| The interface | The built assets. They contain no data; everything drawn in them is fetched with a credential |

## Operation descriptions

| Rule | Detail |
|---|---|
| A summary is an imperative verb and the thing it acts on | In the words the domain uses. Somebody scanning thirty operations has to find theirs in a second |
| The first sentence states what the operation does | A dozen opened with the argument instead and never said what the endpoint returns |
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

**Not found and not yours are one answer.** A product somebody holds nothing on
is invisible rather than unreadable: not listed, not counted, and reported as not
declared — the answer a name nobody ever declared gets. The same applies to a
decision identifier, a person and a credential.

Anything else is an oracle: if "you may not see that" and "that does not exist"
differ, somebody holding one product learns the name of every other by guessing.

The sentences are kept in one place. There were six spellings, two of which
described the wrong thing.

## Refusal shape

**`application/problem+json`, for everything**, including the handlers in front
of the router — the credential check and the sign-in callbacks, which are
ordinary handlers rather than operations because a redirect arriving from a
provider is not an API call. They answered `text/plain`, so a client parsing the
documented error model read a refusal as a transport fault.

**A refusal states where to look.** Each fault travels as its own detail carrying
the line and the offending text. This is an API shape decision rather than a
presentation one: an interface can only point at the problem if the answer says
where it is.

**A store's own sentence and a failed query are distinguished by the engine's
error types**, asked in one place, rather than by the message text. Thirty
handlers answered both as a 422 with the message in it, so a broken database
reached the caller as a bad request carrying the statement text and, for a
connection failure, the address and user it tried. Where the type cannot decide,
the error is treated as a refusal.

**A process with no database answers with one sentence.** Every handler guards
against it, because a nil pointer inside one is worse than a refusal. Each guard
had invented its own wording — twenty-one of them, reading as twenty-one
conditions. It says nothing about what the caller asked for, because the caller
did not cause it and cannot fix it.

## Paging

`limit` and `offset`, with a total. The bound is stated twice:

| Layer | Behavior | Reason |
|---|---|---|
| The API | Declares the ceiling on the parameter and refuses anything larger, naming the bound | That is what a caller should get |
| The store | Clamps | It defends itself against a caller that is not the API — a background pass, a test, a second surface — and has nobody to explain a refusal to |

The clamp is one function. Page sizes are named constants rather than literals: a
list somebody reads and pages through, a list read in bulk, a whole build's
register, a component's worth of findings, a chart's points, a picker. A test
walks the document and fails a declared limit that is not one of them.

Ceilings vary by list. Which list allows what is a judgment about each list.

## Sorting and filtering

Filters are named fields with fixed meanings, bound as parameters.

Sorting was refused outright and is now permitted (REQ-66). A value in a query
can be bound as a parameter; a column name cannot, so a sort column arriving from
a query string becomes part of the statement.

| Rule | |
|---|---|
| Six keys, each selecting an expression stored beside it | The key a caller sends is a lookup and never the value |
| Nothing else reaches the statement | No derivation from the parameter, no mapping that falls through, no default that is the parameter |
| The direction is one of two words written here | Not a word that arrived |
| A key that misses answers in the list's own order | An unknown sort is a mistake about a list, not a reason not to show it |
| The issue table is joined only where the chosen order needs it | The ordinary page still reads one covering index |

This also prevents a sort exposing a column the caller was never meant to order
by.

## Issue-keyed and cross-product reads

**One page answers for an issue** (REQ-64): every product, build and component it
sits at, with how far it has been decided in each.

| Rule | Reason |
|---|---|
| One row per build and component, not per place | The same component in two builds is two things shipped; sixty places of it in one build is one piece of work with a count |
| How far it is decided uses the findings list's own expression | Two screens with two definitions of "decided" come to disagree in front of somebody |
| No new visibility rule, but the narrowing is in the query | A page spanning products is where filtering afterwards gets forgotten, and the count leaks even when no row is shown |
| The search box lands here, with no product picked | An issue by name spans products by construction. Which of the two searches it is is decided by asking the server, not by the shape of the text |

**The findings list spans products too**, at `/v1/findings` with no product in
the path: one row per product, issue and component, with the same filters, sort
allowlist and paging.

Every product's own triage line applies per row from that product's own column
rather than from one number chosen for the page. `severity` raises the line for
the whole page and never lowers it below what a product decided; `below_floor`
turns every line off.

The filters belonging to one build are not offered rather than answered from
whichever build sorted first: `beneath` walks one build's edges, and `differs` is
a statement about a selection of builds. Everything else is one struct shared by
both endpoints.

Still per product: the dependency tree, the inventories, and the list of work
nobody owns.

## Path version

`/v1` is the shape the API will have. Before the first release it is not a
compatibility promise, and a change to a shape is an edit rather than a second
version standing beside the first.

## Declared privileges

Each operation carries a structured statement of what it asks of a caller
(REQ-62).

| Field | Holds |
|---|---|
| Scope | The deployment, a product, yourself, any recognized credential, or answered without one |
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

**Every gate is swept.** A test walks the document the server builds and asks
each gated operation as somebody holding none of its roles; a 2xx fails it.

**A gate refuses an operation declaring neither scope nor roles.** An endpoint
added without one is not broken, it is undocumented.

**The privileges page keeps only what a per-endpoint line cannot carry**: what
each role means, how roles are granted, what a declaration is and is not, and
that seeing is never changing. Two rules in it are not roles and cannot be
granted: visibility narrows every answer, and the proposer of a claim may never
approve it.

## Representation

Text written by people comes back as markdown, as the only representation. There
is no markup representation and no parameter requesting one.

A caller receives the source and renders it themselves. The server has already
refused what its policy forbids at submission (REQ-67), so the text is known-good
under the rules in force when it was written; rules written since are the
renderer's to apply. The rules are in `DESIGN-text.md`.

## Limits

- **The declaration is not the check.** What an operation states is what a caller
  may rely on being asked; the asking is a line in the handler. Where a narrower
  check was written than the operation declares, the two disagree and nothing
  fails. Making the decorator enforce its declaration was refused: a check running
  before the handler would answer 403 and tell a guesser the thing exists.
- **The gate sweep is a floor, not a proof.** A refusal for the wrong reason
  passes it, and it says nothing about what a narrowed operation puts in its
  answer.
- **A note states something the scope does not, or is omitted.** Three said the
  opposite of the value beside them, the worst being an operation answered
  without a credential that declared it required one.
- **Paging is `limit` and `offset`, with a total.** A cursor is better under
  concurrent writes and worse for jumping to a page. The total is separate from
  the page because somebody deciding whether to start work needs to know how much
  there is.
- **A list answers with an object, not an array.** An array at the top level has
  nowhere to put the total.
- **Names in paths, identifiers in bodies.** A product, stream and variant are
  what somebody typing a request knows and what a pipeline has in its
  configuration. A decision is numbered because it has no name.
- **A place in a path is the identity the findings list gave out**, not something
  a caller composes. A caller free to name a place would be choosing which
  decisions apply where.
- **Comment density in this layer is low by design.** It is a registration and a
  mapping: the operation is declared, a store is called, its answer becomes a
  body. What is worth explaining about a rule belongs where the rule is enforced.
