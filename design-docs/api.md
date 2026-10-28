# The HTTP API

The one surface: everything a person or a pipeline does goes through it, and the
web interface is a client of it.

Satisfies REQ-61, REQ-62, REQ-63, REQ-65, REQ-67, REQ-76, REQ-86.

Status codes and refusals are `design-docs/api-refusals.md`; paging, sorting,
filtering and cross-product reads are `design-docs/api-lists.md`.

## Contents

- [No private half](#no-private-half)
- [Document generation](#document-generation)
- [Unauthenticated surfaces](#unauthenticated-surfaces)
- [Operation descriptions](#operation-descriptions)
- [Declared privileges](#declared-privileges)
- [Path version](#path-version)
- [Former upload addresses](#former-upload-addresses)
- [Representation](#representation)
- [Addresses and labels](#addresses-and-labels)
- [File organization](#file-organization)
- [Limits](#limits)

## No private half

No endpoint is reserved for the web interface (REQ-61). The interface uploads a
scan through the pipeline's endpoint, as a testing convenience and no second
contract.

## Document generation

The OpenAPI document is produced from the route definitions (REQ-61); the
published copy is checked in, and the build fails when it has drifted.

| Rule | Reason |
|---|---|
| A closed vocabulary is its domain package's list, never a literal at the route | A copy accepts what the store refuses, or the reverse |
| A subset is a named rule in the domain package | A single decision offers what a person may propose and a bulk decision less; trimmed at the route, the omission is an accident |
| A test walks the document the server builds and holds every enum to a domain list, in its order; a reordered or shortened copy, a new literal, and an entry no enum offers each fail | The enums no domain package owns are named in the test: export formats, a register's two sides, a CVE record's statuses, a commit lookup's answer, an upload's answer and a subject's kind |
| Every list names every constant of its type; a constant no route offers, such as no narrowing at all, is named in the test as set apart | An omitted constant is a word every route refuses |
| A stated list is never a literal enum tag, and a source check fails one | |
| The schemas worked out from the code are shared by every API one process builds, under one lock | They are 8.4 ms of the 17.8 ms an API costs, and the registry is not safe for concurrent use |
| Each API holds its own copy of the top-level schemas; what lies beneath is shared | Registering writes a link into a body's top-level schema only where absent |

## Unauthenticated surfaces

The application serves no documentation of its own (REQ-63). Five surfaces
answer without a credential, written out so a new route adds no exception.

| Surface | Answers |
|---|---|
| `/healthz`, `/readyz` | Whether the process is up, and whether it reaches its database |
| `/v1/sign-in` | The providers an operator configured, for a button per provider |
| `/v1/sign-in/…` | Redirects to a provider, or refuses. It reads and writes only the sign-in key, the session, and the account a first arrival needs, and a route added here is checked against that |
| The interface | The built assets, which hold no data. A path naming a directory of them answers with the page, never a listing |
| `/.well-known/csaf/…`, `/openvex/…` | The security documents of the products an administrator chose, once an operator turns publishing on, read as anybody at all. No credential is looked at, GET and HEAD are the only methods, and a deployment publishing nothing answers every path as unpublished (`design-docs/publishing.md`) |

The published documents are not in the API document; their shapes and paths are
the standards', found from the provider description.

## Operation descriptions

Summaries and descriptions follow `AGENTS.md` § The published API document.

| Rule | Reason |
|---|---|
| The first sentence states what the operation does | |
| Reasoning and decision identifiers are excluded | No caller has `REQUIREMENTS.md` |
| Every parameter carries its own description | |

## Declared privileges

Each operation carries a structured statement of what it asks of a caller
(REQ-62).

| Field | Holds |
|---|---|
| Scope | The deployment, a product, yourself, any signed-in person, any recognized credential, or answered without one |
| Roles | Any one of which is sufficient |
| Note | Only something the scope and roles do not say; it neither restates nor contradicts them, or it is omitted |

| Kind | Behavior |
|---|---|
| Gate | Refuses a caller holding none of its roles |
| Narrowed | Answers everybody; the roles decide the contents, and a stranger gets an empty list or a count of zero |

| Rule | Reason |
|---|---|
| The line in the description is rendered from the declaration | Two hand-written copies disagree |
| The line states the scope and the roles, a scope the middleware enforces whatever roles are held coming after the roles | A pipeline key holding every listed role is not told it may call a person-only operation |
| A declaration states whether it is a gate or narrowed | Each misread as the other hides a hole or invents one |
| A test asks each gated operation as somebody holding none of its roles, and a 2xx fails it | |
| An operation declaring neither scope nor roles is refused by a gate | |
| "Any signed-in person" and "any recognized credential" are two scopes | A pipeline key is not somebody; two operations take any credential, a key reading back the scans filed on a build it may upload to and their receipts |
| The part of a declaration about the subject alone is enforced before any handler; a role on a product stays in the handler | The role needs the product resolved |
| The privileges page holds only what a per-endpoint line cannot: what each role means, how roles are granted, what a declaration is, and that seeing is never changing | Two rules there are not grantable: visibility narrows every answer, and a decision's proposer never approves it |

## Path version

`/v1` is the shape the API will have. Below 1.0 it promises no compatibility
(REQ-76), and a changed shape is an edit, never a second version.

## Former upload addresses

The SBOM upload, the list of a build's SBOM uploads and the read of what one
upload changed also answer under
`/v1/products/{product}/streams/{stream}/variants/{variant}/scans`, where
pipelines called them before the rename (REQ-86). Every other former path
answers as no route, apart from `GET /v1/decisions/{id}`, which answers one
decision.

| Rule | Reason |
|---|---|
| A former address is the same operation registered a second time, taking that operation's parameter names | Declaration, admission, handler and receipt are one |
| The published document leaves a former address out | A new integration finds one path |
| Nothing marks a former address deprecated, and no removal is planned | Every build script calls it |
| A test sends each request to both addresses and compares the answers | |

## Representation

| Rule | Reason |
|---|---|
| Text written by people comes back as markdown, the only representation, with no parameter asking for markup (REQ-65) | The server refused what its policy forbids at submission (REQ-67); later rules are the renderer's (`design-docs/text.md`) |
| A moment is stated in UTC, in RFC 3339, in a response and a file alike, converted before writing | A driver hands back the process's zone, so a literal `Z` would lie |
| A day is the UTC day of its moment, in a response, a report and an export | |
| Every moment goes through one renderer, and a test refuses an API body carrying a time value for the encoder | |
| A moment not known is left out, its field optional, never the year 1 or an empty string | |
| A published document states its dates as its format requires, in UTC | |

## Addresses and labels

A product, a person and a team each answer to an address that resolves it and a
label somebody declared to read.

| Rule | Reason |
|---|---|
| A field a write resolves carries the address, with the label beside it | A label in that field cannot be sent back: a collaborator listed by display name cannot be removed, and `Acme Router` withdraws nothing on `acme-router` |
| A name in a path is the address | Folding only lowercases and trims |
| A field naming a person carries the sign-in identity; one naming a product, branch or tag, variant or team carries its name | A screen matches the viewer's identity, and a caller builds paths from names |
| A label is the field's name suffixed `_name`: `proposed_by_name`, `product_name`, `branch_or_tag_name`, `team_name` | |
| A person's or a team's label is absent where it repeats the address | "No display name" and "the same again" differ |
| A product's, a branch or tag's and a variant's label is always present, the name standing in for a missing display name, read with one helper | |
| The holder of work is a person's identity or a team's name, beside `person_name` | |
| Every listing a person reads by name carries both: collaborators, roles, credentials, bindings, tokens, assignment rules; others gain a label as a screen needs it | |
| The pipeline-key and personal-token lists leave a product's label off where it repeats the name | |
| A file carries a label as a column beside the name: the administration trail the person; the running-out file the product, build and holder; the repeated-deferral and audit files the product; the review-queue file the product and proposer; the reader's own decisions the product, branch or tag and variant | |

## File organization

One description, registered from one area per thing somebody works on.

| Area | Operations |
|---|---|
| Uploads arriving | Uploads, their receipts, the documents a build sent, one scanner run |
| Findings | The findings lists, one finding, entered findings, disclosure, issue notes, one issue, the component graph, collaborators, reports from outside and rulings on them |
| Handing work out | Assignment, assignment rules, teams, labels, bulk acts, planned upgrades, one component |
| Decisions | The review queue, proposing, approving, re-affirmation, comments, incidents, response windows, assessments, scrutiny, readiness |
| Analytics | Trends, comparisons, the compliance register, coverage, measures, effort, the audit, and each list's export |
| Advisories | Advisories, VEX, supplier imports, the suppliers read on a schedule, outbound destinations |
| Administration | The catalog, people and their roles, role bindings, keys, tokens, settings, the trail, failed jobs, saved filters, notifications, the caller's own session |

| Rule | Reason |
|---|---|
| The top holds the router, the middleware before every route, sign-in and the served interface | |
| Areas share one common layer and import nothing of each other, test files included, and a test fails one that does | Each builds and tests alone |
| Each area is one test binary with its own database, over one shared harness | 39 s for the API's tests on four engines on twelve cores, against 107 s as one binary |
| Every area registers into the one description | A method and path claimed twice is caught across areas |
| A source check over every area fails when it finds nothing: the registration count, a trail filter's struct tags, the exact-status rule on refusals | |
| Each area checks its own refusal mappers, and a check at the top fails an area declaring a mapper with no such check | A mapper is private to its area |
| Within an area, one file per subject, a subject being a noun somebody acts on, never a count of lines | |
| The authorization primitives sit beside the declarations they enforce | |

## Limits

| Limit | Detail |
|---|---|
| Half the declaration is the check | A role on a product stays a line in the handler, where a narrower check disagrees with the declaration and nothing fails; checked centrally, a 403 before the handler would tell a guesser the thing exists |
| The gate sweep is a floor, never a proof | A refusal for the wrong reason passes, and a narrowed answer's contents are unchecked. It counts both gated scopes apart, since one alone skips the administrator gates |
| Names in paths, identifiers in bodies | A product, branch or tag, and variant are what a pipeline's configuration holds; a decision has no name |
| A removal takes something out of use, never out of the database | A team, an assignment rule, an outbound destination and a variant are each reached by `DELETE` and keep their row, which findings, decisions and shipped documents name |
| An amendment leaves out what it does not change, and naming nothing is refused | Absent and cleared differ where a field has a default |
| An occurrence in a path is the identity the findings list gave out | A composed one would choose which decisions apply |
