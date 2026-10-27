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
scan through the endpoint a pipeline uses, as a testing convenience and no
second contract; an interface with endpoints nobody else has is a security
boundary nobody designed.

## Document generation

The OpenAPI document is produced from the route definitions (REQ-61). The
published copy is checked in, and the build fails when it has drifted.

| Rule | Reason |
|---|---|
| A closed vocabulary is the owning domain package's list, never a literal beside the route | Retyped at a route, a word added to the domain is stored and refused, and each copy may differ |
| A subset is a named rule in the domain package | A single decision offers what a person may propose there and a bulk decision less again; shortened at the route, the omission is an accident |
| Every word of a held vocabulary is checked against the list owning it, by walking the document the server builds | Asked of a hand-kept list, it checks only that two copies match |
| Every enum in the document is held to a list, in the owner's order; a reordered or shortened copy, a new literal, and an entry no enum offers each fail | The few enums no domain package owns are named in the test as a format's or a route's own words: export formats, a register's two sides, a CVE record's statuses, a commit lookup's answer, an upload's answer and a subject's kind |
| Every list names every constant of its type | A constant the store writes and the list omits is a word every route refuses. A constant no route offers, such as no narrowing at all, is named in the test as set apart |
| A stated list is never a literal enum tag | A source check fails one whose words a domain package states |
| The schemas worked out from the code are shared by every API one process builds, under one lock | Working them out is 8.4 ms of the 17.8 ms an API costs, and every build registers the same operations. The registry is not safe for concurrent use |
| Each API holds its own copy of the top-level schemas; what lies beneath is shared | Registering writes a link into a body's top-level schema only where absent, so a shared copy leaves the second API without it |

## Unauthenticated surfaces

The application serves no documentation of its own (REQ-63). No product,
finding, issue, person or credential is readable without a credential except
through the published security documents, which are off until an operator turns
them on and then limited to the products an administrator chose.

Five surfaces answer without a credential, written out as a list so a new route
never adds an exception.

| Surface | Answers |
|---|---|
| `/healthz`, `/readyz` | Whether the process is up, and whether it reaches its database |
| `/v1/sign-in` | The providers an operator configured, so a sign-in page can draw a button per provider |
| `/v1/sign-in/…` | Redirects to a provider, or refuses. It reads and writes only its own machinery: the sign-in key, the session, and the account a first arrival needs. A route added here is checked against that |
| The interface | The built assets, which hold no data. A path naming a directory of them is answered with the page, never a listing |
| `/.well-known/csaf/…`, `/openvex/…` | The security documents of the publishing products, read as anybody at all. No credential is looked at, GET and HEAD are the only methods, and a deployment publishing nothing answers every path as one nothing is published at (`design-docs/publishing.md`) |

The published documents are not in the API document: their shapes and paths are
the standards', and a reader finds them from the provider description.

## Operation descriptions

Summaries and descriptions follow `AGENTS.md` § The published API document.

| Rule | Reason |
|---|---|
| The first sentence states what the operation does | Opening with the argument leaves the answer unsaid |
| Reasoning and decision identifiers are excluded | They live here and in `REQUIREMENTS.md`, which no caller has |
| Every parameter carries its own description | An undocumented required parameter is guessed at |

## Declared privileges

Each operation carries a structured statement of what it asks of a caller
(REQ-62).

| Field | Holds |
|---|---|
| Scope | The deployment, a product, yourself, any signed-in person, any recognized credential, or answered without one |
| Roles | Any one of which is sufficient |
| Note | Only where a rule is not a role, and never saying the opposite of the scope |

| Kind | Behavior |
|---|---|
| Gate | Refuses a caller holding none of its roles |
| Narrowed | Answers everybody; the roles decide what is in the answer, and a stranger gets an empty list or a count of zero |

| Rule | Reason |
|---|---|
| The line in the description is rendered from the declaration | Two hand-written copies disagree, and a wrong permission is worse than none |
| The line states the scope and the roles; a scope the middleware enforces whatever roles are held is said after the roles | A pipeline key holding every listed role is not told it may call an operation only a person may |
| A declaration states whether it is a gate or narrowed | Read as a gate, a narrowed operation looks unchecked; read as narrowed, a gate hides a hole |
| Every gate is swept: a test asks each gated operation as somebody holding none of its roles, and a 2xx fails it | |
| An operation declaring neither scope nor roles is refused by a gate | |
| "Any signed-in person" and "any recognized credential" are two scopes | A pipeline key is not somebody. Two operations mean any credential: a key reads back the scans filed on a build it may upload to, and their receipts |
| The part of a declaration about the subject alone is enforced before any handler; a role on a product stays in the handler | The handler's check is then a second statement of the rule. The role needs the product resolved |
| The privileges page holds what a per-endpoint line cannot: what each role means, how roles are granted, what a declaration is, and that seeing is never changing | Two rules there are not roles and cannot be granted: visibility narrows every answer, and a decision's proposer never approves it |

## Path version

`/v1` is the shape the API will have. Below 1.0 it promises no compatibility
(REQ-76), and a changed shape is an edit, never a second version beside the
first.

## Former upload addresses

The SBOM upload, the list of a build's SBOM uploads and the read of what one
upload changed also answer under
`/v1/products/{product}/streams/{stream}/variants/{variant}/scans`, the address
pipelines called before the paths were renamed (REQ-86). Every other renamed
path answers at its own address alone, and a former one answers as no route,
apart from `GET /v1/decisions/{id}`, which answers one decision.

| Rule | Reason |
|---|---|
| A former address is the same operation registered a second time | Declaration, admission before the body is read, handler and receipt are one |
| The published document leaves a former address out | A new integration finds one path, and the generated client one call |
| Nothing marks a former address deprecated, and no removal is planned | Every build script calls it |
| A former address takes the parameter names of the operation it stands for | A caller sends values and never sees a name |
| A test sends each request to both addresses and compares the answers | The same refusal, receipt and list |

## Representation

| Rule | Reason |
|---|---|
| Text written by people comes back as markdown, the only representation, with no parameter asking for markup (REQ-65) | A caller renders it. The server refused what its policy forbids at submission (REQ-67), so the text is known good under the rules of its time; later rules are the renderer's (`design-docs/text.md`) |
| A moment is stated in UTC, in RFC 3339, in a response and a file alike | A driver hands back a time in the process's zone, so it is converted before writing, never formatted behind a literal `Z` |
| A day is the UTC day of its moment, in a response, a report and an export | |
| No API body carries a time value for the encoder to write, and a test refuses one | Every moment goes through one renderer |
| A moment not known is left out; such a field is optional, never the year 1 or an empty string | |
| A published document states its dates as its format requires, in UTC | |

## Addresses and labels

A product, a person and a team each answer to two strings: the address that
resolves it, and the label somebody declared to read.

| Rule | Reason |
|---|---|
| A field a write resolves carries the address, and the label goes beside it | A listing publishing the label in the address's field cannot undo what it listed: a collaborator listed by display name cannot be taken off, and a role on `acme-router` listed as `Acme Router` withdraws nothing |
| A name in a path is the address | Folding only lowercases and trims, so a label matches no row |
| A field naming a person carries the sign-in identity | A screen matches it against the viewer's own identity |
| A field naming a product, a branch or tag, a variant or a team carries its name | A caller builds a path from what it was handed |
| A label is the field's name suffixed `_name`: `proposed_by_name`, `product_name`, `branch_or_tag_name`, `team_name` | One suffix, found without reading each description |
| A person's or a team's label is absent where it repeats the address | "No display name" and "the same again" read differently |
| A product's, a branch or tag's and a variant's label is always present: the display name, or the name where there is none | One rule on every endpoint, read with one helper, so a build is named alike everywhere |
| The holder of work is a person's identity or a team's name, beside `person_name` | The holder's own list resolves it |
| Every listing a person reads by name carries both: collaborators, roles, credentials, bindings, tokens, assignment rules | A label beside a name is additive, so other fields gain one as a screen needs it |
| The pipeline-key and personal-token lists leave a product's label off where it repeats the name | |
| A file carries a label as a column beside the name | The administration trail names the person; the running-out file the product, the build and the holder; the repeated-deferral and audit files the product; the review-queue file the product and the proposer; the reader's own decisions the product, the branch or tag and the variant |

## File organization

The API is registered into one description from one package per area somebody
works in.

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
| An area reaches the rest only through one shared package, and areas import nothing of each other, test files included; a test fails one that does | Each builds and tests alone |
| An area's tests sit beside it over one shared harness, one test binary per area with its own database | 39 s for the API's tests on all four engines on twelve cores, against 107 s as one binary |
| Every area registers into the one description | A method and path claimed twice is caught across areas |
| A check over the source reads every area and fails when it finds nothing | The count of registrations, a trail filter's struct tags, the exact-status rule on refusals |
| Each area checks its own refusal mappers; a check at the top fails an area declaring a mapper and running no such check | A mapper is private to its area |
| The authorization primitives sit beside the declarations they enforce, in the shared package | A privilege ladder split across unrelated files is hard to audit |

## Limits

| Limit | Detail |
|---|---|
| Half the declaration is the check | The scope is enforced before any handler. A role on a product stays a line in the handler, where a narrower check disagrees with the declaration and nothing fails. Enforcing it centrally would answer 403 before the handler and tell a guesser the thing exists |
| The gate sweep is a floor, never a proof | A refusal for the wrong reason passes, and it says nothing of what a narrowed answer holds. It walks both gated scopes and counts them apart, since one alone skips the administrator gates |
| Names in paths, identifiers in bodies | A product, branch or tag, and variant are what a pipeline's configuration holds. A decision is numbered because it has no name |
| A removal takes something out of use, never out of the database | A team, an assignment rule, an outbound destination and a variant are each reached by `DELETE` and keep their row, which findings, decisions and shipped documents name |
| An amendment leaves out what it does not change, and naming nothing is refused | Absent and cleared differ wherever a field has a default |
| An occurrence in a path is the identity the findings list gave out | A caller composing one would choose which decisions apply where |
