<picture>
 <source media="(prefers-color-scheme: dark)" srcset="assets/openpsirt-logo-dark.svg">
 <img alt="OpenPSIRT" src="assets/openpsirt-logo.svg" width="180">
</picture>

# OpenPSIRT

Track vulnerabilities in the products you ship.

OpenPSIRT takes in the inventory a build produced, scans it for known
vulnerabilities, works out what changed release to release, and gives people
somewhere to triage what it finds and follow it through to a fix.

!!! note "Alpha"
    Every version below 1.0 promises nothing about the API or the schema, and
    an upgrade may mean recreating the database. What is here describes the
    system as it is being built, and changes as it is.

## Scope

- Takes in inventories pushed by build pipelines, in CycloneDX or SPDX form,
  along with the suppressions the build carries patches for
- Runs the scan here, not in the build, so every product is measured against
  the same scanner and the same vulnerability data
- Keeps the dependency graph, so you can see why a vulnerable component is
  present and which part of the product pulled it in
- Tracks change over time per release, and works out why a finding disappeared
  rather than guessing
- Carries triage decisions forward, so a nightly scan does not reset the work
- Rescans shipped releases, so a vulnerability published after a release still
  gets found
- Reports on what was fixed between releases, what was dismissed and why, what
  is running out of time, and whether the team is keeping pace

## Out of scope

- Generate SBOMs — your build does that
- Work out what is in a product — the component list always comes from the build
- Build or deploy fixes

## Builds over time

A build's inventory moves every night. Each move is recorded as what it did to
the findings and to the judgments standing on them.

| When a build changes | What is recorded |
|---|---|
| An upload arrives | A receipt naming the components it added, removed and moved. An upload that moves more of the build than the deployment allows is raised |
| A component's version moves | The finding at the old version closes as upgraded, or as superseded where the issue came with it. The new finding records the version it arrived from |
| The version moves and the fix does not arrive | The finding is marked as an incomplete upgrade |
| The shipped version changes and the upstream one does not | The finding closes as revised, which is what a carried patch looks like from outside |
| A component leaves the build | Its findings close as removed |
| The scanner stops reporting something present and unchanged | The finding closes as unexplained, and that is flagged at any volume |
| The vulnerability data moves | The scheduled rescan finds it, in shipped releases as well as current ones |
| A judged component moves version | A judgment about risk lapses and returns to triage. A claim that the scanner matched the wrong thing stands |
| Another release or variant ships the same code | The judgment already made there applies |
| A fix is declared for a set of releases | The next scan of each release says whether it arrived |

| Cost | |
|---|---|
| A finding is a component at one place | One switch image is 335,021 findings, 305,487 of them one kernel across 62 modules. Tracking at that grain is heavier per build than tracking per package, and it is what lets a judgment be true in one place and not another |
| A finding is stored once | With when it opened and when it closed, never once per scan |
| Nightly branch scans are transient | Tagged releases are retained |

## Features

What the tool is specified to do. [Current state](built.md) says how far
each area has got, and [REQUIREMENTS.md](https://github.com/nexthop-ai/openpsirt/blob/main/REQUIREMENTS.md) carries the reasoning
behind every line of it.

### Ingest

- Inventories arrive from the build, in CycloneDX, SPDX 2.x or SPDX 3.x form,
  one adapter per producer. A vulnerability report or a third party's VEX
  document may be uploaded alongside. The document says which format it is and
  the reader is chosen from that, so one upload takes any of them
- An upload is accepted, queued and answered later. A scan applies whole or
  changes nothing, and only a scan newer than the state it replaces is taken
- Releases and variants are declared before a scan may name one, so a
  misspelled release is rejected rather than quietly created
- Identity is derived from content. Nothing a scan file supplies is trusted to
  be stable between builds or consistent between producers
- Sized against the largest real input rather than the average: one pipeline
  spans a thousandfold, and nightly branch scans are transient where tagged
  releases are retained and can be fetched back

### Scanning

- The deployment runs the scan, on a schedule, for everything it tracks — so
  every product is measured against the same scanner and the same vulnerability
  data
- The component list always comes from the build. We re-scan; we do not
  discover
- A build's own suppressions are applied and never re-decided
- The scanner, its vulnerability database and the exploitation feeds all work
  with no network, so a scan answers the same way twice and no content network
  sits in the path it is available through. An air-gapped install uses the same
  path as any other
- Every finding records what produced it — which scanner, which version, which
  database, and how the match was made
- OpenPSIRT publishes an inventory of itself, of the binary and of the image,
  and scans itself with them

### The tracked unit

- The tracked unit is a product, a branch or tag, and a variant. A release
  carries a reversible end-of-life date, past which nothing is deleted or
  hidden
- The dependency graph is kept as nodes and edges and walked when asked, never
  flattened: one shared library was 49,170 flattened paths against 48 direct
  consumers
- A finding is one component at one place in one build. Twelve places is twelve
  findings, and grouping is presentation only
- An issue is one issue across every name it goes by, and everything each
  report said about it is kept rather than overwritten
- A flaw in our own product is recorded by hand, under an identifier this
  deployment mints, against every build that ships it

### State and history

- Change over time is a primary query, not an audit log read backwards
- Findings open and close themselves as scans change, every closure records
  why, and a disappearance nobody can explain is flagged at any volume
- Triage history is append-only: records are written and never edited or
  removed, and each is written in the same transaction as the act it describes.
  The database is trusted, and nothing defends against somebody editing rows
  directly
- Administrative changes record who changed what from what, and what a scan
  observed is never merged with what a person declared

### Triage

- One outcome from a fixed set: affected, not applicable, deferred, will not
  fix, already fixed here, and the two that promise work
- Dismissing something needs a written explanation and a second person's
  approval. The proposer and the approver are never the same person, with no
  override; short deferrals are exempt up to a cumulative threshold the
  deployment sets
- A decision survives re-scans, lapses only when the software changes, and
  carries automatically to other releases, tags and variants whose chains and
  versions already match
- One judgment covers every place a finding sits by default; narrowing it is
  deliberate
- Bulk triage is one action across many issues at a component, bounded by a
  configurable cap, recording how the set was chosen
- An approver works at the unit the proposer acted at, approves, sends back or
  undoes a batch as one act, and an approval points at one revision of the
  justification — editing the text withdraws it
- What is recorded against an issue — a rating that disagrees with the
  published one, or a note for whoever decides — belongs to one product,
  applies to every build of it, and does not lapse when a version moves. Two
  products may record different things about the same issue
- A third party's judgment is evidence, never a decision. The build's
  suppressions and a supplier's VEX are shown and offered as a prefill
- A deployment says what it considers worth triaging and a product may say
  something narrower. Below the line a finding is still recorded, counted and
  reportable, and any list that hides something says how much

### Ranking and remediation

- One urgency orders the queue, worked out from severity, known exploitation,
  exploitation likelihood, and whether the component reaches customers
- Deadlines are set by policy from that urgency. Being overdue is reported,
  never acted on automatically
- Work is assigned to a person or to a team. A team queue is picked out of
  rather than held, work nobody holds is routed to a team by standing rule, and
  a human assignment always wins
- A fix is declared as the set of releases it targets, and resolution is
  computed from later scans rather than declared done
- Hand-off to an external tracker is optional and off by default. This does not
  replace anybody's issue tracker

### Disclosure and advisories

- A flaw recorded here starts undisclosed, carrying a disclosure date that
  defaults to 90 days from when the report was received. Reaching it escalates
  rather than publishes
- Extending that date costs a reason and, past a threshold, a second person —
  and it is raised before the date rather than on it
- Disclosure makes the whole record public: comments, decisions, actors. People
  writing in the record know that from the first word
- An advisory is generated as a CSAF document about flaws in our own product,
  and a VEX document per build from approved dismissals. Generating is all it
  does — nothing is sent anywhere, because a published advisory belongs to
  whoever publishes it

### Access and permissions

- Sign-in is federated — OIDC, GitHub or a trusted header — and no account is
  created for anybody nothing authorized in advance. Where roles are derived
  from identity-provider groups, that mapping is the advance grant: somebody it
  covers is recorded on their first arrival, and somebody in no mapped group is
  refused exactly as a stranger is
- Roles are granted per product; administration is global. A product somebody
  holds no role on is invisible to them: not listed, not counted
- Visibility is enforced in the data-access layer, with a required subject,
  covering counts, aggregates, search and exports rather than row reads alone
- One person can be brought into one undisclosed case without being granted the
  product it sits in
- Machine credentials are their own subject type: scoped, ingest-only,
  rotatable, and able to read back only their own uploads
- Losing a role hands back the work it carried, because an identity provider
  never tells us an account was disabled

### Notifications

- Immediate mail only for something a person must act on. Everything else is a
  digest, off until somebody asks for it
- Nothing leaving this deployment about an undisclosed finding carries detail —
  not the identifier, not the component, not the summary. That there is
  something, and a link
- Every channel sits behind one interface, and delivery is queued and retried.
  Email is required; chat adapters are not built
- Operational alerts are their own category: condition-based ones clear
  themselves, event-based ones are acknowledged

### Reporting

- Any two releases can be compared — fixed, newly present, still present — in a
  form that goes into release notes
- Any list that can be read can be exported as CSV or JSON, through the same
  visibility rules the list was read with, carrying the filters of the screen
  it came from
- Scan coverage is reportable: what is being scanned, when each artifact was
  last seen, and what has gone stale
- Dismissals, deadlines, approvals and how long triage is taking are reportable
  in their own right, including the exception report that should come back
  empty
- Trends are plotted on the axis the subject has: calendar time for a branch,
  release over release for tags

### Interface and API

- REST and JSON, with the OpenAPI document generated from the code and never
  hand-maintained. The web interface is a client of it, with no private
  endpoints
- Every operation declares what it asks of a caller, and a gate refuses one
  that declares nothing
- The dependency tree is browsable both ways: from a finding to where it sits,
  and from any node to the findings beneath it
- The findings list is one row per issue at a component, with the places under
  it — 335,021 rows for one image is not a list anybody reads — and it is the
  tool for building a batch
- One home page assembled from what the person holds, and one scope picker that
  narrows the whole interface. A screen that cannot answer at the chosen scope
  says so
- Every screen works on a phone, for reading and responding rather than bulk
  work
- Nothing a person typed is lost — not by a failed submission, a navigation, or
  an expired session

### Operation

- A container image and a Helm chart. A configuration that cannot work is
  refused at install time, naming what is missing
- Any number of replicas: no leader, no shared filesystem, and no state in one
  process that decides anything
- Four database engines are supported and tested: PostgreSQL, MySQL, MariaDB,
  and SQLite for development
- The application creates and migrates its own schema at startup, one instance
  at a time, so there is no migration step to run
- Untrusted input never becomes SQL, markup or a filesystem path, and text a
  scan file supplied is never rendered
- Markdown a person writes is policed on the server at submission: no raw HTML,
  restricted link schemes, and nothing fetched from anywhere when it renders
- Attachments are stored outside the database, in no public bucket, and every
  fetch is authorized against the finding it hangs off before any URL is issued
- Static analysis, vulnerability scanning, dependency review, secret scanning
  and a license check gate every change, and every finding reproduces locally
  with one documented command

## Next steps

| | |
|---|---|
| [Current state](built.md) | How far each area has actually got |
| [Evaluation](trying.md) | Standing one up to look at |
| [Build pipelines](pipeline.md) | A pipeline declares the target, mints a key and posts the inventory |
| [Configuration](configuration.md) | Every setting, and what reads it |
| [API reference](reference/api.md) | Every operation, generated from the server |
| [Privileges](reference/privileges.md) | Which role reaches which endpoint |

The reasoning behind every decision is in
[REQUIREMENTS.md](https://github.com/nexthop-ai/openpsirt/blob/main/REQUIREMENTS.md),
and the `DESIGN-*.md` documents beside it describe how each area works.
