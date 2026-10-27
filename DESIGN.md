# Design

Where each design contract is written. Read the row, then the one document it
names. Each document lists the decisions it satisfies; `REQUIREMENTS.md` says why.

## Model and findings

| Document | Covers | Terms |
|---|---|---|
| [data-model](design-docs/data-model.md) | What a scan is filed against and the structures it produces | product, branch or tag, variant, build, component identity, dependency graph, the fold, occurrence identity, intervals, inventory delta |
| [findings](design-docs/findings.md) | What a scan found, where it sits, how it is ranked and closed | fan-out, issue identity, report merging, match methods, recorded flaws, scoring, urgency, closure reasons, authority of a run, severity ladder, rating in force |
| [kinds](design-docs/kinds.md) | Kinds of finding and what each declares | issue kinds, name resolution, consumers, runs and series, source locations |

## Intake

| Document | Covers | Terms |
|---|---|---|
| [ingest](design-docs/ingest.md) | A scan from arrival to application | upload, arrival decision, document storage, retention, formats read, scanner output, receipts, administrator VEX, supplier advisories, offline scanner database, CVE records |
| [analysis](design-docs/analysis.md) | Static analyzer runs uploaded as SARIF | run contents, placement, code finding triage, code finding queue, weakness families, flaw records, third-party code, upload client |
| [upstream](design-docs/upstream.md) | Trusting a forked project's published VEX | trusted upstreams, statements applied, offers for review, declined statements |

## Triage and remediation

| Document | Covers | Terms |
|---|---|---|
| [triage](design-docs/triage.md) | What people decide about findings, and when a decision stops applying | decision identity, expiry, outcomes, approval, rights, bulk decisions, review queue, extensions, minimum severity, issue assessments, reach across builds, re-affirmation, lapse |
| [remediation](design-docs/remediation.md) | Declared fix intent and whether it arrived | planned upgrades, resolution, deadlines, version ordering, promise states, advisory, CSAF document, VEX document, issuance, provider directory |
| [incidents](design-docs/incidents.md) | A regulator's questions after an incident | stored facts, response windows, notices, fix releases, the shelf |

## Access and the API

| Document | Covers | Terms |
|---|---|---|
| [access](design-docs/access.md) | Who a request is, and what it may see and do | roles, internal visibility, breadth of view, refusals, teams, assignment rules, provider sign-in, trusted-header sign-in, group matching, grant grid, personal tokens, sessions, request forgery |
| [api](design-docs/api.md) | The HTTP API's shape | document generation, status codes, refusal shape, paging, sorting, path version, former upload addresses, representation |

## Output

| Document | Covers | Terms |
|---|---|---|
| [analytics](design-docs/analytics.md) | Figures and what each counts | counting unit, trends, build comparison, release note, deadline compliance, release readiness, disposition register, exports |
| [notifications](design-docs/notifications.md) | What a person is told, through which channel, and when | events, conditions, mentions, report audience, digest, mail, outbound HTTP, chat, embargo notices |
| [publishing](design-docs/publishing.md) | Security documents served without signing in | advisories served, statements, CSAF VEX, OpenVEX, revisions, digests and signatures, publishing pass |

## Interface and text

| Document | Covers | Terms |
|---|---|---|
| [interface](design-docs/interface.md) | The web interface and how it reaches the server | routing, generated client, the shell, findings list, filters, saved filters, finding screen, decision form, review queue, editor, keyboard, screen copy |
| [text](design-docs/text.md) | Text people write, and where it is checked and rendered | markdown policy, raw markup, link schemes, issue references, refusals, code block language tags, bounds |
| [attachments](design-docs/attachments.md) | Files on an issue or a report | references in text, fetch authorization, storage, delivery, quota and removal |

## Platform

| Document | Covers | Terms |
|---|---|---|
| [database](design-docs/database.md) | Engines, migrations, locking and portability | supported engines, engine-specific code, migrations, identifier quoting, affected-row counts, retryable transactions, reads a write depends on, bulk inserts, indexes |
| [queue](design-docs/queue.md) | Background work as rows in the application's database | job structure, exclusive handout, failure handling, leases, backlog refusal |
| [build](design-docs/build.md) | Repository layout, the gate, and what stops a change reaching `main` | make targets, gate tiers, CI jobs, test databases, tool pins, static analysis, licenses, self-inventory |
| [packaging](design-docs/packaging.md) | The container image, the Helm chart, and releases | image structure, bundled scanner, pod sizing, configuration sources, network policy, secret sources, signing and provenance, release procedure |
