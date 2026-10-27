# Design

Where each design contract is written. Read the row, then the one document it
names. Each document lists the decisions it satisfies; `REQUIREMENTS.md` says why.

## Model and findings

| Document | Covers | Terms |
|---|---|---|
| [data-model](design-docs/data-model.md) | What a scan is filed against, and the names it is declared under | vocabulary, product, branch or tag, variant, build, release date, end of support, catalog corrections, retirement, declaration before use, names, engine differences |
| [data-model-components](design-docs/data-model-components.md) | What a component is and how it is identified | component identity, container images, image versions, component references, upstream name, the fold, duplicate descriptions, qualifiers |
| [data-model-graph](design-docs/data-model-graph.md) | The dependency graph, its history, and occurrences | nodes and edges, root, intervals, inventory delta, comparison of two builds, occurrence identity, path traversal, recursive walks |
| [data-model-measurements](design-docs/data-model-measurements.md) | Benchmark runs behind the graph rules | inventory delta timings, a year of nightly scans |
| [findings](design-docs/findings.md) | What a finding is, the row a person reads, work across builds | fan-out, occurrence, fold, decision state on a row, partly decided, variants, spread, incomplete upgrade, total above a list |
| [findings-issues](design-docs/findings-issues.md) | One issue across its names, and what reports say about it | issue identity, aliases, filed name, merged issues, report contents, fix state, report merging, likelihood, issue dates |
| [findings-severity](design-docs/findings-severity.md) | Scores, severity bands, the rating in force, urgency | CVSS 3 and 4, vector, weaknesses, CWE, severity ladder, fold, rating in force, urgency signals, exploitation clock |
| [findings-components](design-docs/findings-components.md) | What is kept about a component beyond identity | interning, supplier, license, match method, by advisory, by identifier, dependency scope, derived addresses, references, index summary |
| [findings-patch-branches](design-docs/findings-patch-branches.md) | Which branches hold a patch commit | link shapes, cgit, repository copies, the pass, host share, git proxy, NAT64, cache quota, Patch branch lookups panel |
| [findings-closure](design-docs/findings-closure.md) | How runs open and close findings, and why each closed | scan as separate work, authority of a run, intervals, closure reasons, unexplained, disclaimed, closure by a person, build-declared claims, CVE record ranges, unaffected |
| [findings-flaws](design-docs/findings-flaws.md) | Flaws recorded here by hand | minted identifier, typed names, CVE assigned later, affected builds, occurrences, recorded words on a shared issue |
| [findings-reports](design-docs/findings-reports.md) | Vulnerability reports worked as cases | report reference, reporter, received date, acknowledgement, the case, correspondence, notes, judgment, report rule, dispositions, rulings, duplicates, unanswered |
| [findings-queries](design-docs/findings-queries.md) | How finding lists and totals are read | page statements, decision state filters, two-level grouping, covering index, product totals, across products, deadline rewrites, receipts pairing |
| [findings-measurements](design-docs/findings-measurements.md) | Benchmark runs behind the findings rules | fan-out cost, batched updates, decision state timings, two-level timings, a year of nightly scans |
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
| [analytics](design-docs/analytics.md) | The unit figures count, how they are computed, report periods, settings | counting unit, closure reasons, computed on demand, period, rolling window, settings |
| [analytics-catalog](design-docs/analytics-catalog.md) | The catalog of named reports and its pages | catalog groups, report pages, printing, program overview, last upload per build, releases out of support, advisories issued, unmatched components |
| [analytics-program](design-docs/analytics-program.md) | How a program is doing over time | trends, subtree trends, deadlines, deadline compliance, remediation metrics, aging buckets, holder workload, effort, triage latency, repeated deferrals |
| [analytics-releases](design-docs/analytics-releases.md) | What changed between builds, and readiness to release | build comparison, release note, release readiness, known issues at release, inheritance preview, one issue across the estate |
| [analytics-controls](design-docs/analytics-controls.md) | What an auditor reads | disposition register, exception report, standing corrections, approval quality, dismissals, audit log, last uploads |
| [analytics-exports](design-docs/analytics-exports.md) | Files and what each states | CSV, JSON, streaming, incomplete marker, stated facts, code findings in a file |
| [analytics-measurements](design-docs/analytics-measurements.md) | Benchmark runs behind the analytics rules | grouping before the join, planned upgrades page cost |
| [notifications](design-docs/notifications.md) | What a notification is, its triggers, and who may read it | events, conditions, triggers, in-application area, links, mentions, dates, notification list, ownership |
| [notifications-alerts](design-docs/notifications-alerts.md) | Operational alerts about the deployment and its data | new criticals, sharp inventory move, analyzer alerts, reports that must come back empty, approval pairs, stale data, absent holders |
| [notifications-work](design-docs/notifications-work.md) | Notices about work | decision outcomes, lapse message, merge message, code finding notices, staleness, report audience, digest, embargo notices, response windows |
| [notifications-delivery](design-docs/notifications-delivery.md) | What a message may carry, and how it is delivered | outbound content, sweeps, leases, mail, outbound HTTP, webhooks, signing, destinations |
| [notifications-chat](design-docs/notifications-chat.md) | Slack and Zulip | chat recipients, channel scope, grouped messages, chat delivery, chat markup |
| [notifications-measurements](design-docs/notifications-measurements.md) | Benchmark runs behind the sweep rules | reconcile batches, sweep index |
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
