# Design

Where each design contract is written. Read the row, then the one document it
names. Each document lists the decisions it satisfies; `REQUIREMENTS.md` says why.

## Model and findings

| Document | Covers | Terms |
|---|---|---|
| [data-model](design-docs/data-model.md) | What a scan is filed against and the structures it produces | product, branch or tag, variant, build, component identity, dependency graph, the fold, occurrence identity, intervals, inventory delta |
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
| [triage](design-docs/triage.md) | What a decision is keyed on, its outcomes, and when it stops applying | decision identity, expiry, outcomes, already fixed, mitigations, outcomes on a tag, dates still to come, corrections, wrong match, one live decision per key, statement scope |
| [triage-decisions](design-docs/triage-decisions.md) | One decision, its rows, and how its record is read back | decision kinds, rows, act placement, readback, undoing a bulk approval, the whole decision, reach when it stopped, standing and previous lists, extensions, comments, notes, labels |
| [triage-approval](design-docs/triage-approval.md) | The second person and the review queue | approval, revisions, carried agreement, rights, visibility of the record, set-aside rows, outliers, partial approval, sending back, deferral threshold, queue entries, queue contents, queue filters |
| [triage-bulk](design-docs/triage-bulk.md) | Decisions over many occurrences, issues and builds | reach across builds, coverage count, bulk decisions, issue limit, occurrence ceiling, narrowing record, decided occurrences, rule-prepared decisions, saved filter prefill, decisions on a new branch |
| [triage-promises](design-docs/triage-promises.md) | Promises to upgrade or patch by a date | planned upgrades, upgrade needed, patch needed, source package coverage, handover, no cap, approval gate, covered work |
| [triage-lapse](design-docs/triage-lapse.md) | How a decision is marked lapsed and re-made | lapse marking, moved versions, worse rating, merged issues, stopped standing, re-affirmation, severity bands, carried agreement, whole-action re-affirmation, To reaffirm, re-affirmation across decisions |
| [triage-severity](design-docs/triage-severity.md) | What is worth triaging and a product's own rating | minimum severity, product minimum, issue assessments, rating in force, milder rating, effects of agreement, deadline windows, deadline rewrite |
| [triage-evidence](design-docs/triage-evidence.md) | What publishers say, what it closes, and decisions elsewhere | evidence from publishers, VEX statements, supplier advisories, supplier statements applied, statements about the build, evidence placement, statement filters, decided elsewhere |
| [triage-measurements](design-docs/triage-measurements.md) | Benchmark runs behind the triage rules | kernel upgrade promise, autovacuum, foreign key checks, review queue reach, query plan cost |
| [remediation](design-docs/remediation.md) | Declared fix intent and whether it arrived | planned upgrades, resolution, deadlines, version ordering, promise states, advisory, CSAF document, VEX document, issuance, provider directory |
| [incidents](design-docs/incidents.md) | A regulator's questions after an incident, and what one does to decisions | three conflated facts, stored facts, decisions against an incident, response windows, window clock, notices, fix releases, the shelf |

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
