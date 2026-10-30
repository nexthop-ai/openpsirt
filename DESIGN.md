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
| [kinds](design-docs/kinds.md) | Kinds of finding and what each declares | issue kinds, name resolution, consumers, inclusion, runs and series, sightings, source locations |

## Intake

| Document | Covers | Terms |
|---|---|---|
| [ingest](design-docs/ingest.md) | A scan from arrival to application | upload, producer behavior, request handling, admission, refusals, arrival decision, submission identity, build time, document storage, retention, scan application, overtaken scans, scheduled rescanning |
| [ingest-parsing](design-docs/ingest-parsing.md) | How an inventory is read, within bounds | header pass, bounds, component bound, claim bound, file identifiers, edges, tolerated, refused, all or nothing, unread fields |
| [ingest-formats](design-docs/ingest-formats.md) | The inventory formats and where each states each fact | CycloneDX JSON and XML, SPDX 2.x, SPDX 3.x, format declaration, format spellings, structural relationships, lifecycle scopes, files, the root |
| [ingest-claims](design-docs/ingest-claims.md) | What builds and publishers claim, and how claims meet components | build-declared suppressions, carried patches, claim matching, product placement, stored claims, administrator VEX, CSAF VEX, OpenVEX, supplier advisories, CSAF bounds, name folding |
| [ingest-suppliers](design-docs/ingest-suppliers.md) | Supplier advisories read on a schedule | supplier directories, provider description, presets, the pass, lease, the mark, digests, outbound requests, unreadable supplier |
| [ingest-scanner](design-docs/ingest-scanner.md) | The scanner, its report and its offline data | scanner environment, scanner output, report bounds, ratings kept, CVSS generations, scanner warnings, offline scanner database, CVE records, snapshot |
| [ingest-receipts](design-docs/ingest-receipts.md) | What is read back about uploads | last upload per build, quiet builds, receipts, receipt states, answering run, receipt counts, document retrieval, upload listing, document uploads |
| [ingest-measurements](design-docs/ingest-measurements.md) | Measurements behind the ingest rules | receipt cost, run indexes, supplier directory volume, claim writes, rating mixture |
| [analysis](design-docs/analysis.md) | Static analyzer runs uploaded as SARIF | SARIF upload, bounds, run contents, dropped results, run parameters, comparable, run application, sharp drop, analysis receipts |
| [analysis-matching](design-docs/analysis-matching.md) | How results pair with code findings across runs and builds | keys, whole key, unprinted key, probable pairing, layers, carrying, fingerprint change, salt |
| [analysis-source](design-docs/analysis-source.md) | Where a code finding is, and the source shown with it | placement, repository settings, hosts, source links, snippets, rule documentation, evidence, third-party code |
| [analysis-triage](design-docs/analysis-triage.md) | Decisions about code findings | code finding triage, outcomes, dismissal reasons, fixed code findings, suppression rules, code finding states, code finding assignment, end of life |
| [analysis-queue](design-docs/analysis-queue.md) | How code findings are listed, ordered and counted | code finding queue, queue across products, order, queue file, code findings by series, weakness families, tiers, grouped code findings |
| [analysis-flaws](design-docs/analysis-flaws.md) | A code finding recorded as a flaw | flaw records, flaw record offer, disclosure inclusion, withdrawn flaw record, fixed in, code finding collaborators |
| [analysis-client](design-docs/analysis-client.md) | The upload client run beside an analyzer | openpsirt-upload, formats read, clang plist, cppcheck XML, paths, repositories, fingerprints, salt, contents sent, sending, distribution |
| [analysis-measurements](design-docs/analysis-measurements.md) | Measurements behind the analyzer rules | producer output, bound defaults, compression |
| [upstream](design-docs/upstream.md) | Trusting a forked project's published VEX | trusted upstreams, fingerprint, requests, reading, complete read, statements recorded, statements applied, offers for review, declined statements, failure notices |
| [upstream-measurements](design-docs/upstream-measurements.md) | Benchmark runs behind the upstream rules | first read, unmoved read, a fork's run |

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
| [remediation](design-docs/remediation.md) | Declared fix intent and whether the next scan says it arrived | commitment, fold, coverage, commitment changes, promise states, landed, lapsed, planned upgrades of a build, build-declared suppressions, external links, tracker hand-off |
| [remediation-deadlines](design-docs/remediation-deadlines.md) | How long a finding has, when its clock starts, and why one has none | deadline, clock start, exploitation date, known-exploited listing, no-deadline reasons, upstream refusal, tag, end-of-life, recount, recorded flaw windows |
| [remediation-currency](design-docs/remediation-currency.md) | Asking public package indexes for the newest version | upstream currency, package index, lease, answer classes, names held back, namespace, unanswered components |
| [remediation-versions](design-docs/remediation-versions.md) | Which of two versions is further along, per ecosystem | version ordering, candidate counts, Debian, RPM, Alpine, PEP 440, Maven, NuGet, published suites, unranked, version refusals |
| [remediation-advisories](design-docs/remediation-advisories.md) | Advisories as records, their agreement and their issuances | publication adapters, advisory identifier, editorial state, editions, agreement, issuance, settled digest, delivered checksum, publisher identity |
| [remediation-csaf](design-docs/remediation-csaf.md) | The CSAF document generated for one advisory | CSAF 2.0, profile, distribution label, release status, marked affected, remediations, scores, weakness names, product identification |
| [remediation-vex](design-docs/remediation-vex.md) | The OpenVEX document of one build | document kinds, with suppliers, statements, patches, supplier statements, earliest decision, statements about one occurrence, VEX revisions |
| [remediation-directory](design-docs/remediation-directory.md) | Issued advisories written as a static CSAF provider directory | provider directory, travel, year folder, provider-metadata.json, index.txt, changes.csv, ROLIE feed, hash files |
| [incidents](design-docs/incidents.md) | A regulator's questions after an incident, and what one does to decisions | three conflated facts, stored facts, decisions against an incident, response windows, window clock, notices, fix releases, the shelf |

## Access and the API

| Document | Covers | Terms |
|---|---|---|
| [access](design-docs/access.md) | Who a request is, and the roles and visibilities it reads under | authentication, roles, security testing visibility, breadth of view, upward tree, subject kinds, pipeline keys, anybody at all, the deployment itself |
| [access-enforcement](design-docs/access-enforcement.md) | Where each access check sits, and refusals that disclose nothing | name resolution order, one resolver, enforcement sites, store methods with no subject, visibility questions, rating rights, mentions, notes on an issue |
| [access-assignment](design-docs/access-assignment.md) | Who holds work and how it moves | assignment rights, assignment by narrowing, teams, team queue, assignment rules, preview, sweep, departure, lost reading, hand-back |
| [access-grants](design-docs/access-grants.md) | How roles are granted, and an account that ends | role assignment modes, group mappings, administration sources, session lifetime ceiling, group matching, grant grid, role across every product, personal tokens, audit permission, somebody who has left, absent holders |
| [access-signin](design-docs/access-signin.md) | Sign-in, sessions and the headers every response carries | provider sign-in, outbound client, internal addresses, trusted-header sign-in, identifier binding, provider attribution, redemption window, username claim, mail addresses, request forgery, return addresses, sealing key, browser headers |
| [access-disclosure](design-docs/access-disclosure.md) | Embargoes and collaborators granted one case | disclosure date, approaching disclosure, issue disclosure, extension, shortening, movement threshold, case collaborators |
| [access-trail](design-docs/access-trail.md) | The administration trail and secrets kept out of logs | trail actors, recorded writes, revocation that matched nothing, trail export, redaction, connection strings |
| [api](design-docs/api.md) | The HTTP API's shape | no private half, document generation, vocabularies, unauthenticated surfaces, operation descriptions, declared privileges, gate sweep, path version, former upload addresses, representation, addresses and labels, area packages |
| [api-refusals](design-docs/api-refusals.md) | Status codes and the shape of a refusal | status codes, not found and not yours, problem+json, published error text, faults, NUL characters |
| [api-lists](design-docs/api-lists.md) | Paging, sorting and filtering, and reads across products | limit and offset, totals, page ceilings, unknown parameters, package kinds, sort allowlist, issue page, findings across products |
| [api-measurements](design-docs/api-measurements.md) | Benchmark runs behind the API rules | package kinds timings |

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
| [publishing](design-docs/publishing.md) | Security documents served without signing in | switches, served surface, rate limit, advisories served, statements, statement scope, CSAF VEX, OpenVEX, revisions, digests and signatures, publishing pass |
| [publishing-measurements](design-docs/publishing-measurements.md) | The benchmark run behind the published documents | document sizes, feed timing, pass duration |

## Interface and text

| Document | Covers | Terms |
|---|---|---|
| [interface](design-docs/interface.md) | The web interface's build, routing and server contract, and rules every screen follows | one artifact, path routing, route table, generated client, capabilities, failed reads, render boundaries, expired session, units, dates, screen copy, copy gate, demo, test coverage |
| [interface-look](design-docs/interface-look.md) | How the interface is drawn | tokens, light and dark, work surface, state chips, phone layout, wide tables, stacking, cards per option, keyboard, focus ring, severity marks, known exploited, incident badge, mockup divergence |
| [interface-shell](design-docs/interface-shell.md) | The frame around every screen | rail, folded rail, top bar, upload, phone tab bar, scope picker, build-only screens, home, tiles, deadline floors, search box, component chooser |
| [interface-findings-list](design-docs/interface-findings-list.md) | The findings list screen | row content, way down, cross-product list, sorting, paging, selection, bulk form, select all, by-component view, by-upgrade view, list navigation, restored position |
| [interface-filters](design-docs/interface-filters.md) | The findings list's filters and saved filters | filter bar, chips, More filters, release kind, support, multi-value filters, Mixed, filters over a group, saved filters, prepared decision, deferral length |
| [interface-finding](design-docs/interface-finding.md) | The finding screen and deciding on it | layout, references, what the build says, dependency path, notes and comments, decision form, deferral forecast, locations, reach sheet, answer placement |
| [interface-component](design-docs/interface-component.md) | The component screen and the dependency tree | source package page, binaries, where it could go, promise form, security testing card, code findings column, code findings trend, unplaced code findings, component reads, tree counts, beneath, unmatched components, tree search |
| [interface-review](design-docs/interface-review.md) | Review, decision and assignment screens | review queue tabs, outliers, reaffirm, queue filters and exports, decision page, reach when lapsed, assignments, unassigned, assignment rules |
| [interface-editor](design-docs/interface-editor.md) | Writing text on screen | editor, preview, drafts, draft keys, sign-out clearing, tab memory, file attachment, mentions, people pickers |
| [interface-catalog](design-docs/interface-catalog.md) | Catalog, upload, product and release screens | catalog drawer, retiring, upload drawer, Uploads tabs, receipts, inherited lines, inventory changes, component comparison, repositories screen, product page, scan run page, release page |
| [interface-flaws](design-docs/interface-flaws.md) | Flaw, report, disclosure and incident screens | flaw entry, score vector, vulnerability reports, rulings, disclosure deadlines, standing notice, advisory screens, published VEX, flaw panel, Incidents screen |
| [interface-security-testing](design-docs/interface-security-testing.md) | Code findings on screen | Security testing screen, code finding page, Also found by, decisions on code findings, flaw records, include in disclosure, suppression rules |
| [interface-administration](design-docs/interface-administration.md) | Reports and administration screens | analytics catalog, printing, audit log, settings, webhooks, suppliers, System screen, Access, credentials, own page, a person whole |
| [interface-measurements](design-docs/interface-measurements.md) | Benchmark runs behind the interface's reads | component read timings, ways down, tree walk, tree search |
| [text](design-docs/text.md) | Text people write, and where it is checked and rendered | markdown policy, sanitizing, raw markup, link schemes, issue references, images, escaping third-party text, refusals, code block language tags, bounds |
| [attachments](design-docs/attachments.md) | Files on an issue or a report | references in text, attachment subjects, fetch authorization, object store, store credentials, plaintext store, delivery, response headers, quota and removal, reaper, redaction |

## Platform

| Document | Covers | Terms |
|---|---|---|
| [database](design-docs/database.md) | Supported engines, where engine-specific code lives, connections, and the test harness | version floors, engine-specific code, make confined, engine detection, connection encryption, connection pool, statement preparation, SQLite settings, test harness, failing commit, partitioning |
| [database-migrations](design-docs/database-migrations.md) | Creating and moving the schema forward | migrate up, schema version, baseline, forward only, migrations that stop half way, release records, release freeze, upgrade rehearsal, migration lock |
| [database-upgrades](design-docs/database-upgrades.md) | What each release's upgrade migration does | release upgrades, v0.8.0, v0.9.0 image merge, v0.10.0, v0.11.0 renames, stored values, SQLite rebuild |
| [database-queries](design-docs/database-queries.md) | Query rules the four engines impose | identifier quoting, reserved words, make reserved, silently wrong query shapes, LIKE escaping, case folding, affected-row counts, recursion bound, collation, text truncation, bulk inserts |
| [database-transactions](design-docs/database-transactions.md) | Coordination through the database and transactions that survive a cluster | replica coordination, retryable transactions, savepoints, one act one transaction, joining a transaction, reads a write depends on, decision stamp, absence and failure |
| [database-schema](design-docs/database-schema.md) | Indexes, statistics and column rules | redundant indexes, hot indexes, vacuum settings, planner statistics, column widths, columns no query reads |
| [database-measurements](design-docs/database-measurements.md) | Benchmark runs behind the database rules | statement preparation modes, bulk insert cost, v0.9.0 upgrade time, v0.11.0 phase times, index reads |
| [queue](design-docs/queue.md) | Background work as rows, and leases for once-only passes | job structure, exclusive handout, failure handling, failed jobs, claim renewal, hold ceiling, passes on a timer, leases, backlog refusal, queue bounds, transaction boundary |
| [build](design-docs/build.md) | Repository layout, make targets, the gate, CI, and repository settings | package table, make targets, gate tiers, CI jobs, CI caches, gate inputs, static analysis, API document generation, probes, review checklist, merge queue |
| [build-tests](design-docs/build-tests.md) | Database servers, test databases, the race pass and commit durability | engines-up, local.mk, test databases, seeded templates, default world, slots, engines-clean, measurement databases, race detector, OPENPSIRT_TEST_ENGINES, relaxed durability |
| [build-dependencies](design-docs/build-dependencies.md) | Pinned versions, tool pins, vulnerabilities, licenses and action pins | pinned pairs, pins-check, go-version, tool modules, hash pinning, govulncheck, web-audit, introduced advisories, license allowlist, copied files, NOTICE, SPDX headers, Dependabot groups |
| [build-interface](design-docs/build-interface.md) | Checks over the interface source | tsc, ESLint, Prettier, Stylelint, web test runs, class-name collisions, unstyled classes, unused exports, route addresses, query keys |
| [build-docs](design-docs/build-docs.md) | The documentation site and the checks over every document | mkdocs, mike, default set, link check, anchors, release version placeholder, scanner pins, settings reference |
| [build-measurements](design-docs/build-measurements.md) | Benchmark runs behind the build and test rules | cache sizes, slot pass timings, race pass configurations, table layouts, durability timings |
| [packaging](design-docs/packaging.md) | The container image, its data, starting and stopping, and configuration | image structure, base version, bundled scanner, CVE record snapshot, repository copies, pod sizing, CPU priority, image checks, startup deadline, upgrading response, shutdown, configuration file, OPENPSIRT_ variables |
| [packaging-chart](design-docs/packaging-chart.md) | The Helm chart | probes, platform health checks, security context, SQLite on one pod, network policy, trusted header, render-time refusals, secret sources, bootstrap admins |
| [packaging-release](design-docs/packaging-release.md) | Release assets and the release procedure | self-inventories, inventory composition, release assets, version sources, image tags, OCI labels, chart version, signing, provenance, release procedure, release notes, multi-architecture |
