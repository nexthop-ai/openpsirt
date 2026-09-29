# TODO

> Deprecated. New work is filed as a GitHub issue, never added here. The items
> below move to issues and leave this file as they do.

Everything still in scope, not built, and not yet filed as a GitHub issue.

| Rule | |
|---|---|
| Each item has an identifier, `TODO-` and a number | Conversation and pull request descriptions cite an item by it |
| An identifier is never changed or reused | A finished item is deleted and its number retired |
| Code, comments, commit messages and design documents do not cite this file or its identifiers | Anything durable moves to `REQUIREMENTS.md` or a `DESIGN-*.md` before an item is deleted |

Each item says what exists today, what is missing or wrong, the work to do,
and what it waits on. Code paths are left out: they move, and the design
document named in an item points at the area.

## Contents

- [Before 1.0](#before-10)
- [Deferred by the owner](#deferred-by-the-owner)
- [Decided, not built](#decided-not-built)
- [Known gaps](#known-gaps)
- [Weak tests](#weak-tests)
- [Measured and left alone](#measured-and-left-alone)

## Before 1.0

Required for 1.0, and wrong to do earlier.

### TODO-01 Migration collapse

| | |
|---|---|
| Today | A new database is built by replaying every migration since v0.1.0. Migrations 1 to 36 build v0.1.0's schema, 37 upgrades v0.1.0 to v0.2.0, 38 upgrades v0.2.0 to v0.3.0, and 39 is the untagged release's own. v0.4.0 changed no schema. Each tagged release's migrations are frozen, and a test enforces it |
| Problem | At 1.0 a fresh install would still build v0.1.0's schema and then reshape it three times. Nobody needs that history |
| Work | Replace migrations 1 to 39 with one migration that creates the 1.0 schema directly, plus one that upgrades a database built by the last 0.x release. Document that a database from an older 0.x release is first upgraded to that last 0.x release |
| Waits on | The 1.0 schema being final. Also open: what happens to the frozen records of v0.1.0 to v0.3.0, and how the rollback rule for a database ahead of the binary changes (`DESIGN-database.md` § Migrations) |

### TODO-02 Schema and API compatibility

| | |
|---|---|
| Today | Below 1.0 nothing is promised (REQ-76). An API change edits `/v1` in place. A schema change edits the untagged migration. The Helm chart stops every old pod before starting a new one, because an upgrade may reshape tables the old release reads |
| Problem | An integrator cannot rely on a field or an endpoint surviving an upgrade. A CI script that uploads inventories can break on the next minor release with no warning |
| Work | From 1.0, add every schema change as a new migration after the tagged ones, keep every API change inside `/v1` backward compatible, move a breaking change to a new path version, and state each release's upgrade path |
| Waits on | The 1.0 tag, and TODO-01 |

## Deferred by the owner

The owner has chosen to wait on each of these.

### TODO-03 Advisory delivery to other platforms

| | |
|---|---|
| Today | An advisory is written, approved by a second person and generated as a CSAF 2.0 document. Every issued advisory marked shareable is written into a CSAF provider directory, which the operator's own web server serves. Anything else is sent by hand, and somebody records that it went out |
| Problem | Nothing pushes an advisory anywhere. A project that publishes through GitHub Security Advisories, or a vendor that posts to a customer portal, copies each one by hand |
| Work | Add optional adapters, configured per deployment, that deliver an issued advisory to a destination. The one the design names is a code forge's advisory system: draft privately, request an identifier, then publish (REQ-39) |
| Waits on | The owner choosing which platforms, and the credentials for each |

### TODO-04 Advisory signatures and key

| | |
|---|---|
| Today | The provider directory is written unsigned. Each document has a SHA-256 checksum file beside it, which proves the file arrived intact and not who wrote it |
| Problem | A customer cannot verify that a document came from this publisher. The CSAF "trusted provider" role needs an OpenPGP signature beside each document and the public key named in the directory's metadata, so a CSAF checker rates this directory below trusted provider |
| Work | Take a signing key from the operator. Write a detached signature beside each issued document, publish the public key, and name both in the directory metadata and the feed |
| Waits on | How a private key enters a deployment: a file or a secret, how it is rotated, and whether a key held in a KMS or HSM is supported. The deployment already takes other secrets, such as the Slack token and the object store keys; it takes no private key |

### TODO-05 CVE Numbering Authority

| | |
|---|---|
| Today | A flaw in our own product gets an identifier this deployment mints. When MITRE or another CNA later assigns a CVE, somebody types it onto the flaw as another name |
| Problem | Getting each CVE means asking another CNA by email or form, and waiting. That does not scale past a handful of advisories a year |
| Work | Once the organization has joined the CVE Program, which is outside this software: reserve a CVE through the CVE Services API when a flaw is recorded or an advisory started, attach it to the flaw, and publish the CVE record from the advisory at disclosure |
| Waits on | The owner, who expects this after 1.0. It needs an API user and key, the same kind of secret as the Slack token |

### TODO-06 More exploitation sources

| | |
|---|---|
| Today | The only signals that an issue is exploited are what the scanner's database carries per match: the CISA known-exploited catalog and the EPSS likelihood. A person can also record that an issue is exploited in one product. Known-exploited drives urgency and the shortest deadline window |
| Problem | An issue that a commercial catalog (VulnCheck KEV, for example) or an exploit database lists as exploited, and CISA does not, ranks and gets a deadline like any other finding |
| Work | Let an administrator configure an extra source with its license and key. Read its data from a bundle that works without a network, like the scanner database. Count an issue it lists as known-exploited, and record the source as the evidence |
| Waits on | The owner choosing sources and accepting their license terms. REQ-12 requires every feed to work with no network, so a source has to be a downloadable dataset, never a live lookup at scan time. No adapter for any second source exists |

### TODO-07 Deadline windows per product

| | |
|---|---|
| Today | Remediation deadline windows are deployment-wide settings on the Settings screen: one set for scanned findings (3, 7, 30, 90 and 180 days by default, for exploited down to low) and one for flaws in our own product. A product can already override its triage floor, and not these windows |
| Problem | A customer-facing appliance and an internal lab tool must both fix a critical issue within the same seven days |
| Work | Let a product set its own windows, falling back to the deployment's when cleared, the way the triage floor override works. Rewrite the deadlines of the product's open findings when its windows change (REQ-33) |
| Waits on | The owner's go-ahead only |

### TODO-08 CSAF VEX profile

| | |
|---|---|
| Today | An advisory's CSAF document lists each release (a branch or tag built as one variant) as known affected when any finding of the flaw is open there, and fixed otherwise. It reads no triage decisions. The per-build OpenVEX document on the VEX screen does: a build's issue is not affected when every open place is covered by an approved, still-valid decision with one outcome |
| Problem | A release covered by an approved not-applicable decision is published as known affected, with a remediation telling customers to update. The advisory has no way to say "known not affected, because…" |
| Work | Move the VEX screen's coverage rule into one shared query and use it for the advisory. List each fully covered release as known not affected, with the decision's reason as the CSAF flag (the five reasons are the CSAF flag names) and its mitigation, never its reasoning, as the impact statement. Leave a partly covered release known affected. Keep not-affected releases out of remediations and scores, and emit the VEX profile when any release is not affected |
| Waits on | A decision reaches every variant whose versions match, because a place is identified without its root. A not-applicable decision made for a variant where the code is compiled out also covers a variant where it is compiled in, in the OpenVEX document today and in the advisory once this is built. Limiting a decision to a variant changes REQ-26 and is a separate decision |

### TODO-09 Microsoft Teams and Google Chat

| | |
|---|---|
| Today | Chat notifications go through a bot on Slack or Zulip. They post to channels an administrator binds to the deployment, a product or a team, and message people directly, found by email address. A signed HTTPS webhook per kind of notification also exists |
| Problem | An organization on Teams or Google Chat gets no chat notifications. A webhook reaches a channel and never a person, and undisclosed work may only reach a person directly (REQ-81) |
| Work | Add Teams and Google Chat as chat platforms the way Slack and Zulip are: channel posts, and direct messages for personal and undisclosed notifications |
| Waits on | Cooperation from each tenant's administrator. A Teams direct message needs a Power Automate workflow in the tenant or a registered bot, and a Google Chat one needs a Chat app installed for each person it reaches |

### TODO-10 Commit lookup by forge API

| | |
|---|---|
| Today | When patch branches are on, OpenPSIRT clones every repository a patch link names, commits only, and asks git which branches contain each linked commit. The branch names label the link |
| Problem | A GitHub repository linked by one or two commits is still cloned in full and kept on disk to answer one question |
| Work | For GitHub and GitLab repositories with few linked commits, ask the host's API which branches hold each commit and skip the clone. Keep cloning for other hosts and heavily linked repositories |
| Waits on | The owner. `DESIGN-findings.md` states that a code host's API is never asked, because the same answer from two routes is two things to keep right, so building this reverses a written rule. It also needs API tokens and handling of rate limits |

### TODO-11 Repository mirrors

| | |
|---|---|
| Today | A repository is fetched only from the host its link names. git.kernel.org does not serve commits-only clones, so the kernel stable tree is a full 5.1 GB clone that takes 15 minutes and 2.4 GB of memory to index. From a host that does, it is 1.1 GB in 90 seconds. 36,000 of the 36,625 patch links in the demo data point at the kernel stable tree |
| Problem | Every deployment with kernel patch links pays for the full clone in disk and time |
| Work | Let a repository be fetched from a mirror, configured or built in, while links and labels keep the original address |
| Waits on | A way to declare that a mirror holds the same repository, which nothing here can check, and the mirror host being allowed by the outbound rules (REQ-69, REQ-78) |

## Decided, not built

A decision in `REQUIREMENTS.md` is in force and nothing implements it.

### TODO-12 Producer vulnerability reports

| | |
|---|---|
| Today | The upload endpoint takes an inventory and, optionally, VEX documents that suppress findings. A vulnerabilities list inside a CycloneDX inventory is skipped. Every scan result recorded is one run here |
| Problem | A pipeline that already ran a scanner such as Trivy cannot send those results to be recorded beside ours (REQ-05) |
| Work | Accept an optional vulnerability report in the upload. Store its findings with the producer's scanner, version and database recorded, and show them apart from findings scanned here |
| Waits on | Deciding how a producer's findings relate to ours: as evidence only, or as findings in their own right. REQ-10 says the scan runs here so that results are reproducible and comparable, which pulls against the second |

### TODO-13 Static analysis and fuzzing findings

| | |
|---|---|
| Today | Nothing. Only scanner matches against inventories become findings |
| Problem | Results from static analyzers such as CodeQL or Semgrep, and crashes from fuzzers such as OSS-Fuzz, cannot be tracked, triaged or compared release to release here (REQ-14) |
| Work | Read analyzer and fuzzer results as SARIF through one adapter per source, scoped to a product, release and variant, with identity computed here, and triage them like scanned findings (`DESIGN-ingest.md` § Analyzer findings) |
| Waits on | Scheduling by the owner. The design says the finding model carries a kind so that a second kind needs no rewrite; no kind column exists on findings, so that claim needs checking first |

### TODO-14 External tracker hand-off

| | |
|---|---|
| Today | A triage decision can carry one link to where its work is happening, typed by a person. Nothing follows the link. The signed outbound webhook could drive a tracker through somebody's own automation |
| Problem | Approving a promise to fix opens no Jira or GitHub issue, and closing that issue changes nothing here. People copy details across and paste links back by hand (REQ-36) |
| Work | Add an optional adapter, off by default, that opens or updates an item in the configured tracker and keeps its link. Give public and private work separate settings, and send undisclosed work only to the tracker configured for private work |
| Waits on | The owner choosing which trackers, and the credentials for each |

### TODO-15 Purging old data

| | |
|---|---|
| Today | Nothing is purged or partitioned. Expired sessions are deleted, and a nightly branch's inventory documents are deleted once read. An unchanged scan writes nothing, so history grows with change rather than with the calendar |
| Problem | History tables grow without bound. REQ-73 requires aging data out by dropping whole partitions, because a large delete on a table that size is an outage |
| Work | Export high-volume history to a compressed file, then drop it a whole partition at a time |
| Waits on | Which column to partition on and at what granularity, both undecided (`DESIGN-database.md`). SQLite has no partitions, and MySQL and MariaDB refuse foreign keys on a partitioned table. Partition names would need an allowlist like any other SQL identifier |

### TODO-16 Issue publication dates

| | |
|---|---|
| Today | The scanner supplies neither the date an issue was published nor the date it last changed. What is stored is when this deployment first saw the issue and when a fix became available |
| Problem | Time to fix measured from public disclosure cannot be reported. An issue published in 2023 and first scanned here last week reads as a week old (REQ-82) |
| Work | Add a background pass that asks OSV, in batches and with no key, for each issue's published and modified dates, and stores only the dates. Show an issue OSV does not know as unknown wherever a figure needs a date |
| Waits on | Nothing decided. No OSV client exists, and no report design says where the dates are used. A scan must not wait on the lookup (REQ-12) |

## Known gaps

Missing or wrong. Where fixing one needs the owner, the item says which question.

### TODO-17 Upload alert against usual churn

| | |
|---|---|
| Today | After an upload, the server counts the names that arrived, left or changed version. The event "A build's contents changed sharply" fires when that count is at least 10 and at least 25% of what the build held before. Both thresholds are deployment-wide settings |
| Problem | The question asked is whether the change is a big share of the build, when the useful one is whether it is unusual for this build. An image that rebases on a new distribution snapshot every Monday moves 30% every Monday, fires every Monday, and teaches people to ignore it |
| Work | Fire the event when an upload moves much more than this build's recent uploads did, so the weekly rebase stays quiet and a sudden jump of 200 names does not |
| Waits on | Nothing. The graph keeps which scan opened and closed each node, so a build's past churn can be worked out when asked, and needs no stored baseline |

### TODO-18 Container image for arm64

| | |
|---|---|
| Today | Releases publish binaries for amd64 and arm64, and a container image for amd64 only. The chart says so |
| Problem | An operator on arm64 nodes, such as AWS Graviton or Ampere, cannot run the image |
| Work | Publish one multi-architecture image per tag covering amd64 and arm64, signed, with an image inventory per architecture |
| Waits on | Nothing. `DESIGN-packaging.md` § Not built names the Dockerfile change. The release pipeline is the larger part: it builds into the local Docker daemon and reads inventories out of the image, and a multi-architecture image needs buildx and a push instead |

### TODO-19 Distribution package descriptions

| | |
|---|---|
| Today | When the upstream-currency setting is on, a background pass asks the public indexes for Go, npm, PyPI, Cargo, Maven and NuGet what each package is. Those components get the newest version, a one-line summary and a project address on the Component screen |
| Problem | Debian, RPM and Alpine packages get no summary, only a link to the distribution's package page built from the name. A reader of `libnl-3-200` on a switch image sees nothing saying what it is |
| Work | Read a one-line description, and an upstream homepage where one is stated, from each distribution's own index (Debian `Packages`, Alpine `APKINDEX`, RPM `primary.xml`) and show them on the Component screen |
| Waits on | Nothing, though it is large. A distribution index is one large file per release, never one request per package, so it needs a different fetcher. It is a new outbound path and stays opt-in (REQ-69) |

### TODO-20 License listing per build

| | |
|---|---|
| Today | Each component's license is read from the inventory and shown on its Component screen. 4,483 of 6,866 components on one switch image carry one |
| Problem | "Does release X ship anything GPL-3.0?" cannot be answered without opening components one at a time. No listing, filter or export gathers licenses across a build |
| Work | List a build's distinct license expressions with a component count each, add a license filter to the component list, and export the listing as CSV. No new data is needed |
| Waits on | The owner confirming it is in scope. `REQUIREMENTS.md` § Out of scope lists license and compliance analysis of inventories as not built |

### TODO-21 Versions on the component chart

| | |
|---|---|
| Today | The "Twelve weeks" chart on the Component screen shows findings opened, resolved and open per week, for this component and everything under it, in one build |
| Problem | It does not show which version the build shipped each week, so it cannot show that the move to 3.2 in week 5 was followed by closures. The chart also follows only the component at its current version, so findings on an earlier version may drop out of it altogether; that part is suspected and unconfirmed |
| Work | Draw the chart for the component by name across versions, and mark each week the shipped version changed, labeled with the version. Work the version per scan out from the graph's history |
| Waits on | Nothing |

### TODO-22 CVSS 4.0 and CSAF 2.1

| | |
|---|---|
| Today | Advisories are written as CSAF 2.0, which has fields for CVSS 2, 3.0 and 3.1 scores and none for 4.0. The document carries the first CVSS 3.0 or 3.1 score found for each flaw. CSAF 2.1, which adds a 4.0 field, is a committee draft at OASIS |
| Problem | A flaw rated only under CVSS 4.0 publishes no score at all, although the application shows it. A flaw rated only under CVSS 2 publishes none either, although CSAF 2.0 has a field for it |
| Work | Two steps. Now: carry a CVSS 2 score in its field, and give a flaw rated only under 4.0 a note with the version, base score, severity and vector (`DESIGN-remediation.md` § Not built). Once CSAF 2.1 is a standard: write advisories as 2.1, move scores into its metrics structure with 4.0 in its own field and drop the note, change the TLP label for public documents from WHITE to CLEAR, let a flaw name several weakness types, and check documents against a 2.1 validator. An advisory issued before the move will not regenerate byte for byte afterwards |
| Waits on | Nothing for the first step. CSAF 2.1 becoming an OASIS standard for the second |

### TODO-23 Advisory-wide notes

| | |
|---|---|
| Today | A person types an advisory's title and each issuance's revision summary. Every other part of the CSAF document is assembled from the flaws it covers, and the document-level notes are always empty |
| Problem | No overview across the flaws, no legal disclaimer or terms of use, and no general or workaround text for the advisory as a whole. A vendor that must put a disclaimer on every advisory cannot |
| Work | Let the advisory screen take document notes, each with a category from the standard (summary, legal disclaimer, general and so on), possibly with a deployment-wide default disclaimer |
| Waits on | Nothing. The notes are what the company says, so editing them opens a new edition and withdraws its approval, as retitling does (REQ-24, REQ-28), and they go through the text policy for typed markdown |

### TODO-25 Promise status across builds

| | |
|---|---|
| Today | A promise to upgrade names several releases, a version and a date. Each build's Pending upgrades page shows that build's state (planned, landed or lapsed). The Claim screen shows the promise and its reach |
| Problem | Nothing shows one promise's state in every release it names. To see that "move openssl to 3.0.15 by 1 October in 4.2, 4.3 and main" landed in two releases and lapsed in one, somebody opens three builds |
| Work | List on the Claim screen each release the promise names, with its state, what is still open there and the date. It reads nothing new (REQ-35) |
| Waits on | Nothing |

### TODO-26 HTML mail

| | |
|---|---|
| Today | Each notification goes out as one plain-text mail, with the link as a bare address |
| Problem | No clickable link and no layout |
| Work | Send a multipart mail: the same text, plus an HTML part with the link as an anchor and nothing fetched remotely. The content rules for undisclosed work are unchanged (REQ-48) |
| Waits on | Nothing. Mail bodies are sentences the server composes, so the HTML part is the escaped text with the link wrapped. |

### TODO-27 Spacing scale

| | |
|---|---|
| Today | The stylesheets define six spacing tokens (4, 6, 8, 10, 12 and 18 px), chosen to match values already in use. Most spacing is still written by hand, at a spread of sizes from 1 px upward, in the stylesheets and inline in components |
| Problem | Screens have uneven rhythm, and a new screen has no scale to follow |
| Work | Choose a scale, draw every spacing value from it, and make the token check refuse a raw pixel spacing value. Review with before and after screenshots |
| Waits on | The owner choosing the scale by looking at it in a browser |

### TODO-28 API operations no screen reaches

| | |
|---|---|
| Today | A test runs handlers nothing else runs. Nothing compares the API document with what the web client calls |
| Problem | An endpoint can exist with no way to use it from a screen, found only by reading. Candidates found by a search: listing unassigned findings, removing a person's identifier, and one finding's reach at one place |
| Work | Add a check that walks every operation in the API document, finds where the web client calls it, and fails on one with no caller unless it is on a list of operations meant for pipelines, each with a reason. Make it fail when it examines nothing, and show it reporting one input and passing another |
| Waits on | Nothing |

### TODO-30 A real SPDX 3 fixture

| | |
|---|---|
| Today | SPDX 3 inventories are read. Every SPDX 3 test document is an example from the specification's repository, and the one written by a real tool holds only its own subject |
| Problem | What real producers emit (which way relationships point, scopes, identifiers) is untested. One specification example already has its relationships backwards. A Yocto build uploading SPDX 3 could lose its dependency tree and no test would notice |
| Work | Add at least one real producer's document, such as Yocto's `create-spdx-3.0` output, under a license the repository may carry and named in `NOTICE`, with a test pinning its component, edge and unplaced counts |
| Waits on | Finding a document with a usable license. |

### TODO-31 Version on build VEX claims

| | |
|---|---|
| Today | A build may upload its own CSAF VEX beside its inventory. A statement about a product named by a version branch, with no package identifier, is matched with its version as the document is read, and stored without it |
| Problem | The stored statement covers every version of that name. A build ships `acme-fw` 4.2 with a statement that CVE-Y does not affect 4.2, moves to 5.0, which is affected, and keeps sending the same file: CVE-Y is suppressed on 5.0 with nothing saying why. The carried patches screen shows "acme-fw" with no version, so nobody can see the mismatch. VEX uploaded for a product keeps the version |
| Work | Store the statement's version, match only that version, and show it |
| Waits on | The owner: the next upload of a moving branch closes and reopens each such statement once, which is acceptable or is avoided by leaving versionless statements' identity alone; and whether statements already stored for tags are re-read from their kept documents |

### TODO-32 Outbound HTTP proxy

| | |
|---|---|
| Today | Only the scanner reads `HTTPS_PROXY`. Every other outbound request connects directly: patch branch clones, package indexes, supplier directories, webhooks and chat |
| Problem | In a network whose only way out is a proxy, those requests all fail. Patch branches report "could not reach" and label nothing |
| Work | Send outbound requests through a configured proxy, starting with patch branch clones |
| Waits on | The owner. REQ-69 and REQ-78 refuse any address inside the network, checked on the address a name resolved to. Through a proxy, the proxy resolves the name. Resolving locally, checking the address and asking the proxy to connect to that address keeps the check, and is a change to a security rule that needs agreeing first |

### TODO-34 Weakness names on screen

| | |
|---|---|
| Today | A finding's weakness types (CWE) show with a name only when the web client's own list of about 55 common ones has it. Every other one shows as a bare number such as "CWE-1321", linked to MITRE. The server holds the whole CWE catalog, about 970 names, and uses it only in advisories. The weakness filter and the picker on the record-a-flaw form show bare numbers too |
| Problem | Kernel and library findings often carry uncommon weakness types, and each costs a click out to MITRE to read |
| Work | Send the catalog name beside each identifier from the server, and show the screen's own short name where it has one and the catalog's otherwise. Specified in `DESIGN-interface.md` |
| Waits on | The owner: whether long catalog names are shown whole, shortened or on hover; whether the filter and picker offer the whole catalog, which needs a lookup endpoint. The same pattern as GitHub issue #137 |

### TODO-35 Saved filters across products

| | |
|---|---|
| Today | A saved filter belongs to the product it was saved in. The same person sees none of their filters in another product, and the list across every product has no saved filters at all. A saved filter also keeps the release and build it was saved on, which the design says it drops |
| Problem | Anybody working in several products saves each filter once per product. Prefill rules are built on saved filters, so the duplication multiplies |
| Work | Keep one list per person, applied within whatever scope is on screen (`DESIGN-interface.md` § Saved filters). Leave release and build out of what is kept. Where one person kept one name in two products, add the product to one of the names |
| Waits on | The owner: whether a filter that prefills a decision applies in every product or only its own; the rename format; whether saving drops the build silently or says so. The schema change goes in migration 39 |

### TODO-36 Package kinds present

| | |
|---|---|
| Today | The findings list's package type filter offers a fixed list of twelve kinds. The server filters on any kind given, and cannot say which kinds a scope holds |
| Problem | A kind outside the twelve, such as Conan, Swift or Composer, is reached only by typing it into the address. A kind the scope does not hold is offered, and ticking it shows an empty list |
| Work | Report from the server the kinds present in a scope, counted over the findings the person may see (REQ-43), and offer those in the filter plus whatever is already chosen |
| Waits on | The owner: whether the kinds follow the whole scope or the list as other filters narrowed it; whether counts show; working the kind out from the package identifier in Go after measuring, or in engine-specific SQL. The same pattern as GitHub issue #137 |

### TODO-37 Full-queue upload refusals

| | |
|---|---|
| Today | An upload that arrives while 1,000 inventories wait to be read is answered 503 "try again shortly". Nothing is logged, and no record of the refused upload is kept, unlike every other refusal. The System screen marks the queue at its limit |
| Problem | A pipeline that does not retry loses the inventory with no trace. A week later the deployment tells administrators the build "has not been scanned for a week. Nothing has failed — nothing has arrived", which blames a pipeline that did send it. |
| Work | Log and record the refusal like any other, name it in the week-quiet message, and alert administrators naming the build, the limit and how to raise it, at most once per build per day |
| Waits on | The owner: an event people acknowledge, or a condition that clears when the build next uploads; administrators only, or the product's triagers too. Logging and recording need nothing |

## Weak tests

Each test passes today, and would keep passing if the code it covers broke.

### TODO-39 Scanner arguments

| | |
|---|---|
| Today | The scanner tests replace the scanner with a stand-in that prints a canned report |
| Problem | The stand-in never looks at the arguments or at the inventory it is sent. Dropping the flag that asks for JSON output, or not sending the inventory at all, leaves every test green |
| Work | Make the stand-in fail unless it is asked for JSON output, and have it report what it read so the test compares it with what was sent |

### TODO-40 Upgrade list sort orders

| | |
|---|---|
| Today | A test asks the list of pending upgrades for each sort order it offers, both directions, and checks only that an answer comes back |
| Problem | An offered order with no matching column silently sorts by the default and still answers, and an order mapped to the wrong column passes too. The findings list has a test tying every offered order to a column. The upgrade list has none |
| Work | Add the same two-way test between offered orders and columns, and data in which each order puts a different upgrade first |

### TODO-41 Connection pool limits

| | |
|---|---|
| Today | One test checks that an unreachable database fails quickly, and another that the pool is bounded |
| Problem | The first dials a port that refuses at once, so it fails in milliseconds whatever the timeout is, and it calls the open function where its name says validate. The second compares the pool's limit with the function that set it, so setting that limit to zero, which means unlimited, still passes |
| Work | Point the timeout test at a listener that accepts and never answers, and check the attempt gives up in time. Make the pool test check a fixed number, or that one query past the limit waits |

### TODO-42 Upstream currency retry

| | |
|---|---|
| Today | A test named for asking a failed package index again runs one pass and checks that nothing was stored |
| Problem | It never runs a second pass. If a failure were remembered between passes and the package never asked again, the test would still pass |
| Work | Fail the first pass, have the index answer, and check that the second pass asks again and stores the answer |

### TODO-43 Empty inventory part

| | |
|---|---|
| Today | A test's comment says an empty upload part is refused. The test checks that an empty document is stored and read back |
| Problem | No test sends an empty inventory through the upload endpoint, so if the endpoint stopped refusing one nothing would notice |
| Work | Rename and recomment this test for what it checks. Add one that sends an empty inventory to the endpoint and checks that it is refused with a reason and recorded as refused |

### TODO-44 Scanned builds in API tests

| | |
|---|---|
| Today | The shared API test fixture has helpers that make a scanned build, and they always make the same one: one fixed product, release and variant, scanned now, with the scan run left unfinished |
| Problem | Tests that need another variant, another time, a graph with no findings or a finished run build it step by step themselves, repeating the same sequence. Tests of the component tree, of inventory comparison and of upload receipts do this, and two tests write scan run rows directly |
| Work | Give the fixture helper parameters for the variant, the time, whether to read findings and whether to finish the run, and use it in those tests |

## Measured and left alone

Nothing is made faster until it is measured slow. These were measured and left.

### TODO-45 Writes on an unchanged rescan

| | |
|---|---|
| Measured | Rescanning unchanged data rewrote every finding that has a fix: 5,882 rows, taking 1.3 s on PostgreSQL, 782 ms on MySQL and 711 ms on MariaDB. SQLite wrote none. No answer was wrong, but each rewrite moves the finding's last-changed time |
| Cause | Probably the measurement's own data. It gives each fix a date with a time of day. The three server engines store the date alone, so the next scan's value never matches the stored one and the row is rewritten. SQLite keeps the time. Real scanner fix dates are midnight UTC, which would match. Not yet confirmed on an engine |
| Next | Rerun the measurement with midnight dates. If rows still rewrite, compare fix dates by calendar day. No test pins that an unchanged rescan with a fix date writes nothing |
