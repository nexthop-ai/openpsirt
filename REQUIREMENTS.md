# OpenPSIRT — Requirements

## Contents

- [1. What this is](#1-what-this-is)
- [2. What we are building](#2-what-we-are-building)
- [3. Requirements](#3-requirements)
  - [3.1 Product and delivery](#31-product-and-delivery)
  - [3.2 Ingest](#32-ingest)
  - [3.3 Vulnerability scanning](#33-vulnerability-scanning)
  - [3.4 What is tracked](#34-what-is-tracked)
  - [3.5 State and history](#35-state-and-history)
  - [3.6 Triage](#36-triage)
  - [3.7 Ranking and deadlines](#37-ranking-and-deadlines)
  - [3.8 Remediation](#38-remediation)
  - [3.9 Disclosure and publication](#39-disclosure-and-publication)
  - [3.10 Access and permissions](#310-access-and-permissions)
  - [3.11 Notifications](#311-notifications)
  - [3.12 Reporting](#312-reporting)
  - [3.13 Interface](#313-interface)
  - [3.14 API](#314-api)
  - [3.15 Security](#315-security)
  - [3.16 Data and operations](#316-data-and-operations)
- [4. Out of scope](#4-out-of-scope)
- [5. Rejected](#5-rejected)

---

## 1. What this is

What OpenPSIRT must cover. Not how it covers it — that is in the `DESIGN-*.md`
documents, which name the requirements they satisfy. What is left to build is
in `TODO.md`.

Identifiers are permanent. A requirement that is dropped is removed, and its
number is never reused.

---

## 2. What we are building

A tool that takes in the inventory a build produced, scans it for known
vulnerabilities here rather than in the build, tracks what changes release to
release, and lets people triage what it finds.

| | |
|---|---|
| **Input** | Inventories pushed by build pipelines, roughly nightly, with the suppressions the build carries patches for |
| **Users** | Staff, signed in with GitHub or Okta |
| **Output** | A triage queue, reports, advisories, and a record of what was decided and why |
| **Shipping as** | Open source, installed and run by others |

The hard parts, in order: the dependency graph, tracking change over time,
making triage decisions survive re-scans, and coping with the size range of the
inputs.

---

## 3. Requirements

### 3.1 Product and delivery

| # | Requirement | Why |
|---|---|---|
| REQ-01 | Open source under Apache 2.0, installed and run by people we never meet. Everything shipped is permissively licensed | The patent grant is what vendor legal teams look for. Self-hosting decides packaging, configuration and secret handling |
| REQ-02 | Ships as a container image and a Helm chart. A configuration that cannot work is refused at install time, naming what is missing | A pod that crash-loops is found in minutes; mail configured halfway is found when somebody asks why they were never told |
| REQ-03 | Runs as any number of replicas — no leader, no shared filesystem, no state in one process that decides anything | Scaling should be adding a node. The alternative is discovered the first time two replicas run, under load |
| REQ-04 | Publishes an inventory of itself, of the binary and of the image, and scans itself with them | A tool whose subject is knowing what is inside what you ship has to know what is inside what it ships |

### 3.2 Ingest

| # | Requirement | Why |
|---|---|---|
| REQ-05 | Takes in inventories pushed by build pipelines, one adapter per producer. A vulnerability report or a third party's VEX document may be uploaded alongside. CycloneDX is read; **SPDX is intended and not built** | Both reference producers emit CycloneDX, so it was written first. An adapter per producer keeps one internal model, which is the seam a second format arrives through |
| REQ-06 | An upload is accepted, queued and answered later. A scan applies whole or changes nothing, and only a scan newer than the state it replaces is accepted | A 46 MB file with 56,600 components cannot be parsed on the request, a half-applied scan looks like real change, and a badly-set build clock would otherwise rewrite current state with stale data |
| REQ-07 | Releases and variants are declared before a scan may name one. A scan naming something undeclared is rejected, saying what is missing | A misspelled release is indistinguishable from a real one |
| REQ-08 | Identity is derived from content. Nothing a scan file supplies is trusted to be stable between builds or consistent between producers | Producers reuse, renumber and reformat their own identifiers |
| REQ-09 | Sized and tested against the largest real input, never the average. Nightly branch scans are transient; tagged releases are retained and can be fetched back | One pipeline spans a thousandfold in input size, and storing every nightly scan in full is 200 million to a billion rows a year |

### 3.3 Vulnerability scanning

| # | Requirement | Why |
|---|---|---|
| REQ-10 | The deployment runs the scan, on a schedule, for everything it tracks. The component list always comes from the build — we re-scan, we do not discover | A producer-run scanner measures each product by whatever version its own pipeline installed, so nothing is comparable. The build knows what it shipped |
| REQ-11 | A build's own suppressions are applied and never re-decided | The build's judgment about the patches it carries is the one nobody here can improve on |
| REQ-12 | The scanner, its vulnerability database and the exploitation feeds all work with no network | Air-gapped installs need the offline path to work, not merely to exist |
| REQ-13 | Every finding records what produced it — which scanner, which version, which database, and how the match was made | "Why is this here" is unanswerable afterwards otherwise, and a scanner upgrade changes results |
| REQ-14 | Static analysis and fuzzing findings are intended scope. **Not built** | The finding model carries a kind from the start, so a second kind needs no rewrite |

### 3.4 What is tracked

| # | Requirement | Why |
|---|---|---|
| REQ-15 | The tracked unit is a product, a branch or tag, and a variant. A release carries a reversible end-of-life date, past which nothing is deleted or hidden | Multi-variant products are the interesting case, and auditors ask about releases long after they stop being supported |
| REQ-16 | The dependency graph is kept as nodes and edges and walked when asked, never flattened | A flattened path restates one fact once per route: 49,170 places for one shared library against 48 direct consumers |
| REQ-17 | A finding is one component at one place in one build. Twelve places is twelve findings, and grouping is presentation only | A dismissal that is true where a library is used one way is not true where it is used another |
| REQ-18 | An issue is one issue across every name it goes by, and everything a report says about it is kept | The same vulnerability arrives as a CVE identifier in one report and an advisory-database identifier in another, and a later report knowing more must not erase what an earlier one knew |
| REQ-19 | A flaw in our own product is recorded by hand, under an identifier this deployment mints, against every build that ships it | Nothing scans for it, and it is the class the disclosure process exists for |

### 3.5 State and history

| # | Requirement | Why |
|---|---|---|
| REQ-20 | Change over time is a primary query, not an audit log read backwards | "What is new since the last release" is the question the tool exists to answer |
| REQ-21 | Findings open and close themselves as scans change, every closure records why, and a disappearance nobody can explain is flagged at any volume | Nobody closes 441,108 findings by hand, and a silent disappearance is either a producer bug or a scanner regression |
| REQ-22 | Triage history is append-only, administrative changes record who and what changed from what, and what a scan observed is never merged with what a person declared | The record is what an auditor reads. Observed state is rewritten nightly; declared state is somebody's word |

### 3.6 Triage

| # | Requirement | Why |
|---|---|---|
| REQ-23 | Every finding takes one outcome from a fixed set: affected, not applicable, deferred, will not fix, already fixed here, and the two that promise work | A free-text disposition cannot be counted, exported or turned into a VEX statement |
| REQ-24 | Dismissing something needs a written explanation and a **second person's approval**. The proposer and approver are never the same person, with no override. A short deferral is exempt at a threshold the deployment sets, applied to cumulative deferred time | Hiding risk needs agreement; re-exposing it does not. Every deferral needing a second person makes triage unaffordable, and unlimited deferral makes approval meaningless |
| REQ-25 | A decision survives re-scans, lapses only when the software changes, and carries automatically to other releases, tags and variants whose chains and versions already match | A decision that lapsed nightly would be re-made nightly, and the same finding across a dozen builds is one judgment |
| REQ-26 | One judgment covers every place a finding sits at by default; narrowing it is deliberate | The default has to be the honest answer, because it is the one people take |
| REQ-27 | One action may record the same judgment against many issues at one component, bounded by a configurable cap, recording how the set was chosen | A kernel carries 5,088 issues at 45 places each. A bulk write with no cap is a denial of service somebody triggers by accident |
| REQ-28 | An approver works at the unit the proposer acted at, and can approve, send back or undo a batch as one act. An approval points at one revision of the justification, and editing the text withdraws it | An approver facing one row per place is given "select all", which is not review. Otherwise the text somebody agreed to can be changed afterwards, silently |
| REQ-29 | An opinion about the issue itself is recorded against the issue, applies wherever it appears including products it has not reached, and does not lapse when a version moves | An opinion should outlive the version it was formed about |
| REQ-30 | A deployment says what it considers worth triaging, and a product may say something narrower. Below the line a finding is still recorded, counted and reportable, and any list that hides something says how much | Nothing is hidden from a count by preference. A number that depends on who is looking lets a metric improve by editing a filter |
| REQ-31 | A third party's judgment — the build's, a supplier's VEX — is shown as evidence and offered as a prefill, and never decides anything by itself | "The distribution will not fix it" is not "we are not affected" |

### 3.7 Ranking and deadlines

| # | Requirement | Why |
|---|---|---|
| REQ-32 | Findings are ordered by one urgency, worked out from severity, known exploitation, exploitation likelihood, and whether the component reaches customers | Severity alone puts every critical in one bucket, and one image produces 335,021 findings (REQ-57) — so "look at the criticals first" names a population too large to order by hand |
| REQ-33 | Every finding above the line carries a deadline set by policy from its urgency. Being overdue is reported, never acted on automatically | Dates people can edit per item are dates that mean nothing |

### 3.8 Remediation

| # | Requirement | Why |
|---|---|---|
| REQ-34 | Work is assigned to a person or to a team. A team queue is picked out of rather than held, and work nobody holds is routed to a team by standing rule — a human assignment always wins | Ownership by a person cannot express a queue, and one rule naming a source package covers every binary built from it |
| REQ-35 | A fix is declared as the set of releases it targets, and resolution is computed from later scans rather than declared | "Done" that nobody verified is the thing every tracker gets wrong |
| REQ-36 | Hand-off to an external tracker is optional, off by default, and configured separately for public and private | This does not replace anybody's issue tracker |

### 3.9 Disclosure and publication

| # | Requirement | Why |
|---|---|---|
| REQ-37 | A flaw recorded here starts undisclosed and carries a disclosure date, defaulting to 90 days from when the report was received. Reaching it escalates rather than publishing | The reporter has a publication scheduled; ours is the clock that has to keep up |
| REQ-38 | Extending a disclosure date needs a reason and, past a threshold, approval — and it is raised before the date rather than on it | An extension nobody can agree to in time is an approval in name only |
| REQ-39 | An advisory is published about flaws in our own product, as a machine-readable document. A VEX document is generated per build from approved dismissals. **Delivery adapters are not built** | Known issues in shipped third-party components are tracked and fixed, not published about — but VEX is precisely the document for them, and it does not drift from prose nobody regenerates |
| REQ-40 | When an undisclosed finding is disclosed, the whole record goes public — comments, decisions, actors | People writing in the record have to know that from the first word |

### 3.10 Access and permissions

| # | Requirement | Why |
|---|---|---|
| REQ-41 | Sign-in is federated — GitHub and Okta — with **one provider configured at a time**, and **a person is one identity: a username, never a username scoped by the path it arrived on**. **No account is created for anybody nothing granted access to in advance**. Where roles are derived from identity-provider groups, the mapping an administrator made is that advance grant, and a record is written for somebody it covers on their first arrival; somebody in no mapped group is refused exactly as a stranger is. Roles come from groups or from grants, deployment-wide, never both modes at once | Access is granted in advance or not at all, and a hybrid is a permission nobody can explain the source of. Stated as "never on any path" it read as forbidding the one path where the advance grant is a mapping rather than a row, which is the mode's whole shape. Scoping an identity by the path it arrived on made one human two accounts: administration granted to one while the other was the one being signed in as, and one person able to be both the proposer and the approver of a dismissal, which REQ-24 forbids with no override |
| REQ-42 | Roles are granted per product, or across every product as one standing grant that covers products declared afterwards; administration is global. A product somebody holds no role on is invisible to them: not listed, not counted | A product name is itself information. A security team holds the same role across the estate, and issuing that one product at a time leaves every new product a permissions sweep across everybody — work that is silently half done |
| REQ-43 | Every finding carries a visibility, enforced in the data-access layer with a required subject — counts, aggregates, search and exports included. One person can be brought into one undisclosed case without being granted the product | Enforcement per handler is enforcement that is missing somewhere. The alternative to a per-case grant is granting the whole product to get one opinion |
| REQ-44 | Machine credentials are their own subject type: scoped, ingest-only, rotatable, and able to read back only their own uploads | A CI pipeline holding a person's rights is a person's rights on a build server |
| REQ-45 | Losing a role hands back the work it carried. We cannot detect that somebody has left, and say so | An identity provider never tells us an account was disabled, and somebody who left never signs in again |

### 3.11 Notifications

| # | Requirement | Why |
|---|---|---|
| REQ-46 | Every channel sits behind one interface and delivery is queued and retried. Email is required; chat adapters are **not built** | A channel that drops a message about a critical is worse than no channel |
| REQ-47 | Immediate mail only for something a person must act on. Everything else is an opt-in digest | A tool that mails on every scan is a tool people filter to a folder |
| REQ-48 | Nothing leaving this deployment about an undisclosed finding carries detail — not the identifier, not the component, not the summary. That there is something, and a link | The channel is somebody else's infrastructure |
| REQ-49 | Operational alerts are their own category: condition-based ones clear themselves, event-based ones are acknowledged, and each goes to somebody who may read what it names | An alert nobody can clear is an alert everybody ignores, and a notification is a read of the thing it names |

### 3.12 Reporting

| # | Requirement | Why |
|---|---|---|
| REQ-50 | Any list that can be read can be exported as a file, through the same visibility rules the list was read with | An export that skips the check is the leak |
| REQ-51 | Any two releases can be compared — fixed, newly present, still present — in a form that goes into release notes | This is the question a release manager asks, and it is not only about adjacent releases |
| REQ-52 | Scan coverage is reportable: what is being scanned, when each artifact was last seen, and what has gone stale | A pipeline that quietly stopped uploading looks exactly like a product with no findings |
| REQ-53 | Dismissals, deadlines, approvals and how long triage is taking are reportable in their own right, including the exception report that should come back empty | An auditor's first question is which dismissals nobody agreed to |
| REQ-54 | Trends are plotted on the axis the subject has: calendar time for a branch, release over release for tags | Tagged releases are frozen points, not a time series |

### 3.13 Interface

| # | Requirement | Why |
|---|---|---|
| REQ-55 | Every screen works on a phone. Small screens are for reading and responding, not bulk work | Approving something from a phone is the case that actually happens |
| REQ-56 | The dependency tree is browsable both ways: from a finding to where it sits, and from any node to the findings beneath it | "Where does this actually come from" is the first question about any finding |
| REQ-57 | The findings list is one row per issue at a component, with the places under it, and it is the tool for building a batch | 335,021 rows for one image is not a list anybody reads |
| REQ-58 | One home page assembled from what the person holds, leading with the work, and one scope picker that narrows the whole interface. A screen that cannot answer at the chosen scope says so | Not a different landing page per role, and a narrowed page that claims to be the unnarrowed one is worse than a refusal |
| REQ-59 | Nothing a person typed is lost — not by a failed submission, a navigation, or an expired session | Losing a forty-line justification is how people stop writing them |
| REQ-60 | Labels are the conventional word for the thing, every count says what it counts, and every filter in force is visible and removable one at a time | A screen full of invented vocabulary is a screen people misread |

### 3.14 API

| # | Requirement | Why |
|---|---|---|
| REQ-61 | REST and JSON, with the OpenAPI document generated from the code and never hand-maintained. The web interface is a client of it, with no private endpoints | A hand-written specification drifts, and it keeps the interface from becoming privileged |
| REQ-62 | Every operation declares what it asks of a caller, and a gate refuses one that declares nothing | "Who may call this" should not be a question you read source code to answer |
| REQ-63 | Documentation is published, versioned, and built from the same specification the application serves. The application itself serves none | It leaves no unauthenticated route at all |
| REQ-64 | Findings are answerable across every product a caller may see, and one page answers for an issue | "A critical just landed in openssl — which of our products ship an affected version" |
| REQ-65 | Markdown is what a person writes and what the API returns, with what each reference resolved to traveling beside it | An integrator can lay out markdown; resolving a mention needs data and checks they do not hold |

### 3.15 Security

| # | Requirement | Why |
|---|---|---|
| REQ-66 | Untrusted input never becomes SQL, markup or a filesystem path. Values are parameterized, identifiers come from an allowlist, and text a scan file supplied is never rendered | A placeholder cannot bind a column name, so a sort column from a query parameter is the live hole. A scan file is a third party's data rendered to staff who hold the most access |
| REQ-67 | Markdown a person writes is policed on the server at submission, before storage: no raw HTML, restricted link schemes, and nothing fetched from anywhere when it renders | A rendered document that fetches a remote image leaks who read it and when |
| REQ-68 | Credentials are stored hashed, shown once, and never logged at any level | A credential this deployment can read back is one an operator, a backup, a support session and anybody who reaches a log already holds. Shown once is what makes the hash honest: a value that can be recovered was never really hashed, it was merely stored twice |
| REQ-69 | Ingest is bounded — file size, nesting depth, component count — every written field is length-bounded, and outbound requests reach only their configured host | A scan file is hostile input, and the deployment sits inside somebody's network |
| REQ-70 | Attachments are stored outside the database, in no public bucket, and every fetch is authorized against the finding it hangs off before any URL is issued | A signed URL issued before the check is the check not happening |

### 3.16 Data and operations

| # | Requirement | Why |
|---|---|---|
| REQ-71 | Four database engines are supported and tested: PostgreSQL, MySQL, MariaDB, and SQLite for development | An operator runs this against whatever they already have. A skipped engine passes, so all four run in CI |
| REQ-72 | The application creates and migrates its own schema at startup, with one instance migrating at a time | An operator should not have to run a migration step to get a working deployment |
| REQ-73 | High-volume history ages out by dropping partitions, exported before it goes | Large deletes on a table this size are an outage |
| REQ-74 | Nothing is made faster until it is measured slow. No cache, precomputed total or refresh job without a measurement behind it | A stale answer is a cost paid up front for a benefit nobody has demonstrated, and it brings invalidation, drift, and a number that is wrong in a way nothing reports |
| REQ-75 | Static analysis, vulnerability scanning, dependency review, secret scanning and the license check gate every change, and every finding reproduces locally with one documented command | A gate that cannot be reproduced locally is a gate people learn to re-run until it passes |

---

## 4. Out of scope

| | |
|---|---|
| Generating SBOMs | We ingest them |
| A portal that vulnerability reporters submit to | A flaw somebody reports is recorded by hand, with who reported it and when (REQ-19) |
| Being a CVE Numbering Authority | |
| Deploying fixes | Remediation is tracked (REQ-35); nothing ships from here |
| Customer-facing status pages | |
| License and compliance analysis of SBOM contents | Adjacent, and likely to be asked for. Noted, not built |
| Replacing an issue tracker | Hand-off is optional and configured (REQ-36) |
| Multi-tenancy | One deployment serves one organization. Isolation by having no shared boundary is stronger than isolation by remembering a filter — and the filter would live where reports, aggregates and exports do |

---

## 5. Rejected

Asked for, and deliberately not built.

| Rejected | Why |
|---|---|
| **Hiding a finding from a count by anything but a decision** | A preference that changes a number makes "312 open criticals" depend on who is looking, and lets a metric improve by editing a filter. A filter narrows a list, rides in the URL, and reports what it hid (REQ-30) |
| **Dismissing everything under a container in one action** | One sentence answering a thousand findings is the shape that makes a dismissal unreadable afterwards, and what is true of a container is rarely true of everything in it. Triage cost is answered at axes where the claim stays honest (REQ-26, REQ-27) |
| **A pass/fail gate in the build pipeline** | An upload answers before the documents are parsed, and what a scan reports depends on what the vulnerability database knows that day rather than on what the commit changed — so the same commit passes today and fails tomorrow. That is the property that makes a gate get switched off. A build that introduced a known-exploited critical tells somebody instead (REQ-49) |
| **SSVC as a vocabulary over the ranking** | Its usual form is for a deployer patching an estate or a coordinator triaging incoming reports. This tool is vendor-side, and its audience asks for CSAF, VEX, CVSS and exploitation data. Adopting a named framework is a standing commitment to track it as it revises |
| **Detecting abandoned dependencies to explain a finding with no fix** | Measured on a real image: of 1,125 findings with no fix, 1,113 are distribution packages. The maintainer is Debian, which is not dead |
| **"Contained another way" as an outcome of its own** | Already sayable as not-applicable with the standard justification for existing mitigations. VEX puts this distinction in the justification rather than the status |
| **Storing when a vulnerability was disclosed** | Nothing we read supplies it. The scanner reports when a fix appeared, never when the issue did |
| **Versions inside the identity of a place** | The top-level version changes every build, so every decision would lapse nightly |
| **Backport tracking through pull requests tagged with a target branch** | Assumes commit and pull-request linkage we do not have. The same picture is derived from scans (REQ-35) |
| **A reverse proxy at the ingress as the only sign-in** | Works in Kubernetes, does not travel to self-hosted or local development |
