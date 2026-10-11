<picture>
 <source media="(prefers-color-scheme: dark)" srcset="assets/openpsirt-logo-wide-dark.svg">
 <img alt="OpenPSIRT" src="assets/openpsirt-logo-wide.svg" width="420">
</picture>

# OpenPSIRT

Product security incident response for the software you ship.

OpenPSIRT is an open-source home for a product security team. It reads the SBOM
each build produces, scans every build in one place, and carries each finding
through triage to a verified fix and a published advisory.

!!! note "Alpha"
    Below 1.0 the API and the schema carry no compatibility promise. A
    database built by a release is upgraded in place, or, where it is too
    old, through an earlier release first; a database built by a release
    candidate or any other earlier build is recreated.
    [Current state](built.md) says what is built and what is not.

## Highlights

| | |
|---|---|
| Built for products | A finding is one component at one place in one build you ship, so a judgment holds exactly where it was made |
| Built for scale | One real product image carries 335,021 findings. Fix bundles group them by the upgrade that closes them, and one act answers a bundle |
| Built for audit | Every dismissal has a written reason, a second person's approval and an append-only history |
| Built for disclosure | CSAF 2.0 advisories, a CSAF provider directory, and an OpenVEX document for every build |
| Built to be yours | Apache 2.0. It runs on your infrastructure, on PostgreSQL, MySQL, MariaDB or SQLite, with or without a network |

## Cyber Resilience Act

The EU Cyber Resilience Act, [Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj), sets vulnerability
handling requirements for products with digital elements. Its reporting
obligations apply from 11 September 2026, and the rest from 11 December 2027.
OpenPSIRT keeps the records those requirements ask a manufacturer to produce.

| Requirement | OpenPSIRT |
|---|---|
| Annex I Part II (1): identify and document the product's components, in a software bill of materials | The SBOM of every build is kept as a dependency graph. Each finding names its component and the path that pulled it in |
| Annex I Part II (2): remediate vulnerabilities without delay | A deadline is set by policy from severity and known exploitation. A fix is declared for the releases it targets, and the next scan of each release confirms it arrived |
| Annex I Part II (4): disclose fixed vulnerabilities | CSAF 2.0 advisories stating each release's status, written into a CSAF provider directory |
| Annex I Part II (5): a policy on coordinated vulnerability disclosure | A report from outside carries a disclosure date, 90 days by default. Moving it takes a reason, and past a threshold a second person |
| Annex I Part II (6): share information about vulnerabilities, including in third-party components | A supplier's VEX documents and CSAF advisories are read and applied at the versions a build ships. Each build publishes its own VEX document |
| Article 14: report an actively exploited vulnerability, with an early warning within 24 hours, a notification within 72 hours, and a final report within 14 days of a fix | The moment exploitation became known is recorded. An administrator declares each notice window, in hours from that moment or from the release carrying the fix. An alert is raised as each window opens and passes, and every notice given is recorded |

Security testing and the delivery of updates, points (3), (7) and (8), belong
to the build and release process. OpenPSIRT confirms that each update reached
each release. It sends nothing to ENISA or a CSIRT, and it states no verdict:
whether an obligation applies, and whether it was met, is the manufacturer's
reading of the regulation.

## FIRST PSIRT Services Framework

The [FIRST PSIRT Services Framework](https://www.first.org/standards/frameworks/psirts/psirt_services_framework_v1.1) describes the services a product security
team provides, in six service areas. OpenPSIRT carries the work of five.

| Service area | OpenPSIRT |
|---|---|
| 1 Stakeholder ecosystem management | Work assigned to people and teams, notifications by mail, webhook, Slack and Zulip, the credit a finder asked for carried into the advisory, and metrics on triage time, deadlines and approvals |
| 2 Vulnerability discovery | Reports recorded before anybody judges them, dated from when they arrived, under a reference per product. Every build rescanned on a schedule, shipped releases included, with supplier advisories read beside it |
| 3 Vulnerability triage and analysis | One outcome per finding, a judgment for every report, and a second person for every dismissal |
| 4 Remediation | A fix declared for the releases it targets and confirmed by their scans. Incidents recorded against the product they hit, with their notice windows |
| 5 Vulnerability disclosure | A disclosure date on every report from outside, an issue held undisclosed until somebody discloses it with a reason, notices recorded as given, and CSAF advisories marked TLP:RED while anything they cover is undisclosed |
| 6 Training and education | A program for people, outside what a tool does |

## Triage at scale

A large SBOM holds thousands of findings, most of them answered by a handful of
upgrades. OpenPSIRT shows the handful.

| Capability | What it does |
|---|---|
| Fix bundles | Findings grouped by the upgrade that closes them. On a real image 5,047 fixable rows are 271 upgrades, and one kernel upgrade closes 917. One act answers a bundle, and the next scan confirms it |
| Source packages | Binary packages built from one source upgrade together. curl, `libcurl4t64` and `libcurl3t64` are one decision |
| Patch branches | A report lists the fix as bare commits. OpenPSIRT labels each with the branches that hold it: one kernel issue names five commits, for 6.1, 6.6, 6.12, 6.16 and the mainline. Optional |
| Bulk judgments | One act records one judgment across many issues at a component, with how the set was chosen |
| Judgments that travel | A judgment carries to every release, tag and variant whose dependency chain matches, and the nightly scan leaves it standing |
| Supplier statements | A supplier's statement that its product is not affected closes every finding reached only through that product |
| Dependency paths | The graph is kept and walked when asked. One shared library was 49,170 flattened paths and 48 direct consumers |
| Upstream currency | The newest upstream release of a component, from the Go, npm, PyPI, Cargo, Maven and NuGet indexes. Optional |

## Accuracy

| Property | |
|---|---|
| Identity from content | Nothing a scan file supplies is trusted to stay stable between builds or match between producers |
| Findings at their place | Twelve places are twelve findings. A judgment holds at one place and lapses at another when the code there moves |
| Every closure explained | A finding closes as upgraded, removed, patched, revised or superseded. One that disappears with no explanation is flagged |
| Wrong matches stay answered | A claim that the scanner matched the wrong component stands at every version until somebody withdraws it |
| CVE records applied | A finding whose release the CVE record states is unaffected closes, and opens again if the record changes |
| Provenance on every finding | The scanner, its version, its database and how the match was made |
| Versions compared only where defined | Upgrades are ordered for Debian, RPM, Alpine, PyPI, Maven, NuGet and Semantic Versioning, and left unordered elsewhere |
| Shipped releases rescanned | A vulnerability published after a release ships is still found in it |
| Fixes verified | Nothing is marked fixed by hand. A release is clear when its scan stops holding the issue |

## Separation of duties

| Control | |
|---|---|
| Two people for a dismissal | The proposer never approves their own, with no override |
| Approval bound to text | An approval points at one revision of the reason, and editing the text withdraws it |
| Append-only history | Each record is written in the same transaction as the act it describes |
| Visibility in the data layer | A product somebody holds no role on is not listed and not counted, in lists, totals, search and exports alike |
| Public and private work | Read and triage are granted separately for public and private findings, per product |
| Machine credentials | Scoped to ingest, rotatable, and able to read back only their own uploads |

## Deployment

| | |
|---|---|
| Inputs | The SBOMs your builds already produce: CycloneDX, and SPDX 2.2, 2.3 and 3.x. OpenPSIRT generates none |
| Packaging | A container image, a Helm chart, and binaries for Linux on amd64 and arm64 |
| Databases | PostgreSQL, MySQL and MariaDB, and SQLite for trials. Every change is tested on all four |
| Scale out | Any number of replicas, with no leader and no shared filesystem |
| Air gap | The scanner, its vulnerability data and the exploitation feeds run with no network, loaded from a bundle |
| Sign-in | OpenID Connect, GitHub, or a trusted header |
| API | REST and JSON, described by an OpenAPI document generated from the code. The web interface uses it and nothing else |

## Next steps

| | |
|---|---|
| [Evaluation](trying.md) | Standing one up to look at |
| [Current state](built.md) | What is built, and what is not |
| [Build pipelines](pipeline.md) | A pipeline declares the target, mints a key and posts the inventory |
| [A vendor's release](vendor-release.md) | Loading a vendor's SBOM and VEX document, so their judgments are recorded as theirs |
| [Configuration](configuration.md) | Every setting, and what reads it |
| [API reference](reference/api.md) | Every operation, generated from the server |
| [Privileges](reference/privileges.md) | Which role reaches which endpoint |

The reasoning behind every decision is in
[REQUIREMENTS.md](https://github.com/nexthop-ai/openpsirt/blob/main/REQUIREMENTS.md).
