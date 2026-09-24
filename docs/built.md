# Current state

The latest release is 0.2.0. Below 1.0 there is no compatibility promise for
the API or the schema. A database built by v0.1.0 or v0.2.0 is upgraded in
place, and a database built by any other earlier build is recreated.
[Configuration](configuration.md#upgrading) says what an upgrade changes.

## Areas

| Area | State |
|---|---|
| Build and validation | The pipeline, and a gate that runs the checks a change touches |
| Database | PostgreSQL, MySQL, MariaDB and SQLite, with the schema created and migrated at startup |
| Catalog and graph | Products, branches and tags, variants, and the dependency graph. Each is renamed and retired in place |
| Ingest | CycloneDX, SPDX 2.x and SPDX 3.x, with the suppressions a build carries, and a receipt per upload naming what it moved |
| Scanning | Run here on a schedule, findings tracked over intervals, CVSS 3 and 4.0 ratings kept side by side |
| Upstream and supplier data | Upstream currency, patch branches, and supplier advisories read from a CSAF provider directory. Each is off by default |
| Sign-in | OpenID Connect, GitHub or a trusted header, with sessions, API keys and personal tokens |
| Access | Roles per product or across every product, public and private as separate grants, enforced in the data layer |
| Triage | Decisions, approval, revision history, comments, bulk judgments, standing corrections and the review queue |
| Vulnerability reports | One form for every report, an inbox per product, and rulings that judge many reports in one act |
| Remediation | Deadlines from severity and exploitation, assignment to people and teams, and fixes declared for releases and confirmed by scans |
| Advisories | CSAF advisories with editorial states and a second person's agreement, a CSAF provider directory, and per-build OpenVEX documents with a revision chain |
| Obligations | Records of exploitation, the windows they may oblige, and the notices given |
| Reporting | Release comparison, trends, deadlines, release readiness, exception reports, and exports as CSV or JSON |
| Notifications | An in-application area, immediate mail, a daily digest, signed webhooks, and operational alerts |
| Web interface | Every screen above, embedded into the binary and served from it |
| Packaging | A container image and a Helm chart for `linux/amd64`, and binary archives for Linux on amd64 and arm64 |

## Not built

| Area | Not built |
|---|---|
| Ingest | Findings from a static analyzer or a fuzzer, and a producer's own vulnerability report uploaded beside an inventory |
| Supplier advisories | A publisher that serves its directory from a second host. Its advisories are uploaded instead |
| Patch branches | Asking a forge's API in place of cloning, and fetching through an outbound HTTP proxy |
| Triage | Narrowing a judgment to some of the places it covers |
| Disclosure | Disclosing a finding. Reaching a disclosure date escalates, and no path makes a finding public. A report from outside ruled a duplicate of a flaw found here starts no disclosure date. Coordinating an embargo with a peer vendor or a coordinator |
| Advisories | Sending one anywhere, signing the provider directory, the VEX profile of the CSAF document, a CVSS 4.0 score in the document, and prose of the deployment's own beyond the title |
| Remediation | Opening or updating an item in an external tracker; a link somebody typed is stored. One view of a promise to upgrade across every build it names |
| Notifications | Chat adapters, an HTML part in mail, and a notice that an edit withdrew an approval |
| Interface | Narrowing the review queue further than a product, and a deadline and an owner in a finding's header |
| Database | Purging old rows and partitioning tables |
| Packaging | Images for any architecture but `amd64` |

The reasoning behind each area is in
[REQUIREMENTS.md](https://github.com/nexthop-ai/openpsirt/blob/main/REQUIREMENTS.md).
