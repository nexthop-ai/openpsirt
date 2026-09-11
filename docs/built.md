# What is built

OpenPSIRT is in early development. Nothing is compatible with anything yet: a
schema change edits the migration that created the thing, and a development
database is recreated rather than migrated.

| Area | Where it has got to |
|---|---|
| Build and validation | The pipeline, and a gate that runs the tier a change lands in |
| Database | All four engines, with the schema created and migrated at startup |
| Catalog and graph | Products, streams, variants, and the dependency graph |
| Ingest | Inventory upload and the reader behind it, with the suppressions a build carries |
| Scanning | Run here, findings tracked over intervals, everything tracked scanned again on a schedule |
| Sign-in | OIDC, GitHub or a trusted header, with sessions, API keys and personal tokens |
| Access | Roles and visibility, enforced in the data layer |
| Triage | Decisions, approval, revision history, comments, bulk claims and the review queue |
| Remediation | A fix is declared rather than completed: somebody says which releases it is meant to reach, and the next scan of each answers whether it arrived |
| Reporting | Release-to-release comparison, trends, deadlines, release readiness, and what a new line would inherit |
| Notifications | An area inside the application, and mail out of it: the categories worth interrupting somebody for go immediately, a daily digest — off until asked for — carries the rest, and a message about an undisclosed finding says only that there is something |
| Private findings | A flaw is recorded by hand from the findings list of the build it is in. It starts undisclosed, its embargo has an end, moving that end costs a reason and past a threshold a second person, and the date arriving tells somebody |
| Advisories | A CSAF document and a per-build VEX document, generated from what is already held. Generated is all: nothing is sent anywhere |
| Web interface | Sign-in, home, the catalog, findings, finding detail, the dependency tree, decisions with their history, the review queue, assignment, bulk triage, inventory upload, release comparison, people and roles, and settings — embedded into the binary and served from it |
| Also built | Files hanging off a finding, authorized against what the finding's visibility allows; teams, and work routed to one by standing rule; a record of who changed a setting or a grant; and six lists that leave as CSV or JSON |

Not built: every adapter that would send an advisory somewhere, the VEX
profile of the CSAF document, chat, hand-off to an external tracker, findings
from a static analyzer, reading SPDX, and images for any architecture but
`amd64`.

The reasoning behind each area is in
[REQUIREMENTS.md](https://github.com/nexthop-ai/openpsirt/blob/main/REQUIREMENTS.md),
and a `DESIGN-*.md` document describes how each one works.
