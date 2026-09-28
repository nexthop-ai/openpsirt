# TODO

Everything still in scope and not built.

Nothing else may reference this file. Anything durable belongs in
`REQUIREMENTS.md` or a `DESIGN-*.md`.

## Contents

- [Before 1.0](#before-10)
- [Deferred by the owner](#deferred-by-the-owner)
- [Decided, not built](#decided-not-built)
- [Known gaps](#known-gaps)
- [Weak tests](#weak-tests)
- [Owner decisions outstanding](#owner-decisions-outstanding)
- [Measured and left alone](#measured-and-left-alone)

## Before 1.0

Required for 1.0, and wrong to do earlier.

| Work | Why it waits |
|---|---|
| Collapse the migrations into one | 1 to 36 stay because v0.1.0 applied them, 37 and 38 because v0.2.0 and v0.3.0 tagged them, and 39 is the untagged release's own. v0.4.0 changed no schema. The collapse keeps one upgrade, from the last 0.x release, so a database that release built is upgraded rather than recreated |
| Start keeping schema and API compatibility | Below 1.0 an upgrade may change the API, and only a database from a tagged release is upgraded in place (REQ-76) |

## Deferred by the owner

The owner has chosen to wait on each of these.

| Work | Where it stands |
|---|---|
| Sending an advisory to somebody's platform | OpenPSIRT writes a provider directory that a web server serves. Every other destination needs its own adapter (REQ-39) |
| Signing published advisories, and publishing the key | Needs key material, which is configuration the deployment does not take |
| Becoming a CVE Numbering Authority | Likely after 1.0. Filing CVEs by hand does not scale, and it needs the same kind of credentials as signing |
| Exploitation sources beyond the known-exploited catalog | A commercial catalog or an exploit feed. Each needs somewhere to configure a license and a key, and none exists |
| Remediation deadline windows per product | There are two sets of windows for the whole deployment: one for scanned findings, one for flaws in our own product |
| The VEX profile of the CSAF advisory | Needs a mapping from each decision to the releases it covers |
| Microsoft Teams and Google Chat | Slack and Zulip are the chat platforms. A Teams direct message needs a workflow in the tenant or a registered bot, and a Google Chat one a Chat app installed for the people it reaches |
| Asking GitHub or GitLab which branches hold a commit | Patch branches clone each repository. An API call would skip the clone for a repository with few linked commits |
| Fetching a repository from a mirror | The kernel stable tree is 5.1 GB from kernel.org and 1.1 GB from a mirror that sends commits only |

## Decided, not built

A decision in `REQUIREMENTS.md` is in force and nothing implements it.

| Decision | Missing |
|---|---|
| REQ-05 | A producer's own vulnerability report uploaded beside an inventory. The upload takes the inventory and its suppressions only |
| REQ-14 | Findings from static analyzers and fuzzers |
| REQ-36 | Opening or updating an item in an external tracker. A finding stores a link somebody typed, and nothing follows it |
| REQ-73 | Purging old data by exporting rows to a file and then dropping them. Nothing is purged or partitioned, and the column to partition on is undecided |
| REQ-82 | Each issue's published and last-modified dates, read from a public vulnerability database. Nothing asks one |

## Known gaps

Missing or wrong, with no decision needed to fix it.

| Gap | Effect |
|---|---|
| The upload alert compares against the size of the build | A build that rolls its base image every week raises the alert every week. Comparing against the build's usual churn needs a stored baseline |
| The container image is `amd64` only | The binaries are built for `arm64` too. `DESIGN-packaging.md` names the fix |
| No distribution package index is asked what a package is | A language package gets a summary and a project address from its index. A distribution package gets only a link to its distribution's package page, built from its name |
| A build cannot be asked which licenses it ships | Each component's license is read and shown on its page. No listing, filter or export gathers them across a build |
| The component screen's twelve-week chart does not mark version changes | It shows findings opened and closed, and not which version the build shipped each week, so it cannot show whether an upgrade worked |
| A version 4 CVSS score is left out of published advisories | CSAF 2.0 has no field for one. A flaw rated only under 4.0 publishes no score until the document moves to CSAF 2.1 |
| Advisories carry no document-level notes of our own | The title and each issuance's revision summary are typed here. Everything else is assembled from the flaws it covers |
| The review queue cannot be narrowed by what is waiting | A claim awaiting agreement, a lapsed decision, a deferral that ran out and a promise past its date share one list |
| No single view of an upgrade promise across the builds it names | Each build answers for itself. The promise already records the releases, the version and the date, so the view reads nothing new |
| Mail is plain text only | An HTML part needs a markdown renderer on the server, and none exists |
| The interface has no spacing scale | Six tokens name values already in use, and most spacing is written by hand at many sizes. Choosing a scale is a design judgment made in a browser |
| Nothing checks that every API operation is reached by some screen | An operation no screen calls is found only by reading |
| Other multi-step flows lack a visible next step | Recording a decision says a second person must approve and offers no way to the review queue. A fix offers no way to the release that ships it |
| A flaw found here and upgraded from v0.2.0 or earlier has no report | Those releases kept nothing saying who recorded it. A later claim about it is accepted as the flaw where it should be ruled a duplicate |
| No real producer's SPDX 3.x output is a fixture | The SPDX 3.x fixtures are the specification's own examples. Yocto and one vendor tool emit it |
| A build's own claim versioned only by branch covers every version | A claim attached to a scan is stored with no version column, so a claim naming no package identifier covers every version of its name. The uploaded VEX path keeps the version |
| Patch branches cannot clone through an outbound HTTP proxy | The fetcher connects directly, so a network with no direct route out fetches nothing |
| The exploitation clock starts when a scan sees the catalog listing | The catalog's own date for the issue is not read, so the pipeline's lag counts against the window |

## Weak tests

| Test | Problem |
|---|---|
| The scanner subprocess | The double does not check the arguments the scanner is given |
| The bump-list sort sweep | Checks only that each offered order answers. An order with no expression also answers, sorted by the default. The findings list pins its keys to expressions |
| The connection-pool timeout | Dials a port that refuses at once, so the timeout is never reached. The pool bound is compared against the function that sets it |
| The upstream-currency retry | Runs one pass, so nothing is asked again |
| The empty-document reader | Its comment says an empty part is refused, and it asserts that the part is stored |
| Scanned builds in the API tests | Several tests build a scanned build by hand. The shared fixture has helpers for the catalog and people only |

## Owner decisions outstanding

Each needs the owner to choose before anything is built.

| Question | Background |
|---|---|
| Name the other builds a finding sits in? | The finding says how many. The issue screen lists them one click away |
| Keep the screen's short list of weakness names? | The screen shows a short list in plain words. Published advisories use the full CWE catalog |
| Offer saved filters on the all-products findings list? | Saved filters belong to one product, so the list the home screen's tiles open has none |
| Have the server list the package kinds present? | The package-kind filter is a fixed list. A kind missing from it is reachable only by editing the address |
| Add a gate for tracker references in comments? | The rule is enforced by reading. No existing gate fits it |
| Alert on the depth of the job queue? | The System screen shows the depth against the bound. An alert needs a threshold and an alert kind |
| Keep 30 days as the longest a sign-in lasts? | It bounds how long a role a group withdrew can still be held. 90 days is defensible |
| Start a disclosure date for an outside report ruled a duplicate? | The flaw was found here and has no date, and the outside reporter may be counting down to publication |

## Measured and left alone

Nothing is made faster until it is measured slow. These were measured and left.

| Measurement | Result |
|---|---|
| A rescan of unchanged data | Rewrites every finding with a fix on PostgreSQL (1.3 s), MySQL (782 ms) and MariaDB (711 ms): 5,882 rows at the scale measured. SQLite writes none. The likely cause is how the date a fix arrived survives a round trip. No answer is wrong |
