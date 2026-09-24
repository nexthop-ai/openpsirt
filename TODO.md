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
- [Not planned](#not-planned)

## Before 1.0

Required for 1.0, and wrong to do earlier.

| Work | Why it waits |
|---|---|
| Collapse the migrations into one | 1 to 36 stay because v0.1.0 applied them, 37 because it upgrades v0.1.0 to v0.2.0, and 38 onward because each changes a tagged release (REQ-72) |
| Start keeping schema and API compatibility | Below 1.0 an upgrade may change the API, and only a database from a tagged release is upgraded in place (REQ-76) |

## Deferred by the owner

The owner has chosen to wait on each of these.

| Work | Where it stands |
|---|---|
| Sending an advisory to somebody's platform | OpenPSIRT writes a provider directory that a web server serves. Every other destination needs its own adapter (REQ-39) |
| Signing published advisories, and publishing the key | Needs key material, which is configuration the deployment does not take |
| Becoming a CVE Numbering Authority | Likely after 1.0. Filing CVEs by hand does not scale, and it needs the same kind of credentials as signing |
| Exploitation sources beyond the known-exploited catalog | A commercial catalog or an exploit feed. Each needs somewhere to configure a license and a key, and none exists |
| Deadline windows per product | There are two sets of windows for the whole deployment: one for scanned findings, one for flaws in our own product |
| The VEX profile of the CSAF advisory | Needs a mapping from each decision to the releases it covers |
| PDF reports rendered on the server | Reports are printed from the browser |
| Asking GitHub or GitLab which branches hold a commit | Patch branches clone each repository. An API call would skip the clone for a repository with few linked commits |
| Fetching a repository from a mirror | The kernel stable tree is 5.1 GB from kernel.org and 1.1 GB from a mirror that sends commits only |
| Marking the patch for the branch a component ships | Matching a branch such as `linux-6.12.y` to a version works differently in every project |
| Cloning through an outbound HTTP proxy | The patch-branch fetcher connects directly, so a network with no direct route cannot use it |

## Decided, not built

A decision in `REQUIREMENTS.md` is in force and nothing implements it.

| Decision | Missing |
|---|---|
| REQ-05 | A producer's own vulnerability report uploaded beside an inventory. The upload takes the inventory and its suppressions only |
| REQ-14 | Findings from static analyzers and fuzzers |
| REQ-36 | Opening or updating an item in an external tracker. A finding stores a link somebody typed, and nothing follows it |
| REQ-40 | Disclosing a finding. Reaching a disclosure date escalates, and nothing makes a finding public |
| REQ-46 | Chat channels such as Slack and Teams. Mail and a generic signed webhook are the only channels |
| REQ-73 | Purging old data by exporting rows to a file and then dropping them. Nothing is purged or partitioned, and the column to partition on is undecided |

## Known gaps

Missing or wrong, with no decision needed to fix it.

| Gap | Effect |
|---|---|
| Approvers are not told when an edit withdraws their approval | Their approval stops counting silently. The API description of notifications says they are told |
| Some routes return a display name where a sign-in identity is documented | Affects the administration trail's `by`, its CSV export, and the disclosure-date movement routes. A caller matching on identity gets a name |
| The webhook listing returns each destination's full address | For Slack and Teams the address is the secret. Hiding it means deciding how somebody tells two destinations apart |
| The upload alert compares against the size of the build | A build that rolls its base image every week raises the alert every week. Comparing against the build's usual churn needs a stored baseline |
| The container image is `amd64` only | The binaries are built for `arm64` too. `DESIGN-packaging.md` names the fix |
| No distribution package index is asked what a package is | A language package gets a summary and an address from its index. A distribution package gets neither |
| A build cannot be asked which licenses it ships | Each component's license is read and shown on its page. No listing, filter or export gathers them across a build |
| The component screen's twelve-week chart does not mark version changes | It shows findings opened and closed, and not which version the build shipped each week, so it cannot show whether an upgrade worked |
| A version 4 CVSS score is left out of published advisories | CSAF 2.0 has no field for one. A flaw rated only under 4.0 publishes no score until the document moves to CSAF 2.1 |
| Advisories carry no text of our own beyond the title | Everything else in the document is assembled from the flaws it covers |
| The review queue filters by product only | No filter for what is waiting, who proposed it, its age or its severity |
| A judgment always covers every place a finding sits | Choosing a subset of the places is not offered |
| No single view of an upgrade promise across the builds it names | Each build answers for itself |
| Mail is plain text only | The server-side markdown renderer is kept for an HTML part that is not built |
| The interface has no spacing scale | Spacing is written by hand at many sizes. Choosing a scale is a design judgment made in a browser |
| Nothing checks that every API operation is reached by some screen | An operation no screen calls is found only by reading |
| Other multi-step flows lack a visible next step | Reporting a flaw was reworked so each step offers the next. Finding to decision to approval, and fix to release to VEX, were not |
| A flaw found here and upgraded from v0.1.0 has no report | v0.1.0 kept nothing saying who recorded it. A later claim about it is accepted as the flaw where it should be ruled a duplicate |
| `cgit.freedesktop.org` patch links fail | That project moved to GitLab. The System screen shows the failure |
| One demo component has no walkable route to the build root | `golang.org/x/net` under `sonic-mgmt-common-codegen`. The screen names the consumer. The inventory may hold a disconnected fragment |
| No real producer's SPDX 3.x output is a fixture | The SPDX 3.x fixtures are the specification's own examples. Yocto and one vendor tool emit it |
| The recorded scanner output is from grype 0.112.0 | The image ships 0.119.0. Re-recording changes what several tests assert |
| The scanner's memory use is not measured | The pod's limits are a judgment. A measurement of peak memory on the full-size fixture, cold and warm, would settle them |
| The interface is designed from mockups | Some of it will be wrong in ways that show only in use. The first release is evidence |

## Weak tests

| Test | Problem |
|---|---|
| Mail sending | No test double. The header sanitizer has no test |
| The scanner subprocess | The double does not check the arguments the scanner is given |
| Process startup | The stale-schema check is tested, and nothing tests that serving calls it |
| Attachment names | Feeds a path with no newline to a check for a newline |
| The SQLite migration lock | Compares the message against the only string that produces it |
| The sort sweep | Checks for a 200 only, which an unknown sort key also returns |
| The connection-pool timeout | Dials a port that refuses at once, so the timeout is never reached. The pool bound is compared against the function that sets it |
| The upstream-currency retry | Runs one pass, so nothing is asked again |
| The empty-document reader | Its comment says an empty part is refused, and it asserts that the part is stored |
| Scanned builds in the API tests | Several tests build a scanned build by hand. The shared fixture has helpers for the catalog and people only |
| People in the API tests | Most are seeded with no display name, so a test cannot tell a name from an identity. This hides the display-name gap above |

## Owner decisions outstanding

Each needs the owner to choose before anything is built.

| Question | Background |
|---|---|
| Refuse unknown query parameters? | A mistyped filter is ignored and the unfiltered list comes back. Refusing applies to every endpoint at once |
| Fetch each issue's own record from a vulnerability database? | The scanner reports no date an issue was published or modified. A second source per issue would supply them. Storing the date as a field alone is rejected in `REQUIREMENTS.md` |
| Count the exploitation clock from the catalog's date? | The clock starts when a scan learns an issue is exploited. The catalog states the date it added the issue, and nothing reads it |
| Name the other builds a finding sits in? | The finding says how many. The issue screen lists them one click away |
| Keep the screen's short list of weakness names? | The screen shows a short list in plain words. Published advisories use the full CWE catalog |
| Add an endpoint that assigns a whole selection? | Assigning loops one request per row at about 400 ms each, so 2,000 rows take about a quarter of an hour. There is no "select all matching" |
| Let a bulk claim skip rows already decided? | A bulk claim covering a decided row is refused, naming the decision. Skipping silently covers less than was selected |
| Offer saved filters on the all-products findings list? | Saved filters belong to one product, so the list the home screen's tiles open has none |
| Have the server list the package kinds present? | The package-kind filter is a fixed list. A kind missing from it is reachable only by editing the address |
| Add a gate for tracker references in comments? | The rule is enforced by reading. No existing gate fits it |
| Alert on the depth of the job queue? | The System screen shows the depth against the bound. An alert needs a threshold and an alert kind |
| Keep 30 days as the longest a sign-in lasts? | It bounds how long a role a group withdrew can still be held. 90 days is defensible |
| Share prepared claims between triagers? | Saved filters and the claims they prepare are personal, so several triagers on one backlog drift apart. Worth revisiting when a team works one backlog |
| Start a disclosure date for an outside report ruled a duplicate? | The flaw was found here and has no date, and the outside reporter may be counting down to publication |

## Measured and left alone

Nothing is made faster until it is measured slow. These were measured and left.

| Measurement | Result |
|---|---|
| A rescan of unchanged data | Rewrites every finding with a fix on PostgreSQL (1.3 s), MySQL (782 ms) and MariaDB (711 ms): 5,882 rows at the scale measured. SQLite writes none. The likely cause is how the date a fix arrived survives a round trip. No answer is wrong |
| Cost per statement | 2,835 µs on MySQL, 404 µs on PostgreSQL, 203 µs on MariaDB. The number of statements a night issues has moved since, so the ratio wants a fresh `make measure` |
| Folding sibling components on the dependency tree | Removes 281 of 36,991 child rows on a real image, and shrinks its worst level from 4,867 rows to 4,679. That level stays too large to browse |
| The scan measurement's model | One build and an assumed churn rate. A deployment tracks several. `make measure` takes different constants |

## Not planned

| Item | Reason |
|---|---|
| A component library | The interface is built from the mockup's tokens and components written here |
| A syntax highlighter for code blocks | Grammar coverage costs bundle size. Worth weighing against a real screen |
| Coordinating an embargo with other organizations | Shared embargoes, a coordinator's record and a peer vendor's schedule are organizational practice |
