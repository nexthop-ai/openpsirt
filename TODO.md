# TODO

Everything still in scope and not built.

Nothing else may reference this file. Anything durable belongs in
`REQUIREMENTS.md` or a `DESIGN-*.md`.

## Contents

- [Before the first release](#before-the-first-release)
- [Deferred by the owner](#deferred-by-the-owner)
- [Decided, not built](#decided-not-built)
- [Known gaps](#known-gaps)
- [Measured, recorded, not fixed](#measured-recorded-not-fixed)
- [Not planned](#not-planned)

## Before the first release

Mandatory, and wrong to do earlier.

| | |
|---|---|
| Collapse the schema into one initial migration | Thirty-seven migrations describe the order things were thought of. They are kept until now because walking the chain catches an ordering mistake between two of them (REQ-72) |
| Start keeping schema and API compatibility | Until this point a schema change edits the migration that created the thing, and a development database is recreated (REQ-61 and REQ-72) |
| Promote a prerelease to a release | The publication path is built and exercised. What a plain `vX.Y.Z` adds is the compatibility promise, which cannot start while the two rows above are open — so tags before then carry a prerelease suffix (REQ-02) |

## Deferred by the owner

| | |
|---|---|
| Adapters that deliver an advisory | The document is generated and handed over; where it goes next differs completely by product (REQ-39) |
| The VEX profile of the CSAF document | Needs the mapping from a decision to the releases it covers. The dismissal vocabulary was aligned to VEX from the start, so no new words are needed |
| Server-side PDF rendering for reports | Printing is the browser's and the stylesheet is the record's, which covers what a report is taken away as today |
| A release note with nothing in it | `get-release-notes` answers 200 with a zero-byte body where nothing was fixed, and a caller cannot tell that from a truncated response or a wrong pair of builds. `finding.Notes` returns the empty string deliberately — a heading over nothing is a question in the reader's mind — and a test pins it, so changing what a published operation returns is a decision rather than a fix |
| Nothing *watches* how deep the queue is | How deep it is, per kind and against the bound, is on the System screen, so it is no longer a backlog nobody sees. What is left is the watching: the threshold it would be measured against and the alert kind it would raise, both of which are decisions |
| Where the ceiling on a sign-in belongs | Thirty days is in force and is a judgment rather than a commitment: it bounds how long a role a group withdrew can still be held, and ninety would be defensible. `DESIGN-access.md` records what is built; the number itself is the owner's to settle, and a decision row is theirs to add |
| Test doubles at three boundaries that have none | The mail sender, the scanner subprocess and process startup. Each is at 0.0% while the pure code in the same file is not, and each is silent when it fails: a newline in an SMTP header, the argv a subprocess is handed, and a process that serves the API against a stale schema while reporting ready |
| Six assertions that cannot be false | In the attachment name check, the SQLite migration lock, the sort conformance sweep, the connection-pool timeout, the upstream-currency retry and the empty-document reader. Each holds for every possible implementation of what it names, or compares a value against the only source that could have produced it |

## Decided, not built

A decision that exists and is not implemented, so it is scheduled rather than a
gap somebody rediscovers by auditing.

| Decision | Waits for |
|---|---|
| REQ-14 | Ingesting static analysis and fuzzing findings. The finding model already carries a kind, so a second kind needs no rewrite |
| REQ-46 | A channel per chat service, behind the interface mail uses, and a screen to configure one. The signed outbound request is not that: it is a general destination somebody points at whatever accepts it, and a channel translates a notification into what one service renders well. Sending a chat service a payload shaped for everything is the shape this is meant to replace |

## Known gaps

| Gap | |
|---|---|
| The published image is `amd64` only | The binaries are cross-compiled for `arm64` as well; the image cannot follow while the stage that catalogs what it ships runs the cataloger at the target architecture, which puts `node`, `go` and `syft` under emulation. `DESIGN-packaging.md` names the fix |
| A producer's own SPDX 3.x output as a fixture | Yocto and one vendor tool emit it, so this is gettable rather than hypothetical. What it would settle is which shapes a real producer actually uses; `DESIGN-ingest.md` records the limitation until it arrives |
| The license a scan states is dropped at parse | Measured on the 6,866-component switch image: 4,483 of them carry one, which is 65%. It is read out of the inventory and thrown away, so nothing can answer which licenses a build ships even though a permissive license is already something the project cares about (REQ-01) |
| A component screen keyed on a name rather than on the source package | The unit of work is one source package at one version, and the schema keys a commitment that way: `curl` at one version ships three binary packages, and nobody upgrades a binary. The screen is keyed on the component name instead, so sibling binaries of one source read as separate work and a name one build holds at two versions needs the reader to pick between them. Moving it moves the route, the endpoint and the store |
| No index is asked what a distribution package is | Three of the four language indexes serve a one-line summary and all four name an address, so a package from one of them can say what it is. A distribution's own description lives in its package index, which is one file for a whole release rather than one request per package — around 13 MB compressed for one Debian suite — and that is a different shape from the per-package asks. `DESIGN-findings.md` records it as unbuilt |
| Two read routes still publish a display name where a sign-in identity is documented | The administration trail fills `by`, documented as "who made the change, by sign-in identity", through the store's presentation helper, and the record-a-finding routes do the same for `asked_by` and `approved_by`. `Handles` is the batch lookup to use. The routes that round-trip a name — the collaborator list, the team members, the routing rules, and the role, credential and token listings — are fixed, each pinned by a person whose two names differ |
| A destination's address comes back whole from `list-outbound` | For Slack and for Teams the path **is** the credential: the token is in it and there is no other authentication, which is why the trail row beside the create records the host alone. The listing and the create response both return `row.URL`. Redacting it means deciding what a caller needs the address for, since somebody has to be able to tell two destinations apart |
| Every person in the `internal/httpapi` fixtures is seeded with no display name | So the identity and the label coincide, and a field publishing the wrong one of the two cannot be told from a field publishing the right one. Giving those people names is what would make the two rows above checkable, and it is deliberately not done until each field is settled one at a time |
| A prepared claim is one person's, so several triagers on one backlog drift | Saved filters and the claims they prepare are personal by design — no ownership, no permissions, and no arguing about whose filter is authoritative. What that costs is a shared vocabulary: "when you see this shape, here is the argument we have agreed on" is per person, so three triagers means three hand-copies drifting apart with no way to see that they have. It needs several people working one backlog to appear, which is the trigger for revisiting it. The line it is not about stays where it is: a rule prepares a claim and a person proposes it, and a rule proposing its own pending claim stays refused |
| The twelve-week history cannot mark where a version moved | The chart draws what opened and closed; what it cannot draw is the release the build was shipping at the time, which is the thing that says whether the last upgrade worked. Counts are what the trend answers, and a version for each week is a new read over the scan history. The build comparison gives one pairwise `from` and `to`, never a series |

## Waiting on the owner, from the interface audit

Each is a proposal rather than a change. **One of them is a wrong answer on
screen rather than a question** — the team queue below — and is marked as such,
because a list that mixes those two reads as though none of it is urgent.

| | |
|---|---|
| **An issue carries no published or modified date, and no date it became known-exploited** | None of the three is in what the scanner reports: its vulnerability record has a description, an advisory link, the scores, the estimate and the weaknesses, and no dates of its own. Recording them means a second source — the issue's own record, fetched — which is a capability rather than a field, and this project fetches nothing from a feed today |
| **A finding does not name the other builds carrying it** | It says how many. Naming them inline is a request per finding against the reach or the issue route, and the issue screen names every one of them a click away from the identifier in the heading — so what is left is whether that click is one too many, which is worth answering with somebody looking at the screen |
| **The weakness names are a short list rather than the catalog** | Around fifty are named inline, which covers what a real backlog is made of; every identifier links to where it is written up, so the rest are one click from their name. Shipping the whole catalog is about a thousand entries, and the question it raises is not the size — it is where the file comes from, what regenerates it, and under what terms, none of which is answered by pasting a list in |
| **Handing a selection over is a request per row** | The findings list assigns by looping the selection, one write each at about 400 ms, so two thousand rows — the deployment's own cap — is a quarter of an hour of round trips, and there is no "select all matching" as the bulk-claim screen has. Both halves want one endpoint that takes a narrowing and assigns what it resolves to, bounded the way a bulk judgment is. That is a capability rather than a fix |
| **A bulk claim refuses a selection covering something already decided** | It names which decision now, which is what somebody holding five hundred rows can act on. Skipping the decided rows instead is a different question: a bulk write that silently covers less than what was selected is one nobody can check afterwards, so if it is offered it is asked for rather than assumed |
| **Saved filters cannot be opened on the list that spans products** | They are stored per product, so the cross-product list — which is where the default landing view is — offers none. Making one span products is a change to what a saved filter is, and the position that they stay personal is about ownership rather than about scope |
| **The package-kind picker enumerates a set the API calls open** | The kind is read out of the identifier a producer wrote, so an image carrying `nuget`, `composer` or `swift` components can be narrowed to them through the address and not from the screen — and the next kind goes short the way `apk` and `rpm` did. The durable shape is the kinds actually present travelling with the read, with the labels a display map falling back to the raw word; that is a question the server does not answer yet, so it is a capability rather than a fix |
| **A tracker reference in a durable comment is not gated** | One was found by reading. `internal/tools/readable` walks every file type and is the gate positioned to carry it, but its whole subject is bytes a text tool skips — a second, unrelated rule there would make its name a lie. It is a gate of its own or nothing |
| **Eight other `internal/httpapi` tests hand-roll the scanned-build seed** | The one this touched now builds it once, in the file. The wider move is a helper in `internal/dbtest/fixture`, which seeds a catalog and has nothing for a scan, a graph or a finding |

## Measured, recorded, not fixed

Nothing is made faster until it is measured slow. These were measured and left.

| | |
|---|---|
| MySQL costs 14× MariaDB per statement | A night issues 1,699 statements on every engine: 203 µs each on MariaDB, 404 µs on PostgreSQL, 2,835 µs on MySQL. There is nothing to find in what the apply does; the lever is issuing fewer statements |
| One component on the demo has no walkable route to the build root | `golang.org/x/net` under `sonic-mgmt-common-codegen`. The consumer has edges upward, the depth bound of 64 is nowhere near reached, and the root exists. The row names the consumer instead of claiming nothing pulls it in, which is true whichever the cause. It may be a disconnected fragment in that inventory |
| The scan measurement covers one build and an assumed churn rate | A deployment tracks several. `make measure` re-runs it against a different model by changing the constants |
| Folding sibling components on the dependency tree buys 3.86% of the worst level | Measured on a real image: 159 of 345 parent-levels hold a foldable group, and folding every one removes 281 child rows of 36,991. The level somebody actually struggles with — a kernel module pulling in 4,867 components — becomes 4,679. It does not make a level browsable, which is what the search and the level cap are for, and aggregating `beneath` over folded siblings would double count whatever two of them both reach |

## Not planned

| | |
|---|---|
| Component library | The interface was built without one, from the mockup's own tokens and hand-written components — so the choice was made by building rather than by deciding |
| Client-side syntax highlighter | Loaded only by a view containing a code block. Grammar coverage against bundle cost, better weighed against a real screen (REQ-67) |
| Partition column and granularity | Which column, what granularity, and how to retire a whole product, which partitioning by time does not solve |
| External tracker hand-off | Optional. The seams are built rather than the integration (REQ-36) |
| Whether the interface decisions survive contact with use | Everything in the interface was decided from mockups. Some of it will be wrong in ways nobody can see from a picture. The first release is read as evidence rather than as confirmation |
