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

## Decided, not built

A decision that exists and is not implemented, so it is scheduled rather than a
gap somebody rediscovers by auditing.

| Decision | Waits for |
|---|---|
| REQ-14 | Ingesting static analysis and fuzzing findings. The finding model already carries a kind, so a second kind needs no rewrite |
| REQ-76 | Reading SPDX 3.0, which is refused by name. It is a second vocabulary rather than a branch in the 2.x one — a flat graph of typed elements sharing no key path with it — and what it waits for is a fixture from a producer this ingests. Nothing that does emits it: the scanner shipped here emits 2.3 and tag-value, and so does the reference producer. Yocto and one vendor tool emit it, so the fixture is gettable rather than hypothetical |

## Known gaps

| Gap | |
|---|---|
| The published image is `amd64` only | The binaries are cross-compiled for `arm64` as well; the image cannot follow while the stage that catalogs what it ships runs the cataloger at the target architecture, which puts `node`, `go` and `syft` under emulation. `DESIGN-packaging.md` names the fix |
| No screen gathers what exists per tag | Navigating to a tag lands on a build's findings list, as though it were a branch. Every piece exists — what was fixed since the last release, the advisories, the VEX document, the register — and they sit in four places. What belongs there is settled; the screen is not built |
| Nine `react-hooks/set-state-in-effect` warnings | Nine components reset local state from an effect when a prop changes or a panel opens. The fix is to remount with a key, which changes how they are mounted rather than what they do, so each needs driving in a browser. The rule reports rather than refuses, deliberately: the count is the honest measure of the work |
| Screens not driven in a browser | "Take this" on the finding and the unassigned bar, the decision form opening with nothing chosen, the way down drawn as one hop where the route up is unknown, "sees nothing" on People, the dropped-mention line under the comment box, and the inventory list's numbers. The type check, lint, unit tests and endpoints behind each pass; nobody has looked at the pixels |

## Measured, recorded, not fixed

Nothing is made faster until it is measured slow. These were measured and left.

| | |
|---|---|
| The receipts page pairs runs quadratically | About a millisecond at the start of a year of nightly scans and about four at the end. A decade is four hundred milliseconds of arithmetic in the application |
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
