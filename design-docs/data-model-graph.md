# Dependency graph

The graph a scan describes, its history as intervals, what a scan changed, and
the occurrence a finding sits at.

Satisfies REQ-08, REQ-14, REQ-16, REQ-17, REQ-20, REQ-25.

## Contents

- [The dependency graph](#the-dependency-graph)
- [History as intervals](#history-as-intervals)
- [Inventory delta](#inventory-delta)
- [Occurrence identity](#occurrence-identity)
- [Path traversal](#path-traversal)
- [Limits](#limits)

## The dependency graph

Nodes and edges, never flattened (REQ-16): a flat list cannot answer "why is
this here".

| | Definition |
|---|---|
| Component | `design-docs/data-model-components.md` § Component identity |
| Node | That component's presence in one variant |
| Edge | One node depending on another |

| Rule | Reason |
|---|---|
| A component reached by several parents is one node with several edges | Routes derive from edges |
| The root, the product itself, is a flagged node excluded from identity and expiry (REQ-08) | Its version changes every build and its name per variant; upward walks stop at the flag |
| A scan naming no root is filed against the build it was sent for | |
| The root flag is reconciled every scan | Promoting or demoting a root otherwise leaves two flags or none |
| The root is not one of the build's components | |
| A component with no name is refused; one with no version is kept | It ships |
| An edge naming a component the snapshot does not list is refused | Edges to undescribed components are dropped and counted at read time, so one here is a snapshot built wrong |

## History as intervals

Every node and edge records the scan that opened it and, once gone, the scan that
closed it.

| Rule | Reason |
|---|---|
| Rows are closed, never deleted | What a release shipped is asked years later |
| Every root a build has had is read from an index of the build's roots | Rows are never deleted, so the read otherwise walks the build's whole history: 19.5 ms on PostgreSQL and 374 ms on MySQL 8.4 against 1.2 ms and 0.5 ms indexed, at 4,000 components a build with a hundred closed copies of each node |
| An unchanged build writes nothing | Storage grows with change, not the calendar (REQ-20). A test asserts it and was watched to fail with the comparison broken |
| One transaction | A half-applied graph reads as components removed |

## Inventory delta

What one scan made of a build's contents: names that arrived, names that went,
and names held at a different set of versions.

| Rule | Reason |
|---|---|
| Counted by name | An upgrade is one dependency moving |
| A name at two versions at once is one entry | A vendored tree ships one routinely |
| The root is excluded from both sides | Its version is not stored and its name differs per variant |
| An image held by name is at no version on either side | What each build stated is on the component screen (`design-docs/interface-component.md` § The component screen) |
| The earliest scan applied to a build has none | |
| Worked out when asked, never stored (REQ-20) | |

It is read off the intervals: a node stands before a scan where it opened
earlier and had not closed by then, and at the scan where it opened no later and
has not closed since; a node the scan closed stands on the near side. Accepted
scans of one build rise in identifier as in build time, an older scan being
refused on arrival.

| Rule | Reason |
|---|---|
| Only names a scan opened or closed a row of are compared, each at the scans that touched it | No other name can have moved |
| Rows standing on neither side of any scan on the page are not read | Otherwise a page of fifty took 78 ms behind 73 nights on SQLite and 264 ms behind 365 |
| The build's rows are read once, by build, and matched to names in the application | Joined per name, PostgreSQL took 40.5 s for an upload touching 54,902 names, against 0.76 s |

`design-docs/data-model-measurements.md` § Inventory delta timings has the runs.

### The names behind the counts

The counts and their names are one fold over the same rows.

| Rule | Reason |
|---|---|
| Removals first, then arrivals, then names at new versions | A build that stopped describing a dependency looks like one that stopped shipping it |
| Every version of a name, on each side | |
| The name as a producer wrote it | |
| Versions are ordered as text | Proper ordering is per-ecosystem |
| A page is cut after the comparison | |

### Comparison of two builds

Any two builds of one product compare by the upload listing's fold, the earlier
before and the later after.

| Rule | Reason |
|---|---|
| Each build is compared as its inventory stands now | |
| A build with no inventory is refused; a build has one once a graph is applied, which its root marks | Every name would read as added |
| Both builds are authorized, each through the lookup answering an unreadable build as never scanned | |
| Worked out when asked, never stored, from both builds' open rows in one indexed read | `design-docs/data-model-measurements.md` § Comparison timings |
| A page is cut after the comparison | |

### The size a change is against

Read with each change: the names the build held immediately before the scan,
counted as the change is, root excluded. Forty names is a rebuild of two
thousand and a different build of sixty.

## Occurrence identity

A component and the thing directly depending on it (REQ-17): names only, no
versions, hashed. Under the root the component's name stands alone.

| Rule | Reason |
|---|---|
| A component and its consumer, never the chain from the top | On a real switch image chains give 134,509 occurrences and 49,170 for the worst component; component and consumer give 27,366, the edge count, and 63 |
| Nothing is lost | The worst component's 48 direct consumers include its containers, one step from the route |
| A finding of the analysis kind has an occurrence minted from its series and the result's match key, carried by matching | `design-docs/analysis-matching.md` § Carrying |
| It carries no build and no product | A decision travels between builds (REQ-25), so every list correlating decisions requires a product |

A decision occurrence relates to a finding by one spelling of the product, the
issue and the occurrence, in a form per way a statement reads the two rows:

- the finding under any alias;
- the product left to a statement holding it through the finding's build;
- the issue asked through the merge, where the statement has not joined the decision's issue;
- a derived table carrying a decision occurrence's issue and occurrence.

Each query composes one and adds its own liveness, version and state condition.
A test fails a comparison of a decision occurrence's issue or occurrence with a
finding's written out in either order under any alias, and lists by name the
occurrence comparisons between other pairs of rows.

## Path traversal

An occurrence is an edge, so the graph is walked. Precomputing costs writes every
scan and bounds nothing: what directly pulled in the worst component (48
answers) takes 3 ms on PostgreSQL and 11 ms on MySQL, everything above it (78)
8 ms and 18 ms.

| Rule | Reason |
|---|---|
| Every walk is one `WITH RECURSIVE` statement: upward from a page's components, downward from a component, and downward from each child row of the tree, open issues united per row in the application | Portable across the four engines |
| No walk carries a depth | The union ends a cycle; a depth keeps a node per route length, 55,060 rows for thirty mutually dependent components on SQLite |
| The upward walk returns the nodes above and their edges, and the shortest route from a root is drawn in memory, to sixty-four steps | Deeper, a component is counted beneath, found in a list narrowed beneath, and shown on a finding as placed nowhere |
| Downward walks are spelled `CROSS JOIN ... WHERE` | On SQLite it keeps the queue outside the join: 0.018 s against 6.6 s under a build's root |
| A walk beneath a component also reaches every component the build held and holds no longer whose name a component it reaches carries: the tree's counts, the list beneath and the trend beneath | A finding keeps the component it opened on, so a rescan at a new version replaces the component and not the finding |
| The replaced components are read from the build's node history first, with the live components of their names; the list and the trend walk once more for which of those names sit beneath, and name the replaced components as values beside the walk | Matched by name in the walk's own statement, the trend beneath the bench kernel took 1.72 s on MySQL 8.4, against 227 ms as values (`design-docs/analytics-measurements.md` § Trend beneath a replaced version) |

## Limits

| Limit | Detail |
|---|---|
| Two builds of one version with different feature flags are one thing to the graph (REQ-16) | An edge means the inventory said so, so a dismissal resting on reachability is keyed on the versions in hand and asked again when they move |
| A finding of a kind with no dependency path gets no tree view (REQ-14) | Screens assuming a path check for one |
| A group's state is read from what its occurrences say, never from the absence of a decision | Otherwise a withdrawn decision falls out of the four states and the total |
