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

Stored as nodes and edges, never flattened (REQ-16): a flat list cannot answer
"why is this here".

| | Definition |
|---|---|
| Component | A package at a version, or an image by its name (`design-docs/data-model-components.md` § Component identity) |
| Node | That component's presence in one variant |
| Edge | One node depending on another |

| Rule | Reason |
|---|---|
| A component reached by several parents is one node with several edges | A node per route multiplies the graph by its sharing; routes derive from edges |
| The root, the product itself, is a flagged node, excluded from identity and expiry (REQ-08) | Its version changes every build and its name per variant. Every upward walk stops at the flag |
| A scan naming no root of its own is filed against the build it was sent for | |
| The root flag is reconciled on every scan like any other column | A build promoting a component to root, or demoting the old one, otherwise keeps the old answer, and two flagged nodes or none draws the tree wrongly |
| The root is not one of the build's components | A count including it says one more than the inventory lists |
| A component with no name is refused | It cannot be identified. One with no version is kept: the format allows it and it ships |
| An edge naming a component the snapshot does not list is refused | Inventing one reports a dependency nobody declared. Edges to things the document never described are dropped and counted at read time, so one reaching here is a snapshot built wrong |

## History as intervals

Every node and edge records the scan that opened it and, once gone, the scan that
closed it. Open rows are what is present; closed rows are what a past release
contained.

| Rule | Reason |
|---|---|
| Rows are closed, never deleted | What a release shipped is asked years later |
| An unchanged build writes nothing | A scan compares against what is open and writes the difference, so storage grows with change rather than the calendar (REQ-20). A test asserts it and has been watched to fail with the comparison broken |
| One transaction | A half-applied graph reads as components removed, closing findings still present |

## Inventory delta

What one scan made of a build's contents: the names that arrived, the names that
went, and the names now held at a different set of versions. True of the
documents as they are read.

| Rule | Reason |
|---|---|
| Counted by name | An upgrade is one dependency moving, never an arrival and a departure |
| A name at two versions at once is one entry | A vendored tree ships one routinely, and one copy going is that name at fewer versions |
| The root is excluded from both sides | |
| An image held by name is at no version on either side | A rebuilt image is no change. What each build stated is on the component screen (`design-docs/interface.md` § The component screen) |
| The earliest scan applied to a build has none | It is the first picture |
| Worked out when asked, never stored | Applying the scan already wrote the rows that answer it (REQ-20) |

It is read off the intervals. A node stands immediately before a scan where it
opened earlier and had not closed by then, and at the scan where it opened no
later and has not closed since; a node the scan closed stands on the near side.
Accepted scans of one build rise in identifier as in build time, because an
older scan is refused on arrival, so a comparison keyed on the interval columns
is one in time.

| Rule | Reason |
|---|---|
| Only names a scan opened or closed a row of are compared, each at the scans that touched it | No other name can have moved; the work is what the page's uploads changed |
| Rows standing on neither side of any scan on the page are not read | Otherwise cost grows with the calendar: a page of fifty took 78 ms behind 73 nights on SQLite and 264 ms behind 365 |
| The build's rows are read once, by build, and matched to names in the application | Joined in one statement, PostgreSQL walked the index led by the build per name: 40.5 s for an upload touching 54,902 names, against 0.76 s |

`design-docs/data-model-measurements.md` § Inventory delta timings has a year of
nightly scans on each engine.

### The names behind the counts

The counts and the names behind them are one fold over the same rows, so a
listing never disagrees with its number.

| Rule | Reason |
|---|---|
| Removals first, then arrivals, then names at new versions | A build that stopped describing a dependency looks like one that stopped shipping it, which is what a listing is opened to find |
| Every version of a name, on each side | Which copy of a vendored tree moved is what the versions say |
| The name as a producer wrote it | Identity is the folded name, and either spelling names the same thing |
| Versions are ordered as text | Ordered properly is per-ecosystem work answering confidently for pairs it cannot order |
| A page is cut after the comparison | The names compared are the scan's change; the rows read are the build's on either side |

### Comparison of two builds

Any two builds of one product compare the same way: two releases, two platforms
of one release, or a tag and its branch. The fold is the upload listing's, the
earlier build before and the later after.

| Rule | Reason |
|---|---|
| Each build is compared as its inventory stands now | Its open rows are what it ships |
| A build with no inventory is refused | Every name in the other would read as added. A build has an inventory once a graph is applied, which its root marks |
| Both builds are authorized, each through the lookup answering an unreadable build as never scanned | |
| Worked out when asked, never stored | Both builds' open rows are one indexed read: 18 to 29 ms on each engine for 6,866 components against 6,748 |
| A page is cut after the comparison | The total is of the kind asked for, the order the server's |

### The size a change is against

Read with each change: the names the build held immediately before the scan,
counted as the change is, root excluded. Forty names moving is a rebuild of an
inventory of two thousand and a different build of one of sixty.

## Occurrence identity

The unit of triage is a component at an occurrence: the component and the thing
directly depending on it (REQ-17). Names only, no versions, hashed. Under the
root the component's name stands alone, because the root's name differs per
variant.

| Rule | Reason |
|---|---|
| A component and its consumer, never the chain from the top | On a real switch image a chain gives 134,509 occurrences and 49,170 for the worst component, a shared library whose ten sub-packages depend on each other; component and consumer gives 27,366, the edge count, and 63 |
| Nothing is lost | The worst component's 48 direct consumers are its containers, siblings and callers; the container is one step up and the route is walkable |
| A finding of the analysis kind has an occurrence of its own, minted from its series and the result's match key and carried by matching | `design-docs/analysis.md` § Matching. It sits at a component as every finding does |
| It carries no build and no product | A decision travels between builds shipping the same versions (REQ-25), so every list correlating decisions requires a product |

A decision occurrence is related to a finding by one spelling of the product,
the issue and the occurrence, with a form for each way a statement reads the two
rows:

- the finding under any alias;
- the product left to a statement holding it through the finding's build;
- the issue asked through the merge, where the statement has not joined the issue a decision is filed under;
- a derived table carrying a decision occurrence's issue and occurrence.

Every query correlating the two composes one of them and adds its own condition
on liveness, versions and state. A test fails a comparison of a decision
occurrence's issue or occurrence with a finding's written out in either order
under any alias, and lists by name the occurrence comparisons between other
pairs of rows.

## Path traversal

An occurrence is an edge, so no row per route is stored; the graph is walked.
Precomputing costs writes every scan and bounds nothing, because the route count
is the producer's. On the worst component of a real image, what directly pulled
it in (48 answers) takes 3 ms on PostgreSQL and 11 ms on MySQL, and everything
above it (78) 8 ms and 18 ms.

| Rule | Reason |
|---|---|
| Every walk is one `WITH RECURSIVE` statement | Portable across the four engines. Upward from a page's components, downward from a component, and downward from each child row of the tree, whose open issues are united per row in the application |
| No walk carries a depth | The union adds a node once, ending a cycle; a depth keeps a node once per route length, and thirty mutually dependent components return 55,060 rows for one start on SQLite |
| The upward walk returns the nodes above and the edges among them, and the shortest route from a root is drawn in memory, to sixty-four steps | A component deeper than sixty-four is counted beneath, found in a list narrowed beneath, and shown on a finding as placed nowhere |
| Downward walks are spelled `CROSS JOIN ... WHERE` | An inner join everywhere, and on SQLite the instruction to keep the queue outside the join: otherwise listing under a build's root takes 6.6 s, against 0.018 s |

## Limits

| Limit | Detail |
|---|---|
| Two builds of one version with different feature flags are one thing to the graph (REQ-16) | An edge means the inventory said so, not that the code takes that path at run time. A dismissal resting on reachability is therefore keyed on the versions in hand and asked again when they move |
| A finding of a kind with no dependency path gets no tree view (REQ-14) | For a source-file finding the answer is the file. Screens assuming a path check for one |
| A group's state is read from what its occurrences say, never from the absence of a decision | Counted as "no decision here", a withdrawn decision falls in none of the four states and out of the total |
