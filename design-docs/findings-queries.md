# Finding list queries

How the findings lists, their totals and the views beside them are read. Each
rule is a statement shape a measurement chose; the numbers are in
`design-docs/findings-measurements.md`.

## Contents

- [The page](#the-page)
- [Decision state filters](#decision-state-filters)
- [Two-level grouping](#two-level-grouping)
- [Product totals](#product-totals)
- [Across products](#across-products)
- [Deadline rewrites](#deadline-rewrites)
- [Receipts pairing](#receipts-pairing)
- [Limits](#limits)

## The page

The grouping is done by the database; a page of fifty groups out of a third of
a million findings cannot be counted in the application. Names are fetched in a
second pass, because aggregating text is spelled differently per engine.

1. Group every open finding in the build by issue and fold, reading only the
   columns the finding table's covering index holds, keep the fifty most urgent, and count the total on the same statement (§ Two-level grouping).
2. Read what the page shows about those fifty groups only: likelihood, score,
   the four decision counts, the ways down, the fix.

| Rule | Reason |
|---|---|
| Every condition on an occurrence narrows both statements through the same clauses | |
| No condition needs the issue or component joined under the grouping; a rating or a name is a membership test | |
| The decision-state filter is built from the decision occurrences outward, in the first statement only | Built per page issue and joined to its occurrences, PostgreSQL rebuilt it per occurrence: 87 s against 35 ms |
| The second statement reads the page's groups by the occurrence conditions only, dropping any group not on the page | The first already chose them |
| Another view keeping the list's groups under a decision condition reads them from the list's own statement | |

## Decision state filters

| Rule | Reason |
|---|---|
| A filter needing a decision reads those decisions' issues first, narrowing occurrences and decisions both | Every state but undecided needs a decision in that state, and an outcome or a promised upgrade one in force. The set is a superset; the group conditions decide |
| Under such a filter, issues are stated on the decisions and the list's occurrences, never on the decided side's occurrences | Otherwise PostgreSQL probes the occurrence index per decision: 2,726 ms against 419 ms |
| A filter that can pass with no decision narrows the decided side to the issues of every decision that can mark one | Undecided: 479 ms against 543 ms over every occurrence |
| A live decision's versions are compared in an EXISTS on the component's key, never a joined component | Joined, PostgreSQL scanned every component per decided occurrence: 290 ms of 433 ms |
| An occurrence with no consumer holds the empty version | Nothing to look up |
| Conditions over decision counts are ranges: "none" is below one, "every" is at least the occurrences | A planner estimates a range at a third of groups and an equality at a two-hundredth |

## Two-level grouping

The fold is a 64-character key; grouping on it directly sorts every open row on
that string, which spills to disk at 367,000 rows. The rows are grouped by issue
and component first, on two integers, and the partial groups are joined to the
component and grouped again by fold.

| Rule | Reason |
|---|---|
| An occurrence condition is asked of the first level | |
| A group condition is asked of the second level | A fold with one package decided is neither undecided nor agreed |
| The first level carries what the second reads: sums, minimums, maximums, earliest opening and soonest deadline under their own names | Both levels read them alike |
| A distinct build count adds the build to the first level's key | It does not decompose |
| The issue is joined after the first level | Likelihood or score is read once per partial group |
| Decision flags are counted beside the first level on its keys, from decision occurrences matched under every occurrence condition | Joined to every open occurrence, each of 368,847 rows is looked up in 148,102 decided occurrences: 1,067 ms against 575 ms |
| The decided groups are stacked with the partial groups and folded on the keys, never joined | Joined, MariaDB recomputed them for each of 12,260 partial groups: 71 s against 0.23 s |
| The holder is read from the covering index, which carries the assignee last, never counted in an arm of its own | 0.67 s against 1.08 s for the unassigned badge over 368,849 open occurrences. An arm grows with what is held |
| Each occurrence is counted once only where a condition compares decided occurrences with occurrences | Agreed and an outcome need every occurrence; the rest ask any or none |
| Across products, the minimum severity applies after the first level, which also keys on product and exploitation signal | Each partial group is wholly above or below |
| Another view's groups under a condition reading no decision are grouped in one level and joined back | Over two levels PostgreSQL misestimates tenfold and did not finish in two minutes |
| Another view's groups under a decision condition are the list's two-level statement | One level: MariaDB gave no answer in 985 s |
| Under a filter needing a decision, the view's own first level is restricted by membership in the kept groups | Joined, PostgreSQL took 185 s for lapsed planned upgrades |
| Under a filter that can pass with no decision, the kept groups are joined to the view's rows | Most of the list is kept: 2.6 s on MariaDB |
| A planned upgrade's names are grouped over the page's components, named as a list | 166 ms against 287 ms joined |
| By component, the first level is one row per issue; by upgrade, it keys on component, issue, build and fixed version | |

## Product totals

| Shape | Asked by | Reason |
|---|---|---|
| A lookup per occurrence | A page's groups | A few hundred occurrences |
| One row per decided occurrence, built once and joined on the finding | The product page's totals and build rows | 367,000 lookups otherwise: 4.6 s against 1.2 s |

The product page reads its build rows and totals from one statement, one row per
build, issue and component, folded again for the totals; every column folds
exactly (sums, a minimum deadline, a maximum exploitation flag).

## Across products

Planner statistics are refreshed by a server once about a tenth of a table has
changed, and by a SQLite deployment at start and after every scan.

Each decision occurrence is matched to its finding's product, with the decision
occurrences outermost, written `CROSS JOIN ... WHERE`. That is an inner join on
every engine and fixes the order on SQLite, which otherwise reads every decision
occurrence once per open finding: 331 s against 0.78 s.

## Deadline rewrites

Rewriting every deadline walks the identifier range once, with a batch of
opening moments inside each statement as a case. A statement per moment, band
and slice is 189,000 statements for a product scanned nightly for a year, which
holds about 1,800 distinct moments, and overruns the half-hour its caller allows.

## Receipts pairing

Receipts pair uploads with runs over all history, walking both newest first
once, so the last page costs what the first does.

| Order | Reason |
|---|---|
| Uploads by arrival, never identifier | Two at one moment take identifiers in either order |
| Runs by when they finished | The order the page reads |

## Limits

| Limit | Detail |
|---|---|
| The component and planned upgrade views depend on statement shape to stay fast on MariaDB | MariaDB recomputes a grouped table per joined row, so kept groups under a decision filter are a membership test, never a join. Only the across-products measurement checks it, at a three-minute bound; readings after a timeout on that engine are not measured, because MySQL and MariaDB keep running an abandoned statement |
| Undecided matches every decision occurrence to the occurrences of their issues | Most of the undecided page's 0.5 s, against 0.11 s unfiltered. A first-match probe answers in 148 ms, and PostgreSQL then compiles the plan for 0.6 s more. No shape below the match was found that stores no decision state |
| PostgreSQL compiles a plan it costs above 100,000 before running it | 0.36 s of a 1.07 s statement. Moving an estimate across the line moves the time, and only a measurement shows it |
| On MariaDB a single-product list whose partial groups read only the covering index's columns reads open occurrences through the closed-at index | Nobody's work among them. A table scan takes 0.19 s against 0.45 s. Lists across products do not |
| The page by component is slower over two levels on SQLite | 0.12 s against 0.10 s; every other statement is faster |
