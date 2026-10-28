# Findings

What a finding is, the row a person reads, and how rows group across builds.

Satisfies REQ-15, REQ-17, REQ-25.

## Contents

- [Fan-out](#fan-out)
- [The row a person reads](#the-row-a-person-reads)
- [Decision state on a row](#decision-state-on-a-row)
- [Work across builds](#work-across-builds)
- [Incomplete upgrades](#incomplete-upgrades)
- [The total above a list](#the-total-above-a-list)
- [Limits](#limits)

## Fan-out

A scanner reports that a package at a version is affected; it never sees the
graph. This deployment fans each reported issue out across the occurrences the
inventory's edges describe.

| Rule | Reason |
|---|---|
| An occurrence is a component and what directly pulled it in | Different consumers use different parts of a dependency |
| One issue at a shared library under two consumers is two findings (REQ-17) | |
| A component nothing leads to has one occurrence: itself | It ships, and an incomplete graph is normal |
| An occurrence directly under the product records no consumer | The root's name differs per variant, and a key somebody has to remember to ignore gets forgotten |
| A report against a component this deployment does not hold is counted and reported, never dropped | The two documents describe different builds |

`design-docs/findings-measurements.md` § Fan-out cost has the 335,021-finding image.

## The row a person reads

Every occurrence is stored; a person reads the **fold**: one issue at one
source package at the version it was built at. The fold cuts the demo's rows by
11.4%, concentrated where the work was already one thing (`util-linux`'s
fourteen rows are one decision).

| Rule | Reason |
|---|---|
| Every number a person sees is in the unit they act in | A row says how many packages of the fold sit here and how many things pull them in, because deciding the row decides all of them |
| The occurrence count is stored and is what the bulk ceiling and the disposition register count | It is never a figure a reader reconciles with the row's |
| A group takes the urgency of its worst occurrence | |
| A row names its consumer even where no route up from the root reaches it | The route is what is missing; blank at both ends says nothing pulls it in, which is false. The owner is left empty |

## Decision state on a row

Each row carries one of four states, by the same definition the state filter
uses.

| State | Condition |
|---|---|
| Undecided | Nothing stands, waits or has lapsed at any occurrence |
| Waiting | A decision needing a second person is proposed and nobody has agreed |
| Agreed | Every occurrence is answered by a decision in force: agreed, or proposed and needing nobody |
| Lapsed | A decision here stopped applying and nothing replaced it |

| Rule | Reason |
|---|---|
| Some occurrences agreed, the rest undecided, nothing waiting or lapsed: no state; the interface labels it partly decided, in the waiting color | |
| Undecided means nothing stands, never nothing ever said | A withdrawn decision's row covers the occurrence so "lapsed" can be said of a decision holding no key |
| The row's word and the filter's bucket are one rule | Two spellings drop a withdrawn decision from every list and count |
| A live decision matches by product, issue, occurrence and both versions; a lapsed or withdrawn one by occurrence alone | Matched by occurrence alone, an approval at one version reads as agreed over the next build's version |
| A row says when a live decision at one of its occurrences is sent back to its author | That is the row a proposer looks for, and the queue no longer shows it |
| An occurrence names the decision standing on it, not only the decision's row | A person acts on the decision |

## Work across builds

A decision carries no variant: it is keyed on product, occurrence and upstream
versions, so answering it on one build answers every build of the product
holding the same code (REQ-25). Work lists show one item per issue in a
component in a product; listed per build, a second variant took the list from
7,354 items to 14,681 against one estate. On two variants of one switch image,
7,587 and 7,610 rows read per build are 7,612 items: 7,585 seen twice and 27
genuine differences.

| Rule | Reason |
|---|---|
| Genuine differences break out by themselves | A component row is one name at one version, so two variants at one version group and at two versions do not |
| The product stays in the key | A decision is about one product's code |
| An item names one build of its product's branches, tags and variants (REQ-15), chosen stably, with the count beside it | A screen needs somewhere to link |
| Acting on an item acts on every build of the product holding it | Assigning one build leaves identical work unassigned beside it |
| Counted in pieces of work; late when any occurrence is late | One kernel flaw is one item, not forty-eight |
| The spread over variants is asked on an occurrence's own branch | Asked over several branches at once, a variant on two branches is compared against the other branch's variants |
| An occurrence is specific to a variant when no other variant of its branch holds the issue at the same fold, common when every build of the branch does | An occurrence at another version counts as not held |
| A group keeps the occurrences the spread admits | The question is about an occurrence; answered per group, one branch's unanimity decides another's |
| A build answers once its first scan is read | Until then a branch holds nothing common to every variant |
| Across builds, the way down is empty | A chain belongs to one build's graph. Screens about a chain require one build, and narrowing to a subtree across builds is refused |

Two rows share one occurrence where an inventory describes one consumer twice,
as a source package and as the distribution's package.

| Folding two rows into one occurrence | |
|---|---|
| The way down is whichever the graph reaches | Usually only one is reachable from the root |
| Argued away by the build only where the build argued away both | |
| A decision standing on either stands at the occurrence, lowest identifier first | The two rows differ by a packaging revision, so a decision matches one and not the other |

## Incomplete upgrades

A finding still open after its component's upstream version changed, where the
shipped version is not the one recorded as fixing the issue, is an incomplete
upgrade. Aimed at whoever did the bump.

| Rule | Reason |
|---|---|
| The test is inequality, never ordering | The fixed-in field is free text and sometimes a list. A confident order for a pair nothing can order is a wrong recommendation |
| The closed row records `superseded` and the version it moved to; the new row records the version it arrived from | Written as the scan applies; the old component leaves the inventory when the run ends |
| Recorded only where a version change closed the finding | Never for a removed component or an unexplained closure |
| Shown on the finding and in a release comparison's still-present column; never in the review queue | The queue lists decisions |
| The inverse, a component at or past the fix that the scanner still reports, is not detected | It needs an ordering per ecosystem |

## The total above a list

The figure above a list is what somebody quotes, so it counts the population
the list pages through.

| Rule | Reason |
|---|---|
| It rides on the page: a window count after the grouping, before the limit | The number and the rows cannot describe different sets |
| The window sits outside the grouping | The findings lists narrow their groups with a `HAVING`; `design-docs/database-queries.md` § Silently wrong query shapes names the distinct-count case |
| An empty page counts with a second statement grouped exactly as the page groups | Grouped one step finer, two binaries of one source count as two |
| Any separate count repeats the page's key | Counting per component name where the page draws per component lists nine and says ten |
| `limit=0` answers the total and no rows | The by-component view, planned upgrades and the review queue: a button's count and a polled badge |
| Two overlapping filters are one question | Lapsed decisions and expired deferrals together count a row once |

## Limits

| Limit | Detail |
|---|---|
| Severity is stored on the issue, fix state on the finding | Severity belongs to the vulnerability; whether a fix exists belongs to the version in front of you |
