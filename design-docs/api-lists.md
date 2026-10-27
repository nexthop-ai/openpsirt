# API lists

How the API pages, sorts and filters a list, and the reads that span products
or answer for one issue.

Satisfies REQ-43, REQ-64, REQ-66.

## Contents

- [Paging](#paging)
- [Sorting and filtering](#sorting-and-filtering)
- [Issue-keyed and cross-product reads](#issue-keyed-and-cross-product-reads)
- [Limits](#limits)

## Paging

`limit` and `offset`, with a total, wherever a caller reads a second page. A list
taking a limit and no offset cannot be read past its ceiling, so a limit alone is
only for a list a screen draws whole, with a ceiling above anything the list can
hold, refusing an absurd request rather than cutting a page.

| List | Paging |
|---|---|
| What is running out of time, what approaches disclosure, the disclosure-date movements waiting for a second person, the deferrals that keep repeating | `limit`, `offset` and a total: each grows with the estate |
| The pickers: who holds something, who may be mentioned, what sits at the top of one build's tree | A limit alone: each is scrolled once. One grown past its ceiling on a real deployment gains an offset, and its screen the control to use it |

| Rule | Reason |
|---|---|
| What is running out of time orders totally, ending at the build, the component's version, the component and whether the row is exploited, exploited first | A page boundary between rows tied on the deadline, the issue and the name repeats none and skips none. One name ships at several versions in one build, and a merge can leave one component with an exploited row and one not |
| The API declares the ceiling on the parameter and refuses anything larger, naming the bound | That is what a caller should get |
| The store clamps, in one function | It defends against a caller that is not the API and has nobody to explain a refusal to |
| Page sizes are named constants: a list read and paged, a list read in bulk, a whole build's register, a component's worth of findings, a chart's points, a picker. A test fails a declared limit that is none of them | Ceilings are a judgment per list |
| A capped listing carries the whole-answer count | Otherwise a full page reads as the whole list, and a tile says 200 over a list of 462 |
| A figure counted over the whole answer is returned beside the rows, never recomputed from them | Coverage counts builds, quiet builds, never-scanned builds, builds out of support, builds out of use and builds being scanned before the page is cut |
| A bound declared for a listing bounds the whole listing | Applied to the people alone, it appends every team after them |
| What a request asked for and could not act on comes back | A note naming more people than one act may tell reaches some, and the rest would go unmentioned |

## Sorting and filtering

Filters are named fields with fixed meanings, bound as parameters.

| Rule | Reason |
|---|---|
| A narrowing that cannot be applied answers nothing, never everything | "Assigned to me" from a credential holding no party names nobody; dropping the condition hands over every finding while the screen shows the filter on |
| A filter with three answers is a word, never a flag | Origin is one: a "Scanner" flag can only send the absence of "entered by hand" |
| A filter taking words from a fixed set takes each word once, and is refused 422 where one repeats; a free-text filter carries a count of items instead | Each word is bound, and only distinct words bound how many. A test fails a repeatable query parameter declaring neither |
| A query parameter the operation does not declare is refused 400, naming it | A mistyped filter otherwise returns the unfiltered list as a correct answer. What is accepted is what the document publishes |
| A query string that cannot be read is refused 400 | A malformed escape or a semicolon otherwise drops a pair, and its filter reads as absent |
| Those refusals come after the scope on the operation's declaration is checked; a role on the product is checked by the handler after them | A caller outside the scope learns nothing; the parameters are published, so the order discloses nothing past it |

### Package kinds

The kind of package is read from the identifier a producer wrote, so its set is
open: the parameter takes any string, and one nothing carries matches nothing.
What the set holds in a scope is its own read, per product with the branch and
variant as the list takes them, and across every product, each kind with how
many findings list rows are open at it.

| Rule | Reason |
|---|---|
| Counted over what the reader may see (REQ-43) | A kind present only on an undisclosed finding is absent for a disclosed reader |
| Over the whole scope: the list's other filters, its release and support defaults and the minimum severity do not narrow it | It answers what the filter can offer |
| A row counts once per product, however many builds and binaries hold it; across products it counts in each | As the list holds it |
| Every binary of one source package is one kind | A row's lowest package identifier speaks for it |
| A kind is read as the filter reads it: the stored identifier, without regard to capitals, beginning `pkg:`, the kind and a slash | An identifier under no kind, and a component with none, is not counted, because ticking it would empty the list |
| Read in Go from each distinct identifier, after the statement folds the distinct issues at components into rows and counts rows per identifier | Reading the kind in SQL is spelled per engine. It stays below the page it sits beside on every engine, so nothing stores it (`design-docs/api-measurements.md` § Package kinds) |

### Sorting

Sorting is permitted (REQ-66). A column name cannot be bound, so a sort column
from a query string becomes part of the statement.

| Rule | Reason |
|---|---|
| Six keys, each selecting an expression stored beside it | The key sent is a lookup, never the value |
| The planned upgrades list has six of its own, read the same way with the same direction word, offered by the same generated enum | A planned upgrade is one upstream bump, with issue and build counts and no age |
| Nothing else reaches the statement: no derivation, no mapping that falls through, no default that is the parameter | A sort cannot expose a column the caller was never meant to order by |
| The direction is one of two words written here | |
| A key that misses answers in the list's own order | It is a mistake about a list, not a reason not to show it |
| The issue table is joined only where the chosen order needs it | The ordinary page reads one covering index |

## Issue-keyed and cross-product reads

One page answers for an issue (REQ-64): every product, build and component it
sits at, with how far it is decided in each.

| Rule | Reason |
|---|---|
| One row per build and component, never per occurrence | Sixty occurrences in one build are one piece of work with a count |
| How far it is decided uses the findings list's own expression | Two definitions of "decided" disagree in front of somebody |
| No new visibility rule, and the narrowing is in the query | A count leaks even when no row is shown |
| The search box lands here with no product picked; the server decides which search the text is | An issue name spans products |
| The findings list spans products at `/v1/findings`: one row per product, issue and component, with the same filters, sort allowlist and paging | |
| Each row applies its own product's minimum severity; `severity` raises it for the whole page and never lowers it, so the higher applies whether the product states its own or inherits; an exploited row passes both; `below_minimum_severity` turns every one off | A product's decision is never overridden downward |
| `beneath`, `differs` and `across_variants` are not offered across products | Each is about one build's edges or a selection of builds. Every other filter is shared by both endpoints |
| `across_variants` compares a row with the other builds of its branch: `only` keeps what no other variant holds and needs a variant in the selection; `every` keeps what every build of the branch holds and needs none | |
| The dependency tree, the inventories and the list of work nobody owns stay per product | |

## Limits

| Limit | Detail |
|---|---|
| Paging is `limit` and `offset`, with a total | A cursor is better under concurrent writes and worse for jumping to a page. The total is apart from the page because somebody deciding whether to start needs to know how much there is |
| A list answers with an object, never an array | An array has nowhere to put the total |
