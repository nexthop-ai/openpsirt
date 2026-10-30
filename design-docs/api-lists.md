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

`limit` and `offset`, with a total, wherever a caller reads a second page. A
limit alone is only for a list a screen draws whole, its ceiling above anything
the list holds, refusing an absurd request rather than cutting a page.

| List | Paging |
|---|---|
| What is running out of time, what approaches disclosure, the disclosure-date movements awaiting a second person, the deferrals that keep repeating | `limit`, `offset` and a total; each grows with the estate |
| The pickers: who holds something, who may be mentioned, what sits at the top of one build's tree | A limit alone. One outgrowing its ceiling on a real deployment gains an offset and a control |

| Rule | Reason |
|---|---|
| What is running out of time orders totally, ending at the build, the component's version, the component and whether exploited, exploited first | No page boundary between ties on deadline, issue and name repeats or skips; one name ships at several versions, and a merge can leave a component with an exploited and an unexploited row |
| The API declares the ceiling and refuses anything larger, naming the bound; the store clamps, in one function | The store has nobody to explain a refusal to |
| Page sizes are named constants: a list read and paged, a list read in bulk, a whole build's register, a component's worth of findings, a chart's points, a picker. A test fails a declared limit that is none of them | |
| A capped listing carries the whole-answer count | Otherwise a tile says 200 over a list of 462 |
| A figure over the whole answer is returned beside the rows, never recounted from them | Coverage counts builds, quiet, never-scanned, out-of-support, out-of-use and being-scanned builds before the page is cut |
| A bound declared for a listing bounds all of it | Applied to the people alone, it appends every team |
| What a request asked for and could not act on comes back | A note naming more people than one act may tell says who went unmentioned |

## Sorting and filtering

Filters are named fields with fixed meanings, bound as parameters.

| Rule | Reason |
|---|---|
| A narrowing that cannot be applied answers nothing, never everything | "Assigned to me" from a credential holding no party names nobody |
| A filter with three answers is a word, never a flag | A "Scanner" flag could only send the absence of "entered by hand" |
| A filter taking words from a fixed set takes each once, refused 422 on a repeat; a free-text filter carries a count of items instead. A test fails a repeatable parameter declaring neither | Only distinct words bound how many are bound |
| An undeclared query parameter is refused 400, naming it | A mistyped filter would return the unfiltered list |
| An unreadable query string is refused 400 | A malformed escape or a semicolon otherwise drops its filter |
| Those refusals follow the check of the declared scope; a role on the product is checked by the handler after them | A caller outside the scope learns nothing |

### Package kinds

The kind of package comes from the identifier a producer wrote, so the set is
open: the parameter takes any string, and one nothing carries matches nothing.
The set in a scope is its own read, per product with branch and variant as the
list takes them, and across every product, each kind with how many findings
list rows are open at it, a row being one issue at a source package and version.

| Rule | Reason |
|---|---|
| Counted over what the reader may see (REQ-43) | |
| Over the whole scope: the list's other filters, its release and support defaults and the minimum severity do not narrow it | It answers what the filter can offer |
| A row counts once per product, and in each product across products | |
| Every binary of one source package is one kind, read from a row's lowest package identifier | |
| A kind is read as the filter reads it: the stored identifier, ignoring capitals, beginning `pkg:`, the kind and a slash; an identifier under no kind, or a component with none, is not counted | Ticking it would empty the list |
| The kinds are read in Go from each distinct identifier, after the statement folds the distinct issues at components into rows | SQL would spell it per engine; it stays below the page beside it, so nothing stores it (`design-docs/api-measurements.md` § Package kinds) |

### Sorting

Sorting is permitted (REQ-66); a column name cannot be bound.

| Rule | Reason |
|---|---|
| Six keys, each selecting an expression stored beside it; nothing derived from the parameter reaches the statement | A sort exposes no other column |
| The planned upgrades list has six of its own, read the same way, with the same direction word and generated enum | An upgrade has issue and build counts and no age |
| The direction is one of two words written here | |
| A key that misses answers in the list's own order | |
| The issue table is joined only where the order needs it | The ordinary page reads one covering index |

## Issue-keyed and cross-product reads

One page answers for an issue (REQ-64): every product, build and component it
sits at, with how far it is decided in each.

| Rule | Reason |
|---|---|
| One row per build and component, never per occurrence | |
| How far it is decided uses the findings list's expression | |
| The narrowing is in the query | A count leaks with no row shown |
| The search box lands on an issue's page where the term names one, and on the component chooser otherwise (`design-docs/interface-shell.md` § The search box) | |
| `/v1/findings` spans products: one row per product, issue and component, with the same filters, sort keys and paging | |
| Each row applies its own product's minimum severity; `severity` raises it for the page and never lowers it, an exploited row passes both, and `below_minimum_severity` turns every one off | |
| `beneath`, `differs` and `across_variants` are not offered across products; every other filter is shared | They are about one build or a selection of builds |
| `across_variants` compares a row with the other builds of its branch: `only` keeps what no other variant holds and needs a variant selected; `every` keeps what every build of the branch holds | |
| The dependency tree, the inventories and the list of unowned work stay per product | |

## Limits

| Limit | Detail |
|---|---|
| Paging is `limit` and `offset`, with a total | A cursor suits concurrent writes and not jumping to a page; the total tells somebody how much work there is |
| A list answers with an object, never an array | An array has nowhere for the total |
