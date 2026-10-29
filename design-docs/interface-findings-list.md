# Findings list screen

The findings list: what a row is and carries, the list across products, sorting,
paging and selection, the two other views, walking from one finding to the next,
and the restored scroll position.

Satisfies REQ-13, REQ-27, REQ-32, REQ-33, REQ-55, REQ-57, REQ-60, REQ-64, REQ-66.

## Contents

- [The findings list](#the-findings-list)
- [The cross-product list](#the-cross-product-list)
- [Sorting, paging and selection](#sorting-paging-and-selection)
- [The by-component view](#the-by-component-view)
- [The by-upgrade view](#the-by-upgrade-view)
- [List navigation](#list-navigation)
- [Restored position](#restored-position)
- [Limits](#limits)

## The findings list

One row per issue and fold (REQ-57): the source package at the version it was
built at, so curl, `libcurl4t64` and `libcurl3t64` are one row, one thing to
decide, upgrade and route. A real image's 281,890 findings are 6,775 rows; keyed
on the component they are 7,648.

| Rule | Reason |
|---|---|
| A row says how many packages and consumers it covers | The units somebody acts in |
| The occurrence count is stored, sorted on, and shown as the row's title | It is what the ceiling on one action is measured against and what the disposition register expands to |
| For a reader not reading dependency findings at its scope, the list is "Nothing to list." and the line `design-docs/interface.md` § Families a reader holds gives, with no total, view count or control, and none of them asked; a reader of one half alone has its line under the heading | Its total is narrowed to the reader |
| The row previews in place: its plus opens, under the row, the description, where the component sits, and the finding screen's decision form, with one link to the finding | What a decision requires and writes is unchanged |

### Row content

| Rule | Reason |
|---|---|
| The row carries the first line of what the issue says about itself, cut on the server | Every reader and the export get one summary, and a page carries no paragraphs |
| The summary is clamped to one line; the whole is on the finding and the row's title | Row height sets page height: fifty rows are five thousand pixels |
| The version sits beside the component | Every line a row spends is fifty on a page |
| Narrow screens get cards, never a table that scrolls sideways (REQ-55) | |
| A row names both ends of the way down: the part of the product it belongs to, and what directly pulls it in, with the steps between counted | The ends are what differ between sibling rows |
| Where its occurrences are reached different ways, the row says the pair shown is one of several | |
| Where the inventory placed the component nowhere, it says so, never naming the product itself | |
| It says what upstream has done, so "upstream declined" and "nobody has fixed this yet" differ | |
| The age is the finding's own, "open 12d" (REQ-60), never the year in the identifier | The age a deadline relates to |
| The deadline is on the row (REQ-33): the date while far off, days left as it nears, days over once passed. A row without one says which of the two reasons applies | A blank would mean two things |
| A match from comparing a published identifier against an upstream range is marked "not confirmed" (REQ-13), and the filters narrow to those | |
| A minimum severity in force is announced, with how many rows it hides | |
| The row carries the source package and how many other rows on this page are the same issue at another of its binaries, linking to the component | Counted over the page, so it agrees with the total beside it |

Both ends of the way down cost one recursive statement for the page: the database
climbs from every consumer on the page and returns each node above them once,
with the edges among them. Routes are drawn in memory, the shortest from a root
to each consumer; a route over sixty-four steps is not drawn. The climb is
bounded by the graph above the page however edges loop
(`design-docs/interface-measurements.md` § Ways down on the list).

## The cross-product list

The list with the product left out (REQ-64): one screen, one rail entry, and on
the server the same filters from one definition.

| Rule | Reason |
|---|---|
| Without a product, no subtree, "differs between builds" or spread across variants is offered or sent, and each is dropped from the query | A subtree is one build's edges; the others describe a selection; a hidden filter narrows silently |
| "Only this variant" is offered and sent only where the selection names a variant | |
| The export and the row's preview, decision form included, are offered here too; each row decides on its own build | |
| Assigning to somebody else and Select all return once a product is picked | Who may hold work is a question about one product |
| Saved filters are offered | A saved filter keeps no scope |
| The product is a column where it varies, and the row links to that product's list | |
| There is one view and no view tabs | |
| Each row reads its own product's rating (`design-docs/interface-look.md` § The ordering signals) | |

## Sorting, paging and selection

Sorting is by a column the server names (REQ-66): the server stores an expression
against each of its own keys, because a placeholder cannot bind a column. A word
that is not a key leaves the list in its own order.

| Rule | Reason |
|---|---|
| Four headers order the list: severity, EPSS, locations, deadline; clicking the sorted one reverses it | |
| "Sorted by", beside the count above the rows, names the order in force and carries all six, including urgency (REQ-32), the opening order, and age | Two orders have no column |
| An order opens its meaningful way round: worst severity, highest likelihood and widest reach first; deadline and age soonest and oldest | |
| A finding with no deadline sorts last either way | |
| The tie-break is always one pair of identifiers | Equal rows do not swap between pages |
| A page holds fifty, a hundred or two hundred, kept in the address | Fifty is 153 pages of one product |
| A switched or narrowed list starts at its own beginning; an address past the end draws the pager, never "empty" | |
| The columns deciding the next action come first: severity, deadline and decision state; the component, path, estimate, fix and reach may run off the edge | The table is 1,583 px in 1,088 at a 1,366 laptop |
| An empty list names how many filters are in force and offers removing them all, or says nothing is open here where none was | |
| A filter change keeps and dims the rows while the next answer is read, with `aria-busy` | Unmounting blanks the search box and takes the cursor |
| A waiting screen shows a moving mark beside the word; reduced motion stills it | A still page reads as stopped; the mark carries no text, so a screen reader hears the word once |
| The views are tabs above the filters, each carrying its figure, the by-component and by-upgrade figures asked with a limit of zero | One narrowing at three grains: 7,455 rows by issue, 341 by component, 284 by upgrade |
| The list opens by issue at any size; another view is a tab and an address chip that removes itself | A size threshold answers different questions on two products |
| Searching is submitted, never per keystroke, matching anywhere in a component name regardless of capitals | Each is a query over every open finding in the build |
| A component's name opens the component, here and on the finding; narrowing and hiding are small acts beside it | One word, one meaning |

### Selection

Selection is a prerequisite: accepting a publisher's statement and declaring a
bump both start from a filtered set.

| Rule | Reason |
|---|---|
| A row is selected by what it is and carried with its key, surviving paging | The list is re-read after every decision; acting on a selection acts on all of it |
| Changing the question clears the selection, through the one hook holding the rule, removing a chip included | A selection belongs to a population |
| Select-all and deselect-all are inverses, both this page | |
| A figure about a selection counts what it holds: the bulk form sums rows written across every page seen, and the line under the list names the limit the selection is past, issues or findings written | The ceiling is read against it (REQ-27) |
| The bulk form asks, by an unticked box "Skip occurrences already decided", before skipping. Ticked, the result lists each occurrence left out linking its decision (`design-docs/triage-bulk.md` § Decided occurrences); unticked, a decided occurrence refuses the bulk decision naming it | |
| Approving a selection runs one at a time: what was agreed goes, a refusal stays ticked unless unticked meanwhile, and what was ticked meanwhile stays | |
| Assigning a selection in one product is one request, resolved on the server against the list's filter. A refusal is the whole act's and the selection stays; rows a colleague holds that the caller may not take stay selected with a count (`design-docs/access-assignment.md` § Assignment by narrowing) | |
| Select all, offered on the batch bar in one product once something is ticked, takes every row the filter matches, counted by the list's total and naming no rows; a changed filter ends it | The server assigns what matches when the act lands |
| Across products each row is its own request, and a loop over a selection survives a refusal: the rest are tried, failures stay selected with a count, and the undo control still appears | |

## The by-component view

The list grouped by component: "what is wrong with this thing", the upgrader's
question.

| Rule | Reason |
|---|---|
| Each row carries its issues by severity and the worst among them | By count alone forty-four lows outrank three criticals |
| The weight stays the default order; the worst column is sortable | Where the volume is, is the view's question |
| The share bar is scaled to the heaviest row on the page | The first row may not be the heaviest |
| The count beside a version says which it is: ranked, everything reaching it closes; unranked, what that release fixed alone; the reason on hover | |
| It asks the same question as the by-issue view, every filter included (`design-docs/interface-filters.md` § Multi-value filters) | |
| There is no By fix view; the act follows the source package, so upgrading curl reaches both binaries | An action column parts the act from the thing |

## The by-upgrade view

One row per upstream upgrade, keyed on the fold, with what moving it would
close: a build's planned upgrades read from the triager's end.

| Rule | Reason |
|---|---|
| No action column; the package name opens the component, where the upgrade is planned: one source of three binaries is one upgrade and three links | |
| Versions are listed and never ordered, one package once per version upstream released, with no nearest or latest | An ordering is per ecosystem |
| The filters it cannot apply are named on the screen; it takes six of the list's | The rest ask about an occurrence, a deadline or an assignee |
| Nothing counts occurrences: it says the packages moved, the issues closed, the builds holding it | An upgrade is a fold |
| The word on screen is "upgrade" | The decisions' word |

## List navigation

The next finding is reachable without going back (REQ-60); the form sat at about
1,550 pixels on a page of 2,800.

| Rule | Reason |
|---|---|
| The list travels with the finding as one value in the address | A filter added to the list collides with nothing on the finding |
| The page the list holds answers first: a neighbor on either side, or an end of the whole list, asks nothing; a finding at a page edge with more beyond asks for the window below, where that window is wider than the page | |
| The window is the list's page widened by one row at each end, and a neighbor is handed the list at its own page; at the largest page the window is the page and the walk ends at its edge | Widening backward alone leaves the page's last row outside its own window |
| The row is found by what it is; where it cannot be, there is no walk | Under a state filter it may have moved |
| A list that asked for everything is a list: present-and-empty differs from absent | |
| What a saved filter prepares travels with the walk (`design-docs/interface-filters.md` § Saved filters) | |

## Restored position

A browser restores scroll only on a real navigation, which this application never
makes.

| Rule | Reason |
|---|---|
| A list opened by Back opens where it was read | The place in the list is the one thing the address cannot re-derive |
| A list opened fresh opens at the top | Arrivals are told apart by how they happened |
| Restored after the rows are drawn | A short page clamps the scroll |
| Written as somebody scrolls | An unmount is too late |
| A handful of pages, oldest by mark dropped; anything that is not a position is the top | The store is editable and grows; a browser's storage order is not write order |
| Back and Forward do not scroll the frame to the top | The list owns where it opens |
| Cleared with everything the session holds | |

## Limits

| Limit | Detail |
|---|---|
| A row's way down is drawn within one build | A chain belongs to one build's graph; across builds the Path column names a build and a count (`design-docs/interface-shell.md` § The scope picker) |
