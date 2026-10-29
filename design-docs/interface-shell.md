# Interface shell

The frame every screen sits in: the rail, the top bar, the scope picker, home,
and the search box.

Satisfies REQ-05, REQ-25, REQ-42, REQ-58, REQ-60, REQ-64.

## Contents

- [The shell](#the-shell)
- [The scope picker](#the-scope-picker)
- [Home](#home)
- [The search box](#the-search-box)
- [Limits](#limits)

## The shell

A rail down the side carries the brand and the entries grouped by what they
span. A bar across the top carries what is being looked at, search, upload, what
is waiting on the reader, and who they are.

| Rail group | Holds |
|---|---|
| Across products | Home, the review queue, what nobody holds, assignments, the audit log. The audit log is here because an auditor asks about a period |
| The named build | Dependency findings, the dependency tree, Uploads, what the build is waiting on. At its foot: Record a flaw, the disclosure deadlines, published advisories, incidents |
| Manage | The catalog in order (products, then their branches and tags, then variants), access, teams, assignment rules, settings, the deployment |

| Rule | Reason |
|---|---|
| The findings entry is Dependency findings, with SCA on hover | It lists what a scan of the inventory matched; Security testing holds the rest |
| The comparison of two releases is not on the rail: it is a named report under Analytics, arriving with the selection made, linked from the front page | One screen, one door |
| With a product, branch or variant unpicked, the tree and Uploads entries are disabled and say why | A build-only entry declines rather than opening on a meaningless scope |
| Dependency findings takes whatever is selected; its count is asked with the narrowings the list writes into a silent address, as the Unassigned entry's is | The count is of what the list will show |
| The bar's search is the findings list's search; "/" focuses it unless somebody is typing | |
| Upload is in the bar on every screen (REQ-05), and on Uploads | The form picks its own build; Uploads is where the result appears |
| On a narrow screen the rail gives way to a tab bar: home, findings, queue, and a fourth tab and a bar control opening the whole rail as a panel | What somebody reviews and responds from on a phone |

### Rail entries by holding

Each entry follows `design-docs/interface.md` § Families a reader holds, or the
right its screen asks for.

| Entry | Drawn for |
|---|---|
| Dependency findings, Unassigned, the phone tab Findings | A reader of dependency findings in some product |
| Dependency findings with a product picked | Declines where the reader holds them in another product, saying so on hover; its count is asked only where they are read here |
| The Dependency findings and Unassigned badges | A disclosed-only reader's unit says the count is of disclosed findings |
| Security testing | A reader of security testing work in some product; declines in a product where it is not read |
| Vulnerability reports, Disclosure deadlines | A reader of undisclosed work in some product |
| Record a flaw | A reader who may triage undisclosed or disclosed work in some product |
| Access, Settings | An administrator or a holder of the audit permission |

### The folded rail

Twenty-four entries ask about 935 pixels, taller than most laptop windows. A
scroll region of its own puts a second scrollbar mid-screen; scrolling with the
page leaves the menu far above the foot of a list.

| Rule | Reason |
|---|---|
| A group heading folds what is under it, and Manage starts folded | It is occasional work; folded, the rail asks under 700 pixels |
| A first visit needs nothing folded open | A product is picked in the bar |
| The heading stays drawn as a heading, a caret its only control mark | Three headings drawn as buttons read as three more places |
| What is folded is kept in the browser, per person | |

## The scope picker

The picker narrows the whole interface, and every level offers "all" (REQ-58).
Product, branch and variant are chosen once and every screen answers for the
selection. The levels are independent: "this product, every branch, this
variant" is a real question. "All" products leaves the two below unselectable.

Five screens exist for one build alone, because there is no dependency graph
across branches: a finding, deciding an occurrence, the dependency tree, a bulk
decision, and scans. On those, levels that would go to "all" are disabled and
say why; a control that declines beats one that relocates.

The findings list is not one of them. Its row is an issue at a component, and
nothing about it is keyed on a build (REQ-25). With a branch or variant at
"all", a row counts occurrences across every build in scope, names one of them,
and says how many hold it; the Path column becomes that build and the count. It
has two addresses that are one screen: a whole build keeps the build's address,
anything wider is the product's list carrying the set levels. Widening on either
moves to the other.

| Rule | Reason |
|---|---|
| The picker stays open until the last level is chosen; each pick applies at once, and it closes on the variant, Escape, or a click elsewhere | A partial scope is a real answer, and a build is one opening |
| Changing scope keeps the screen; a build screen swaps its build | |
| A screen naming a build in its address is the authority for it; everything else remembers the last, per tab | Where somebody works now; a second tab must not drag the first |
| A screen whose address names the product has the address rewritten on a product change; choosing every product from one is the catalog | The path is the authority, so a remembered product would be put back |
| Every address under `/products/:product` names that product to the bar and rail, including one no rule lists by shape. An address naming only the product (a component, the vulnerability reports) keeps that product's picked branch and variant. A test walks every product route and holds this and the rewrite | A report link opened in a fresh tab names its product |
| What sat below the product in the address and belonged to it (a branch, a component) is dropped, falling back to the new product's branch list or the product | |
| What comes back from the tab's memory is checked, never cast | It becomes a path segment and a query parameter |
| What the tab remembers goes with the session (`design-docs/interface-editor.md` § Drafts) | The next person in the tab |
| A narrowed screen and every panel in it say what they count | A narrowed chart labeled "all products" is believed by its label |
| A branch or variant with no product above it is dropped on the way out | The server refuses it |
| Picking a branch keeps the product's variants in the column until the release's arrive | A superset; a blank column reads as lost choices |
| The picker asks for no counts; the products, branches and variants screens, whose subject they are, pass a parameter for them | Counts are the expensive half of a catalog read (`design-docs/interface-catalog.md` § Catalog and uploads) |
| Variants are unselectable on a build screen until a branch is picked | A variant over no branch changes nothing |
| A run or an inventory's changes, rescoped, lands on the new build's Uploads | Both are numbered within the old build |
| A screen saying what it needs picked opens this picker and brings the bar into view | One picker; the bar does not follow the page down |

## Home

Home leads with the reader's work, then the estate (REQ-58): assigned to them
and decisions of theirs sent back; then open at or above the floor, incidents
where there are any, known exploited, pending their approval, and overdue; then
trends; operational state at the foot. The trends are asked occasionally and
are the slowest read.

| Rule | Reason |
|---|---|
| Open is the trend's latest point at every scope, counting distinct issues | A tile switching unit as the picker moves quotes two figures for one word |
| What became of decisions is counted from a page read, and the tile says where the page was cut | It is derived, with no count to ask for |
| Every figure opens the list it counts, narrowed as counted, the aging buckets included (`design-docs/interface-administration.md` § Analytics) | |
| A figure counting anything closed opens nothing | The findings list holds what is open (`design-docs/analytics-catalog.md`) |

| Panel | Rule |
|---|---|
| Release readiness | The picked branch against the last release cut from it, band by band, the move shown as a direction colored by meaning (fewer is better). Drawn only for a whole build on a branch |
| Quiet builds | A build no longer scanned, named one at a time. Also on the scans screen. It reports nothing new and fails nothing, so looks healthy |
| Incidents | Standing incidents, one per issue and product, from the shelf, narrowed to the picked product, opening the shelf narrowed so. Its own tile beside known exploited, because the feed's count says nothing about this product. Drawn only where there is one. A branch or variant scope counts the whole product and says so, since an incident is against a product |
| Overdue and due soon | One read of the deadline list, each tile opening the list it counts. The read is capped and ordered soonest first, so a cut page holding a row still due holds every overdue row. Overdue is a floor only where the whole cut page is overdue; due soon wherever the page is cut. The all-products figure follows the same rule over its own read |
| Review queue count | One count per product: the rail's badge, the pending figure and the across-products figure are one request under one key, polled once a minute by the rail |
| Assigned to you | What the reader and their teams hold, in the list's unit, with the reports they hold beside it, never among them: a report is against a product and no build |
| In progress | How much each person and team holds, open findings and reports together, three rows, the reader's own first |

## The search box

One box, matching component names and issue names alike, at whatever scope is
chosen (REQ-64).

| Rule | Reason |
|---|---|
| It is labeled "Find a component or an issue" and matches issue names, aliases included, and component names | "Where is this in what we ship" is asked by the name the reporter used |
| One box, never two fields | Somebody typing a name does not classify it |
| It asks at the picker's selection, including none, which is every product the reader sees | Returning without navigating swallows what was typed |
| A term resolving to an issue goes to the issue, decided by asking | A second copy of name resolution is wrong about minted identifiers |
| A term resolves to an issue when the issue's read holds a row; an empty answer is a component search; only an unanswered read stops at the box | The read answers an issue nobody here carries with an empty list |
| The findings list's box holds the term the list applies, and whatever removes it from the address (its chip, clearing filters, a saved filter, Back) empties the box | Enter would restore a search the reader thought gone |

## Limits

| Limit | Detail |
|---|---|
| A known-exploited tile needs a product | Nothing counts exploited findings without one to narrow inside |
