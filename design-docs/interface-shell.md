# Interface shell

The frame every screen sits in: the rail, the top bar, the scope picker, home,
and the search box.

Satisfies REQ-05, REQ-17, REQ-25, REQ-42, REQ-58, REQ-60, REQ-64, REQ-87.

## Contents

- [The shell](#the-shell)
- [The scope picker](#the-scope-picker)
- [Home](#home)
- [The search box](#the-search-box)
- [Limits](#limits)

## The shell

A rail down the side carries the brand and the entries grouped by workflow. A
bar across the top carries what is being looked at, search, upload, what is
waiting on the reader, and who they are.

| Rail group | Holds |
|---|---|
| Work | Home, the review queue, what nobody holds, assignments |
| Investigate | Components, Dependency findings, Security testing, the dependency tree, Builds and releases, Uploads, what the build is waiting on |
| Respond | Vulnerability reports, the disclosure deadlines, incidents, published advisories, Record a flaw |
| Reports | Analytics, Code findings over time, the audit log. The audit log is here because an auditor asks about a period |
| Manage | The catalog in order (products, then their branches and tags, then variants), teams, access, assignment rules, settings, the deployment |

| Rule | Reason |
|---|---|
| The component is the hub every screen links into; no group is built around it | Remediation runs along the component, review along the decision, an embargo along the issue (REQ-17) |
| The two queues are separate entries, Dependency findings and Security testing, beside each other under Investigate; Unassigned, the review queue and assignments under Work open both families | Their units differ, and an unjudged result reaches no customer document; the doors are shared |
| The findings entry is Dependency findings, with SCA on hover | It lists what a scan of the inventory matched; Security testing holds the rest |
| Components opens the component chooser (§ The search box) with no term, a box asking for part of a name | The way into the hub without an issue to search for |
| Builds and releases opens the product page, and with a branch or tag picked that line's own page, a tag's being its release (`design-docs/interface-catalog.md` § Product and scan pages, § A release, gathered); it declines until a product is picked | Reading how a product goes is investigation; the catalog's lists stay under Manage |
| The comparison of two releases is not on the rail: it is a named report under Analytics, arriving with the selection made, linked from the front page | One screen, one door |
| With a product, branch or variant unpicked, the tree, Uploads and planned upgrades entries are disabled and say why | A build-only entry declines rather than opening on a meaningless scope |
| Dependency findings takes whatever is selected; its count is asked with the narrowings the list writes into a silent address, as the Unassigned entry's is | The count is of what the list will show |
| A screen's breadcrumb opens the product page from the product's name, and the branch or tag's own page from its name | The product page names every build with what is open in it |
| The bar's search finds an issue or a component (§ The search box); "/" focuses it unless somebody is typing | |
| Upload is in the bar on every screen (REQ-05), and on Uploads | The form picks its own build; Uploads is where the result appears |
| On a narrow screen the rail gives way to a tab bar: home, the reader's findings, the review queue, and a fourth tab and a bar control opening the whole rail as a panel | What somebody reviews and responds from on a phone |
| The phone's findings tab is Findings, opening Dependency findings, for a reader of them in some product; Code findings, opening the Security testing queue, for a reader of code findings alone; absent for a reader of neither | The tab follows the entries the rail draws for the reader |

### Rail entries by holding

Each entry follows `design-docs/interface.md` § Families a reader holds, or the
right its screen asks for.

| Entry | Drawn for |
|---|---|
| Dependency findings, the phone tab Findings | A reader of dependency findings in some product |
| Components | A reader of either family in some product, since the chooser searches only products where they read one |
| The phone tab Code findings | A reader of code findings in some product and of dependency findings in none; it opens the picked product's queue where they read it there, else the queue across products |
| Builds and releases, Products, Branches and tags, Variants, Assignments, Auto-assignment, Published advisories, the audit log | Everybody; the screens answer each reader with what they may see |
| Unassigned | A reader of either family in some product. It opens `/unassigned` where both families are counted, and the one family's list of unheld work where one is: the findings list under nobody assigned and nothing decided, or the code finding queue across products under nobody assigned (`design-docs/interface-review.md` § Work nobody holds) |
| Dependency findings with a product picked | Declines where the reader holds them in another product, saying so on hover; its count is asked only where they are read here |
| The Dependency findings and Unassigned badges | A reader of one half alone has the unit say which half the count is of (REQ-60) |
| The Unassigned badges | One per family counted, side by side, each with its unit on hover and never summed; a family not counted is not asked (`design-docs/kinds.md` § Consumers) |
| Security testing | A reader of security testing work in some product; declines in a product where it is not read, with the code family's line on hover |
| Code findings over time | The same readers, below Security testing; declines until a product is picked, and in a product where the work is not read, saying why on hover |
| Vulnerability reports, Disclosure deadlines | A reader of undisclosed work in some product |
| Record a flaw | A reader who may triage undisclosed or disclosed work in some product |
| Incidents | Everybody: the shelf holds what each reader may be told of, a collaborator's own case included, and an administrator declares the response windows there |
| Analytics | Everybody: the coverage reports answer what is scanned to anybody who sees a build, and a report counting a family the reader does not hold shows the line |
| Access, Settings | An administrator or a holder of the audit permission |

### The folded rail

The whole rail unfolded is taller than most laptop windows. A
scroll region of its own puts a second scrollbar mid-screen; scrolling with the
page leaves the menu far above the foot of a list.

| Rule | Reason |
|---|---|
| A group heading folds what is under it, and Manage starts folded | It is occasional work; folded, the rail asks 982 pixels at 1440 wide for a reader drawn every other entry |
| A first visit needs nothing folded open | A product is picked in the bar |
| The heading stays drawn as a heading, a caret its only control mark | Five headings drawn as buttons read as five more places |
| What is folded is kept in the browser, per person, by group name; a name no group has folds nothing | |

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

Home is one page leading with the reader's work (REQ-58), then the estate's
figures one family at a time, then operational state at the foot. The trends
are asked occasionally and are the slowest read.

| Part | Holds |
|---|---|
| The work | Assigned to the reader per family, sent back, incidents where there are any, pending their approval; then the panels: Records or Your cases where they apply, pending approval, in progress, lapsed decisions. Both families, mixed |
| The figures | A tab strip, Dependencies and Security testing, over one family's figures and trends (§ Dependencies figures, § Security testing figures) |
| Operational state | The status panel: builds being scanned, quiet builds, the last inventory received, and for a reader of code findings at the scope, the last analyzer run received and the series gone quiet |

| Rule | Reason |
|---|---|
| The strip is drawn for a reader holding both families in some product. A reader holding one sees that family's figures with no strip; a reader holding neither sees no figures | A family held nowhere is absent (`design-docs/interface.md` § Families a reader holds) |
| The tab rides in the address, `figures=security-testing`; the address naming none is Dependencies, and a reader holding one family is shown it whatever the address names | A link opens the same tab |
| The strip governs the figures and trends alone; the work stays above it, unchanged by the tab | Tabs inside the page keep it one page leading with the work |
| A tab whose family the reader holds in another product and not the picked one draws the family's line in place of its figures | A zero for work the reader cannot see reads as nothing open |
| Lapsed decisions are drawn for a reader of either family at the picked scope; its line counting findings with a lapsed decision is asked only where dependency findings are counted there | A decision lapses on either family; the findings line counts dependency findings |
| The work figures (sent back, pending approval) and in progress stay for every reader of either family | They hold both families' work |
| What is assigned to the reader is one figure per family, under the rule for the reader's own lists in `design-docs/interface-review.md` § Assignments and assignment rules; held in another product and holding none, the figure is a dash with the family's line | One figure over both families counts two units as one |
| A reader of no finding in any product who administers, audits or collaborates on nothing has a Records panel among the work, opening the audit log, access and settings where they may read them; the work figures and panels stay; the line under the greeting says they audit or hold no role | An auditor's work is the deployment's records, and a capability held without a read role still brings assigned work (`design-docs/access.md` § Breadth of view) |
| A reader the session says collaborates has a Your cases panel, whatever else they read: each case by its issue and product, opening the product's findings list searched for the issue, and each code finding granted by its rule, file, flaw and product, opening it on the build it was last seen in (`design-docs/access-disclosure.md` § Own cases). The list is asked only for them, and the panel is absent where every grant has ended | A grant reaches one thing, and the notice that brought them in scrolls away |
| The line under the greeting counts the products the reader reads | |
| What became of decisions is counted from a page read, and the tile says where the page was cut | It is derived, with no count to ask for |
| Every figure opens the list it counts, narrowed as counted, the aging buckets included (`design-docs/interface-administration.md` § Analytics) | |
| A figure counting anything closed opens nothing | The findings list holds what is open (`design-docs/analytics-catalog.md`) |

| Panel | Rule |
|---|---|
| Quiet builds | A build no longer scanned, named one at a time. Also on the scans screen. It reports nothing new and fails nothing, so looks healthy |
| Incidents | Standing incidents, one per issue and product, from the shelf, narrowed to the picked product, opening the shelf narrowed so. A tile of its own among the work, because the feed's count says nothing about this product. Drawn only where there is one, and the shelf asked of every reader, since it holds what each may be told of, a collaborator's own case included. A branch or variant scope counts the whole product and says so, since an incident is against a product |
| Review queue count | One count per product: the rail's badge, the pending figure and the across-products figure are one request under one key, polled once a minute by the rail |
| Dependency findings and code findings assigned to you | What the reader and their teams hold of each family, in the list's unit; the dependency figure carries the reports they hold beside it, never among them: a report is against a product and no build |
| In progress | How much each person and team holds, open findings and reports together, three rows, the reader's own first |
| Analyzer runs in the status panel | The newest run received and the series gone quiet, over the products the Security testing figures count, from the same reads |

### Dependencies figures

Open issues, known exploited, overdue and due soon, then the trend of open, new
and resolved issues, severity over time, open issues by severity, and release
readiness. Each counts dependency findings, drawn under `design-docs/interface.md`
§ Families a reader holds at the picked scope.

| Rule | Reason |
|---|---|
| Open is the trend's latest point at every scope, counting distinct issues | A tile switching unit as the picker moves quotes two figures for one word |
| Known exploited is drawn only with a product picked | The list across products counts a row per product |

| Panel | Rule |
|---|---|
| Release readiness | The picked branch against the last release cut from it, band by band, the move shown as a direction colored by meaning (fewer is better). Drawn only for a whole build on a branch |
| Overdue and due soon | One read of the deadline list, each tile opening the list it counts. The read is capped and ordered soonest first, so a cut page holding a row still due holds every overdue row. Overdue is a floor only where the whole cut page is overdue; due soon wherever the page is cut. The all-products figure follows the same rule over its own read |

### Security testing figures

Code findings alone, counted per testing method and never added to a dependency
figure (REQ-87), from the Security testing statistics consumer and the queue
(`design-docs/kinds.md` § Consumers).

| Part | Shows | Opens |
|---|---|---|
| Open | Code findings to be judged, the queue's open state; split by testing method once there is more than one | The queue in that state |
| Waiting for a judgment | The queue: open code findings no decision is proposed for, and how long the oldest has waited | The queue |
| This week | New and fixed in the trend's last week | Code findings over time, with one product counted |
| No longer detected | Today's count, which has no weekly line | The queue in that state |
| Analyzers gone quiet | Series with no comparable run within their own expected interval, on a release in support, the first two named | Analysis coverage, with one product counted |
| Code findings over twelve weeks | Not fixed, new and fixed per week, with a mark at each tool, version or rule-set change and each run not comparable | |
| Not fixed by tier | Not fixed per week, stacked by the tier of the rule's weaknesses as rated now | |

| Rule | Reason |
|---|---|
| With no product picked, the figures count every product where the reader reads security testing material, and say how many | REQ-42: a product read nowhere is never counted |
| A product, branch or variant picked narrows every figure as the queue narrows | |
| The trend, the oldest wait and the coverage are asked per product and added across products; a failed read of one product fails the figure | A series is one product's, and a total missing one product is wrong |
| A marker names its product where more than one is counted | A series name is one product's |
| Where no series has run in the scope, one line says no analyzer has run there, in place of the figures | A series never run reads as clean at zero |
| This week and Analyzers gone quiet open nothing across products | Both pages are one product's |
| The charts plot on when a run was applied, as the dependency trend does | |

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
| The rail's Components entry opens the chooser with no term: a box for part of a name, and no search until one is typed. A name typed there is the chooser's term, as the bar's is | The way into the hub with no issue in hand |
| A component search lands on a chooser: each source package matching the term in the picker's selection, one row per product, with its open issues and open code findings, each opening the component screen (`design-docs/interface-component.md` § Security testing on the component) | The component is the hub both families link into |
| A family the reader does not read in a row's product is a dash with the family's line on hover, never a zero; a count the server left out is such a family, in a product the session does not list too | A retired product has no row in the session |
| The chooser offers the findings list's search for the same term | A finding's name is not always a component's |
| The term is in the chooser's path and the scope is the picker's, so a change of selection answers the same term again | |
| The findings list's box holds the term the list applies, and whatever removes it from the address (its chip, clearing filters, a saved filter, Back) empties the box | Enter would restore a search the reader thought gone |

## Limits

| Limit | Detail |
|---|---|
| A known-exploited tile needs a product | Nothing counts exploited findings without one to narrow inside |
