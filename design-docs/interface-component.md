# Component screen and dependency tree

The component screen, the reads behind it, and the dependency tree with its
counts and search.

Satisfies REQ-42, REQ-56, REQ-60.

## Contents

- [The component screen](#the-component-screen)
- [Security testing on the component](#security-testing-on-the-component)
- [Component screen reads](#component-screen-reads)
- [The dependency tree](#the-dependency-tree)
- [Tree search](#tree-search)
- [Limits](#limits)

## The component screen

The page is a source package at the version it was built at: the fold
`design-docs/data-model-components.md` § The fold defines. It is arranged on where the package sits,
because that decides what can be done: a leaf carries its own risk and is
upgraded; a package vendored pre-built carries everything beneath it and moves
only when it does. The graph leads (what pulls it in, the package, what it
carries) and the act hangs off it.

| Rule | Reason |
|---|---|
| The position is drawn before the action | The same numbers read oppositely at the two ends of a graph |
| One page per source package; a binary whose inventory names no source is its own source | An upgrade is what the page is for |
| A binary name and a source name open the same page, compared regardless of capitals | A tree link names the binary; a person asking names the source |
| The binaries are listed and one is picked: the one the address named, else the one carrying most. The graph and the twelve weeks answer for it | What pulls a library in is not what pulls its command in |
| Counts cover the source package, once per issue; each binary carries its own count | |
| Consumers are counted from outside the source package | |
| More than one version is a choice offered with what is open at each, never a refusal | Two versions are two pieces of code |
| The open issues are a button beside the name, "1,840 open issues →", to the findings list for every binary of the source; absent where nothing is open | The question most people arrive with |
| A count is the link to what it counts: a binary's "N open" opens that binary's list, each build's count that build's | |
| A row per build shipping it, with the binaries it ships, what is open, where it could go, the earliest deadline among what is open, and what is promised | |
| A build is listed because it ships the component; the counts are joined on | A package whose risk is all beneath it would list no builds |
| One row per source version per build | Collapsed, the other version is hidden |
| A deadline is absent where nothing is open, never zero | |
| Per build, because the answer differs by build | A maintained older line and a moved-on branch are different work |
| The package identifier travels with the row; the ecosystem and upstream address are read from it, stored nowhere, fetched from nowhere | |
| Where to read about the package is built from its identifier, an ecosystem with no address offering none; the name is encoded into the path | It came from a scan file |
| Where it could go carries two counts: what a release fixed (open issues naming that exact version) and what reaching it closes (that plus everything fixed before) | Sorted on the first, the version worth taking sinks: on the demo kernel the release closing all 158 fixed 2 of its own, and the one fixing 49 led |
| Furthest along first where versions order; unranked where any comparison refuses, the two counts then equal and the screen saying so | An ordering is per ecosystem |
| The second count is consumers; occurrences are the row's title | The ceiling on one action is in occurrences |
| It carries where the component sits: what pulls it in, what it pulls in, and twelve weeks of what opened and closed under it | Arriving from the tree is a question about the graph |
| The graph answers for one build, picked from the rows; a link naming a build arrives on it | An edge is a fact about one build |
| Releases are picked inside the promise form, ticked to those shipping this version | One bump moves every release at that version |
| The version to move to is offered and never required | A version newer than any advisory can be named; the server refuses an unknown one |
| Nothing to upgrade to is a state, not an empty form | Where no version fixes anything, the work is a decision |
| The decision over many issues at one component is linked here, beside the count no version fixes, and as the action where nothing fixes anything | |
| What the product's upstream says about the component is a card: every standing statement about a component of this name at any version, with issue, version, status, mark, link and decline control; drawn only where it says something | |
| A container image lists the versions each build stated for it, newest first, with the dates each was stated across; the first five shown and the rest counted | An image carries no version of its own (`design-docs/data-model-components.md` § Container images) |

Every count on the page but the security testing ones is of dependency
findings, drawn under `design-docs/interface.md` § Families a reader holds.

| Rule | Reason |
|---|---|
| Where the reader does not read dependency findings in the product, no count, open button, severity band, fix card or twelve weeks is drawn, and nothing calls the component clean | A zero over open code findings reads as a clean component |
| Where they read them in another product, one line says so | |
| Where nothing is open, the chip says "no dependency findings open" | The page counts one family, and its zero names it |
| A reader of one half alone has its counts carry the line saying which half | |
| The page is drawn either way: the package, where it sits and the builds shipping it | They are the inventory, which the product's readers hold |

An upgrade is promised here on the terms `design-docs/triage-promises.md` § Promised work sets: the
releases, the version, the date, the reason, and who carries it.

## Security testing on the component

The component is where both families meet: every screen naming a component
links here, and what the analyzers hold on it sits beside the issues
(`design-docs/analysis-queue.md` § Code findings of a component).

| Part | Holds |
|---|---|
| The Security testing card, under the heading | Open code findings over every build, opening the queue on the source package; a row per analyzer series with a count per state, each opening the queue at that series and state; the open ones on the build itself, named as unplaced, with a link to Repositories |
| A code findings column on each build row | The open ones that build places on the source package at the row's version, opening the queue at that build and version |
| A second twelve-week panel | Code findings at the package and under it on the graph's build not fixed each week, with weekly new and fixed; its own panel beside the issues' |

| Rule | Reason |
|---|---|
| The families are never summed: no total, line or column adds code findings to issues | A rule at a place and an advisory at a component are different units |
| Drawn and asked for only where the reader reads security testing material in the product, once the session says so; held elsewhere, the card is the family's one line; held nowhere, nothing is drawn (`design-docs/interface.md` § Families a reader holds) | A count not drawn is not asked for, and a zero here reads as clean code |
| The card's counts are over every build of the product | The card answers for the source package; the build column answers per build |
| A count of zero is drawn, never linked: the header, the state cells and the build column | The list it would open is empty |
| Every count is asked, and every link opens the queue, by the name in the address, which may be a binary's | A binary's name reaches only the versions that binary ships, a source's every one, so counting by one and linking by the other opens a different list |
| The build column and the trend are drawn from the counts' answer alone: not while they load, not where they failed | A column drawn before the answer reads as zeros |
| A product the session does not list is asked; a refusal of the counts is the family's one line, with no column or trend | A retired product has no row in the session, and only the server says whether its code findings are read |
| On a build's root, which no build row ships, the card is drawn alone where its counts hold any code finding; where they hold none, the screen says no build ships the name | Code findings no repository holds sit on the root, and the tree links its name here |
| The card is drawn whether or not the reader reads dependency findings | A developer reading code findings alone arrives here from the queue |

## Component screen reads

A kernel is most of a build: 322,616 open occurrences across the bench image's
two builds. Every read is shaped by that size;
`design-docs/interface-measurements.md` § Component screen holds the runs.

| Rule | Reason |
|---|---|
| The source package's component rows are read first and named to every statement over findings as values | Restricted by a join on the fold key, PostgreSQL estimates the kernel's occurrences at 106, sorts on disk and probes a decision per occurrence |
| The counts, their bands, each binary's count, where it could go and what is promised are one pass over the occurrences | 243 ms as one, against four statements each reading the table |
| The occurrences are grouped three times: by issue and fix per component, by issue per source package, then by fix, band and source package | Key, rating and fix are worked out over 17,866 rows, and 174 come back |
| The source package an issue belongs to is the component's position in the list already read | Joined for the fold key, 204 ms against 175 |
| An issue is counted under the one fix it names across the source package; one whose binaries name different fixes comes back on its own row, its fixes read after | Fix counts are of issues |
| Each binary's count is a column of the pass; past 512 binaries it is read alone | PostgreSQL refuses over 1,664 columns; MariaDB and SQLite fail not far above |
| What is promised joins each occurrence as one number, the promise's rank above its decision's identifier: a version over none, then a date over none, then the later date; alike, the later decision. Promises are one row per issue and occurrence before the join | The greatest per source package names the decision |
| What is promised is correlated by the scope's product, bound once | Every build on the page is in it |
| A component's own open count in the tree groups to one row per issue before counting | 42 ms against 103 counted distinct |
| One step through the graph reads the neighbors first and counts what is open on them and beneath them, named as values | 3 ms against 32 for the whole build joined |
| What is beneath each neighbor is the per-neighbor union of issues on what it reaches, taken in the application | Joined, each of 45 parents brings the kernel's issues: 302,269 rows sorted, 345 ms |
| The issues on what the walk reaches are read for the reached components, named as values | Walked again, statistics after a large scan made it 4.2 s on PostgreSQL |
| A neighbor reaching one carrying component takes that component's counts, with no union | 44 of the kernel's 45 parents |
| Rows of one name at one rank are ordered by component identifier | A build ships a name at two versions |

## The dependency tree

A tree browsable both ways (REQ-56): from a finding to where it sits, and from a
node to the findings beneath it. Each row carries what is open beneath it as well
as on it, worked out when read, never stored, because findings move.

| Rule | Reason |
|---|---|
| Both numbers are distinct issues: a node's own, and across it and everything under it with each component once however reached | A library at thirty-six occurrences with two issues is two, not seventy-two |
| One recursive walk answers which components each child of a row reaches; a second statement over the same walk answers the issues on those components once each; the union per child is taken in the application | 0.08 s for the root's thirty children on the full-size image |
| The walk records reach and not distance | Distance keeps a component once per path: 1,612,405 rows for 43,904 pairs |
| Every row is ordered on its number: beneath it for a branch, its own for a leaf; what opens comes first | |
| Ordered cumulatively, forty kernel-module packages each depending on the kernel all report its total | The document does not tell contains from depends on; the fault sits deep and is the lesser one |
| The header says how many components the scanner cannot match and opens them, only when there are some (`design-docs/analytics-catalog.md` § Unmatched components) | A build of nothing else scans clean; a real 37-package image did |
| What nothing pulls in hangs from the root, whose count is everything beneath it as one set | A real switch image of 60,935 components has no edges from its root |
| A level is drawn whole; the cap is for inventories that are not honest | 5,270 components seen under one root |
| Arriving from a finding opens on the component with every parent expanded; the chain travels in the link, and a step past a level's cap is kept | |
| A version every component at a level shares is drawn once above the rows | A switch image's thirty containers carry one build stamp |
| A node's number is shown as one bar of band widths, the component screen's control, in a fixed-width column, numbers on the title, rolled up in the counting statement so bands sum to the total, banded by the rating in force in this product | The list it opens groups by that rating |
| A node count opens its list: `beneath`, every open finding at or under the component by the same walk; `under` stays the direct consumer | The figures need not match; the list is one row per issue and component |
| A name the build does not hold answers not found | An empty list is a clean subtree |
| The count is every open issue, answered or not | The screen answers "what is open here" |
| The marker opening a row is a button | Otherwise no node past the first level is reachable without a pointer |
| A row is keyed by name, version, package kind and namespace: what is open, what was drawn, what sits under it, and the request for children; a request naming two things is refused | A component shipped twice must open |
| A component's name opens the component; the node name selects, so the link is the row's own control and the names in the two lists beside the tree | |
| There is no pane over the tree | The component screen answers it |
| For a reader not reading dependency findings in the product, rows carry no count or band and search hits are not said to be ordered by findings; one line says where they are read elsewhere (`design-docs/interface.md` § Families a reader holds) | A tree of zeros reads as a clean build |
| For a reader of security testing material in the product, each row and search hit carries a code findings badge of its own: open code findings at it and under it, opening the queue beneath it on the build. Asked for only then; held elsewhere, one line says so | The families are different units, so the badge sits beside the issue count, never added to it |
| Under the root row, a line states how many open code findings are unplaced, on the build itself, with a link to Repositories, zero included | Code findings in files no repository holds sit on the root; a repository's settings are what place them |

## Tree search

Searching the tree counts what the tree counts: distinct open issues the reader
may read, per component, ordered by count then name. A component at several
occurrences is one answer.

| Rule | Reason |
|---|---|
| Issues, never finding rows | |
| A hit carries what is beneath it, by the tree's walk and bands | |
| The build's own root is not a hit | |
| Counted in one pass over the build, grouped by component; a narrow term is slower than counted per match on three engines, since the pass reads the whole build | Every term is under half a second on every engine (`design-docs/interface-measurements.md` § Tree search) |
| Hits are marked in the list, which stays while the term does, each with a link to its component | A hit carries no chain, so the tree cannot open at it |

## Limits

| Limit | Detail |
|---|---|
| The component read has a floor of one pass over a source package's occurrences | Fix, deadline and occurrence are read from the table, as no index carries them: 100 ms of 243 on PostgreSQL. Lower needs a stored per-issue total rewritten as findings move |
| Sibling components are not folded on the tree | Folding removes 281 of 36,991 child rows and shrinks the largest level from 4,867 to 4,679, still too large to browse |
