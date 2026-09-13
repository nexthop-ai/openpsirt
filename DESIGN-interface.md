# Interface

The web interface, how it is built, and how it reaches the server.

Satisfies REQ-05, REQ-15, REQ-18, REQ-19, REQ-25, REQ-26, REQ-28, REQ-34,
REQ-40, REQ-41, REQ-42, REQ-43, REQ-54, REQ-55, REQ-56, REQ-57, REQ-58,
REQ-59, REQ-60, REQ-61, REQ-64, REQ-65, REQ-67, and the half of REQ-69 that is
shown rather than collected.

The markdown rules are in `DESIGN-text.md`. What is not built is named at the
end rather than left to be found by clicking.

## Contents

- [One artifact](#one-artifact)
- [Path routing](#path-routing)
- [The generated client](#the-generated-client)
- [Capabilities before drawing](#capabilities-before-drawing)
- [The look](#the-look)
- [The shell](#the-shell)
- [The scope picker](#the-scope-picker)
- [Home](#home)
- [The findings list](#the-findings-list)
- [Filters](#filters)
- [Sorting, paging and selection](#sorting-paging-and-selection)
- [Saved filters](#saved-filters)
- [The by-component view](#the-by-component-view)
- [The by-bump view](#the-by-bump-view)
- [The component screen](#the-component-screen)
- [The finding screen](#the-finding-screen)
- [The decision form](#the-decision-form)
- [The reach sheet](#the-reach-sheet)
- [Walking the list](#walking-the-list)
- [The dependency tree](#the-dependency-tree)
- [The review queue](#the-review-queue)
- [The claim page](#the-claim-page)
- [Assignments and routing rules](#assignments-and-routing-rules)
- [Catalog and inventories](#catalog-and-inventories)
- [Product and scan-run pages](#product-and-scan-run-pages)
- [Recording a flaw](#recording-a-flaw)
- [Disclosure and advisories](#disclosure-and-advisories)
- [The editor](#the-editor)
- [An expired session](#an-expired-session)
- [Attaching a file](#attaching-a-file)
- [Mentions and assignment pickers](#mentions-and-assignment-pickers)
- [The search box](#the-search-box)
- [A person's own page](#a-persons-own-page)
- [A person, whole](#a-person-whole)
- [A release, gathered](#a-release-gathered)
- [Reports, settings, inheritance](#reports-settings-inheritance)
- [Showing the ordering signals](#showing-the-ordering-signals)
- [Units, dates and copy](#units-dates-and-copy)
- [Interface-wide rules](#interface-wide-rules)
- [The initial load](#the-initial-load)
- [Running it locally](#running-it-locally)
- [Divergence from the mockup](#divergence-from-the-mockup)
- [Test coverage](#test-coverage)
- [Not built](#not-built)
- [What the checks missed](#what-the-checks-missed)
- [File organization](#file-organization)
- [Limits](#limits)

## One artifact

The built interface is embedded into the binary and served from it. A deployment
is one container, and the interface cannot be a version behind the API it talks
to.

| Rule | |
|---|---|
| Nothing is fetched at run time | No font, no script, no stylesheet from anywhere, so an air-gapped install is an ordinary install rather than a configuration |
| The embed needs a directory that always exists | `//go:embed` fails to compile when its target is missing and the built output is not in the repository, so `internal/webui/dist` is tracked, empty, and the frontend build fills it. Two rules, not one: `dist/` is ignored everywhere and git does not descend into an excluded directory, so the placeholder is un-ignored at the top level along with its directory |
| A binary built without the interface serves the API alone | The embed is read for `index.html` and yields nothing without one, so a checkout with no node toolchain still builds and runs. A supported way to build this |

## Path routing

| Path | Answered by |
|---|---|
| **A route the server has** | The server, credential required as always |
| **A file in the built output** | Itself, cached by its content-hashed name |
| **Anything else** | The page, which does its own routing |

A single-page application owns its routing, so a path this server has never heard
of is a route the page knows. Answering 404 would make every deep link fail on
reload while working when navigated to.

| Rule | |
|---|---|
| Anything beginning `/v1` is answered by the server, routed or not | Handing a page back to a client parsing JSON reports a mistyped endpoint as a parse failure |
| The rule is "the router has no route for this", asked of the router | Not "the path is outside `/v1`". The framework registers routes of its own — the API document and the schemas it references — and a prefix rule hands those to anybody who asks |
| Names the server owns are reserved even when nothing is routed there | The framework's documentation route is disabled by configuration, and unrouted is exactly what marks a path as the page's. Without a reserved list the interface would have claimed `/docs`. A test asserts that mounting the interface opens nothing |
| The page loads without a credential and nothing else changes | The sign-in screen *is* the page. What is served is a compiled application and its assets, carrying no data |

## The generated client

The API client comes from the committed OpenAPI document. No path and no response
shape is hand-written, so an endpoint that changes shape is a compile error rather
than a screen rendering `undefined`. `make web-api` regenerates it and fails if
the result differs from what is committed — the generated types say a list may be
`null`, which the hand-written version would have discovered in a browser.

The session is a cookie the browser holds and nothing in the application ever
sees. The application holds the cross-site-request token, deliberately readable
by script where the session cookie is not: echoing it distinguishes a request our
page made from one somebody else's page caused. Every unsafe request carries it,
**attached once as middleware rather than per call** — the one call somebody
forgets is the one that breaks in production and not in review.

## Capabilities before drawing

`GET /v1/session/me` answers who is asking and what they may do in each product
they can reach.

| Rule | |
|---|---|
| Capabilities, not roles | A screen needs to know whether to offer an action. Answering from a list of roles means every client re-implementing the mapping, and the copy that drifts is the one offering a button that leads to a refusal |
| A product somebody cannot reach is absent | A screen treats that as not-there rather than as forbidden, which is the answer the server gives |
| `GET /v1/sign-in` is answered without a credential | It lists the providers an operator configured, which is what somebody sees before they have a credential. It discloses names an operator chose and nothing about whether any account exists, and a test asserts that rather than assuming it |
| A 401 from `session/me` is an answer, not a failure | It means nobody is signed in, which is what a fresh browser looks like |
| Markdown is rendered and sanitized in the browser | The server returns markdown and only markdown, so preview and published text are the same renderer rather than two that agree by luck, and there is no round trip per keystroke |

## The look

The tokens, the type scale, the shell and every component come from the restyled
mockup, taken as settled rather than approximated (REQ-60). The mockup drew the
interface inside a frame; here the frame is the page, so its tokens sit on the
root element and its grid on the application container. That is the whole
translation, and it is why a screen here can be put beside its mockup and
compared control for control.

Two looks, one markup. A look is a token set — colors, the two typefaces, radii,
shadows — and nothing else. One is a dark rail over a light surface; the other
is dark throughout. They are called light mode and dark mode, because that is
what every other application on the same screen calls them.

| Rule | |
|---|---|
| Nothing chosen means the operating system is answering, and keeps answering | A machine that turns dark at sunset turns this dark at sunset |
| A person who picks one pins it, and picking "system" hands the question back | Otherwise choosing once is a door that opens one way, and somebody who tried dark at noon can never get their evening back |
| Stamped on the root element before the first paint | Setting it after the first frame is a flash of the wrong look on every fresh page |
| Kept in the browser, changing nothing anybody else sees | The same rule as saved filters |
| Severity never borrows the accent | Each look has its own accent and the same five-band severity scale beside it, with exploited above critical. A page that paints "critical" in the brand color has nothing left that means "act on this" |

A third look — an all-light hairline set — was dropped. Three looks named for
their aesthetics asked somebody to guess which of "Dojo", "Ledger" and "Obsidian"
was the light one.

## The shell

A rail down the side carries the brand and the entries grouped by what they span;
a bar across the top carries what you are looking at, a way to find things, a way
to upload, what is waiting on you, and who you are.

| Rail group | Holds |
|---|---|
| **Across products** | Home, the review queue, what is unassigned, the assignments and the record. The record is here because that is how it is asked for: an auditor asks about a period, not about a build |
| **The named build** | The findings, the dependency tree, the inventories and what the build is waiting on. The comparison of two releases is not here: it is a named report, listed in the report catalog with the selection already made, and linked from the front page. Three doors to one screen is two too many |
| **Manage** | The catalog, the users and the settings. Branches, tags and variants have entries of their own, scoped to the picked product |

A build-only entry declines rather than opening on a scope that means nothing.
With a product, branch or variant unpicked, the tree and inventories entries are
disabled and say why. Findings is not one of them: it takes whatever is
selected, and the count beside it is of what the list it opens will show.

Other bar rules:

- **The search in the bar is the findings list's own search**, reached without
  going there first. "/" focuses it, unless somebody is already typing.
- **Upload is in the bar on every screen** (REQ-05), because the form picks its
  own target; the inventories screen has it too, because that is where the result
  appears.
- **On a narrow screen the rail goes and a tab bar of three arrives** — home,
  findings, queue — which is what somebody reviews and responds from on a phone.
  A menu control in the bar and a fourth tab open the whole rail as a panel over
  the page.

### Folding the rail

Twenty-four entries ask for about 935 pixels, taller than the window on most
laptops. A scroll region of its own puts a second scrollbar down the middle of
the screen; scrolling with the page leaves the menu a thousand pixels above
somebody reading the foot of a findings list, which is where they are when they
want it.

A group heading folds what is under it, and "Manage" starts folded. Declaring a
product or granting a role is occasional rather than something done while
working, and with it away the rail asks for under seven hundred. The heading
stays a heading to look at — a caret is the only thing marking it as a control,
because three headings drawn as buttons read as three more places to go. What is
folded is kept in the browser, per person.

## The scope picker

The picker narrows the whole interface, and every level offers "all" (REQ-58).
Product, branch and variant are chosen once and every cross-product screen
answers for that selection. The levels are independent: a variant belongs to its
product, so "this product, every branch, this variant" is a real question.
Choosing "all" for the product leaves the two below it unselectable.

A screen that needs a whole build cannot be given half a scope. Five exist for
one build and no other — a finding, deciding a place, the dependency tree,
deciding several together, and scans — because there is no dependency graph
across branches and each is about a way down. On those the levels that would go
to "all" are disabled and say why. A control that declines is less surprising
than one that relocates you.

The findings list is not one of them. What the list is of is an issue at a
component, and neither that nor any decision about it is keyed on a build
(REQ-25). With a product picked and the branch or variant at "all", the list
answers for every build in scope: a row is still one issue at one component, its
places counted across every build, naming one of those builds and saying how
many hold it. The one thing it cannot draw there is the way down, because a
chain belongs to one build's graph, so the Path column becomes the build the row
names and the count of builds beside it.

It has two addresses, and they are the same screen. A whole build keeps the
address the rest of that build shares; anything wider is the product's list
carrying the levels that are set. Choosing a wider scope while standing on
either moves to the other — not the jump refused above, because it is the same
screen answering the question just asked of it.

| Rule | |
|---|---|
| The picker stays open until the last level is chosen | Each pick applies at once, because a partial scope is a real answer, but the panel closes only on the variant, on Escape, or on a click elsewhere. Closing after every pick made choosing a build three openings of the same panel |
| Changing scope keeps you where you are | A build-scoped screen swaps its build and stays the same screen |
| A screen that names a build in its address is the authority for it | Everything else remembers the last one. That memory belongs to the tab rather than the browser: it is where somebody is working right now, not a preference, and a second tab looking at another product must not drag the first one with it |
| A narrowed screen says what it is counting | A page answering for one product that looks exactly like a page answering for all of them is how two people quote different figures. That applies to the panels within it: a chart the picker has narrowed and a label reading "all products" state opposite things, and the label is the half a reader believes |
| A selection the server would refuse is never sent | A branch or variant with no product above it is dropped on the way out |

## Home

Home leads with the work and puts the shape of things underneath: what is
waiting for review, what is being worked on, what stopped applying, then the
trends, and the operational state at the foot. The trends answer a question
asked occasionally, and they are also the slowest part of the page.

Four figures lead, and they follow the scope: open at or above the floor, known
exploited, pending the reader's approval, and overdue. Open is the trend's
latest point at every scope, which counts distinct issues — the findings list
counts one row per issue and component, and a tile switching between the two as
the picker moved would quote two figures for one word.

| Panel | |
|---|---|
| **Release readiness** | The picked branch against the last release cut from it, band by band, with the move shown as a direction rather than a signed number: fewer is better here, so the color follows the meaning and not the arithmetic. Drawn only where the question has an answer — it needs a whole build, because a count across products is not a release, and a branch, because a tag is one frozen point |
| **Quiet builds** | A build that stops being scanned reports no new findings and fails nothing, so it looks healthier than one still being scanned. Named one at a time rather than counted, because a number is read past and a name is acted on. On the front page and on the scans screen |
| **Overdue and due soon** | Overdue is a report about something that has already happened; due-soon is the week somebody can still finish. Both come from one read of the deadline list. The overdue tile pointed at the assignments screen, which answers what is *mine*, so the number and the screen it opened disagreed for everybody but the person holding all of it |

Every figure opens the list it counts, narrowed the way the figure was counted —
the aging buckets, the fixed and appeared counts, both deadline tiles. A number
nobody can act on from where they read it sends somebody to build the same
question by hand, and the question they build is not always the same one.

## The findings list

One row per issue and fold, not per place and not per package. A real image
produced 281,890 individual findings that collapse to 6,775 rows.

The fold is the source package at the version it was built at — curl,
libcurl4t64 and libcurl3t64 are one row, because they are one thing to decide
about, one thing to upgrade and one rule to route. Keyed on the component
instead, the same image gives 7,648 rows, a third of the difference being the
same work said again.

Each row says how many packages and how many consumers it covers, because one
judgment covering sixty consumers is a different act from one covering one — and
because those are the units somebody acts in. The place count is stored, sorted
on, and shown as a title; it is what the bulk cap is measured against and what
the disposition register expands to, rather than a figure a reader is asked to
reconcile with the other two.

The list is where a day's work is assembled, so the sort, the page size, the
filters, selection across pages and saved filters are all built.

### Row content

The row carries the first line of what the issue says about itself. Fifty rows
reading "CVE-2026-74280 · linux-image" cost a click each to tell apart.

| Rule | |
|---|---|
| Cut on the way out, not on the screen | Every reader gets the same summary — an export and a row disagreeing about what an issue says would be two answers to one question — and a page of fifty does not carry fifty paragraphs to render one line each |
| Clamped to one line | The row's height is what makes a page of fifty five thousand pixels tall. The whole of it is on the finding, and on the row's title |
| The version sits beside the component, not under it | Every line a row spends is fifty lines on a page |

A row says where the component sits, as both ends of the way down: the part of
the product it belongs to, and what directly pulls it in. Those two are what
differ between sibling rows; the steps between them rarely distinguish anything,
so they are counted rather than named.

Both ends cost **one recursive statement for the whole page**: the database climbs
from every consumer on the page to the root and returns the nodes on the way.
Climbing is bounded by the depth of the graph rather than its size, and bounded at
sixty-four steps so a document in a loop is answered rather than followed. The
first version read every edge of the build into memory — 18,561 rows on a switch
image — and walked them in Go, which was three to eighteen milliseconds and scaled
with the graph rather than with the page.

Where a row's places are reached different ways, the row says the pair it shows is
one of several. Where the inventory placed the component nowhere, it says that
rather than naming the product itself.

| Rule | |
|---|---|
| A row says what upstream has done, and how old the issue is | "Upstream declined" and "nobody has fixed this yet" were the same blank, and they call for different responses |
| The age is the finding's own (REQ-60) | Not the year in the issue identifier. A 2019 CVE that first appeared last week read as six years old, and how long this has been open *here* — the age a deadline relates to — was shown nowhere. The row says "open 12d" |
| A deadline is on the row, with its reason where there is none (REQ-33) | The date while it is far off, days left as it approaches, days over once it has passed. There are exactly two reasons for having none, so a blank would mean two intended things at once |
| A finding says whether anybody who packages it confirmed it (REQ-13) | A row reached by comparing a published identifier against an upstream version range is marked "not confirmed", and the filters can narrow to those |
| A triage line is announced where it applies, never silently | The list says so and says how many it is not showing |
| Narrow screens get cards, not a table that scrolls sideways (REQ-55) | |

One CVE at three binaries is one piece of work, and the row says so. A third of
the rows on a real image are the same issue at a sibling package: curl,
`libcurl4t64` and `libcurl3t64` are one source package. Said on the row rather
than folded away — the places are real, and a reader counting them should get
the same number the list and the export do. So the row carries the source
package and how many other rows on this page are the same issue at another of
its binaries, with the way through to the component. **Counted over the page**,
because a page is what somebody is reading and a number gathered any other way
would disagree with the total printed beside it.

The row previews in place. The plus on a row opens the description and where the
component sits, under the row, without going anywhere. Deciding is a click
further on, and that click is the point.

### The cross-product list

The cross-product list is this screen with the product left out (REQ-64), not a
screen of its own, and one entry on the rail rather than two. It was a second
screen offering four of this one's filters, so "which of our products carry
this, and what is running out anywhere" was answered by the weaker of the two
lists. The server never had that split: both routes take the same filters from
one definition.

What is absent without a product is what has no meaning without one. A subtree
is a walk over one build's edges and "differs between builds" is a statement
about a selection, so neither is offered and neither is sent — dropped from the
query rather than left in the address, because a filter somebody can no longer
see or clear is one that narrows a list for reasons it does not show. Saved
filters, deciding from the list and the export are a product's own and come back
the moment a product is picked.

The product becomes a column where it varies, and the row links to that product's
list.

## Filters

Every filter the server offers is on the screen (REQ-60). That sentence was not
true when it was written: the server narrowed by twenty-nine things and the
screen could reach twenty-five, with the exploit-likelihood threshold and the
three date bounds having no control at all.

| Rule | |
|---|---|
| Every filter is labeled with the question it asks, grouped by what they are about | Severity and risk, what upstream did, where triage has got to, where the row came from, the component, and time. A value says what it is rather than completing a sentence begun by a label nobody can see |
| What is narrowing the list is above the list | One chip per filter naming both the filter and its value, removable by clicking, whether or not the panel is open. The control used to carry a count and nothing else, and the count was a hand-maintained list of variables that had already fallen behind |
| The count is read from the address | The one place that knows what every filter is called |
| Filtering is the server's, not the browser's | A list narrowed after it arrives is narrowed within one page of it, so "hide the kernel" would hide it from the twenty rows already fetched and from nothing else |
| The common ones stay one click away | Severity, exploited and fix-available. Package kind, what holds a thing, and how far it has been decided sit in a panel that opens, with how many are on written on the control while it is shut |

Exploited and fix-available are two flags, not one parameter holding one of two
words — otherwise "exploited, and a fix exists", the first population anybody
assembling a batch wants, could not be asked for. The old word is still read so
a saved address still opens the list it saved.

Two filters are about the release rather than the row, and are the reason the
list is a work list rather than an inventory.

| Filter | Default | Widens to |
|---|---|---|
| **Release kind** | Branches | Tags, or both. A tag was built once and is what somebody received; no work lands in it whatever anybody decides about it |
| **Support** | In support | Past end-of-life, or both. The release's own date, or the product's where it states none |

| Rule | |
|---|---|
| They are separable | A tag can be in support and a branch can be past its date, so one control offering four combinations as four words is a control nobody reads correctly |
| Both defaults are written into the address | Which makes each a chip above the list like every other filter, removable by clicking. A default that narrows silently makes the count something other than the whole count with nothing on the screen saying so — which is what the planned-upgrade default did before it was written in the same way |
| Removing the chip widens to both rather than deleting the parameter | Deleting it is how the address asks for the default back |
| Applied where the builds are resolved, not as a condition on every row | The list reads its page from an index that leads with the build, and joining the catalog into that statement would make the engine reach a row to discover what it already knew from the key. The list that spans products resolves no builds, so there it is a condition — the same rule, applied where each query can reach it |
| Not applied at all where the selection names one whole build | These two choose between releases, and a request naming the release has answered that. Applied anyway, the defaults reported "0 of 0" about a tag holding twenty-five findings, and did the same for a release past its end of life — which is worse, because that is the pile nothing else counts |
| The end-of-life rule is the catalog's own | It inherits the product's date where a release states none, and two copies of that disagree the first time one of them is changed |

Three filters need defining:

| Filter | |
|---|---|
| **Package kind** | Read from the package identifier rather than stored beside it. It is also the closest the data comes to "userland and not the rest": a kernel and its modules are Debian packages and a statically linked service is Go, and somebody triaging one is usually not triaging the other |
| **What holds it** | The consumer a place records. What the build holds directly has no container to name, so it is asked for separately rather than by typing something |
| **How far it has been decided** | A group covers places that can be in different states: undecided is no place decided, waiting is a claim standing proposed, agreed is every place answered, lapsed is a decision that stopped applying with nothing replacing it. *Partly answered* is deliberately not one of them — the row already says "12 places · 3 answered" |

### Multi-value filters

A filter whose values are not exclusive takes several at once. Four do: the
decision state, the decision outcome, what upstream did, and the kind of
package. Each was one word, so "undecided or pending approval" had to be asked
twice and read side by side. **Four more take a set**: who is dealing with it,
what a VEX document says, and, among the typed boxes, the component, the tag,
the VEX publisher and the weakness. The typed ones are chip fields, because a
box showing one value while narrowing by three is what the summary above the
list exists to prevent.

| Rule | |
|---|---|
| Several answers OR rather than AND | "Mine or whatever nobody has picked up" is why. Applied one at a time they would AND, and that pair would be a list of nothing |
| Severity stays a floor | Nobody wants to see low and high without medium |
| Drawn as checkboxes behind a control that says what is ticked | A closed control reading "Any" over three ticked boxes is how a narrowed list comes to look unnarrowed. The chips above name each separately, so removing one leaves the rest |
| Carried in the address as the parameter repeated | A server reading only the first word narrows to less than was asked for, which looks like an answer rather than a mistake. Marked exploded on both sides, with a test at the HTTP layer that asks for two states and counts the rows |

The decision state is above the list, beside the severity floor, where the
exploited and fix-available chips used to sit. Neither earned the place: the
list is ordered by urgency, so what is being exploited is already at the top,
and a fix being available is a column on every row. What somebody reaches for
first is what has not been answered yet.

| Rule | |
|---|---|
| Two filters are about a group rather than a row | The age is the *oldest* place, because a group open for a month with one place added yesterday has been somebody's problem for a month. What upstream did has to hold at every place, or a state known at one place and not another would drop the places that lack it and report a group smaller than it is |
| A group whose places disagree has its own word | A package fixed in one variant and not in another is one row with two answers, and asked for any single state it matched none of them. "Mixed" is also the population worth looking at: a bump that has landed in one build and not the others is a pending upgrade somebody is halfway through |
| Filtering by outcome asks what stands, not what was proposed | "What have we dismissed" is a question about this deployment's answer, and a claim still waiting for a second person is not an answer. Counting a proposal would let one person put their own unreviewed claim into the number the question was asked about |
| "Assigned to me" means mine or a team I am on | Here as everywhere the phrase appears. A group whose places are held by different parties is neither mine nor anybody's |
| The by-component view asks the same question as the by-issue view | It was building its own query out of a hand-copied subset of nine filters, so switching views quietly widened the list back out by everything the subset left out — a deadline, an assignee, an outcome — while the chips above went on saying they were on |

## Sorting, paging and selection

Sorting is by a column the server names, never by one a caller does (REQ-66).
Four headers order the list — severity, EPSS, locations and the deadline — and
clicking the one already sorted turns it around. What reaches the statement is
an expression the server stores against each of its own keys: a placeholder
cannot bind a column name, so this is the one query parameter that has to become
SQL text. A word that is not one of the keys is not a sort, and the list comes
back in its own order rather than refusing.

| Rule | |
|---|---|
| A finding with no deadline sorts last whichever direction is asked for | "No deadline" is neither early nor late |
| The tie-break is always the same pair of identifiers | Two rows equal on the sorted column do not swap between pages and drop one while repeating another |
| A page size of fifty, a hundred or two hundred, kept in the address | Fifty is 153 pages of one product's findings |
| A row is selected by what it is, not by where it sits | The list is read again after every decision and on every page, so an index would select a different row each time. That also makes a selection survive paging, which is what "a filtered set" means when the filter matches more than a page |
| **The row is carried with its key** | Acting on a selection then acts on what was selected rather than on the part of it the current page happens to hold. Holding keys alone, the queue counted every ticked claim in its button and approved only the ones on screen, dropping the rest with no message |
| **Changing the question clears the selection** | A selection is made out of a population, so replacing the population replaces what was selected. Kept across a filter change, the bar went on counting rows chosen under one question while none of them was listed — and acting wrote against all of them |
| **Select-all and deselect-all are inverses** | Ticking the header box took this page and unticking it took every page, so the two did different amounts of work in opposite directions |
| **A loop over a selection survives a refusal** | Each row is its own act, so one refusal leaves the rest to be tried and the failures stay selected with a count saying how many. Unguarded, the first refusal abandoned everything after it, left the selection reading its original size, and skipped the control that undoes what did land |
| Searching is submitted rather than sent per keystroke | Each is a query over every open finding in the build, and a half-typed word is not a question worth asking. It matches anywhere in a component's name, ignoring capitals |
| A component's name opens the component (reversed) | It narrowed the list, and the component itself sat behind a small "Open →" in the last column next to "Hide" — an act parked away from the thing it acts on, which is the shape the By fix view was deleted for. The name is the way to the thing; narrowing and hiding are the two small acts beside it, and they sit together. The same name on the finding screen opens the same screen, so one word means one thing everywhere it appears |

Selection across rows is a prerequisite, not a convenience. Both bulk workflows
— accepting a publisher's judgment, and declaring a bump — start by picking a
filtered set out of the list.

## Saved filters

Personal, and nothing is shared (REQ-57). No ownership, no permissions, no
arguing about whose filter is authoritative, and nobody hesitates to save
something half-formed.

| Rule | |
|---|---|
| They belong to the product they narrow | The query names branches and variants, which belong to one product and usually exist in no other. A filter offered everywhere was offered where it matched nothing, and picking one *replaces* what is on screen, so the wrong narrowing was applied rather than merely suggested |
| What is kept is the list's own query string, not a column per filter | The filters belong to the list and they move; a table mirroring them would need a migration every time one was added while still being a second place where what a filter means is decided. A saved filter naming something the list no longer offers stops narrowing by it, which is a way back to a slightly wider list rather than a refusal to open one |
| Saving over a name replaces it | The act is deciding what that name means, and refusing would make somebody delete before they could correct |
| Personal is enforced at the query, not only on the screen | A name somebody else kept is not there, which is the same answer a name nobody kept gives |
| Opening one goes back to exactly the list that was on screen | The saved address wins outright rather than merging. The page it happened to be on is dropped — a saved filter is a narrowing rather than a position in one |

A saved filter can prepare a claim, and proposes nothing (REQ-27). Where it
carries an outcome and the words, picking it fills the decision form and says so
above the list. Submitting is a person's act, and the record carries their name.

What a filter prepares carries its own length rather than a date. A rule saved
in March means "put this off for a quarter", not "until 3 March", so a deferral
it prepares is kept as a number of days and turned into a date when somebody
opens the form. Kept as a date and never read, the prefill opened the form with
the outcome chosen and no date, which cannot be submitted.

**What the list is narrowed by is what prepares a claim**, read off the address
rather than remembered from the act of picking. Narrowing further asks a
different question and drops it; coming back to the list finds it again. A rule
that outlived the narrowing it was picked for would fill a form on a finding it
never drew, with somebody's name about to go on the claim.

What it prepares travels with every row, and with the walk from one finding to
the next, because a list worked under a rule is worked under it to the end. The
finding's address names the filter rather than repeating what it says, so what a
rule prepares is decided in one place and cannot go stale against a name
somebody saved over. Emptying the form on one finding drops it there and nowhere
else.

A filter is personal, so a link somebody sends carries a name rather than a
claim: it prepares whatever the person opening it has kept under that name, and
nothing at all where they have kept none.

| Refusal | |
|---|---|
| A rule preparing a deferral carries how long it defers for | The date is worked out from the length as somebody submits it, so one saved without a length prepares a form that cannot be submitted |
| A length beside any other outcome is refused, not dropped | The same answer a decision gives to a date beside an outcome that is not a deferral, and a value silently discarded is one somebody believes they set |
| A deferral kept before there was a length to keep fills nothing, and says so | Reading it as "no rule" would leave the form blank under a banner saying the filter prepared it |

Saved filters were argued for as the cheap half of ownership by subtree; the
expensive half is now team routing, so what they are for is being the thing a
prefill rule is built on.

## The by-component view

The default list asks "what is wrong", grouped by issue; this asks "what is wrong
*with this thing*", which is the question somebody upgrading a package has. Same
data, different subject.

| Rule | |
|---|---|
| Each row carries the issues by severity and the worst among them | Ranking by count alone answers the view's own question backwards: a package with forty-four issues outranks one with three criticals |
| The weight stays the order | Where the volume is is what the view is for. Making urgency the default would reproduce the by-issue list at worse resolution. "Which of these is worst" is the other question people read it for, so the column is sortable |

The By fix view is gone. It listed one row per version pair with an action in
the last column — the thing somebody does presented apart from the thing it is
done to — and read as a stray list of version numbers with an unexplained link.
The grouping it existed for did not go with it: the act follows the source
package, so upgrading curl still reaches both of its binaries in one go.

## The by-bump view

One row per upstream bump, with what moving it would close: the pending-upgrades
question read from the triager's end rather than the coordinator's. Keyed on the
fold, so packages built from one source are one row.

| Rule | |
|---|---|
| **No action column** | That is what the By fix view was deleted for. The package name opens the component, where the upgrade is planned; a source package that builds three binaries is one bump and three links |
| Versions are listed, not ordered | Comparing two needs a per-ecosystem ordering this does not have, so one package appears once per version upstream released, and there is no nearest and no latest |
| The filters it cannot apply are named on the screen | It takes six of the list's thirty-odd; the rest ask about a place, a deadline or an assignee, and a bump has none of those. Dropping them quietly widens the list back out while the chips go on saying they are on |
| Nothing here counts places | A bump is a fold. What it says is the packages it moves, the issues it would close, and the builds that hold it |

## The component screen

A component has **a row per build that carries it**, with what that build ships,
what is open against it there, where it could go, the earliest deadline among what
is open, and what has already been promised. The issue count is the way through
to the findings list. Before this, clicking a component opened a filtered list of
its findings and nothing else, so a component could be read and never acted on.

| Rule | |
|---|---|
| Per build, because the answer differs by build | A stream staying on a maintained older line and a stream that has moved on are different work with different testing, and one target across both would be wrong for one of them |
| Where it could go is listed, never ordered | Telling which of two versions comes first needs an ordering per ecosystem this does not have, so what is offered is every version the scanner named as carrying a fix, most-closing first. "Nearest" is not a question this can answer |
| The second count is consumers, not places | One judgment covers the whole fold, and what varies underneath it is what pulls the package in. A place count is a unit nobody acts in; it is the row's title, being what the bulk cap is measured against |

It is where an upgrade is promised, on the terms `DESIGN-triage.md` sets: the
releases it is for, the version, the date, the reason, and who carries it.

## The finding screen

The finding is the working screen after a decision as well as before it.

| | Carries |
|---|---|
| **Before a decision** | What the issue is, how bad, what upstream has done, where it sits, the evidence, the assessment, and the decision form |
| **After** | The decision that stands, in its state — pending, approved, lapsed — with outcome, justification, scope and who agreed to which revision, and the actions that fit the state |
| **Under both** | One activity timeline built from the claim's proposal, revisions, approvals and comments; the revision history, marking which revision each approval named; the comments; and the decisions made here before, with their reasoning offered back as "reuse this reasoning" |

The description leads, at full width (REQ-60, as amended). The rule that put the
action first is still the defect it fixes — the form had been three screens down
— but the description went into the narrow column with it, where a paragraph
runs four words to a line.

Evidence full width, then the action full width beneath it — a reversal of
evidence on one side and the action on the other. Both are still above the fold,
which is what the side-by-side arrangement was for, and what it cost was
measurable: rendered from the demo the narrow column held severity 7.8, EPSS
0.999, CWE-1288, "yes — exploited", the CVSS vector and eleven references, read
at 380 pixels, while the widest thing on the screen was an empty text area.
Somebody weighs the evidence and then acts, and the page runs in that order.

The references move down, with the timeline, the revisions and the comments.
Eleven links between the facts and the form recreates the defect the
side-by-side layout was built to fix, arriving by a different route: what is
consulted elsewhere is read after the judgment rather than during it. What is
neither evidence nor action — the timeline, the revisions, the comments, the
holder, the fix targets, the assessment — was already there.

A decision is made on the finding's own screen, and nowhere else (REQ-57,
reversed). The list opened the decision form inside a row for a while, so a run
of similar findings could be answered without leaving it. What that did not
carry was everything else the finding puts beside a judgment — the references,
the way down, what a VEX document said, the history, the comments. The saving
was navigation and the cost was the evidence.

| Rule | |
|---|---|
| It says when it runs out and who has it | The list carried the deadline, the age and the owner, and the screen somebody decides on carried none of them |
| It says how many of its places have been decided (REQ-57) | A finding half answered has to look different from one nobody has touched. The count of what the build argued away through its own VEX documents cannot stand in for this: reading it as ours would credit somebody else's reasoning to us |
| It states how the match was made, and says where it came from | The list marks these and the screen somebody decides on did not, which is the wrong way round. Both answers are stated rather than only the weaker one, and nothing is said where the scanner said nothing — unknown is not unconfirmed |
| Where to read about it is worked out from the identifiers, not only relayed (REQ-18) | The issue's own record, the record under each other name, the answer from the distribution that packages the component, and the package's own page. Derived at read time, kept apart from what the scanner supplied, and empty rather than approximate where a name resolves to no scheme this knows. The server derives them, so a machine client gets the same list; nothing is fetched |
| Where it sits shows the chain, not the immediate parent | The same parent can be reached by several routes, and a screen naming only the nearest cannot tell them apart |
| Where upstream currency is switched on, it says what upstream released and when (REQ-69) | Two facts rather than a judgment about anybody's project. Where an issue was named a clear year after the last release and is still unfixed, the screen says that is why there is no fix — never as a claim that a project is abandoned. It needs a full year of silence, because comparing two year-numbers makes a five-week gap look identical to a five-year one. Switched off, the panel is absent rather than empty |

Four situations for what pulls something in, and they are not one.

| Situation | Drawn as |
|---|---|
| A named consumer, walkable to the build | The whole chain, the build first and the component last |
| The build contains it directly | A chain of two — the build, then the component — which *is* the answer |
| A named consumer nothing places | Two rows — the consumer, then the component under it — with "nothing recorded what pulls this in" on the consumer, which is the row it is true of |
| The inventory placed it nowhere | The component, with "nothing recorded what pulls this in" |

The middle two used to be drawn as the last, which said "nothing recorded what
pulls this in" over records that named the consumer. The third also drew an
empty name, read off the end of a chain that was not there.

One row per place, however many rows a finding holds there. `DESIGN-findings.md`
owns that rule.

| Rule | |
|---|---|
| A link that names a component ambiguously offers the choices rather than refusing | A name and a version together are not unique — a source repository and the package built from it can share both. Two lists are possible and are not interchangeable: the components this issue is open at, and every component of that name. Each says what is true of it |
| A claim's scope names its locations rather than only counting them | "One location" says how large a judgment was and not which code it was about. Three at most, then how many more, because a kernel sits at sixty and the list would become the card |
| An approved claim at the same component and consumer is offered to a new issue (REQ-28) | With its reasoning and "apply decision #N", which fills the form and records the new claim as an extension. It still needs a second person |
| A comment can be rewritten by whoever wrote it, in place | The control is offered only to the author so nobody is invited into a refusal the server would give them anyway. The box opens on the text as stored rather than as a draft: a copy of something already stored would come back later as an unsent draft of somebody's own comment |
| A recorded flaw is closed from its own finding screen, and only a recorded one shows the control | Everything a scanner found is resolved by the next scan, and offering a button that overrules that would offer the thing the rule exists to prevent. The panel says outright that nothing else can close it and that nothing reopens it, because both are surprising and the second is irreversible |

## The decision form

Nothing is chosen for you (REQ-59). The outcome opens unselected, the
justification opens unselected, and submit is refused until each question being
asked has an answer.

It opened on "not applicable" with "vulnerable code not in execute path" already
selected, so every finding was one click from a dismissal carrying a justification
nobody had chosen — and a justification is a claim about our build that a reader
is entitled to take literally. There is no neutral default to reach for instead:
"affected" is a claim as well, and a form that pre-answers its own question
collects the answer it suggested.

| Rule | |
|---|---|
| The deferral threshold is a number on the form, not a sentence about a threshold | Which side of it a date falls on decides whether a second person has to agree, and reading that off the response is reading it after the choice was made |
| It names the next missing answer, beside the button | A disabled button says something is missing and never what, and Ctrl+Enter does nothing until the same answer is given. One rule decides both the sentence and the refusal |
| Ctrl+Enter submits, and the form says so | A shortcut nobody knows about is a shortcut nobody has, and the person it is for is making a hundred of these a day |
| The last pair is offered, never applied | Retyping the outcome and the justification is the cost the review measured, but a judgment prefilled with the last one made is a record that can say what nobody meant. So it is a button that says what it will fill in, and the fill is somebody's own click. Per session, because a default that survives a night is a default nobody chose |
| A justification is shown with a label and a one-line meaning, never as its bare token (REQ-60) | An accuracy defect rather than a cosmetic one: the token somebody picks out of a list of five snake_case strings at the end of a long day is what ships to a customer, machine-readable, as our claim about their exposure. The stored token stays reachable, on the title, because it is what an approver is checking |
| One list, and one way of rendering it | The vocabulary carries its own labels, the two forms that offer a choice read from it, and the six places that display a stored one go through a single renderer. Two screens had already started to diverge. A test asserts that every value the type allows is in the list and carries a label that is not its own token |

Which locations a decision covers is a summary with an exception, not a list of
checkboxes (REQ-26). The form says "all 62 locations"; "exclude locations" opens
the list grouped by what pulls the component in — the consumer, which is the
axis that decides applicability — with a checkbox per group that reads as mixed
when part of a group is out, and a filter box when there are more than a dozen.
What it reads back is "59 of 62, three left open under X".

## The reach sheet

A guided review on submit (REQ-25), not a list of checkboxes. The sheet opens on
a summary: this build, the builds covered automatically, the builds at other
versions, and any not offered.

The builds at other versions are **one list rather than one sheet each**, ticked
where the reasoning holds at that version too and unticked to start, because a
tick is the claim. Two steps — where it applies, then confirm — with Enter to
advance, Escape to leave and the arrows to move. The last lists what will be
written, and only then is anything sent.

| Rule | |
|---|---|
| The decision here is recorded first, then each build applied, one at a time | With the places narrowed where any were excluded. A refusal on one is reported for that one and does not decide the rest |
| The reach is answered whole rather than sampled | Where a judgment lands beyond this build is a question per place, and asking per place is a request each — so it asked about the first eight. That was a cost control that had become a rule about what a decision covers: what is offered is what gets written, so a build reachable only from the ninth place was never offered and nothing said so |
| The review step is skipped where there is nothing to review | It ran even when the reach it exists to confirm is zero, and at around 150 decisions a day that is some 300 keystrokes spent confirming nothing |
| What counts as nothing is one thing: no build holds this issue at another version | Builds already matching are named on the sheet rather than asked about, so their absence from a skipped sheet costs nothing — the confirmation that follows names them |
| An unread reach is not an empty one | A query still in flight, or one that failed, contributes no other versions, and treating that silence as "there are none" would submit past a question rather than skip one that was not there. The sheet is skipped only when every one of those reads succeeded |

## Walking the list

The primary action is above the fold, and the next finding is reachable without
going back (REQ-60). The decision form sat at about 1,550 pixels on a page
running to 2,800.

| Rule | |
|---|---|
| The list travels with the finding, as one value in the address | A filter added to the list needs nothing on the finding and cannot collide with a name it already uses. With the list's own address in hand the finding asks the server the same question, so the row before and after are the ones that were on screen |
| The walk does not stop at a page boundary the reader never chose | The window asked for is the list's page widened by one row at each end, and a neighbor is handed the list at the page *it* sits on. At the largest page there is no room to widen, so the walk ends at the page edge rather than asking twice |
| The row is found by what it is, not by where it sat | The list is read afresh, and under a state filter the row may have moved or gone. Where it cannot be found there is no walk, which is the same answer as arriving from somewhere that was not a list |
| A list that asked for everything is still a list | Present-and-empty and absent are different: the first has a row before and after like any other |
| After submitting, the next finding is offered first, and the review queue second | The queue is where the claim went rather than where the person is going |

## The dependency tree

A tree, and its counts are cumulative. Each row carries what is open beneath it
as well as on it, so a container reads as the sum of what it holds rather than
as zero. Those totals are worked out when the tree is read rather than stored
after a scan, because they are derived from findings and findings move.

Both numbers are distinct issues, per path. A node's own count is the distinct
issues open against that component; the cumulative count is the distinct issues
across it and everything under it, each component counted once however many ways
it is reached. A finding is one issue at one place, and a library at thirty-six
places with two issues is seventy-two rows — which is what every parent used to
read, where somebody who drilled down one path is looking at one place and
expects two. **One recursive statement for the row's whole set of children**:
0.08 s for the root's thirty children on the full-size image.

| Rule | |
|---|---|
| Every row is ordered on the number that describes it | For a branch, what is open beneath it; for a leaf, its own count. What opens still comes before what does not, so the structure of a build is on the first screen |
| A level is drawn whole | An honest inventory has tens of components at a level. The remaining cap is high and exists for the inventory that is not honest — a real image has been seen with 5,270 components directly under its root |
| Arriving from a finding opens the tree on the component, with every parent expanded | The chain travels in the link rather than being walked upward here. Where a level is past its cap, the step on the path is kept whatever its position: a link that opens a tree without the component it was opened for shows the one thing it exists to show |
| A version every component at a level shares is drawn once | Shared by components of different names, it is the producer describing the build — a switch image whose thirty containers carry one build stamp. The level says it above the rows |
| A node says what its number is made of, as a short strip of the bands | Five thousand beneath a node says nothing about whether any of it matters. Rolled up in the statement that already counts the subtree, so the bands sum back to the total |
| The node counts open their lists | A node saying "5,650 beneath · 0 here" and going nowhere is a figure nobody can act on from where they read it |
| The count is every open issue, answered or not | A dismissal does not subtract from it. Written down because "what is open here" and "what is still to answer here" are both reasonable readings and the screen gives the first |
| The marker that opens a row is a button | It was a span with a click handler, so every node past the first level was unreachable without a pointer, on the screen whose whole purpose is walking down |

Ordering on the cumulative count reverses an earlier decision worth keeping in
view. Ordered on the row's own count the tree opened as an alphabetical list of
containers saying nothing about which was worth opening; the correction before
this one made branches alphabetical on purpose, because an edge means "contains
*or* depends on" and the document does not distinguish them, so forty kernel-module
packages each depending on the one kernel all report its total. That fault is
back, deep in the tree, and it is the lesser of the two.

The list a tree number opens is `beneath`: every open finding at the component
or anywhere under it, by the same walk. `under` stays the direct consumer. The
two do not always show the same figure and are not forced to — the tree counts
distinct issues and the list is one row per issue and component. A name the
build does not hold is refused rather than answered with an empty list, since an
empty list is also what a clean subtree looks like.

## The review queue

One card per claim (REQ-28): one proposer's action, however many decisions it
wrote. The card carries the reasoning as it stands, how many records the claim
wrote, how many locations and builds it reaches, whether it was approved before
and came back, and how long the finding has been put off.

`DESIGN-triage.md` says what the queue holds and on what terms. What the screen
adds:

| | |
|---|---|
| **Approving and rejecting** | Work on the claim, and rejecting needs a reason. Selecting several and naming a batch approves them together, so they can be undone together |
| **A bulk claim draws its outliers** (REQ-28) | The counts and the rows that stood out. Any can be set aside; the button then reads "approve N, reject M". An extension says which claim it rests on |
| **Lapsed decisions and deferrals that ran out sit underneath** | The row carries the decision and not the build it was made in, so reaffirming happens on the finding, where its locations are |
| **A bulk approval can be taken back from where it was made** | The control appears only just after a batch is agreed to, because that is the moment somebody notices. A permanent control for undoing a batch named at some point in the past is one nobody can use safely |

The queue filters on mine and nothing else, so an approver holding several
products reads one interleaved list. *Not built* — see the list at the end.

## The claim page

One claim, whole, and every act at that grain: revise, withdraw, comment,
agree, send it back, hold rows back, and say where the work is happening.
`DESIGN-triage.md` says what a claim is and what the read answers.

| Rule | |
|---|---|
| **Nothing on it acts on one decision** | A claim is one argument; an act on one of its rows is an act at a grain nobody decided in. The argument it shows names no row and carries no row state |
| **The state is the claim's, in one word** | Waiting, sent back, approved, withdrawn, lapsed, agreement undone, or ended several ways. The same word the proposer's own list reads, so the two cannot disagree |
| **Nothing on it counts places** | What it covers is said in the units somebody acted in: one judgment at one fold, the packages that fold holds and the things that pull them in, and every build it reaches. The place count is a title on the coverage figure and nothing else |
| **What it covers is what it covers now** | A claim reaches by matching, so it grows as builds appear with nobody acting. What somebody agreed to covering is on the approval, in the revision history below |
| **A decision's address resolves here** | Notifications, the record, the reports and the evidence list all name a decision by identifier. Each of those is somebody being sent to read what was decided, and what was decided belongs to the claim. The address is replaced rather than pushed, so going back does not land on it again |
| **Reaffirming is not here** | It is a claim about one place in one build, and this screen is about an argument that may cover many. It happens on the finding, where the places are |

Which acts are offered follows the act-and-needs table in `DESIGN-triage.md`,
rather than being restated here: offering a button that would refuse somebody is
worse than offering nothing, and a second copy of the rule is a copy that
disagrees. It said revising and withdrawing were the author's, where the rule
and the code both ask for triage on the product at the finding's visibility — so
a triager reading a colleague's stale claim had no way to revise it on this
screen and every way to do it from the finding.

The one thing drawn narrower than the rule is holding rows back, which is
offered only on a bulk claim that still has outliers, because it is the
author's side of the choice an approver already has.

A screen asks what it may do rather than working it out from roles. That is what
the capability answer is for, and it is only usable as a gate while it means
what the operation accepts: agreeing was reported from the approver capability
alone while the operation accepts a triager too, so a two-person team where
neither holds the capability — the ordinary shape of a small team — was shown a
claim, its reasoning and its history with no way to answer it.

## Assignments and routing rules

Assignments is two tabs: what is due soon and undecided, and who holds what.
Unassigned work is its own screen with its own rail entry, and a row nobody
holds says "unassigned" in muted text rather than drawing nobody as a person
with an avatar.

| Rule | |
|---|---|
| Every figure counts pieces of work, and says so | A person's row and the list behind their name are one measurement, so clicking through never turns one number into a different one. The findings those cover are a second, quieter column, and the screen states in words what each counts |
| Taking unowned work is one action | A triager may take what nobody owns without the assigner right, and the API always allowed it; there was no control that asked. The finding carries "Take this" and the unassigned list's batch bar carries "Take", beside the picker rather than through it |
| Who holds it is the field's value, never its placeholder | A placeholder is the grey a browser paints when nobody has typed, so work somebody had taken read as an empty box asking for a name |
| A picker nobody can use says so in the box | With no product chosen it reads "Pick a product to assign". A tooltip is a sentence nobody sees, and a disabled field is drawn as disabled everywhere rather than looking live |
| Offering work to somebody is a question about one product | The unassigned list spans every product somebody can see, so the picker fills once a product is chosen and says why it is not otherwise. Taking work yourself needs no product chosen |

A screen for the standing rules (REQ-34), per product, shown as a numbered list
because the order *is* the precedence: the first rule that matches places the
work, and a set with no visible order is a precedence nobody wrote down.

The form says which of the two kinds does what before anybody fills it in.
Saving says the sweep has started, not that it has finished — one rule can place
thousands of findings, so it is queued, and a reply claiming the work was done
would be a reply about something that has not happened yet.

The finding says which rule placed it, on the same card that says who is dealing
with it, along with what somebody needs to know next: taking it is picking up
work nobody holds, and the rule will not take it back.

## Catalog and inventories

Adding to the catalog is an action, not a form above the table (REQ-60).
Products, branches and tags, variants and users each carry an "add" control in
the header and a floating action, both opening a drawer with the form; the table
is what the screen is about.

| Rule | |
|---|---|
| The catalog says what each entry holds | Products carry their branch, tag and variant counts, what is open against them and when they were last scanned; branches and tags carry what they came from; variants carry whether they ship to customers. A list of names alone makes somebody open every row. Every count is issues at components, the way the findings list counts |
| A product row says what it triages from | An administrator changes it there. Everybody sees it because it explains a number, and "deployment's" is shown rather than the deployment's current word, because following it and stating it are different things |
| An inventory can be uploaded from the interface (REQ-05) | From the bar and from the inventories screen. The drawer takes the target — prefilled from the scope, refused by the server if undeclared — one inventory — CycloneDX or SPDX, as the file itself says — and any number of OpenVEX suppression documents, which is what the endpoint takes. It posts the same multipart request a pipeline sends, then opens the inventories screen, where the receipt shows "queued" until the run says what it changed |
| The screen that lists receipts is called Inventories | A scan is what the deployment does to an inventory after it arrives; what a person uploads is inventories |
| It says what each run changed, and what the numbers were measured against | Which scanner, at which version, reading which vulnerability database. Without it, a build with nothing wrong and a build last measured against a months-old database read identically. A run covers a build rather than an upload, so where several uploads are answered by one run the numbers sit on the newest and the rest are blank |
| A run that changed nothing says 0; a row with no numbers to report is blank | Both were drawn as a dash, so an upload superseded before anything read it read as a scan that found the build clean. The wire tells them apart too — a count that drops its zero cannot |

## Product and scan-run pages

The product page names every declared build with what is open, overdue,
exploited, undecided and agreed in each, and when each was last scanned. "How is
SONiC doing" was five requests and a spreadsheet, and the products table is an
administration surface — a triage line in a select, an end-of-support date in an
input — which is a different job from reading how something is going.

| Rule | |
|---|---|
| Every number opens the list that produced it | A figure somebody cannot follow is one they stop trusting, and then they count it themselves |
| Counted as issues at components | The unit the findings list counts, so the page and the list it opens agree. Counting rows would report how much the dependency graph shares |
| The product's totals are not the sum of its builds | A library carrying one issue in two builds is one thing to decide about and two build rows. The totals are counted again over the product — a sum put 15,231 at the top of a page whose own list said 7,629 |
| "Undecided" and "agreed" are the findings list's own words | By the same definition and from the same expression. Two screens with two definitions of "decided" is how they come to disagree in front of somebody |
| A build nobody has ever scanned is a row, not an omission | A product reads as clean when part of it was never looked at. One whose release is out of support says so |

A scan run has a detail page. A receipt says a run happened; a row reading
"7,604 opened" is a number with no shape. The page says what the run opened and
closed, broken down by the rating in force, with how much of what it opened is
known to be exploited — which is what decides whether an overnight jump is an
evening's work or a night's. A band with none in it is left out rather than
drawn as a zero, because a row of zeros reads as a chart that failed to load.

Release comparison carries a chart across every build, not only the two being
compared: the comparison answers what changed between two, and the chart answers
whether it is getting better or worse. Bars rather than a line, because these
are separate builds and a line between two releases draws a trend through a gap
where nothing happened.

## Recording a flaw

A screen of its own, reached from the rail rather than from the findings list.
What is being recorded is precisely what is **not** in that list, so opening it
from there asks somebody to start where the answer is absent.

It asks for the product and then for **sets** of lines and variants, because the
same code goes out on several lines and as several variants at once and a flaw in
it is one issue in every build that ships it. The builds are the product of the
two, and the scope prefills it without constraining it. Ticked rather than chosen
from a multiple-select box: those are hard to use with a mouse and impossible to
read the state of at a glance, and what somebody needs is to see which builds they
are about to file against — which the screen also says as a count.

| Rule | |
|---|---|
| The control appears only for somebody who may record one | A button leading to a refusal is worse than no button. Undisclosed needs private triage, already-public needs the ordinary right, and somebody holding only the ordinary one is offered the second with the first saying why it is not theirs |
| It is undisclosed unless somebody says otherwise | A choice of two stated options rather than a checkbox: the dangerous mistake should not be the quiet one |
| The severity has no default, and may be left unset | A judgment sitting in the field as though somebody had made it is this screen making it for them. An unrated finding comes due as a medium, which is what every unrated finding already does |
| The component is searched against what that build actually holds | A name typed from memory is a name the server refuses, and a name the build holds at two versions is a question the refusal asks properly rather than something to guess at |
| The score is composed as a vector and worked out on the server | The metrics are offered in words rather than letters, because somebody rating a flaw is choosing between "over the network" and "physical access". The formula lives in one place, so a second copy in the browser cannot disagree with the number in the database. A vector settles the severity, so it is not asked twice |
| Weaknesses are suggested and never restricted | A picker that refused an identifier it had not heard of would refuse next year's |
| Files that prove it are attached on the same screen | Stored after the finding exists, because an attachment hangs off an issue and there is no issue until it is recorded. A file that will not store does not undo the record — the words are the finding and the file is evidence for them — and what is reported is which file failed |

The description is written and read as markdown. It is our own prose, so it goes
through the same editor and the same submission policy as a justification. What
a scan file said stays escaped and unrendered (REQ-66): the two live in the same
column, so which it is decides, and rendering the column would render the
scanner's text.

A VEX publisher's own words are shown the same way, and for the same reason.
What a distribution or an upstream security team publishes arrives in a document
they wrote, so it is a third party's text reaching the people who hold the most
access here. It was being rendered as markdown on the finding screen. Raw HTML
is off at the parser and the page's own policy blocks scripts, so what that
bought an author was not code: **it was headings, tables, bold assertions and
the text of arbitrary outbound links, laid out on the screen a triager is
deciding from**, plus the ability to name one of this deployment's own
attachments and have it drawn beside their argument. A judgment somebody else
publishes may be evidence and may never be presentation.

## Disclosure and advisories

Partly built. A finding says whether it is disclosed, and there is a screen for
what is running out with the extension request on it. Agreeing to an extension
is still reachable over HTTP and referenced nowhere in the interface.

| Rule | |
|---|---|
| A finding says whether it is disclosed, wherever it is shown (REQ-40) | Somebody holding private reading could not tell which rows they must not talk about, which makes the embargo a property of the database rather than of anybody's behavior. An undisclosed recorded flaw drew as "Unrated · Undecided · 1 location", which is what any other row draws |
| A group is undisclosed when *any* of its places is | One embargoed place among fifty makes the whole of it embargoed for anybody deciding what may be said about it, and the earliest date is the one that matters. Both read as aggregates rather than off whichever row sorted first — counted, because a maximum of the visibility word answers "public" for exactly the mixed group the question is about, and the list then drew no marker on a row holding an undisclosed place |
| The standing notice is unmissable on the finding page (REQ-40) | A notice somebody has to look for is one that has not been given. It sits above everything, on the screen where a person is about to write something down, and it names the places a disclosure actually happens: a ticket, a commit message, a chat. The row's chip is the secondary signal |
| A screen lists what is approaching disclosure (REQ-38) | Soonest first with what is past due at the top, and an extension asked for on it. That list is itself a disclosure and is narrowed the way `DESIGN-access.md` describes — a product somebody may not read undisclosed work in contributes nothing to it, not even a count |
| The screen says what a date arriving means | The answer is counter-intuitive: nothing has been published, and the row is waiting for somebody to say what happens. It also says what an extension will do before it is asked for |
| Agreeing to an extension sits on the review queue | Beside the ratings that wait there for the same reason: both are a second person's turn, and a queue holding one kind and not the other is one somebody has to remember to look past |
| A waiting rating names its product, on the card and in every sentence about what agreeing does | A rating belongs to one product and two products may rate one issue differently (REQ-29), so a card reading only "CVE-… low" is a word an approver cannot act on. What they are agreeing to is a deadline and a triage line in one named place |
| A notice arrives at a lead time somebody sets (REQ-38), inside the application rather than by mail | A screen alone surfaces nothing to the person who needs it — an approver who touches disclosure a few times a year has no reason to open it — and an extension nobody can agree to in time is an approval in name only |

### The advisory

The advisory has a screen, on the issue. Both endpoints answered and nothing
called them, so **the one output of this tool that leaves the company was the one
output nobody here could make**.

| Rule | |
|---|---|
| Drafted per product | That is the grain of the document: an advisory is a vendor's statement about something they ship, and an issue may sit in several products. A flaw in somebody else's component is refused, and the refusal is shown rather than swallowed |
| Shown as text and never rendered (REQ-66) | What a reader has to check is exactly what a customer's tooling will receive |
| What has already gone out is said before anything is drafted | Every issuance is in the document's own revision history, which is right for a reader of the document — but it made "has an advisory gone out, and is what is published still what we would generate" a question you had to build a CSAF document to answer |
| Recording that it went out is its own act, next to the draft rather than inside it | What was published on a date cannot be worked out again once a release is added or a decision is revised, and without the record a second document cannot be a revision — which a customer's validator checks |

## The editor

A formatting toolbar over a plain textarea with Write and Preview tabs, not a
rich-text editor. What is stored is markdown, and an editor that hides that
eventually disagrees with what gets published.

| Rule | |
|---|---|
| Every toolbar control is a button rather than a keyboard shortcut | It has to work on a phone |
| A control is drawn with something the bundle carries | A mark whose character one of the bundled fonts has is that character; the rest are icons from the set the rail uses. An emoji is neither — no emoji font ships here, so a link and a paperclip drawn as one are an empty box on any machine that has none installed. That is the same failure as fetching a font at run time, and it is invisible to whoever picks the glyph, because their own machine has the font |
| Preview is the published rendering, not a second one that resembles it | |
| Preview returns warnings as well as rendered output (REQ-67) | Anything that would be refused says so before somebody presses submit. A refusal at submit, on a long justification, sends somebody hunting for the line by eye |

### Drafts

Unsent text is kept and restored. A draft is written to the browser as somebody
types and cleared only once the server has taken it, so a refused submission, an
expired session and a closed tab all leave the words where they were. Losing
what somebody wrote is what teaches people to write less, and the reasoning is
the part of a decision that matters most.

| Rule | |
|---|---|
| Restoring is deliberately narrow | Only into an empty field, and only once. A draft that overwrote something a caller supplied would lose the thing it exists to protect |
| Storage a browser refuses is not a failure | The draft is a convenience; the text in front of somebody is the real thing, so every read and write of it tolerates being turned down |
| Signing out clears every draft the browser holds | Every writer's, not only the one signing out: a draft left by an earlier session is the one nobody would think to clear, and drafts hold triage text with private findings among it. Cleared *before* the request that ends the session: a sign-out that could not reach the server is the case where clearing matters most |
| A draft is kept under the identity that wrote it | Which covers the sign-out that never happened. A session can expire quietly, and the next person to sign in on that browser must not be handed somebody else's reasoning. Text typed before anybody is recognized is not kept at all |
| Where a draft lives, and under whose name, is decided in one place | A control spelled at each of six call sites is a control that is missing at the seventh |

## An expired session

A write refused for want of a session offers the way back over the screen rather
than instead of it. What the person was looking at stays behind it and comes
back when they return. The words are already safe — a draft is written as it is
typed — but the finding somebody was reading, the filters they had set and the
row they had open are not a draft.

| Rule | |
|---|---|
| It is noticed once, where the client is built | Recognizing it at each call site is how the one that forgets shows "not authorized" against a button somebody just pressed |
| A sign-in carries the address it began at, query as well as path | A findings list *is* its filters, and coming back to the same path with none of them is coming back to a different screen |
| Re-authenticating without leaving the page is not what this does | The requirement allows for that: where a redirect is unavoidable, the draft is saved first and the person returns to what they were writing. It is unavoidable here — a provider sign-in is a redirect to somebody else's host, which cannot be framed and increasingly cannot be done silently in a hidden frame either |
| Where the address is checked is the server, not here | A sign-in that sends a browser wherever a parameter says makes this deployment's own domain vouch for somebody else's page; see `DESIGN-access.md` |

## Attaching a file

The editor carries an attach control wherever an issue is in hand — writing a
justification, writing a comment, editing one. It puts the file against that issue
and writes the reference at the cursor: an image as an image, everything else as a
link, and which it is comes from the type the server decided rather than from the
file's name.

| Rule | |
|---|---|
| A refusal is shown beside the control | The two somebody can act on — a file larger than the deployment accepts, and a deployment with no room — are invisible if the control simply does nothing |
| A reference becomes a path to this origin before anything renders it | The scheme is one no browser knows, so an attribute still carrying it when the sanitizer runs is dropped as unknown, and there would be nothing left to rewrite. By the time anything is judged, what is there is a relative path |
| An image pointing anywhere else loses the whole element, not just its source | Such text is refused at submission, so what reaches this was written before that rule, and an `img` with its source taken away is a broken-image icon in the middle of somebody's reasoning |
| The finding lists what is attached, beside rendering it | A file referred to from a revision nobody is reading now is still part of the record, and somebody who has to take one back out needs to find it without hunting through every justification. A removed file is still listed, saying so and why |

## Mentions and assignment pickers

Autocomplete after an `@` offers the people who can read findings of that
visibility in that product, and nobody else. An autocomplete listing everybody
teaches somebody to name a colleague who then cannot open what they were called
to; on an undisclosed finding the mention itself says a finding exists.

| Rule | |
|---|---|
| Asking who may be mentioned on an undisclosed finding is itself a question about undisclosed findings | Somebody who cannot read them is answered as though the product were not there. Without that, the endpoint is a way to enumerate who holds private access, which is a more useful thing to steal than the list it is attached to |
| What is being typed after an `@` is read from the text before the cursor | Rather than tracked as state, so it stays right however somebody edits |
| The pickers that say who is dealing with a finding ask the same endpoint (REQ-34) | They asked for the list of people, which is administration, so for every triager in the deployment both selects were empty. Asking who may *read* it rather than who *exists* also narrows the offer to people who can open what they are handed |
| A box people type an `@` into offers names, at the visibility of what is being discussed | The comment box is where mentions get written and it offered nobody, while the line under it explained afterwards that the name had reached nobody. A claim is asked at the visibility of its most careful row |
| The one box that offers nothing is the bulk form, and it is the one that cannot ask | Deciding many findings at once carries no visibility on the wire, so the question has no answer to send. Asking as though the set were public would offer people who cannot open half of it |

Both people pickers are typed against the list rather than scrolled. Adding
somebody to a team and bringing somebody onto a case were selects over
everybody, which is a control that stops working at the size a deployment
reaches: a scroll through hundreds of names in no order anybody chose. The one
over a whole team's candidates narrows in the browser, which already holds the
list; the one over who may be brought onto a case sends the term the endpoint
has always taken and never received.

| Rule | |
|---|---|
| An offer carries the identity beside the name where they differ | Two colleagues can share a display name, and a picker offering only that would resolve to whichever of them the list held first |
| The button stays disabled until what is typed resolves to somebody offered | Which is the guarantee the select gave for free. Neither picker can bring anybody into the deployment, so a name matching nobody is refused by the server either way, and being refused after typing is a worse way to learn that than not being offered it |
| The list opens on focus | Somebody adding to a team is looking for a name rather than recalling one, so waiting for two characters would leave it reading as a plain text box |

## The search box

One box, matching component names and issue names alike, at whatever scope is
chosen (REQ-64).

| Rule | |
|---|---|
| It matches issue names as well as component names | Labeled "Find a component or an issue", it searched component names only, so the question a PSIRT is asked first when an advisory lands — where is this in what we ship — returned an empty list, which reads as "we do not ship it" |
| Aliases are matched | An issue is one thing under several names, so the name a reporter used has to reach the row filed under the name a scanner used, or the answer depends on which feed arrived first |
| Both halves are one box rather than two fields | Somebody typing a name does not classify it first, and an identifier is not mistakable for a package name in practice |
| It stops at a product where the address it is on does | Asking "wherever we have it" across every product is a view of its own with a query behind it, which is better than a box that quietly answers about one product while looking like it answered about all of them |

## A person's own page

Reached from their own menu rather than from the rail: it is about the person
rather than about the work. A person could not mint a personal token for scripts
anywhere in the interface, and could not turn the daily digest on at all — though
the documentation says it is off until asked for, which left somebody looking for
a switch that exists only in the API.

| Rule | |
|---|---|
| A switch that changes nothing is not offered | Nothing is sent without an address recorded, so where there is none the card says so instead of drawing a control that would look like it worked. Asking for the unassigned lines without the digest is refused by the server, and the screen does not offer it |
| A token's secret is shown once, and the screen says so while it is on screen | What is stored is a digest, so a secret nobody copied is a token nobody can use |
| What they may do, not which roles they hold | The mapping from one to the other is the server's rule, and a second copy here is the one that drifts |
| The version is in the footer, read from the deployment | An interface and a server that disagree about the version produce the bug report nobody can act on |

## A person, whole

`/people/:identity`, reached from the people list by their name — the same move
as a component's name opening the component. An administrator's screen: it
carries what somebody was told, which is the question asked after a leak.

Four things that were answerable only by reading four screens against each
other, and two that could not be asked at all.

| Section | What it answers |
|---|---|
| What they hold | The roles in force, and whether a role they hold grants nothing — which reads very differently from holding none |
| Their part in the record | How many claims they argued, how many they agreed to that still stand, and how many agreements they took back. What the rubber-stamp report asks across a program, asked about one person |
| Roles granted and withdrawn | Every change against them, newest first, with who made it. Absent before means nobody had set it; absent after means it was withdrawn, and a blank cannot tell the two apart |
| What they were told | Everything sent to them, acknowledged and cleared included |

| Rule | |
|---|---|
| An agreement taken back is counted apart from one that stands | It is not somebody who agrees, and the record's own file already says so |
| What they were told is not narrowed by what they may read now | The area somebody reads themselves is narrowed; this is a different question, asked by somebody who administers the deployment. A line about an undisclosed finding, sent while they held the role that reached it, is what the screen is for |
| A name nobody holds and a name the caller may not reach answer alike | Resolving first and refusing after makes the refusal informative, which turns a lookup into a directory |
| Each list is a page, with its total beside it | Both only grow, and a screen that asks for all of either is one that stops answering |

Leaving is recorded here, at the foot, and says what it does before it is done:
refused at every way in, sessions ended, work handed back, nothing deleted and
no role withdrawn. Once it is recorded the screen says so at the top rather than
at the foot — every other number on it reads differently once somebody has gone
— and offers bringing them back.

## A release, gathered

`/products/:product/streams/:name` when that name is a tag. The address a
branch and a tag share resolves to whichever screen answers the question that
line poses, from the catalog rather than from a naming convention: a branch is
rebuilt nightly and what matters is what it is built as, and a tag never
changes and what matters is what was handed over when it was cut.

A release is a hand-off, not a fifth summary page. What belongs here is what
goes out with the release, which sat in four places reached four ways.

| Section | What it answers |
|---|---|
| What this is | The variants it was actually built as, each with what is open in it |
| What is true of it now | Open across every variant, by severity |
| What changed | The release before this one, and the comparison against it |
| What we told customers | The release note, the advisories, and a VEX document per variant |
| The record | The disposition register per variant |

| Rule | |
|---|---|
| No overdue section | A tag never changes, so nothing on it has a deadline to miss |
| The release before this one is the newest earlier tag with a day recorded | A day nobody recorded cannot be ordered against one that was. Reading a declaration date as a release date is what makes a release recorded months late sort wrongly |
| Cut from the same branch, where both say so | Two branches are two pieces of software, and comparing them reads as a regression somebody then goes looking for |
| Advisories are not narrowed to the release | An advisory is about a flaw and goes out once, however many releases carry it. Tying it to whichever release was cut nearby would invent a relationship the record does not hold |
| The per-variant count comes from the same answer the severity split is added from | The endpoint that lists what a release was built as does not fill a count in, so reading it there drew a column of zeroes under a section reporting twenty-six |

## Reports, settings, inheritance

Reports is a catalog of named reports, under "Across products", beside "The
record" rather than inside it — the record is what was judged and who agreed; a
report is the shape of the judging. **Reports may span products**, unlike every
other screen: comparing products is often the point, and it costs no visibility,
since a person only ever sees products they hold a role on.

| Rule | |
|---|---|
| A report is a page of its own, at `/reports/<name>` | A page is printable, linkable and quotable; a section of a dashboard is none of those. The catalog screen holds the list and the files reachable nowhere else; a question with no name is asked on the findings list, which is where the filters live |
| A report about the thing you are standing on stays on that screen and is listed in the catalog; one that spans things lives only in the catalog | The comparison of two releases is the screen where the two are picked, so it keeps its address and gains a catalog entry that arrives with the product already chosen |
| An entry that cannot answer at the current selection is still listed, saying which picker to touch | A report missing from a list reads as a report that does not exist |
| A name the catalog does not hold returns to the catalog, not to the front page | Somebody following a stale link is looking for a report, and the list of them is the nearest answer |
| Every report states what it was asked of and when it was taken, and prints | The stylesheet is the record's: the shell, the rail and the controls drop out, and a row does not break across a page. A control that does not print has its value stated in the printed header instead |
| A report that is a list exports as CSV and JSON; one that is figures prints, and every figure links to the list it counts | There is no stream behind an aggregate, and inventing one would publish a file nothing computed. The list a figure opens is the export, and it is also the traceable form of the number |

| Rule | |
|---|---|
| The settings screen is grouped, and its values are formatted for whoever reads it (REQ-60) | Cards are titled by what the setting decides rather than by the last segment of its key, and a duration is composed from a count and a unit rather than typed as one. Under REQ-01 that reader is an operator nobody here will ever meet, and this is the screen where every threshold that changes what the tool reports is set. Sizes are still raw byte counts, which is the half that is not done |
| A setting whose value is one of a few words is a select, not a text box | A free field invites a value the server then refuses, and for a switch it invites "true", "yes" and "1", none of which are what it takes |
| A setting nobody has set is composed like one that is set | Nothing to read is not a value the composer refuses. The embargo periods arrive with no value at all, and they fell to the plain box kept for a duration this cannot say — which is the one control that cannot ask whether a typed 90 means hours, days or weeks. An empty composer opens on days, because a period nobody has set here is an embargo and an embargo is said in days |
| What a new line inherits is on the inventories screen | That is where somebody is when a line has just had its first scan, which is the moment the question arises. It names the line to carry from, says how many reach this one already and how many cover nothing here, and offers the rest as a list to tick. Only two of the four groups are questions, and the screen says which |
| What was recorded here is a filter | A flaw somebody entered is the only kind a person may close by hand (REQ-19), and the screen that records one is where "is this already filed" gets asked. Offered on the list and linked from the recording screen, with the line off, because the question is what exists rather than what is worth an afternoon |

## Showing the ordering signals

The findings list is ordered by urgency: known-exploited, then whether the build
reaches customers, then severity, then likelihood. **Every one of those is on the
row.** An order that sorts on something it does not show reads as no order at all:
the first version showed only the severity word, and the top of a real list came
out "high, high, medium, medium, medium, high, high, critical" — correct, and
indistinguishable from unsorted. The first five were known-exploited and nothing
said so.

| Rule | |
|---|---|
| Known-exploited is its own badge, not a replacement for the severity word | Replacing it answers one question by destroying another: an exploited medium is still a medium, and the reader needs both facts to see why it sits above an unexploited high |
| The score sits beside the word | They come from different places and can tie while the words differ — a 2003 issue scored 10.0 reads "high" under CVSS v2 and "critical" under v3. Two rows tied at 10.0 with different words look mis-sorted until the number is there. Genuine disagreement between word and number is rare, measured at 3 of 2,645; the vocabulary difference is not |
| Where this product has rated something itself, that is what orders its list, and both ratings are shown | Being able to say a published rating is wrong is pointless if everything that sorts and filters then ignores us. The world's stays beside it, because a rating of ours standing where the world's goes reads as the world's. The list that spans products reads each row against its own product's rating, because a rating belongs to one (REQ-29) |

## Units, dates and copy

Every count says what it is a count of (REQ-60). Five counts appeared within one
screen of each other in three units — findings, distinct issues, and distinct
issues beneath a path — and only one was labeled, so a rail badge and the page
title beside it disagreed by thousands and both were right.

| Word | Means |
|---|---|
| **Issue** | The vulnerability itself, one identity across its aliases |
| **Finding** | One component at one place in one build |
| **Group** | One issue at one component across every place it sits at — the row the findings list returns |

Home's open figure, the trend and the severity ring count issues and are labeled
"issues". The findings list and the rail's counts are groups, so the same issue at
three versions of one library is three rows there. "CVE" is not used as a label,
because not every issue carries one. The list says "N places" on each row rather
than calling the row a finding. **The rail has room for a number and not for a
noun**, so a badge carries its unit on the title and on what a screen reader is
given.

Dates take one absolute form and one relative form. Four were in use at once,
two of them machine-shaped — a stored moment interpolated whole, with its time
and its offset, is the tool showing its storage rather than answering the
question.

| Form | |
|---|---|
| **Absolute** | The calendar day as stored, deliberately not localized. These are dates people quote to each other across time zones, and one that reads differently for two people looking at the same row is worse than one that reads unfamiliarly for both |
| **Relative** | For the reader asking whether something is stale. It reads the same scale in both directions, because a deadline and a last scan are the same question about opposite sides of now, and it carries the absolute form on the title |

Waiting looks the same everywhere, and says so. The sentence was typed out
thirty-nine times in four spellings, and none of them announced anything — which
leaves a reader who cannot see the page with nothing between asking and arriving
that distinguishes a slow answer from a page that did nothing. One component,
announced politely, with the one real variation the thirty-nine had between
them.

A statement about a trend waits for enough history to support it (REQ-54). The
trend answers for a fixed window whether or not this deployment existed through
it, so a week-old deployment gets twelve weekly steps of which eleven are zeros
— and the copy read "Backlog growing: new exceeded resolved in 1 of 12 weeks"
and "Critical went 0 → 389", both describing the first scan landing. The guard
was there and counted the steps *returned* rather than the steps that held
anything.

Leading empty steps are dropped and the rest are kept. An empty week inside the
history is real; a leading one is only the absence of us. Four steps of real
history before a direction is claimed, because three points is one change plus a
confirmation. The panels still draw — the chart shows what there is and claims
nothing; only the sentence is held back.

## Interface-wide rules

A screen works on a phone, and that is a requirement rather than an enhancement
(REQ-55). It rules out any packaged data grid that owns its own markup: the
findings table has to become something else on a narrow screen rather than
scroll sideways. That is why the tables here are written rather than installed.

| Rule | |
|---|---|
| A small screen is shaped around review and respond, not bulk work | Read a finding, agree to one or send it back, see what is assigned to you. Nobody triages three hundred findings on a phone, so the wide-only screens stay wide and say so rather than being folded into something unusable |
| Every table that scrolls says so | Thirty of thirty-one scrolled sideways inside their own frame and none mentioned it, which reads as a page cut off rather than as a table with more in it. Said above the table and pinned so it stays visible while the table moves |
| Headings and field labels are noun phrases (REQ-60) | The name of the thing, the way a settings screen anywhere else names one. Written as descriptions — "When somebody counts as absent" — they make somebody scanning for the one they came to change read thirty sentences instead of thirty names. The explanation stays underneath. Three had no name at all, falling through to the last segment of a configuration key: a card headed "After" |
| Labels use the conventional word (REQ-60) | Reject, Trend, Assignments, Unassigned, Justification, Path, EPSS, Locations, Users and roles, Lapsed decisions, Submit. A caption on a screen is a sentence at most |
| A form field is not a credential | Every text and number box says so in the four attributes the password managers actually read. They guess from shape and proximity, so a short box beside another short box is offered a saved login. `autocomplete` alone does not do it: browsers ignore it for saved logins by design. Nothing here is exempt, because nothing here is a credential — this deployment never holds a password |
| A control carries no prose, and names itself | Saying a field is not a credential is not enough where the field's own words read as one. A manager reads whatever text it can reach through a control, and three settings were offered a saved login with all four attributes set: their explanation sat on the control as a tooltip, and it said sign-in, account and date. So the explanation sits on the label, where a person hovering still finds it, and each control is named for what it holds rather than left for a manager to name from its surroundings |
| Two rows are only ambiguous when both ends match (REQ-57) | The same subproject reaching the same component twice by different routes. Rare, and visible when it happens: expanding the row, or the tree, resolves it. Nothing is invented to disambiguate a case the reader can see |
| Panel order and what is left out are decided rather than accumulated | The risk in a page that gathers everything is that it succeeds at nothing |

## The initial load

Screens are split by route. The findings list has to stay usable against a
full-size product and has no business downloading a charting library, and the
markdown renderer is only needed where somebody reads or writes a justification.

Measured: one bundle of 820 KB became a 248 KB initial load, with the chart (369
KB) and the renderer (146 KB) fetched only by the screens that use them.

## Running it locally

    make demo                    # build the image, start it, seed it, say where to go
    make demo DEMO_HOST=yourbox  # if you browse by something but localhost

| Target | |
|---|---|
| `make demo-status` | Whether the scan has landed and how much it found |
| `make demo-down` | Stops it |
| `make demo-reset` | Throws the database away and keeps the scanner's vulnerability database, which is a gigabyte and is not what anybody is resetting |

| Rule | |
|---|---|
| The only thing it needs on the machine is docker | A demo that needs a page of prerequisites is one that gets run by the person who wrote it and nobody else |
| It builds the image from the working tree | What comes up is the change being tested. The interface and the binary are built *inside* the image: the Go build embeds the interface, and the directory it embeds is git-ignored, so an image built from a clean checkout would otherwise carry no interface at all |
| Everything it writes lives in a git-ignored directory in the tree | Deleting the checkout deletes the state. A command run from a checkout that writes to somebody's home directory is a surprise |
| Seeding is idempotent | It can be run repeatedly without tearing anything down |
| It is the real thing behind a real proxy | The application is authenticated by a trusted header, and the demo runs exactly that — the image, with a small proxy in front adding the header — rather than a development server standing in for one. **No mode in the application trusts anybody**: the alternative was a development switch that assumes an identity, which is a hole nobody should ship |
| It is a demonstration deployment, not a small production one | It serves plain HTTP and hands administration to whoever the proxy says they are. Both are holes; together they are a machine somebody can click around on |

## Divergence from the mockup

The restyled mockup is the reference, and each screen has been put beside it and
compared control for control. What differs is listed so that it is chosen rather
than inherited.

| Mockup | Here |
|---|---|
| A known-exploited tile at every scope | It needs a product: nothing counts exploited findings without one to narrow inside, and a tile that guessed would be worse than one that is not there |
| A finding sample carrying builds already past the fix, shown and not offered | The reach endpoint does not say whether a build's version sits past the fixing version — there is no version ordering here — so every build at another version is offered and the "not offered" card is empty |
| Reaffirms a lapsed decision inline on the queue card | The queue row does not carry the build, and reaffirming is a claim about one place in one build, so it happens on the finding |
| Variants and branches screens carry a product select of their own | The scope picker is that control, and the screens follow it |
| The queue card draws "matching automatically" and "ticked deliberately" apart | The record does not keep which builds were reached by lookup and which by an applied decision, and the number an approval keeps is one |
| The users table lists user, identity, last sign-in, roles and assigned | User, identity, roles and a grant control on the row. Granting is what an administrator opens the screen to do; last sign-in and assigned work are read from the person's own row |
| Administration sits in the grant grid | It is global rather than held against a product, so it is a control of its own beside the grid. It had none at all: the endpoint took it and the screens only displayed it, so the ways to grant it were the configuration file, a group binding, or calling the API by hand |
| Creating a pipeline key is somewhere other than the credentials card | It is created where the keys are listed, because deciding to make one follows from reading what exists. The card listed and withdrew them and could not make one, so a deployment could be read for credentials it had no way to issue |
| A personal token's reach is chosen after it is made | The narrowing is fixed at creation, so it is asked for there. The list carries what each token reaches, because a credential whose scope is invisible is one nobody withdraws with confidence |
| A withdrawn credential leaves the list | Withdrawing marks rather than deletes, so that what used it stays answerable — so the row stays, dimmed, with the button replaced by the word. Drawing it unchanged, with a live button still on it, made withdrawing look like nothing had happened |
| The sign-in screen is drawn where there is one way in | It is sent straight on to the provider. Nothing is collected there and there is nothing to choose, so the screen was a button whose only purpose was to be pressed. Three arrivals still draw it: the offer made over live work after a session ended, the one straight after a sign-out — where the provider still holds its own session, so forwarding signs somebody back in and makes signing out impossible — and any second arrival in a tab that already forwarded, because somebody refused after authenticating has to be able to reach a screen rather than be sent round again |
| The inventories table carries product, branch and variant columns | The screen is scoped to one build, so those are the scope bar rather than a column repeated on every row. What it adds is when the producer says the build was made |
| Settings write "3 days" in the field | The server takes and returns its own duration syntax, so what is typed is what is stored and the reading — "= 3 days" — sits beside it rather than in it |

The trend is drawn by hand rather than by the charting library. Open runs to
thousands and a week's new or resolved to tens, so on the library's one shared
scale the two lines the chart exists for flattened into the baseline. The
mockup's form — open as an area in its own band, new against resolved as paired
bars beneath on their own scale, one x axis — has no expression in the library
short of two charts pretending to be one. The severity split and the ring stay
with the library.

## Test coverage

`make check` type-checks every screen against a client generated from the API
document, so a screen cannot disagree with the shape the server sends and a
drifted endpoint is a compile error rather than a blank panel. **That is real
coverage and it is most of what the frontend needs.**

What it is not is a test of what a screen *says*. Five pieces are pulled out and
tested on their own — what a notification is called, the count on the control
that opens it, where an unsent draft is kept, where a sign-in comes back to, and
how a session that ended is noticed — because each is a defect rather than a
matter of taste if it is wrong. Everything else is checked by a person looking
at it.

The draft rules are tested; the sign-out that calls them is not, and nor is the
panel that offers a way back in. There is no component test here to click a
control or to see what is drawn over what, so both connections are checked by
reading. They are the weakest links in the chains those rules describe.

Several thousand lines of interface, six test files. Where a screen computes
something rather than draws it, that computation should come out into a function
beside them.

## Not built

| | |
|---|---|
| **A claim scoped to a consumer subtree** | Proposed in the workflow review and rejected on the owner's judgment: the rules would have held, and one sentence answering a thousand findings is the shape that makes a dismissal unreadable afterwards |
| **Narrowing the review queue** | By product, by what kind of thing is waiting, by who proposed it, by age or by severity |
| **A deadline and an owner in the finding's header** | The row carries both; the header does not |
| **A spacing scale** | Six values are named at exactly the numbers already in use, so naming them moved nothing — but there were nine hundred values written by hand running 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16, 18, which is continuous rather than a scale. Inventing one is a judgment about how the interface looks, made against a running browser rather than as a mechanical substitution |

## What the checks missed

| | |
|---|---|
| **A source file that reads as binary is skipped by every text tool, and none says so** | One stray NUL byte in the busiest screen did that: the class-collision script, the design-token check and every hand audit passed over it, and the four chart components it draws were reported as reached by nothing. The absence of an answer rather than a wrong one, which is the shape that survives review. It is a gate now, over every text file the repository holds |
| **A token named and never defined** | CSS drops the declaration, the element keeps whatever it inherited, and the screen looks nearly right. Three were in the stylesheet, each a rename with one reference left behind, and each invisible until two screens were compared side by side. Every reference is put to the set of definitions, and a token set per element in a style object counts as defined |
| **Five rules restated what a wider media query already applied** | A phone layout fixed by appending a corrected copy at the bottom of the stylesheet rather than editing the rule where it lives: anything under 780 is under 900, so they changed nothing and read as though they did |
| **The thirty-first table that scrolls** | The release-readiness table on home, cut off on a phone with nothing explaining why |
| **An operation the API offers that no screen reaches** | The generated client type-checks what a screen sends against what the server takes, so a screen cannot disagree with the shape — but an endpoint or a field nothing calls is not a disagreement, and neither the unreachable-code check nor the decision gate looks at it. Four were found by configuring a deployment from empty: creating a pipeline key, granting administration, narrowing a personal token to a product, and the withdrawn flag on a token row. Walking the API document against the generated client's call sites is what would catch it |
| **What only a browser shows** | Six screens passed the type check, the lint and their tests, and every one was wrong on screen. A chip styled by a block-level class stood a row of pills on end. A holder's name was drawn in placeholder grey. A component's name came out empty, read off a chain that was not there. A form refused to submit and never said what was missing. A comment box offered no mentions. A superseded upload reported a clean scan. None of these is a screen disagreeing with the server, which is the only kind of wrong the checks can see |

## File organization

The finding screen was three thousand lines and the stylesheet four thousand two
hundred: every addition is small and beside something related, and none of them is
the one that made it too long.

| | |
|---|---|
| **The finding screen splits into four, by question** | What the record says about this finding and how it came to say it; what is known about the flaw as against what anybody claimed; who is involved and what hangs off it; and the screen that arranges them |
| **The list screen gives up the parts that take rows and draw them** | Expanded in place, by component, by bump, the pager. It keeps the one component that holds the selection, the filters, the page and what is picked across pages. That one is still long, and it is one thing: cutting a component that shares that much state between halves would be splitting badly |
| **The queue screen splits by which queue** | Five lists lived there. What became of what you proposed is a whole tab with its own endpoint, sharing nothing with the claims but the offset in the address; an embargo extension and a severity rating are two things waiting for a second person that are not claims, and share neither the card nor the selection nor the batch. What is left is the claim queue, which is one thing |
| **The dependency tree gives up the panel** | Walking the graph and asking what is known about one node are two questions, and the second took a third of the page while the first was on screen |
| **The finding screen gives up the one form among its readings** | Rating the issue is a claim about the issue in this product, made from a screen that is otherwise four readings of what the record already says |
| **The stylesheet splits by position, not by theme** | Order is the mechanism — the last rule wins — so grouping rules by what they are about would silently reorder the cascade. The files are the sections in the order they were already in: the tokens, the frame, what every screen is built from, the shapes belonging to one screen, and what a narrow screen changes. 653 rules before and after, same order, same content |
| **A shape many screens draw belongs to the parts, whatever it was written beside** | Four sections — the charts, the report sheet, the drawer, the covering panel — styled components in `ui/` from the file that says it holds "shapes that belong to one screen". Moving one earlier in the cascade is a behavior change only where a per-screen rule of equal specificity was relying on losing to it, so it is checked selector by selector rather than assumed; for these four the two files shared none |
| **What the parts file costs is the size of the parts file** | It is the shared vocabulary every screen is built from, so it grows with that vocabulary, and the only split available is per-component — which the cascade rule makes hazardous for no gain. Around nineteen hundred lines is the honest price of this split axis, recorded here rather than paid by cutting the file into pieces that have to be kept in order |

## Limits

| | |
|---|---|
| Color and the brand mark resolve through tokens in one place | How an operator overrides them is deliberately unsettled — that gets decided against real screens — but keeping the whole palette in one stylesheet means the answer will be a stylesheet rather than a hunt through components |
| Dependencies are pinned exactly, not by range | A range resolves at build time and CI stops being reproducible; a caret in a manifest does exactly that. `npm ci` installs the lockfile |
| A failure shows what the server said | Inventing a friendlier sentence hides the one the server wrote, which names the line to fix or which part of a declaration is missing — and is the more useful of the two |
