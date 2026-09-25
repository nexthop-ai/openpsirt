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
- [The by-upgrade view](#the-by-upgrade-view)
- [The component screen](#the-component-screen)
- [The finding screen](#the-finding-screen)
- [The decision form](#the-decision-form)
- [The reach sheet](#the-reach-sheet)
- [List navigation](#list-navigation)
- [The dependency tree](#the-dependency-tree)
- [The review queue](#the-review-queue)
- [The claim page](#the-claim-page)
- [Assignments and routing rules](#assignments-and-routing-rules)
- [Catalog and inventories](#catalog-and-inventories)
- [Product and scan-run pages](#product-and-scan-run-pages)
- [Flaw entry](#flaw-entry)
- [The inbox](#the-inbox)
- [Disclosure and advisories](#disclosure-and-advisories)
- [The editor](#the-editor)
- [Reachable from a keyboard](#reachable-from-a-keyboard)
- [A read that failed](#a-read-that-failed)
- [A render that threw](#a-render-that-threw)
- [An expired session](#an-expired-session)
- [File attachment](#file-attachment)
- [Mentions and assignment pickers](#mentions-and-assignment-pickers)
- [The search box](#the-search-box)
- [A person's own page](#a-persons-own-page)
- [A person, whole](#a-person-whole)
- [A release, gathered](#a-release-gathered)
- [Reports, settings, inheritance](#reports-settings-inheritance)
- [The System screen](#the-system-screen)
- [The administration screens](#the-administration-screens)
- [The ordering signals](#the-ordering-signals)
- [Units, dates and copy](#units-dates-and-copy)
- [Screen copy](#screen-copy)
- [Interface-wide rules](#interface-wide-rules)
- [The initial load](#the-initial-load)
- [Local development](#local-development)
- [Divergence from the mockup](#divergence-from-the-mockup)
- [Test coverage](#test-coverage)
- [Not built](#not-built)
- [Gaps the checks left](#gaps-the-checks-left)
- [File organization](#file-organization)
- [Limits](#limits)

## One artifact

The built interface is embedded into the binary and served from it. A deployment
is one container, and the interface cannot be a version behind the API it talks
to.

| Rule | |
|---|---|
| Nothing is fetched at run time | No font, no script, no stylesheet from anywhere, so nothing a screen needs depends on somebody else's server being up. An air-gapped install is then an ordinary install rather than a configuration |
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
| An address the page does not know says so, and keeps the address | A redirect to the home screen throws away the one piece of evidence a link built wrong leaves behind: a component link composed with no product selected is reported as "it brings you back to the homepage", and the reporter cannot say what address they were on, because it is gone from the bar |

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
attached once as middleware rather than per call — the one call somebody
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

The shell — the rail, the top bar, the scope picker — is the restyled mockup's,
taken as settled rather than approximated (REQ-60). The work surface below it
is quieter than the mockup drew it, and § Divergence from the mockup lists each
difference. The mockup drew the interface inside a frame; here the frame is the
page, so its tokens sit on the root element and its grid on the application
container.

Two looks, one markup. A look is a token set — colors, the two typefaces, radii,
shadows — and nothing else. One is a dark rail over a light surface; the other
is dark throughout. They are called light mode and dark mode, because that is
what every other application on the same screen calls them.

### The work surface

| Rule | |
|---|---|
| One plane | The canvas and the surface are the same color. A card, a table and a figure are set off by a hairline and nothing else; a shadow says there are two planes, and it is kept for what floats — a list of suggestions, the picker, a drawer |
| Corners are small | Six pixels on a control and eight on a card. A tag takes four |
| A label is sentence case | The label over a block, a column head, a field's name and a figure's caption are the words a person would use, in the muted tone and at the small step. Uppercase is kept for the two marks that are read as marks — known-exploited and a bulk claim |
| The primary button is ink | Black on the canvas in the light look, white on it in the dark look. The accent is for what opens something, so a button and a link never read as the same kind of thing. A secondary button is the same outline in two weights of text |
| A pressed filter is ink too | A chip or a segment that is on is drawn in ink, and a filter in force above the list sits on the raised tone with its label quieter than its value. Neither borrows the accent, because a state and a link must not read alike on one toolbar |
| Every state is ink or the raised tone | Picked, pressed, checked, selected, the page you are on, the component a path leads to, a setting that is set. The accent stays with links, focus rings, hover on what opens, and the row or option the keys are on. A web test fails on a style rule for a state that uses the accent |
| Severity is a dot and a word | Colored by the band, with no fill behind them. A tinted pill on every row of a fifty-row list is fifty patches of color competing with the column that is read first |
| A count beside a tab is a number | Quieter than the word it counts and the same shape whether the tab is selected or not |

| Rule | |
|---|---|
| Nothing chosen means the operating system is answering, and keeps answering | A machine that turns dark at sunset turns this dark at sunset |
| A person who picks one pins it, and picking "system" hands the question back | Otherwise choosing once is a door that opens one way, and somebody who tried dark at noon can never get their evening back |
| Stamped on the root element before the first paint | Setting it after the first frame is a flash of the wrong look on every fresh page |
| Kept in the browser, changing nothing anybody else sees | The same rule as saved filters |
| Severity never borrows the accent | Each look has its own accent and the same five-band severity scale beside it, with exploited above critical. A page that paints "critical" in the brand color has nothing left that means "act on this" |

Two looks, not three. Named for their aesthetics they ask somebody to guess
which of "Dojo", "Ledger" and "Obsidian" is the light one.

### State chips

A state is a word on a tint of its color. The color says how the reader should
take the word, so one color never carries two readings.

| Class | Means | Color | Examples |
|---|---|---|---|
| `closed` | Asked for and done | Good | Scanned, met |
| `agreed` | Agreed to | Good | Decided, approved, in force |
| `waiting` | Under way, or waiting on somebody | Amber | Pending, scanning |
| `warn` | Not wrong yet, and close to it | Amber | A queue at its limit |
| `lapsed` | Ended without standing | Orange | Lapsed, withdrawn, sent back |
| `bad` | Wrong, and somebody should look | Red | Failing, failed, stopped |
| none | A fact, neither good nor bad | Muted | Left, held back |

| Rule | |
|---|---|
| A problem is never drawn in the done color | Green reads as good news, which is the one reading a failure must not get. A web test fails on a chip drawn as done whose words say something is wrong |

## The shell

A rail down the side carries the brand and the entries grouped by what they span;
a bar across the top carries what you are looking at, a way to find things, a way
to upload, what is waiting on you, and who you are.

| Rail group | Holds |
|---|---|
| **Across products** | Home, the review queue, what nobody holds, the assignments and the record. The record is here because that is how it is asked for: an auditor asks about a period, not about a build |
| **The named build** | The findings, the dependency tree, the inventories and what the build is waiting on. The comparison of two releases is not here: it is a named report, listed in the report catalog with the selection already made, and linked from the front page. Three doors to one screen is two too many. Reporting a flaw, what is disclosing, the advisories and the standing attacks sit at its foot, each a date or a document somebody outside is waiting on |
| **Manage** | The catalog, the access, the teams, the standing assignment rules, the settings and the deployment itself. The catalog is whole and in order here — a product, then the branches and tags under it, then what those are built as — because the two lower levels need a product picked, and a catalog split across two groups makes managing one a visit to both |

A build-only entry declines rather than opening on a scope that means nothing.
With a product, branch or variant unpicked, the tree and inventories entries are
disabled and say why. Findings is not one of them: it takes whatever is
selected, and the count beside it is of what the list it opens will show.

Other bar rules:

- The search in the bar is the findings list's own search, reached without
  going there first. "/" focuses it, unless somebody is already typing.
- Upload is in the bar on every screen (REQ-05), because the form picks its own
  target; the inventories screen has it too, because that is where the result
  appears.
- On a narrow screen the rail goes and a tab bar of three arrives — home,
  findings, queue — which is what somebody reviews and responds from on a
  phone. A menu control in the bar and a fourth tab open the whole rail as a
  panel over the page.

### The folded rail

Twenty-four entries ask for about 935 pixels, taller than the window on most
laptops. A scroll region of its own puts a second scrollbar down the middle of
the screen; scrolling with the page leaves the menu a thousand pixels above
somebody reading the foot of a findings list, which is where they are when they
want it.

A group heading folds what is under it, and "Manage" starts folded. Granting a
role or changing a setting is occasional rather than something done while
working, and with it away the rail asks for under seven hundred. A first visit
needs nothing out of it: somebody who has just arrived picks a product in the
bar above, which is what that control is for, rather than in the rail. The heading
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
| **A screen whose address names the product has that address rewritten** | The same rule, one level up: the path is the authority, so remembering a different product and staying put lets the path put the old one back. The bar snapped to the product in the address and nothing said why. Choosing every product from one of these is the catalog |
| **What sat below the product in the address is dropped where it belonged to it** | A branch is one product's and so is a component, so neither carries across. The address falls back to the new product's branch list, or to the product |
| What comes back out of the tab's memory is checked, not cast | The value becomes a path segment and a query parameter. An entry an older build wrote, or one edited by hand, otherwise reaches the server as `[object Object]` |
| What the tab remembers goes with the session | Signing out takes it away, which the drafts section states in full: the next person in that tab was shown the previous person's product |
| A narrowed screen says what it is counting | A page answering for one product that looks exactly like a page answering for all of them is how two people quote different figures. That applies to the panels within it: a chart the picker has narrowed and a label reading "all products" state opposite things, and the label is the half a reader believes |
| A selection the server would refuse is never sent | A branch or variant with no product above it is dropped on the way out |
| **The variant column does not empty while it narrows** | Picking a branch swaps what the column offers from the product's variants to that release's, which is a different question and a different read. The first stands in until the second arrives: it is a superset, and a column that goes blank in front of somebody halfway through choosing reads as the picker losing what it had |
| **The picker asks for no counts** | What is open against a row is the expensive half of a catalog read — a list of two products answered in 0.39s against 1ms for a liveness probe, and the time went with the findings rather than the rows. This panel draws names. So the counts are a parameter the two screens whose subject they are pass, and everybody else gets the cheap answer |

## Home

Home leads with the work and puts the shape of things underneath: what is
waiting for review, what is being worked on, what stopped applying, then the
trends, and the operational state at the foot. The trends answer a question
asked occasionally, and they are also the slowest part of the page.

The reader's own work leads, then the shape of the estate. Assigned to them,
and claims of theirs an approver sent back; then open at or above the floor,
known exploited, pending their approval, and overdue. Led by the estate, home
answers "how much is there" and never "what do I do next": the largest number
on the screen is the whole estate's open count, which is the least actionable
thing on it, and the one panel that could carry somebody's own work is
everybody else's.

Open is the trend's latest point at every scope, which counts distinct issues —
the findings list counts one row per issue and component, and a tile switching
between the two as the picker moved would quote two figures for one word.

What became of a claim is derived rather than stored, so there is no count
to ask the server for: a page is read and what is on it is counted, and the
tile says so where the page was cut. That is the treatment the deadline tiles
beside it already get.

| Panel | |
|---|---|
| **Release readiness** | The picked branch against the last release cut from it, band by band, with the move shown as a direction rather than a signed number: fewer is better here, so the color follows the meaning and not the arithmetic. Drawn only where the question has an answer — it needs a whole build, because a count across products is not a release, and a branch, because a tag is one frozen point |
| **Quiet builds** | A build that stops being scanned reports no new findings and fails nothing, so it looks healthier than one still being scanned. Named one at a time rather than counted, because a number is read past and a name is acted on. On the front page and on the scans screen |
| **Overdue and due soon** | Overdue is a report about something that has already happened; due-soon is the week somebody can still finish. Both come from one read of the deadline list. The overdue tile pointed at the assignments screen, which answers what is *mine*, so the number and the screen it opened disagreed for everybody but the person holding all of it |
| **In progress** | How much each person and team holds, with the reader's own row first. The panel is about the shape of the work rather than about one person, and it stays that way — but reading your own row off a list of colleagues, where it may fall below the three this shows, is why somebody who works here went elsewhere to find out |

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

Both ends cost one recursive statement for the whole page: the database climbs
from every consumer on the page to the root and returns the nodes on the way.
Climbing is bounded by the depth of the graph rather than its size, and bounded
at sixty-four steps so a document in a loop is answered rather than followed.
Reading every edge of the build into memory instead — 18,561 rows on a switch
image — and walking them in Go is three to eighteen milliseconds, and scales
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
screen of its own, and one entry on the rail rather than two. A second screen
offering four of this one's filters answers "which of our products carry this,
and what is running out anywhere" with the weaker of the two lists. The server
has no such split: both routes take the same filters from one definition.

What is absent without a product is what has no meaning without one. A subtree
is a walk over one build's edges, and "differs between builds" and the spread
across variants are statements about a selection, so none is offered and none
is sent — dropped from the query rather than left in the address, because a
filter somebody can no longer see or clear is one that narrows a list for
reasons it does not show. "Only this variant" is likewise offered and sent only
where the selection names a variant, because it is a question about that one.
Saved filters, deciding from the list and the export are a product's own and
come back the moment a product is picked.

The product becomes a column where it varies, and the row links to that product's
list.

## Filters

Every filter the server offers is on the screen (REQ-60). A filter the server
takes and the screen cannot reach — an exploit-likelihood threshold, a date
bound — is a narrowing only somebody editing the address can use.

| Rule | |
|---|---|
| Every filter is labeled with the question it asks, grouped by what they are about | Severity and risk, what upstream did, where triage has got to, where the row came from, the component, and time. A value says what it is rather than completing a sentence begun by a label nobody can see |
| The filters narrowing the list are above the list | One chip per filter naming both the filter and its value, removable by clicking, whether or not the panel is open. A control carrying a count and nothing else keeps that count as a hand-maintained list of variables, which falls behind the filters it counts |
| **The selection is a chip too, and the first of them** | It rides on the path rather than in the parameters, so it draws nothing of its own — and a list scoped to one product then sits under filters identical to the list across every product, counting fewer rows, with nothing on screen to explain the difference. The rail's own unassigned count is across every product a reader may see, so the two disagree by exactly what the other products hold. A chip per level, product first, because each is narrowing what the one before it chose |
| Removing a selection chip widens by a level and carries the filters | Widening is a move rather than a parameter change, and dropping what somebody actually narrowed by on the way would be a second surprise on top of the one the chip ends. The branch and the variant are the new address's to put back, so they are not carried |
| **A filter cleared drops its key; it does not write out its own default** | The three narrowings the list applies when the address is silent are applied only where the key is absent. Two controls wrote both of their values to mean "not narrowed", which made the address say something, suppressed the default and widened the list — and left no way to express from the panel what the rail's address says |
| The count is read from the address | The one place that knows what every filter is called |
| Filtering is the server's, not the browser's | A list narrowed after it arrives is narrowed within one page of it, so "hide the kernel" would hide it from the twenty rows already fetched and from nothing else |
| The daily questions are on the bar | Decision state, severity, who holds it and when it is due, each a button naming itself and its value, with New today beside them. Everything else is behind More filters, a panel that opens with how many of its own filters are on written on the control while it is shut. A filter is on the bar or in the panel, never both. New today is the one shortcut: a single value of the panel's First seen after, drawn pressed only while that date is a day back, so any other date stays the panel's and the button does not clear it |
| A filter on the bar is one button | The name, the value and the menu of values are one control, so a name cannot wrap to a different line from its value. A value in force tints the button. A question with several answers at once — decision state, who holds it — takes ticks and stays open; a step on a scale — severity, due — takes one and closes |
| The panel is shut until somebody opens it, whatever the address narrows by | It is most of a screen. Opened because a filter is set, a link to a narrowed list covers the rows somebody followed it to read — and it says nothing the chips above the list do not already say, each of which removes its own filter when clicked |

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
twice and read side by side. Four more take a set: who is dealing with it,
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

The decision state is above the list, beside the severity floor, in the place
the exploited and fix-available chips would take. Neither earns it: the list is
ordered by urgency, so what is being exploited is already at the top, and a fix
being available is a column on every row. The first thing somebody reaches for
is what has not been answered yet.

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
clicking the one already sorted turns it around. The "Sorted by" control on
the line over the rows carries all six, including the two with no column: the ranking the list
is in when nothing is asked, and how long something has been open. What reaches
the statement is
an expression the server stores against each of its own keys: a placeholder
cannot bind a column name, so this is the one query parameter that has to become
SQL text. A word that is not one of the keys is not a sort, and the list comes
back in its own order rather than refusing.

| Rule | |
|---|---|
| A finding with no deadline sorts last whichever direction is asked for | "No deadline" is neither early nor late |
| **What came in overnight is a control, not a typed date** | The first question of a working day was a date box behind the filter panel. A chip writes the date a day back into the address — the date rather than the word, so a list somebody sends means the same thing when it is opened |
| **An empty list says what emptied it and offers the way back** | A narrowed list matching nothing is a dead end: the controls that produced it are scrolled off above, and what is left on screen says so and offers nothing. It names how many filters are in force and carries a control that takes all of them off — and says "nothing is open here at all" where none was in force, which is a different answer |
| **The columns that decide the next action come first** | The table is wider than its container on a laptop — 1,583 px in 1,088 at 1,366 — so the right-hand end is cut, and what was cut was Due and State: the two facts somebody reads a list of findings to get at. Severity, the deadline and how far it is decided lead now; the component, the path, the estimate, the fix and the reach can run off the edge without taking the next action with them, and the orders they carry are all in the "Sorted by" control over the rows |
| **A row is decided where it sits** | Opening a row carries the same decision form the finding screen does, over the list rather than instead of it. What a claim requires and what it writes are unchanged — a second person still agrees — and what changes is the two journeys per row, each of which read the list again on the way back. Everything the form cannot show there is one link away |
| A screen that is waiting says so with a mark that moves | The word alone is one faint line on a page that is otherwise still, and a still page reads as a stopped one. The mark carries no text, so a screen reader hears the word once; the page-wide reduced-motion rule stops it, and a still ring beside the word is still a mark |
| **A filter change narrows the list rather than replacing the screen** | The rows on screen stay and dim while the next answer is read. Unmounting the whole screen — the search box, the chips, the count and the controls with it — blanks the thing being narrowed and takes the cursor with it. `aria-busy` says the same thing to a reader who cannot see the dimming |
| **The views are tabs above the filters, each carrying what it would show** | A view changes what a row is rather than which rows show, so it sits apart from the filters. Across every product there is one view, and no tabs.  The three answer one narrowing at three grains and the difference is the whole reason to switch: a by-issue list of 7,455 rows is 341 by component and 284 by upgrade. Without the numbers the list opened on its longest view and read as the only one. The by-upgrade figure is a fix-bundle aggregate, measured at 2.2 s against a backlog of 8,376, so it is held for five minutes rather than asked again as somebody pages |
| **The list opens by issue, whatever the size** | No threshold, and the other two are a click away in the tabs and in the address as a chip that removes itself. A list that jumps to a different grain past a number nobody set is a list that answers a different question on two products |
| The order in force is named over the list, and every order can be asked for | "Sorted by" sits beside the count on the line above the rows, because the order is about the list rather than what is in it. Four of the six sit under a column header, so the other two could be reached by typing an address and by nothing else — one of them being urgency, which is the order the list opens in and what REQ-32 is for. Sorting by a column and then wanting the ranking back was a dead end |
| An order opens the way round that order means | The worst severity, the highest likelihood and the widest reach are all "most first"; a deadline and an age are not. Due opened at the furthest-away date, which is the answer to a question nobody asks |
| The tie-break is always the same pair of identifiers | Two rows equal on the sorted column do not swap between pages and drop one while repeating another |
| A page size of fifty, a hundred or two hundred, kept in the address | Fifty is 153 pages of one product's findings |
| A row is selected by what it is, not by where it sits | The list is read again after every decision and on every page, so an index would select a different row each time. That also makes a selection survive paging, which is what "a filtered set" means when the filter matches more than a page |
| **The row is carried with its key** | Acting on a selection then acts on what was selected rather than on the part of it the current page happens to hold. Holding keys alone, the queue counted every ticked claim in its button and approved only the ones on screen, dropping the rest with no message |
| **Changing the question clears the selection** | A selection is made out of a population, so replacing the population replaces what was selected. Kept across a filter change, the bar went on counting rows chosen under one question while none of them was listed — and acting wrote against all of them. Every change goes through the one function that holds the rule, including removing a single chip: today every chip only ever widens, so the rule held by a property of the chips rather than by construction |
| **A figure about a selection counts what the selection holds** | The bulk-claim screen sums rows written across every page it has seen, not the page in hand, because the selection outlives the page and the figure is what the cap is read against |
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

What the list is narrowed by is what prepares a claim, read off the address
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
| The count beside a version says which count it is | Ranked, it is everything reaching that version would close; unranked, it is what that release fixed on its own. The two are the same shape and often the same number, so the word in front of it changes with the flag and the reason is on hover. Drawn as one number under one heading, the column changes question without saying so |

The By fix view is gone. It listed one row per version pair with an action in
the last column — the thing somebody does presented apart from the thing it is
done to — and read as a stray list of version numbers with an unexplained link.
The grouping it existed for did not go with it: the act follows the source
package, so upgrading curl still reaches both of its binaries in one go.

## The by-upgrade view

One row per upstream upgrade, with what moving it would close: the
pending-upgrades question read from the triager's end rather than the
coordinator's. Keyed on the fold, so packages built from one source are one row.

| Rule | |
|---|---|
| **No action column** | That is what the By fix view was deleted for. The package name opens the component, where the upgrade is planned; a source package that builds three binaries is one upgrade and three links |
| Versions are listed, not ordered | This view does not rank them: an ordering exists per ecosystem rather than in general, and a list ordered for some packages and not others reads as one ordering somebody can trust. So one package appears once per version upstream released, and there is no nearest and no latest |
| The filters it cannot apply are named on the screen | It takes six of the list's thirty-odd; the rest ask about a place, a deadline or an assignee, and an upgrade has none of those. Dropping them quietly widens the list back out while the chips go on saying they are on |
| Nothing here counts places | An upgrade is a fold. What it says is the packages it moves, the issues it would close, and the builds that hold it |
| **The word on screen is "upgrade"** | It read "bump", which is not the word the decisions use. A vocabulary a screen and a document share reads as two things when it is spelled two ways, which is the rule the product name is already held to |

## The component screen

The page is a source package at the version it was built at: the fold
`DESIGN-data-model.md` defines. It has a row per build shipping it, with the
binaries that build ships from it, what is open across them, where it could go,
the earliest deadline among what is open, and what has already been promised.
The issue count is the way through to the findings list, filtered to every
binary of the source.

The screen is arranged on where the package sits, because that is what
decides what can be done about it. A leaf carries its own risk and is upgraded; a
package vendored in pre-built carries everything beneath it and moves only when
it does. So the graph leads — what pulls it in, the package, what it carries —
and the act hangs off it.

| Rule | |
|---|---|
| The position is drawn before the action | What is possible follows from where it sits, and the same two numbers read opposite ways at the two ends of a graph: nothing open on it and everything beneath means the package itself is the only lever |
| Releases are picked inside the promise, ticked to the ones shipping this version | One bump moves every release at that version. Picked in a column of the table instead, the form appeared only once something was ticked, so the control was invisible until somebody guessed at it |
| The version to move to is offered and never required | The list is what the scanner named; the server is what refuses one it has not heard of. So a version newer than anything reported can still be named, which is the case where an upgrade is ahead of the advisories |
| Nothing to upgrade to is a state, not an empty form | Where no version fixes any of it, an upgrade would lapse and the work is a judgment. A form that cannot be filled in is one somebody fills in anyway |
| The way to make that judgment is on this page | One judgment about many issues at one component is its own screen, and nothing in the application linked to it — it could be reached by typing the address. This page is where the question is asked: beside the count of what no version fixes, and as the action where nothing fixes anything at all |
| One page per source package | curl, libcurl4t64 and libcurl3t64 are one upgrade, and an upgrade is what the page is for. A binary whose inventory names no source package is its own source, and its page is the same shape with one binary |
| A binary name and a source name open the same page | The address takes either, compared without regard to capitals. A link from the tree names the binary somebody was reading; a person asking about a kernel names the source |
| The binaries are listed, and one is picked | The graph and the twelve weeks answer for the picked binary: what pulls a library in is not what pulls its command in. The one the address named is picked, then the one carrying most |
| Counts cover the source package, once per issue | An issue on three binaries is one issue. Each binary carries its own count beside its name |
| Consumers are counted from outside the source package | One binary pulling in another is the source depending on itself |
| More than one version is a choice, not a refusal | A source at two versions is two pieces of code. The versions are offered with what is open at each, rather than the request being refused with an instruction to add a parameter |
| A build is listed because it ships the component, not because something is open | The presence is a fact about the graph and the counts are joined onto it. Read off the findings instead, a package whose whole risk sits in what it pulls in — nothing on the package, everything underneath — answered with no builds, which reads as a name the product does not ship. That is the ordinary state of anything vendored in pre-built |
| One row per source version rather than per build | A build shipping a source at two versions holds two folds, and they are two pieces of code to decide about separately. Collapsed to one version, the other is hidden |
| A deadline is absent where nothing is open, never zero | It is the earliest among what is open, so with nothing open there is no such date |
| The package identifier travels with the row | The ecosystem is read out of it and so is an upstream address, and neither is stored. Nothing is fetched from either |
| Per build, because the answer differs by build | A stream staying on a maintained older line and a stream that has moved on are different work with different testing, and one target across both would be wrong for one of them |
| Where it could go carries two counts | What a release fixed is how many of what is open name that exact version; what reaching it closes is that plus everything fixed before it. Sorted on the first, the version worth taking sinks: measured on the demo's kernel, the release that closes all 158 fixed 2 of its own and the one that fixed 49 leads |
| Furthest along first where the versions can be ordered, unranked where they cannot | An ordering exists per ecosystem rather than in general, and one version a comparison refuses makes the whole list unrankable. Shown unranked the two counts are equal and the screen says so, rather than implying an order nothing established |
| The second count is consumers, not places | One judgment covers the whole fold, and what varies underneath it is what pulls the package in. A place count is a unit nobody acts in; it is the row's title, being what the bulk cap is measured against |
| It carries where the component sits in the graph | What pulls it in, what it pulls in, and twelve weeks of what opened and closed under it. Somebody arriving from the tree asked a question about the graph, and answering it on a page they have to leave to reach is the same page drawn twice |
| Where to read about the package is built from its identifier | An identifier already names the ecosystem and the name within it, and each ecosystem has one address where a package is read about. Nothing is fetched and nothing is stored — the same way the issue records are worked out. An ecosystem with no address offers none rather than a guess, and a name is encoded into the path because it came out of a scan file |
| The graph is answered for one build, picked from the rows above | An edge is a fact about one build: the same library is pulled in by different things in different builds. A link naming a build arrives on it, so the tree opens the component on the graph somebody was already looking at |

It is where an upgrade is promised, on the terms `DESIGN-triage.md` sets: the
releases it is for, the version, the date, the reason, and who carries it.

## The finding screen

The finding is the working screen after a decision as well as before it.

| | Carries |
|---|---|
| **Before a decision** | What the issue is, how bad, what upstream has done, where it sits, the evidence, the assessment, and the decision form |
| **After** | The decision that stands, in its state — pending, approved, lapsed — with outcome, justification, scope and who agreed to which revision, and the actions that fit the state |
| **Under both** | The dependency path, in a pane of its own below triage — the longest block on the screen and among the least often read; the notes on this issue in this product; one activity timeline built from the claim's proposal, revisions, approvals and comments; the revision history, marking which revision each approval named; the comments; and the decisions made here before, with their reasoning offered back as "reuse this reasoning" |

The dependency path shows the first six ways down, with a row beneath it.

| Rule | |
|---|---|
| The rest unfold from a secondary button that names what it adds | "Show 24 more", then "Show fewer". A total says how many there are, and what somebody deciding whether to click wants is how many they have not seen |
| The link into the tree sits apart from it, at the row's far end | Two inline controls side by side read as one run of text. The row wraps at a phone's width rather than squeezing them together |

The notes thread and the claim's comments are two threads, rendered near each
other (REQ-29).

| | Shown | Says |
|---|---|---|
| Notes | Always | What it is about, in words: this issue in this product, every build of it, and no other product. Read beside a row that may be one of several the same issue sits on, so "not this component" is the part a reader has to be told |
| Comments | Only where a claim exists | What was said about the argument somebody made, at this place |

The notes thread is the one somebody can write in before anybody has decided
anything, which is why it is not gated on a claim. Nothing about writing one
changes what ranks, a deadline, or what the product triages, and it says so
beside the button.

The identifier in the heading opens the issue screen. That screen answers
"everywhere this issue sits", and without this the doors into it are an
exact-match search, one report and one queue link — none of them reachable by
the reader most likely to want it, who is already looking at one place the
issue sits.

The issue screen carries the same thread, a product at a time. That screen
shows an issue wherever it sits, and a note belongs to one product — so one
thread merging what several teams wrote would be the deployment-wide record a
per-product note exists to avoid, and a reader could not tell which product any
line of it was about. A product is picked where the issue sits in more than
one.

The description leads, at full width (REQ-60, as amended). The rule putting the
action first still holds against the defect it fixes, which is a form three
screens down; what it must not take with it is the description, which in the
narrow column runs four words to a line.

Evidence full width, then the action full width beneath it, rather than
evidence on one side and the action on the other. Both are still above the
fold, which is what a side-by-side arrangement buys, and what it costs is
measurable: rendered from the demo the narrow column holds severity 7.8, EPSS
0.999, CWE-1288, "yes — exploited", the CVSS vector and eleven references, read
at 380 pixels, while the widest thing on the screen is an empty text area.
Somebody weighs the evidence and then acts, and the page runs in that order.

Triage is one pane and both questions: who is dealing with it, and what was
decided. Two panes with a screen between them is two visits. Where nothing is
left to decide the form is not drawn and the assignee stands alone, because
reassigning a decided finding is ordinary.

The rating sits inside the severity block, under the words it disagrees with,
so it is changed where it is read. A pane of its own further down asks somebody
reading a severity to go and find the control for it.

The references sit above what publishers say, at the head of what is read to
decide. A write-up is what somebody triaging reads first, and a third party's
claim about the finding is read against it rather than before it.

A patch link carries the branches its commit is on, once its repository has
been asked (`DESIGN-findings.md` § Patch branches): three by name in version
order, the rest as a count, all of them on hover. A commit its repository does
not hold says so. A link not yet looked up carries nothing, because "not yet"
is not a fact about the patch.

A publisher's claim carries the version it was made about. A supplier's
advisory names the version that carries the fix, which is not the version
shipped here, so a status shown alone reads as the opposite of what it says.
The claim is shown at every version and offers to fill the form in only at the
version it named.

Below the form they answer the objection that eleven links beside the action
recreate the defect the side-by-side layout fixes. That holds for the whole
block of them and not for the advisory somebody is about to judge from, which
is consulted during the judgment rather than after it.

What is neither evidence nor action — the timeline, the revisions, the
comments, the holder, the assessment — stays below.

Where a fix will land is not on this screen. It is settled by the judgment that
promises the work, and the releases it is for are named there. A pane of its
own offers the same set with no version, no date and no reasoning attached,
which is a plan nothing can chase. What became of it is read from the release
and from the build's list of what it is waiting on.

A decision is made on the finding's own screen, and nowhere else (REQ-57,
reversed). A decision form inside a row answers a run of similar findings
without leaving the list, and carries none of what the finding puts beside a
judgment — the references, the way down, what a VEX document said, the history,
the comments. The saving is navigation and the cost is the evidence.

| Rule | |
|---|---|
| It says when it runs out and who has it | The list carries the deadline, the age and the owner, and the screen somebody decides on is the wrong place for none of them |
| It says how many of its places have been decided (REQ-57) | A finding half answered has to look different from one nobody has touched. The count of what the build argued away through its own VEX documents cannot stand in for this: reading it as ours would credit somebody else's reasoning to us |
| It states how the match was made, and says where it came from | The list marks these, and the screen somebody decides on is where they matter more. Both answers are stated rather than only the weaker one, and nothing is said where the scanner said nothing — unknown is not unconfirmed |
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

The three are distinct answers. Drawn alike, "nothing recorded what pulls this
in" stands over records that name the consumer, and the third draws an empty
name read off the end of a chain that is not there.

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

Opened on "not applicable" with "vulnerable code not in execute path" already
selected, every finding is one click from a dismissal carrying a justification
nobody chose — and a justification is a claim about our build that a reader is
entitled to take literally. There is no neutral default to reach for instead:
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
| **The form is rebuilt when what it decides changes** | Changing scope on a build-scoped screen is a parameter change rather than a navigation, so the form stayed mounted and kept the previous build's outcome, justification, version and date in its fields — offered against a different build |

Which locations a decision covers is a summary with an exception, not a list of
checkboxes (REQ-26). The form says "all 62 locations"; "exclude locations" opens
the list grouped by what pulls the component in — the consumer, which is the
axis that decides applicability — with a checkbox per group that reads as mixed
when part of a group is out, and a filter box when there are more than a dozen.
What it reads back is "59 of 62, three left open under X".

The filter narrows what the group checkbox acts on, not only what is drawn.
Given the whole group while one row was shown, unticking a consumer excluded
all forty under it — and this control is what decides what a claim covers. The
count beside the name is read off the same rows, so the number says what the
click will do, and a consumer with nothing matching is not drawn at all.

## The reach sheet

A guided review on submit (REQ-25), not a list of checkboxes. The sheet opens on
a summary: this build, the builds covered automatically, the builds at other
versions, and any not offered.

The builds at other versions are one list rather than one sheet each, ticked
where the reasoning holds at that version too and unticked to start, because a
tick is the claim. Two steps — where it applies, then confirm — with Enter to
advance, Escape to leave and the arrows to move. The last lists what will be
written, and only then is anything sent.

| Rule | |
|---|---|
| **A build is one entry, however many places reach it** | A judgment is about a group of places, and a build the claim already reaches is one thing to be told about. Answered per place, a kernel flaw at sixty places listed the same other build sixty times, once per consumer that pulls the package in — so what the sheet led with was a count of this build's own graph rather than of builds the judgment travels to. A build at *another* version is one entry per version, because each version is a separate judgment |
| The decision here is recorded first, then each build applied, one at a time | With the places narrowed where any were excluded. A refusal on one is reported for that one and does not decide the rest |
| The reach is answered whole rather than sampled | Where a judgment lands beyond this build is a question per place, and asking per place is a request each — so it asked about the first eight. That was a cost control that had become a rule about what a decision covers: what is offered is what gets written, so a build reachable only from the ninth place was never offered and nothing said so |
| The review step is skipped where there is nothing to review | It ran even when the reach it exists to confirm is zero, and at around 150 decisions a day that is some 300 keystrokes spent confirming nothing |
| What counts as nothing is one thing: no build holds this issue at another version | Builds already matching are named on the sheet rather than asked about, so their absence from a skipped sheet costs nothing — the confirmation that follows names them |
| An unread reach is not an empty one | A query still in flight, or one that failed, contributes no other versions, and treating that silence as "there are none" would submit past a question rather than skip one that was not there. The sheet is skipped only when every one of those reads succeeded |

## List navigation

The primary action is above the fold, and the next finding is reachable without
going back (REQ-60). The decision form sat at about 1,550 pixels on a page
running to 2,800.

| Rule | |
|---|---|
| The list travels with the finding, as one value in the address | A filter added to the list needs nothing on the finding and cannot collide with a name it already uses. With the list's own address in hand the finding asks the server the same question, so the row before and after are the ones that were on screen |
| The walk does not stop at a page boundary the reader never chose | The window asked for is the list's page widened by one row at each end, and a neighbor is handed the list at the page *it* sits on. At the largest page there is no room to widen, so the window is the page itself and the walk ends at its edge rather than asking twice. **Unmoved**: widening backward alone put the page's last row outside its own window, and the row found nothing to walk from |
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
places with two issues is seventy-two rows — which is what a parent reads if it
counts findings, where somebody who drilled down one path is looking at one
place and expects two. One recursive statement for the row's whole set of
children: 0.08 s for the root's thirty children on the full-size image.

| Rule | |
|---|---|
| Every row is ordered on the number that describes it | For a branch, what is open beneath it; for a leaf, its own count. What opens still comes before what does not, so the structure of a build is on the first screen |
| A level is drawn whole | An honest inventory has tens of components at a level. The remaining cap is high and exists for the inventory that is not honest — a real image has been seen with 5,270 components directly under its root |
| Arriving from a finding opens the tree on the component, with every parent expanded | The chain travels in the link rather than being walked upward here. Where a level is past its cap, the step on the path is kept whatever its position: a link that opens a tree without the component it was opened for shows the one thing it exists to show |
| A version every component at a level shares is drawn once | Shared by components of different names, it is the producer describing the build — a switch image whose thirty containers carry one build stamp. The level says it above the rows |
| A node says what its number is made of, as one bar whose widths are the counts | Five thousand beneath a node says nothing about whether any of it matters. The same control the component screen draws: a bar mostly one color says where the weight is before a number is read, where a chip per band at a fixed width said only which bands were present. Held in a column of a fixed width, so the bars compare down a page of rows at six different depths; the numbers are on the title, because a legend per row says the same thing every row. Rolled up in the statement that already counts the subtree, so the bands sum back to the total. Banded by **the rating in force in this product**, which is the same word the list the number opens groups by — drawn from the published rating alone, a product that had re-rated an issue read its own decision in the list and the world's in the strip over it |
| The node counts open their lists | A node saying "5,650 beneath · 0 here" and going nowhere is a figure nobody can act on from where they read it |
| The count is every open issue, answered or not | A dismissal does not subtract from it. Written down because "what is open here" and "what is still to answer here" are both reasonable readings and the screen gives the first |
| The marker that opens a row is a button | A span with a click handler leaves every node past the first level unreachable without a pointer, on the screen whose whole purpose is walking down |
| **A row is remembered by what it is, not by its name** | The name, the version and the kind of package together. What is open, what has already been drawn, and what sits under each node are all held against that — and so is the request for a node's children, which is refused for a name that means two things. Keyed on the name, a component the build ships twice could not be opened at all |
| A component's name opens the component | The tree is where somebody asks about a component, and its own screen answers it. The node name is a button, because selecting is how the tree is walked, so the link is the row's own control and the names in the two lists beside the tree |
| There is no pane over the tree | What sat in it — what pulls a component in, what it pulls in, its history, what is open against it — is the component's screen. Drawn over the tree it was a second copy of a page that already existed, and the page was the thinner of the two |

Ordering on the cumulative count carries a fault worth naming. Ordered on the
row's own count the tree opens as an alphabetical list of containers saying
nothing about which is worth opening; ordered cumulatively, an edge means
"contains or depends on" and the document does not distinguish them, so forty
kernel-module packages each depending on the one kernel all report its total.
That fault sits deep in the tree, and it is the lesser of the two.

The list a tree number opens is `beneath`: every open finding at the component
or anywhere under it, by the same walk. `under` stays the direct consumer. The
two do not always show the same figure and are not forced to — the tree counts
distinct issues and the list is one row per issue and component. A name the
build does not hold is refused rather than answered with an empty list, since an
empty list is also what a clean subtree looks like.

Searching the tree counts what the tree counts: distinct open issues the reader
may read, per component, ordered by that count and then by name. A component at
several places is one answer with one count.

| Rule | |
|---|---|
| Issues, not finding rows | A library reachable under three parents is one issue. Counted as rows it reads three times its number, and the order follows the count |
| Counted in one pass over the build, grouped by component | Counted per matched component, SQLite reads the build's open findings once for each, and a term matching many names takes most of a minute |

Measured on the demo's switch image, 6,867 components and 297,881 open
findings, before and after counting in one pass:

| Term | SQLite | PostgreSQL | MySQL | MariaDB |
|---|---|---|---|---|
| `li`, 698 matches | 17.1 s → 0.24 s | 1.38 s → 0.09 s | 0.33 s → 0.37 s | 33.5 s → 0.13 s |
| `open` | 12.7 s → 0.24 s | 0.30 s → 0.08 s | 16 ms → 0.35 s | 13 ms → 0.13 s |
| `ssl`, 6 matches | 0.15 s → 0.22 s | 6 ms → 75 ms | 14 ms → 0.36 s | 12 ms → 0.13 s |

A narrow term is slower than it was on three engines, because the pass reads the
whole build however few names match. Every term is under half a second on every
engine, where a broad term was over half a minute on two.

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
| **Lapsed decisions and deferrals that ran out sit underneath** | The row carries the decision and not the build it was made in, so reaffirming happens on the finding, where its locations are. One list, because a deferral that ran out on code that then moved is both — asked as two, the section merged them by hand and the count over it added the two totals |
| **A bulk approval can be taken back from where it was made** | The control appears only just after a batch is agreed to, because that is the moment somebody notices. A permanent control for undoing a batch named at some point in the past is one nobody can use safely |
| **Rulings on vulnerability reports waiting for approval sit underneath, with the rating and date-movement sections** | A ruling rejecting a report or declaring it out of scope waits for a second person, and this is where somebody goes to be one. Its own section, because a ruling is about claims somebody sent rather than about code. Listed across the products the reader may read reports in, and narrowed with the rest where the address names a product |

The queue narrows to one product, which is what a figure on the home screen
counts: the address carries the product it was counted for, and the line under
the heading names it. The exports narrow the same way, so a file taken from a
narrowed screen is the narrowed backlog. Nothing narrower is offered — a claim is
decided in a product and no finer.

The count beside the queue on the rail, and the home screen's figure for what is
pending your approval, add the rulings on vulnerability reports the reader may
agree to — waiting, proposed by somebody else, in a product where they may
approve a ruling — because those sit in the same queue. Rating downgrades and
disclosure-date movements waiting on somebody are not in that count; they are
their own sections of the queue.

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
rather than being restated here: offering a button that would refuse somebody
is worse than offering nothing, and a second copy of the rule is a copy that
disagrees. A copy saying revising and withdrawing are the author's, where the
rule and the code both ask for triage on the product at the finding's
visibility, leaves a triager reading a colleague's stale claim no way to revise
it on this screen and every way to do it from the finding.

The one thing drawn narrower than the rule is holding rows back, which is
offered only on a bulk claim that still has outliers, because it is the
author's side of the choice an approver already has.

A screen asks what it may do rather than working it out from roles. That is
what the capability answer is for, and it is only usable as a gate while it
means what the operation accepts: reported from the approver capability alone
while the operation accepts a triager too, a two-person team where neither
holds the capability — the ordinary shape of a small team — is shown a claim,
its reasoning and its history with no way to answer it.

## Assignments and routing rules

Assignments is two tabs: what is due soon and undecided, and who holds what.
A row nobody holds says "unassigned" in muted text rather than drawing nobody
as a person with an avatar.

Work nobody holds is the findings list under two filters, not a screen of
its own: nobody assigned, and nothing decided. The rail entry keeps its label,
its icon and its place, and its address carries those two filters. The badge
beside it is counted from that same address, through the list's own query, so
the number and the list it opens cannot disagree — the list writes three
narrowings of its own into any address it is given, and a total counted without
them is a different question.

| Why it is not its own screen | |
|---|---|
| The list already does the whole of it | Deadline, age, EPSS, every filter and every order, over thousands of rows. The screen had none of those and no way to narrow |
| The screen and its own heading disagreed | It said "undecided" and asked a question with no decision predicate in it |
| `/unassigned` still resolves | A bookmark and a link in an old digest land on the list rather than being swallowed by the catch-all |

| Rule | |
|---|---|
| Every figure counts pieces of work, and says so | A person's row and the list behind their name are one measurement, so clicking through never turns one number into a different one. The findings those cover are a second, quieter column, and the screen states in words what each counts |
| Taking unowned work is one action | A triager may take what nobody owns without the assigner right, and the API always allowed it; there was no control that asked. On a finding it is the picker's first option, because taking work is the common case and should need no typing; the findings list carries a Take of its own on its batch bar |
| Who holds it is the field's value, never its placeholder | A placeholder is the grey a browser paints when nobody has typed, so work somebody had taken read as an empty box asking for a name |
| A picker nobody can use says so in the box | With no product chosen it reads "Pick a product to assign". A tooltip is a sentence nobody sees, and a disabled field is drawn as disabled everywhere rather than looking live |
| Offering work to somebody is a question about one product | The findings list spans every product somebody can see when none is picked, so the picker fills once a product is chosen and says why it is not otherwise. Taking work yourself needs no product chosen |
| **A team's row opens the team's queue** | A team holds work the way a person does: routed by standing rule, or by an assignment naming one. The drill-down resolved an identity, so a team's name matched nobody and the screen answered "they are not holding anything" over work the row beside it had just counted. Worse than an absent view, because it answered |
| A holder nothing matches holds nothing, rather than being refused | Refusing would answer "does this team exist" for any credential at all, which is how the organization divides its work for the price of one request. The read is narrowed by what the caller may see anyway |

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
| **What is open is counted when it is asked for** | It is counted over the findings and is the whole cost of a catalog read: 0.39s for a list of two products against 1ms for a liveness probe, and 0.39s against 0.24s for a product holding 8,839 findings against one holding 28. The three screens that draw the column ask for it; the pickers that read the same lists for their names do not, and were paying it on every open. **Absent rather than zero where nobody asked** — these screens render a missing number as "0", and a variant holding twenty-five reported as clean is the failure the count was added to fix |
| A product row says what it triages from | An administrator changes it there. Everybody sees it because it explains a number, and "deployment's" is shown rather than the deployment's current word, because following it and stating it are different things |
| A product, a release and a variant are each corrected and retired from the list that declares them | An administrator edits a name, or takes the thing out of use, from the row. The release list of variants is what a release was built as rather than what the product declares, so it carries no control: correcting one thing in two places is how the two come to disagree |
| A product's edit offers both of its names and says which one is fixed by publication | The name scans and documents use, and the name screens show. They move independently and only the first can be refused, so offering them together with one sentence beside them is what makes the difference visible at the moment somebody types |
| A retired product says so on its own page | Nothing lists it, so the page is reached by a link somebody kept. Unmarked it reads as a product in use whose scans have quietly stopped. It is not the out-of-support date shown beside it: that is a date support ended on, and this is not tracked here at all |
| A retired variant is marked on the release that was built as it | It is gone from what the product declares and still named by the releases it was built as, because the findings filed against it are still open. Unmarked, a release names a build nothing will ever scan again and says nothing about why |
| The edit says when a name can no longer be corrected | A published document is held by readers under the name it carried. The drawer says so where somebody is about to type a new one, rather than leaving the refusal to explain it afterwards |
| An inventory can be uploaded from the interface (REQ-05) | From the bar and from the inventories screen. The drawer takes the target — prefilled from the scope, refused by the server if undeclared — one inventory — CycloneDX or SPDX, as the file itself says — and any number of OpenVEX suppression documents, which is what the endpoint takes. It posts the same multipart request a pipeline sends, then opens the inventories screen, where the receipt shows "queued" until the run says what it changed |
| The screen that lists receipts is called Inventories | A scan is what the deployment does to an inventory after it arrives; what a person uploads is inventories |
| It says what each run changed, and what the numbers were measured against | Which scanner, at which version, reading which vulnerability database. Without it, a build with nothing wrong and a build last measured against a months-old database read identically. A run covers a build rather than an upload, so where several uploads are answered by one run the numbers sit on the newest and the rest are blank |
| A run that changed nothing says 0; a row with no numbers to report is blank | Both were drawn as a dash, so an upload superseded before anything read it read as a scan that found the build clean. The wire tells them apart too — a count that drops its zero cannot |
| Each receipt says what its upload did to the build's contents, and opens the names behind it | Removals are marked and drawn first: a build that stopped describing a dependency looks exactly like one that stopped shipping it. An upload that moved nothing says so, and the first upload read for a build says nothing at all, because it is a picture rather than a change to one |

The listing behind that column is one upload's own screen: the names it added,
removed and moved to another version, against the upload before it, with every
version each name stood at on both sides. It is where an alert about a build
that changed sharply leads, which is why it is a screen rather than a panel —
an alert whose investigation path does not exist is an alarm pointing at
nothing.

| Rule | |
|---|---|
| Removals, then arrivals, then names at new versions | The order is the answer to what to look at, so it is the server's rather than whichever column somebody sorted by |
| One kind at a time is a filter, asked of the server | A build that replaced two hundred names is read one kind at a time, and a count taken over the page would be of the page |
| A name that went is not a link | Its component page is about what is open against something this build no longer ships. Everything else opens the component |

## Product and scan-run pages

The product page names every declared build with what is open, overdue,
exploited, undecided and agreed in each, and when each was last scanned.
Without it "how is SONiC doing" is five requests and a spreadsheet, because the
products table is an administration surface — a triage line in a select, an
end-of-support date in an input — which is a different job from reading how
something is going.

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

| Rule | |
|---|---|
| **What it opened is a list, reached from the count** | A run saying it opened four thousand findings and offering no way to read them is the problem the page exists to fix. The findings list narrows to one run by its identifier — "opened after a date" is the wrong question when two runs landed the same day — and the narrowing is a chip that removes itself, so arriving from that link widens back to the whole build |
| **What it closed is not** | Those findings are closed, and the list is of what is open |
| **How long it took is said** | The page carried both moments it is the difference of and drew only the second. "Did the nightly scan take four minutes or four hours" is what somebody asks when a build is late, and a run still going says when it started instead |

Release comparison carries a chart across every build, not only the two being
compared: the comparison answers what changed between two, and the chart answers
whether it is getting better or worse. Bars rather than a line, because these
are separate builds and a line between two releases draws a trend through a gap
where nothing happened.

## Flaw entry

One screen for every flaw reported in what we ship, whether somebody outside
sent it or somebody here found it. It is reached from the rail as "Report a
flaw", from a product's Inbox with that product picked, and from a report being
recorded as a flaw. Not from the findings list: what is being reported is
precisely what is **not** in that list.

| Rule | |
|---|---|
| Where it came from is asked, with no default | It decides the disclosure date and whether anybody is owed an answer (REQ-37). A preselected answer is a choice nobody made. Found here asks for the finder and the credit; sent in from outside asks for the reporter, how to reach them, the credit and the day it arrived |
| Filing and recording are one choice on the same form | Filed, it waits in the Inbox to be recorded as a flaw, matched to one, or ruled out. Recorded now, it asks for the builds, the component and the severity, and its report is written in the same act. Offered to whoever may work reports; somebody who may not is offered recording alone, because filing is working reports |
| Opened from a report, it records that report | Where it came from is read from the report rather than asked again, and recording accepts it |
| A recorded flaw opens on its issue page | Every build it landed in, and the advisory panel, which is where a flaw in our own product is headed |
| A filed report opens on its own page in the Inbox | Where it is judged |

Recording asks for the product and then for **sets** of lines and variants, because the
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
| The severity has no default, and may be left unset | A judgment sitting in the field as though somebody had made it is this screen making it for them. An unrated flaw has no deadline until somebody rates it (REQ-33), and the hint says so |
| The component is searched against what that build actually holds | A name typed from memory is a name the server refuses, and a name the build holds at two versions is a question the refusal asks properly rather than something to guess at |
| The score is composed as a vector and worked out on the server | The metrics are offered in words rather than letters, because somebody rating a flaw is choosing between "over the network" and "physical access". The formula lives in one place, so a second copy in the browser cannot disagree with the number in the database. A vector settles the severity, so it is not asked twice |
| The scheme is picked, and the metrics follow it | Version 4 asks eleven metrics, version 3 asks eight, and the two they share are asked in different words. Changing the scheme keeps the answers the new one also asks for |
| A new assessment is composed under 3.1 | A published advisory has a field for a version 3 score and none for a version 4 one, so a flaw assessed under version 4 publishes without a score. The picker says so where version 4 is chosen, because it is a consequence somebody has to weigh before they answer eleven metrics |
| A score is shown with the scheme it is on | Two schemes are scorable and their numbers are not comparable. Where the number leads, the scheme is beside it; where the band leads and the number is a hint, the scheme is on the number |
| Weaknesses are suggested and never restricted | A picker that refused an identifier it had not heard of would refuse next year's |
| Files that prove it are attached on the same screen | Stored against the report when it is filed, and against the issue when it is recorded, after either exists. A file that will not store does not undo the record — the words are the finding and the file is evidence for them — and what is reported is which file failed |

The description is written and read as markdown. It is our own prose, so it goes
through the same editor and the same submission policy as a justification. What
a scan file said stays escaped and unrendered (REQ-66): the two live in the same
column, so which it is decides, and rendering the column would render the
scanner's text.

A VEX publisher's own words are shown the same way, and for the same reason.
What a distribution or an upstream security team publishes arrives in a document
they wrote, so it is a third party's text reaching the people who hold the most
access here. Rendered as markdown on the finding screen it is not code — raw
markup is refused at submission and the page's own policy blocks scripts — but
it is headings, tables, bold assertions and
the text of arbitrary outbound links, laid out on the screen a triager is
deciding from, plus the ability to name one of this deployment's own
attachments and have it drawn beside their argument. A judgment somebody else
publishes may be evidence and may never be presentation.

## The inbox

One product's reports, reached from the product page and from the two notices
that name a report. `DESIGN-findings.md` § Reports holds what a report is and
§ Dispositions what a ruling does; this is how the screens draw them.

| Rule | |
|---|---|
| The link appears only for somebody who may read reports | Reading undisclosed work in the product, which is what every read of a report asks. A link leading to a refusal is worse than none. The product page's link says how many rulings wait for approval there |
| The rail carries it under the scope, for somebody who may read reports anywhere | It needs a product picked, and declines and says so where none is or where the reader may not read reports in the one picked |
| A reader of reports sees no control that writes | Recording, answering, accepting, attaching, proposing and withdrawing are working reports. Approve is offered where the reader may agree to a ruling, which the answer to what they may do reports as its own field |
| A claim somebody sent is called a vulnerability report wherever a person reads it | The rail has a Reports entry for the named reports, and a bare "report" beside it reads as one of those |
| The claim and a ruling's reason offer no mentions | Nothing reads a mention in either. An autocomplete there names somebody who is never told |
| Two tabs: the reports, and the rulings waiting for approval | The second is where the waiting notice points. Its count is on the tab, because it is somebody else's turn and nothing else on the screen says so |
| A report's status is one word, and a waiting ruling says so in it | "Rejected, waiting" reads differently from "Rejected", which is the whole of what the second person changes |
| Only an open report can be selected | One under a ruling or accepted is refused by the server, and a checkbox that leads to a refusal is a control that always fails |
| The selection and the form for one report are one form | A ruling covers any number of reports and the second person approves the selection as one act, so the two screens cannot come to say different things |
| A selection past the bulk cap holds the button back and says why | The server refuses a ruling past what one act may write, and a button that always fails is worse than none |
| The button names the act | "Propose" where somebody else has to agree, "Submit" where nobody does. The count is on it where more than one report is covered |
| A duplicate asks for the issue, and says a closed one is rejected instead | The server refuses a duplicate of an issue not open here; the hint says what to do before the refusal does |
| Approve is not offered to the ruling's own proposer | The server tells them apart and says so on the ruling. Withdrawing is offered to whoever works reports, and reads "Withdraw" to the proposer, "Send back" to anybody else while it waits, and "Undo" once it is in force — one act under three names, each the word for that moment |
| A report's page holds the claim, the answer to the reporter, the files and the judgment | In that order, which is the order they happen in. While nothing answers the report, the judgment offers recording it as a new flaw first, as a button, then accepting it as an issue a scan reported, then a ruling; the ruling itself once one does. A new flaw is what a real claim usually is |
| A report found here says so, and is never shown as unanswered | Its From column reads "found here". Nobody outside sent it, so nobody is owed an answer and no control offers to record one |
| The Inbox's control for a new report opens the flaw entry form | With the product picked. One form for every report, so a flaw found here and one sent in are filed the same way |
| Files are attached from the report's page and held at once | A report carries no text a reference could be written into |
| Duplicates are listed on the issue: in the reporter card where the flaw was recorded here, and in a card of their own on an issue a scanner found | A scanner-found issue has no reporter card and is the usual thing a claim duplicates. Read under the report rule, so the list is absent for somebody who may not read reports rather than drawn empty |
| Rulings sit beside the record, over its products and period | A ruling is a judgment somebody could be asked to account for, and an auditor asks about a period. Beside the judgments rather than among them: a ruling is about a claim rather than a finding and takes none of their filters. Printed with them, without the controls |

## Disclosure and advisories

A finding says whether it is disclosed, and there is a screen for what is
running out with every movement of an embargo on it, disclosure included.

| Rule | |
|---|---|
| A finding says whether it is disclosed, wherever it is shown (REQ-40) | Somebody holding private reading could not tell which rows they must not talk about, which makes the embargo a property of the database rather than of anybody's behavior. An undisclosed recorded flaw drew as "Unrated · Undecided · 1 location", which is what any other row draws |
| A group is undisclosed when *any* of its places is | One embargoed place among fifty makes the whole of it embargoed for anybody deciding what may be said about it, and the earliest date is the one that matters. Both read as aggregates rather than off whichever row sorted first — counted, because a maximum of the visibility word answers "public" for exactly the mixed group the question is about, and the list then drew no marker on a row holding an undisclosed place |
| The standing notice is unmissable on the finding page (REQ-40) | A notice somebody has to look for is one that has not been given. It sits above everything, on the screen where a person is about to write something down, and it names the places a disclosure actually happens: a ticket, a commit message, a chat. The row's chip is the secondary signal |
| A screen lists what is approaching disclosure (REQ-38) | Soonest first with what is past due at the top, and a date moved from it. That list is itself a disclosure and is narrowed the way `DESIGN-access.md` describes — a product somebody may not read undisclosed work in contributes nothing to it, not even a count |
| Disclosing is offered in the standing notice and on the disclosing screen | The notice is where somebody is thinking about who may know, and the screen is where every other movement of the embargo is made. Offered to whoever may triage undisclosed work in the product. It says it cannot be undone, and after it is asked for it says whether it took effect or waits for a second person |
| The act is chosen before the date, not derived from it | Extending and bringing forward are different events, so the form asks which and labels the reason for that one. Derived from whichever way the typed date pointed, a date typed the wrong way round would be recorded as a decision somebody made |
| **The window it opens on is this deployment's own embargo length** | It opened on thirty days against the ninety-day policy that ships, so a deployment with five embargoes running drew an empty screen — which reads as "nothing is coming". The server answers over its own window where the caller names none, and the picker's first option says that is what it is doing |
| The screen says what a date arriving means | The answer is counter-intuitive: nothing has been published, and the row is waiting for somebody to say what happens. It also says what moving the date will do before it is asked for |
| Agreeing to a movement sits on the review queue | Beside the ratings that wait there for the same reason: both are a second person's turn, and a queue holding one kind and not the other is one somebody has to remember to look past. The card names the act, because an embargo ending later, one ending sooner and an issue made public for good are different things to agree to, and a disclosure says it cannot be undone |
| A waiting rating names its product, on the card and in every sentence about what agreeing does | A rating belongs to one product and two products may rate one issue differently (REQ-29), so a card reading only "CVE-… low" is a word an approver cannot act on. What they are agreeing to is a deadline and a triage line in one named place |
| A notice arrives at a lead time somebody sets (REQ-38), inside the application rather than by mail | A screen alone surfaces nothing to the person who needs it — an approver who touches disclosure a few times a year has no reason to open it — and a movement nobody can agree to in time is an approval in name only |

### The advisory

An advisory has screens of its own: a list of every one this deployment minted,
and one advisory whole. `DESIGN-remediation.md` § The advisory holds what an
advisory is and § Editorial state holds who may agree.

| Rule | |
|---|---|
| The screens are for care rather than throughput | Single or low double digits a year, each one the company speaking. No filters, no selection, no bulk anything, and the review step is a person reading text |
| The panels are compose, review, approve, publish, in that order | They are the four acts in the order they happen. Panel order is decided rather than accumulated |
| What is left before it can go out is said once, at the top | Naming no flaw and nobody agreeing are the two. Naming no flaw comes first: an advisory covering nothing generates no document, so an agreement is not the next thing to go looking for |
| A control is disabled only on a fact the server has answered | Taking an agreement back and recording an issuance are disabled where the advisory reports nobody agreeing, which is the server's own count. Agreeing is offered to whoever reaches the screen: who may agree turns on who wrote the edition standing, which the screen is not told, so hiding it would be hiding on a guess |
| Who agrees is named, with when | Somebody about to publish checks who vouched for the words, and a count does not say |
| Whether it changed since it went out is said above what went out | The server's answer, compared on the settled digest. Drawn as an alert where it changed and a line where it did not, and absent where the server has no answer |
| The refusal a control reaches is the server's sentence | Agreeing as the person who started it, and naming a flaw a scanner reported. Each says what the store said rather than a sentence invented on the screen |
| Starting one names its first flaw | The list's control asks for a product and a flaw, then mints the name and names the flaw on it. An advisory covering nothing generates no document, so one started empty is a name with nothing behind it. A name minted before the naming was refused is kept for the next attempt, so a mistyped identifier spends no second number |
| A flaw is typed as well as picked | One picker serves starting an advisory and naming a further flaw on one. The list offered is every flaw recorded in the chosen product, open or fixed, without what the advisory already names there, and a fixed one says so. A read that failed says so and leaves the typing, because an empty picker reads as "this product has none", which is the one thing a failed read did not say |
| The picker says when it is holding less than what is there | It stops at the endpoint's own maximum, and a truncated list otherwise reads as the whole of what a product holds |
| Retitling and taking a flaw off are on the compose panel | They are the other two acts that open an edition, so each takes back every agreement standing, which is said beside the control. `DESIGN-remediation.md` § Editions and agreement holds the rule |
| The document is asked for only where a flaw is named | One covering nothing is refused, and a refusal on every visit draws a failure on a screen where nothing failed |
| Shown as text and never rendered (REQ-66) | What a reader has to check is exactly what a customer's tooling will receive |
| What has already gone out is readable without generating anything | Every issuance is in the document's own revision history, which is right for a reader of the document — but it made "has an advisory gone out, and is what is published still what we would generate" a question you had to build a CSAF document to answer |
| Recording that it went out is its own act | What was published on a date cannot be worked out again once a release is added or a decision is revised, and without the record a second document cannot be a revision — which a customer's validator checks |
| The three editorial statuses are shown under the standard's own names | Draft, final and interim, each with what reaching it means on hover. Interim is not "it has changed since it went out": a withdrawn agreement reaches it with nothing a reader acts on having moved |

#### The VEX document

One build's VEX document has a screen of its own, reached from the release's
customer documents. `DESIGN-remediation.md` § The VEX document holds what it
says and § Issuance records what recording keeps.

| Rule | |
|---|---|
| What has gone out is listed with who published it, and each revision is a download | The kept bytes are what a customer holds |
| Recording offers the document it recorded | It is the one to send, because it carries the version it is recorded under |
| The control is offered to whoever reaches the screen | Recording asks for a triage role on the product. The refusal is the server's sentence rather than a control hidden on a guess about roles |
| Whether it changed since it went out is said the way the advisory says it | One component draws both, so the two documents cannot come to say it differently |

#### The panel on a flaw

The narrow case that begins with one flaw: start an advisory, name this flaw in
this product on it, read what it generates, and open it.

| Rule | |
|---|---|
| Open on a flaw recorded here, folded on anything else | An advisory is about a flaw in our own product, which is where somebody arriving from recording one goes next. Most issues the screen shows are a scanner's report about somebody else's component, which the naming refuses, and asking about those on every visit is a refusal per page load |
| What already covers this flaw is said before another is started | The question before starting a second is whether one already says it, and each is a link to the advisory that says it |
| Where each advisory covering this flaw stands is shown beside its name | Whether one is agreed to and whether it has gone out is what somebody asks before starting a second |
| A flaw in somebody else's component is refused when it is named | The refusal names the issue somebody chose, and is shown rather than swallowed |
| The panel hands over once there is a draft | Everything after it is the advisory's own, starting with the agreement. Whoever reaches this panel started the advisory a moment ago and is the person agreeing refuses, so a control here for agreeing, or for recording an issuance that needs one, could only ever reach a refusal |

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
| Restoring is deliberately narrow | Only into an empty field, and only once per draft. Once per *editor* meant the second draft an open editor was asked for was never restored, because the key changes under it when what it is about changes |
| **What is on screen is stored under the key it was typed under** | The key and the text move in separate renders, so the first write after the key moves carries the previous text — which put one thing's reasoning into another's draft |
| Storage a browser refuses is not a failure | The draft is a convenience; the text in front of somebody is the real thing, so every read and write of it tolerates being turned down |
| Signing out clears every draft the browser holds | Every writer's, not only the one signing out: a draft left by an earlier session is the one nobody would think to clear, and drafts hold triage text with private findings among it. Cleared *before* the request that ends the session: a sign-out that could not reach the server is the case where clearing matters most |
| A draft is kept under the identity that wrote it, **encoded** | Which covers the sign-out that never happened: a session can expire quietly, and the next person to sign in on that browser must not be handed somebody else's reasoning. Text typed before anybody is recognized is not kept at all. The identity is encoded into the key, because nothing refuses a colon in one and the separator is a colon — so `alice` read `alice:b`'s drafts as her own and the sweep left them in the browser |
| **A draft key names everything the text is about** | The build and the version included. A build ships one name at more than one version often enough that leaving the version out shares a draft between two of them, and they are different code at a different number of places |
| **Signing out also clears what the tab remembers** | The scope somebody picked and the last judgment they recorded. Sign-out is a same-tab navigation, so the session store survives it by construction: the next person was handed the previous person's product in the scope bar — a name they may hold no grant on — and their last outcome in the decision form. The look and the rail stay, because a preference surviving a sign-out is what a preference is |
| Where a draft lives, and under whose name, is decided in one place | A control spelled at each of six call sites is a control that is missing at the seventh |
| **A draft keeps the answer as well as the prose** | The outcome, the justification, the date, the fixed version. A draft that kept three paragraphs and lost what they argued for came back as text somebody had to read to find out what they had meant — and the prose is about the answer |
| It is restored into the form it was typed in, and is not a default | The rule that the decision form opens on nothing chosen is about what somebody has *not* answered. This is their own answer to this exact finding, keyed on every part of it, and an explicit "start from this" beats it |

### Restored position

A browser restores the scroll position on a real navigation and this
application never makes one.

| Rule | |
|---|---|
| **A list opened by pressing back opens where it was read** | Going into a finding and coming back otherwise rebuilds the list at the top: eighteen rows above where somebody was, on the screen whose whole use is working down a list one row at a time. The address and the filters survive because they are in the address; the place in the list is the one thing that cannot be re-derived from it |
| A list opened fresh opens at the top | Which is what a fresh list is. The two are told apart by how the arrival happened, and restoring on both would drop somebody into the middle of a list they have not read |
| Restored after the rows are drawn | Scrolling a page that is a few hundred pixels tall clamps to the bottom, so the restore lands somewhere arbitrary and reads as a fault in the list |
| Written as somebody scrolls, not as they leave | A route change unmounts the screen, and an unmount is too late to read a position the browser has already moved |
| A handful of pages, and anything that is not a position is the top | The store is the browser's and a person may edit it, and the value goes straight into a scroll call. An unbounded map in storage grows for as long as the tab is open |
| Cleared with everything else the session holds | The next person on this browser does not land in the middle of somebody else's page |

### Answer placement

A confirmation belongs where the button that produced it was pressed. The
decision form's submit sits at the foot of a long form and the confirmation is
drawn at the head of the screen, so somebody pressing it was left looking at
the form they had just sent, with the answer a page and a half above them and
nothing saying anything had happened. The page is brought to it, smoothly, so
that the movement is something they watch rather than a jump they have to
re-find themselves after.

## Reachable from a keyboard

A control somebody can see and cannot reach is a control that is not there.

| Rule | |
|---|---|
| **The findings list is worked from the keyboard** | `j` and `k` move a cursor through the rows, `Enter` opens one where it sits, `Escape` closes it and `o` opens the finding. It is the screen a triager spends the day on and it answered one key, which was the search box's. Every key means nothing while what has focus takes typing — `j` inside a justification is the letter — and a modified key is the browser's |
| **The cursor is drawn, and goes when the question changes** | A cursor nobody can see is a key that appears to do nothing, and a cursor pointing at row nine of a list that has been re-read points at a different finding |
| The focus ring is added to, never replaced | An accent border and a wash around it are an addition to the global ring. A checkbox and a radio are painted by the browser, so a border declaration reaches nothing on them and a wash at a tenth of full strength is 1.16:1 against the surface — where 3:1 is the floor. Tabbing into the permission grid, where one press writes a grant per product, nothing on screen said which box had focus |
| Where a control has no border of its own, the ring goes on the box around it | The two search boxes draw their own frame and the input inside has none, so the ring taken off the input had nowhere to go |
| Nothing a person operates is hidden with `display: none` | It leaves the tab order. A drop zone's file input is out of sight and still focusable, and the zone draws the focus ring, because a label is not focusable and nothing else reaches the input |
| Text on a severity color reads the token that flips with the look | Every severity token in the dark look is a light tint, so white on one of them is 2.54:1. One rule hardcoded white over the critical token at nine and a half pixels |
| One ratio for one meaning | A disabled chip and a disabled button said the same thing at two strengths, and the weaker composited to about 2.2:1 against white |

## A read that failed

A screen draws what it was told, and "I could not ask" is not one of the things
it can be told. An empty list, a zero and a spinner are answers; a read that
did not happen is none of them, and drawing it as one is a wrong answer with a
right answer's confidence.

| Rule | |
|---|---|
| Every read has an arm for its failure, beside the arm for its data | A 500 drawn as zero, as an empty list or as a spinner that never stops is a screen stating something nobody computed. "Nothing changed between those two releases" was what a failed release-note read said |
| A refusal is an answer; a fault is not | 403 and 404 say this is not yours to see, and the card that shows it stays quiet. Anything else is a question nobody answered, and it is said. The two were one test — "the read failed" — so a card hiding itself for the first hid itself for the second |
| A count from a page is not a count | Where the server reports how many there are, that is the figure. Where it only caps what it returns, the list says the cap was reached. A tile counting its own page said 200 over a list of 462 |
| A set read under a cap is never written back whole | The affected-build editor sends the complete list and the server closes everything absent from it, so a page short of the answer is a write that closes the rest. It refuses to edit rather than editing part |
| A printed sheet stamps the moment it was taken, so it prints only once every figure has arrived | A dated record of numbers nobody computed is worse than no record |
| A failed identity read is not "signed out" | Where one provider is configured the sign-in screen forwards straight to it, so drawing a transient failure as signed out sends somebody through their identity provider over a hiccup |
| What the server said is what is shown, and where it said nothing the status is | HTTP/2 carries no reason phrase, so the fallback was the empty string and a refusal reached the reader as no message at all |

## A render that threw

One boundary around the application and one around the routed screens, keyed on
the address.

| Rule | |
|---|---|
| The inner boundary is inside the frame | A screen that throws leaves the rail, the scope bar and the way to another screen where they are. Without one, React unmounts the whole tree and what is left is a blank page with nothing to press |
| It is keyed on the address | Walking away from a screen that threw clears it, rather than carrying one screen's failure to every other |
| It logs as well as drawing | A boundary that only draws swallows the stack that was going to the console, which takes away what a developer needs and leaves a sentence a reader cannot act on |
| A number from the address is checked where it is read | `Number("lastweek")` is not a wrong figure — it is a date arithmetic that throws on the render path and takes the sheet down. The window a report is asked for is a whole number of days inside the range the sheets offer, or the sheet's own default |
| A cookie is decoded where it can be and passed on where it cannot | The decode runs in the middleware every write goes through, so one malformed cookie set by anything on this host failed every write in the application |

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

## File attachment

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
| It asks at whatever the picker has selected, including nothing | A term goes to the list at that scope, which spans every product a reader can see where no product is picked — the same list at its widest address. Returning without navigating anywhere leaves the box looking live and swallowing what was typed |
| A term that resolves to an issue goes to the issue instead | Decided by asking rather than by the shape of the text: a second copy of the server's name resolution is wrong about every identifier a deployment mints for itself |

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
| Grants in force | The roles in force, and whether a role they hold grants nothing — which reads very differently from holding none |
| Their part in the record | How many claims they argued, how many they agreed to that still stand, and how many agreements they took back. What the rubber-stamp report asks across a program, asked about one person |
| Roles granted and withdrawn | Every change against them, newest first, with who made it. Absent before means nobody had set it; absent after means it was withdrawn, and a blank cannot tell the two apart |
| Notifications sent | Everything sent to them, acknowledged and cleared included |

| Rule | |
|---|---|
| An agreement taken back is counted apart from one that stands | It is not somebody who agrees, and the record's own file already says so |
| The record of what they were told is not narrowed by what they may read now | The area somebody reads themselves is narrowed; this is a different question, asked by somebody who administers the deployment. A line about an undisclosed finding, sent while they held the role that reached it, is what the screen is for |
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
| The variants | The variants it was actually built as, each with what is open in it |
| Open now | Open across every variant, by severity |
| Changes | The release before this one, and the comparison against it |
| Customer documents | The release note, the advisories, and a VEX document per variant |
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
| **A figure opens the list it was counted with** | The findings list writes three narrowings into its own address when the address says nothing, and the figures on the home and product screens are counted with none of them — so every number opened a list with fewer rows in it than the number said. Those links carry the three turned off, and a sheet's figures carry its window and its product for the same reason |
| A report that is a list exports as CSV and JSON; one that is figures prints, and every figure links to the list it counts | There is no stream behind an aggregate, and inventing one would publish a file nothing computed. The list a figure opens is the export, and it is also the traceable form of the number |
| **A figure is the answer's, and the list under it is a page** | The estate figures on the coverage sheet come from the response rather than being recounted from the rows beneath them, and each list says how many there are. Recounted from a page, "being scanned" was a figure about two hundred builds under a heading about the estate |
| **Print waits until every figure has arrived** | A printed sheet stamps the moment it was taken on itself, so one printed mid-read is a dated record of numbers nobody computed |
| **A page past the end of a list says so, and keeps its footer** | The register holds its position when the build under it changes, and a footer drawn only where there are rows left nowhere to press Previous from — so an empty page read as "nothing is known about this build yet" |

| Rule | |
|---|---|
| The settings screen is one section at a time, in tabs, and its values are formatted for whoever reads it (REQ-60) | Deadlines, Our products, Triage, Disclosure, Scanning, Sign-in, Limits and Outbound, then Webhooks and Suppliers for administrators. The tab is in the address. A duration is composed from a count and a unit, and a size from a count and a unit, rather than typed as one. Under REQ-01 that reader is an operator nobody here will ever meet |
| A tab says how many of its settings hold a stored value | A value set on a tab nobody opened is otherwise invisible. Stored rather than differing: a value set back to what ships still counts. A tab with none set says how many it holds |
| The sections are the server's list, and the screen names each one | A section the server adds does not compile in the screen until it has a name, so no setting is served under a tab nobody draws |
| Patch branch lookups show on Outbound, read-only, for administrators | The deployment's configuration turns them on, because they need memory, a volume and excluded hosts only whoever deployed it can provide. Shown here so the screen answers what leaves the deployment; administrators alone, because the progress endpoint behind it refuses anybody else. A failed read says so rather than drawing Off |
| Every setting is one row: its title and a one-line summary beside the control, the rest under Details | One text width for every setting, whatever its control. A summary sitting inside a field the width of its control wrapped into a tall column while the note under it ran the width of the card |
| A setting's title, section, summary and detail are served with it | The same reason its kind is: a title or section kept in the interface is a second list keyed on the name, and a setting added to the server and not to it is drawn under its dotted key. What a section is called and the order of the tabs are the screen's |
| Save appears on a row once its value changes | A button on every row reads as a change waiting on every row |
| A setting whose value is one of a few words is a select, not a text box | A free field invites a value the server then refuses, and for a switch it invites "true", "yes" and "1", none of which are what it takes |
| A setting nobody has set is composed like one that is set | Nothing to read is not a value the composer refuses. The embargo periods arrive with no value at all, and they fell to the plain box kept for a duration this cannot say — which is the one control that cannot ask whether a typed 90 means hours, days or weeks. An empty composer opens on days, because a period nobody has set here is an embargo and an embargo is said in days |
| What a new line inherits is on the inventories screen | That is where somebody is when a line has just had its first scan, which is the moment the question arises. It names the line to carry from, says how many reach this one already and how many cover nothing here, and offers the rest as a list to tick. Only two of the four groups are questions, and the screen says which |
| What was recorded here is a filter | A flaw somebody entered is the only kind a person may close by hand (REQ-19), and the screen that records one is where "is this already filed" gets asked. Offered on the list and linked from the recording screen, with the line off, because the question is what exists rather than what is worth an afternoon |
| **A setting says what it does in words, under its name** | It said so on the label's hover, which is where clarification goes — and what a setting does is not clarification, it is the whole of what the control is. Three of them rewrite what the tool reports without anything being scanned. Not on the control itself: a password manager classifies a field by the words it can reach through it |
| **A setting's control is identified by a generated id, never by its key** | The prose moved off the control and the key stayed on it as `id`, and `signin.claim-window` is a sign-in field to a manager reading attributes however many ignore flags sit beside it. `name` was already pinned to a constant for this; `id` was the half that was missed. Generated rather than sanitized, because sanitizing moves the problem to the next key somebody adds |
| **Webhooks are configured here** | Adding one is administration and this is where a deployment is set to things. Administrators only, and the panel as a whole rather than its controls: the endpoint refuses anybody else, so drawn for an auditor it is a table that can only fail to load. Whether they arrive is the system screen's |
| **Advisory sources are configured here** | Naming a supplier is administration, and the panel is administrator-only for the reason the one above it is: the endpoint refuses anybody else. It takes a product before it takes an address, because a claim is recorded against a product and a supplier feeding two is two rows |
| **A publisher's document is uploaded on the same panel** | An advisory and a statement set, each to the endpoint a script uses. The panel says what each does to what the publisher said before — an advisory adds, a statement set replaces — because that is the difference somebody holding a file needs, and the endpoint refusing the other kind names the one that takes it |
| **A supplier nothing has reached reads differently from one that failed** | "Not yet" and "failed three days ago" are different facts, and a single last-read moment collapses them. What stopped the last attempt is on hover, where the address is not — a publisher unreachable for a week is otherwise invisible |

## The System screen

What this deployment is doing, rather than what it has found.

| Rule | |
|---|---|
| The vulnerability data, the queue, the jobs it gave up on, whether the webhooks are arriving, and what asking upstream could not answer, on one screen | They are one question — is this deployment working — and each of them fails the same way. Data that stopped moving goes on answering as confidently as ever, a queue that has given up looks exactly like a quiet one, a webhook refusing every request for a week looks exactly like one nothing has been sent to, and a component held back looks exactly like one no index has heard of |
| **The vulnerability data comes first** | Every answer on every other screen is measured against it. What follows is the engine, then an optional extra, then what goes out |
| **The data version is shown, never ordered** | What a scanner reports is an opaque string, so the screen says what it is and when it last moved and compares nothing. Having no version at all is drawn as a deployment nobody has pointed at anything yet, which is a different thing from data that has stopped |
| The condition telling somebody the data stopped links here | The fact and a link, and the link has to land where the fact can be checked. It pointed at a screen carrying the job queue and nothing about the data |
| **What upstream could not answer says why of each** | Held back because the name is ours, sent and unheard of, or an identifier nothing can turn into a request. Three different things, and none of them a fault. The held-back rows say what the default is costing; the unheard-of rows are the private modules and vendored forks an operator promotes into the list of names to hold back |
| The names a component was matched against are drawn beside the list | A derived default nobody can see is one an operator turns the whole feature off to escape. Shown whatever the table holds, because it is the part that answers "why is this being held back" and it is not a statement about any product |
| The table is narrowed to the products the reader may read, and the panel says so | A package identifier says what a build is made of. An administrator holding no role on any product reads the names and an empty table, which is the honest answer rather than a hidden one — the same answer their dashboard gives, for the same reason |
| **Configuring a webhook is not here; whether it is arriving is** | Adding one is administration and sits under Settings with the rest of what a deployment is set to. The delivery half stays because it fails silently, which is what this screen is for |
| The delivery panel is named for delivery, not for what is wrong | An empty panel has to read correctly. "Webhooks failing" drawn empty is good news; "webhook delivery" drawn empty means none is configured, which is what it means here |
| What is waiting is said per kind, against the limit | The limit is per kind, so one producer's own backlog hides behind everybody else's empty queues. What an operator does about a full queue needs both numbers |
| Work held by a worker that stopped reporting counts as waiting | It is work waiting for whoever takes it next. Counted as running, a queue in the middle of a reclaim cycle reads as empty |
| A set-aside job is shown in the queue's own words | What it points at may have been deleted since, and a list that fails to render because one row points at nothing is worse than one that says what the row says |
| An operator's screen, not an auditor's | What a worker reported quotes what its job was about, so a failed parse can carry a component name out of an SBOM the reader holds nothing on. That is not one of the deployment's own records, which is what that grant reads |
| A webhook is shown by its name, kind and host, never its address | For two of the services it names the path is the credential, so the server returns the host alone and records a failure with the address replaced by its host. The host is not a link: it is somewhere this deployment posts to rather than somewhere a person goes |
| What a full queue needs is both numbers | An operator adds workers or raises the limit, and neither is decided from the depth alone. Said beside the count rather than drawn as a bar, because at the limit is a state rather than a proportion |
| A resolved issue is counted at the severity it held while it was open | The step it left in no longer has one, and counting it as unrated would make every answered critical disappear from the answered column |
| The signing secret is never shown, so changing one means recording the destination again | It signs our requests rather than authenticating anybody to us. A configuration screen that showed it would put a shared secret on a page |
| Patch branch lookups are shown in the order the pass works: Now, Next, Failed, and Done folded away | A host that stops answering leaves labels missing from findings, and nothing on a finding says so. Now carries the step and a bar of commits looked up against those due, and the panel asks again every ten seconds while a visit is under way. Next is numbered. A failure's first line shows, the whole on hover, with when it is retried. Every repository is reachable, a page at a time; `DESIGN-findings.md` § Patch branches holds what each part means |

## The administration screens

Who may sign in, what they hold, and the credentials that carry it. Called
Access, because all three are one subject and two of the three are not users
or roles: a pipeline key belongs to no person, and a personal token is listed
against the person whose reach it carries. Naming the screen after the first of
the three left the credentials on a screen that did not mention them.

| Rule | |
|---|---|
| **Every field that ages is shown**, not only the ones that identify | A credential review asks how old something is, when it stops working and when it was last used. The table showed the last of those alone, so "never used and two years old" and "never used and made this morning" drew identically |
| A pipeline key says it never expires | It has no expiry, and a blank column reads as one nobody has set. A credential that never runs out is the one nobody revokes |
| **Who has left is on the list** | The date was on each person's own screen, so "who still has access" was a question somebody answered by opening every row |
| The list narrows to who holds what | "Who approves on this product" is what an access review asks. A grant out of force does not match, because what somebody holds is a statement about now |
| A person's name and their address are recorded here | Both are on the record and neither could be typed: the whole mail path could never reach anybody created through the interface, and what the person was told when they went looking was that an administrator has to record one |
| An address stated empty clears it; an address left out is left alone | Coming off mail is not coming off the tool, and a screen that cannot tell the two apart makes one of them unreachable |
| A control an auditor may not use is disabled and says why | Hidden, it teaches nobody that it exists; live, it is a button that can only reach a refusal. Only a signed-in administrator mints or withdraws a credential — a credential cannot create another |
| The credentials panel is drawn for an administrator only | Both of its reads are administrator-only, and its one empty state says nothing is issued — so an auditor, whom the rail admits here, was told a deployment holding keys had none. The same shape the webhooks panel is gated for |
| The branch and the variant on a key are offered from what the product holds | A key names a build that exists: both are resolved through the catalog and refused unless declared. Offered rather than restricting, because the server is what refuses and a name declared between the two requests is not one this should decline. Choosing a product clears them, since a branch belongs to one |
| The two things held over the deployment are checkboxes beside the grid, not roles in it | A role is held against a product and neither of these is. What each grants is written beside it, because one of them is a reader who changes nothing and that is not what "administrator" reads as |

## The ordering signals

The findings list is ordered by urgency: known-exploited, then whether the build
reaches customers, then severity, then likelihood. Every one of those is on the
row. An order that sorts on something it does not show reads as no order at all:
the first version showed only the severity word, and the top of a real list came
out "high, high, medium, medium, medium, high, high, critical" — correct, and
indistinguishable from unsorted. The first five were known-exploited and nothing
said so.

| Rule | |
|---|---|
| **The kind of flaw, all of it and named** | One identifier shown and the rest dropped, as a bare number, leaves a reader with "CWE-401" — and the four commonest in a kernel backlog are a memory leak, a race, improper locking and a double free, none of them named. The common ones are named inline and every one links to where it is written up, built from the identifier rather than stored. The two words a feed uses to say it has no classification are stated rather than drawn as one |
| **The band a row is drawn in and the word it says are two answers** | They differ for exactly the two words a scanner reports below low. Both rank inside the low band everywhere that sorts and filters, so that is the color; what the row says is what was rated. Folded together, "rated negligible" read as "Unrated" — which tells a reader nobody has looked at a finding somebody looked at and dismissed |
| Known-exploited is its own badge, not a replacement for the severity word | Replacing it answers one question by destroying another: an exploited medium is still a medium, and the reader needs both facts to see why it sits above an unexploited high |
| The score sits beside the word | They come from different places and can tie while the words differ — a 2003 issue scored 10.0 reads "high" under CVSS v2 and "critical" under v3. Two rows tied at 10.0 with different words look mis-sorted until the number is there. Genuine disagreement between word and number is rare, measured at 3 of 2,645; the vocabulary difference is not |
| The word is what compares down a column | Two schemes weigh reachability and impact differently, so a column of numbers from both is not a ranking. `DESIGN-findings.md` § One ladder for every scheme holds the whole of it |
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
than calling the row a finding. The rail has room for a number and not for a
noun, so a badge carries its unit on the title and on what a screen reader is
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

## Screen copy

Screen copy is labels and values. The reasoning behind a screen belongs in this
document, not on it.

| Rule | |
|---|---|
| **Cut before rewriting** | Most of what a screen explains, it already shows. A clickable row looks clickable, a column header names its column, a version on a row says the row is not a repeat |
| **Nouns and intents** | What survives says what a thing is, or what a control does, in a couple of words. A reader working a list does not read sentences |
| **Clarification where it is needed, not everywhere** | A note on every panel is noise that hides the one note that matters |
| **Help on hover** | A tooltip carries what a reader may want and nobody needs standing on the screen. It sits on the thing it is about and appears only when it applies: a rule about exploited findings does not belong on a finding that is not exploited |
| **Plain spoken English** | The way one engineer tells another. Not literary, not mannered, no sentence that has to be read twice |
| **Professional, for technical users** | The reader knows what a CVE, a VEX document and a version range are. Nothing is reassured, justified or explained down to them |

Screen copy is the one register here that is written to be skimmed rather than
read, which is why it does not follow the house style the documents use. The
same fact is written one way in this document and another on a screen.

| On the screen | In this document |
|---|---|
| Nothing uploaded, under "What publishers say" | An empty panel reads as "nobody has an opinion about this", and what it means is that no document saying so has been uploaded here |
| Planned fixes. Cleared by the next scan | A release clears when the next scan of it stops finding the issue, so nothing is marked done by hand |
| Applies to every build with this component | The same code built several ways is one piece of work |

Measured before the sweep that applied this: 262 standing strings, about
6,700 words, across 65 of the interface's files — 69 of them on the screens
somebody opens every day. The copy had drifted into explaining the design to
the reader, which is what a design document is for.

### The copy gate

`npm run copy`, part of `make web-check`, bounds how much a screen says at once.

| It checks | |
|---|---|
| Every paragraph, every element styled as a hint, and every `hint` or `detail` given as text | The shapes the explanation drifted into, whatever element carries them |
| At most 20 words each | A label, a value and one short line fit. A second sentence of reasoning does not |
| What a paragraph can show at once | Every text node and string it renders. The longer side of a condition is counted, so a sentence inside a branch is prose like any other. A list it maps over is data and is not counted |
| Nothing examined fails the run | A check that found no paragraph looked at nothing |

| It cannot check | |
|---|---|
| Whether a short line is plain | Twenty mannered words pass |
| Whether a line is needed at all | Cut before rewriting is judgment |
| Text a helper builds | A string assembled in a function and passed in is counted as nothing |
| Tooltips | A `title` is where clarification belongs, so it is left alone |

A paragraph that has to stay longer is named in the gate's allowlist with its
reason.

Contractions are allowed here. The rule against them covers the durable
documents, which are read years later by somebody deciding whether a decision
still holds. Screen
copy is not one of those and is written as spoken. In practice it rarely needs
one: plain and short gets there without.

## Interface-wide rules

A screen works on a phone, and that is a requirement rather than an enhancement
(REQ-55). It rules out any packaged data grid that owns its own markup: the
findings table has to become something else on a narrow screen rather than
scroll sideways. That is why the tables here are written rather than installed.

| Rule | |
|---|---|
| A small screen is shaped around review and respond, not bulk work | Read a finding, agree to one or send it back, see what is assigned to you. Nobody triages three hundred findings on a phone, so the wide-only screens stay wide and say so rather than being folded into something unusable |
| Every table that is wider than its box says so, at every width | A table scrolling sideways inside its own frame with nothing saying so reads as a page cut off rather than as a table with more in it. Said above the table and pinned so it stays visible while the table moves, and the clipped edge is shaded so the overflow shows before the note is read. **Only the ones that are wider**: a stylesheet cannot ask, so the table measures itself and says which it is — a note about scrolling over a two-column table that fits teaches people to stop reading the notes |
| A table that scrolls takes a tab stop | The arrow keys move a box only once it has focus, and a box only a pointer can scroll is a table a keyboard cannot read to the end of. The stop is there only while there is somewhere to scroll to |
| Headings and field labels are noun phrases (REQ-60) | The name of the thing, the way a settings screen anywhere else names one. Written as descriptions — "When somebody counts as absent" — they make somebody scanning for the one they came to change read thirty sentences instead of thirty names. The explanation stays underneath. Three had no name at all, falling through to the last segment of a configuration key: a card headed "After" |
| Labels use the conventional word (REQ-60) | Reject, Trend, Assignments, Unassigned, Justification, Path, EPSS, Locations, Access, Lapsed decisions, Submit. A caption on a screen is a sentence at most |
| A form field is not a credential | Every text and number box says so in the four attributes the password managers actually read. They guess from shape and proximity, so a short box beside another short box is offered a saved login. `autocomplete` alone does not do it: browsers ignore it for saved logins by design. Nothing here is exempt, because nothing here is a credential — this deployment never holds a password |
| A control carries no prose, and names itself | Saying a field is not a credential is not enough where the field's own words read as one. A manager reads whatever text it can reach through a control, and three settings were offered a saved login with all four attributes set: their explanation sat on the control as a tooltip, and it said sign-in, account and date. So the explanation sits on the label, where a person hovering still finds it, and each control is named for what it holds rather than left for a manager to name from its surroundings |
| Two rows are only ambiguous when both ends match (REQ-57) | The same subproject reaching the same component twice by different routes. Rare, and visible when it happens: expanding the row, or the tree, resolves it. Nothing is invented to disambiguate a case the reader can see |
| Panel order and what is left out are decided rather than accumulated | The risk in a page that gathers everything is that it succeeds at nothing |
| **What sits over the page is positioned against the viewport** | The nearest positioned ancestor is the frame, which grows with the content — so on a tall page the drawer's height became the whole document: Close at the top of it, submit at the bottom, and neither on screen. A floating action that is not fixed does not float |
| **Stacking is a named scale, not hand-picked numbers** | They were spread across the stylesheets with nothing to read to decide the next one, and two unrelated overlays claimed the same step: the drawer and the rail's scrim resolve in one context, so the drawer won on document order and the rail's click-to-dismiss stopped working wherever they overlapped |
| **A closed vocabulary the server owns is rendered from the generated client** | They were hand-kept tables here, and every one had a member it could not label: an outcome drew an empty cell wherever it was the whole of it, register states printed as wire tokens, and a narrowing over the claim kinds could not fail because its comparisons exhausted every value but one |
| **A word the table does not know is shown as it arrived** | A server that grows a vocabulary before the interface does should leave somebody reading something unfamiliar rather than a blank |
| **A choice with a consequence is a card per option** | Where it came from, filing or recording, a recorded flaw's disclosure, and a ruling's disposition each decide something that follows. The card carries what picking it does, so it is read before the choice. An option somebody may not pick is left out and said in a line below, not drawn as a card that refuses. A radio group to the keyboard: one tab stop, arrows move and pick |
| **A switch between values is a segmented control** | Each option is drawn as a button, the picked one filled, and the frame is dashed while nothing is picked. It keeps its own width inside a panel, which otherwise stretches it to the panel's edge |
| **A file is picked in a drop zone** | Click or drop, a button-look at its end, and what was picked listed under it as chips that come off again. The browser's own file input changes with the browser and takes no drop |

## The initial load

Screens are split by route. The findings list has to stay usable against a
full-size product and has no business downloading a charting library, and the
markdown renderer is only needed where somebody reads or writes a justification.

Measured: one bundle of 820 KB became a 248 KB initial load, with the chart (369
KB) and the renderer (146 KB) fetched only by the screens that use them.

## Local development

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
| A gray canvas with white cards raised on a shadow | One white plane with hairlines. § The work surface holds the whole of it |
| Uppercase, letter-spaced labels over every block | Sentence case, at the small step, in the muted tone |
| The accent on the primary button, on a pressed chip and on a selected tab | Ink on all three. The accent is kept for what opens something |
| A tinted pill for the severity word | A dot and the word, colored by the band |

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
drifted endpoint is a compile error rather than a blank panel. That is real
coverage and it is most of what the frontend needs.

What it is not is a test of what a screen *says*. Five pieces are pulled out and
tested on their own — what a notification is called, the count on the control
that opens it, where an unsent draft is kept, where a sign-in comes back to, and
how a session that ended is noticed — because each is a defect rather than a
matter of taste if it is wrong. Everything else is checked by a person looking
at it.

The draft rules are tested and so is the sign-out that calls them: the sequence
sits in a function of its own rather than in the click handler, because what
makes it correct is which parts run before the request and outside the part that
can fail. The panel that offers a way back in is still checked by reading — no
component is rendered in any test here, so what is drawn over what, and what a
click does to it, is a person looking at it.

Where a screen computes something rather than draws it, that computation comes
out into a function beside the screen, which is what makes it testable at all.
Coverage of the interface is measured and reported by the gate.

## Not built

| | |
|---|---|
| **A claim scoped to a consumer subtree** | Proposed in the workflow review and rejected on the owner's judgment: the rules would have held, and one sentence answering a thousand findings is the shape that makes a dismissal unreadable afterwards |
| **Narrowing the review queue further than a product** | By what kind of thing is waiting, by who proposed it, by age or by severity. Narrowing by product is built, because a figure that counts one product has to open a list about that product |
| **A spacing scale** | Six values are named at exactly the numbers already in use, so naming them moved nothing — but there were nine hundred values written by hand running 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16, 18, which is continuous rather than a scale. Inventing one is a judgment about how the interface looks, made against a running browser rather than as a mechanical substitution |

## Gaps the checks left

| | |
|---|---|
| **A source file that reads as binary is skipped by every text tool, and none says so** | One stray NUL byte in the busiest screen did that: the class-collision script, the design-token check and every hand audit passed over it, and the four chart components it draws were reported as reached by nothing. The absence of an answer rather than a wrong one, which is the shape that survives review. It is a gate now, over every text file the repository holds |
| **A token named and never defined** | CSS drops the declaration, the element keeps whatever it inherited, and the screen looks nearly right. Three were in the stylesheet, each a rename with one reference left behind, and each invisible until two screens were compared side by side. Every reference is put to the set of definitions, and a token set per element in a style object counts as defined |
| **Five rules restated what a wider media query already applied** | A phone layout fixed by appending a corrected copy at the bottom of the stylesheet rather than editing the rule where it lives: anything under 780 is under 900, so they changed nothing and read as though they did |
| **The thirty-first table that scrolls** | The release-readiness table on home, cut off on a phone with nothing explaining why |
| **An operation the API offers that no screen reaches** | The generated client type-checks what a screen sends against what the server takes, so a screen cannot disagree with the shape — but an endpoint or a field nothing calls is not a disagreement, and neither the unreachable-code check nor the decision gate looks at it. Four were found by configuring a deployment from empty: creating a pipeline key, granting administration, narrowing a personal token to a product, and the withdrawn flag on a token row. Walking the API document against the generated client's call sites is what would catch it |
| **A background shorthand one sheet later resets an image another set** | The shade on a clipped table edge is a background image, and a rule giving that box a background color with the shorthand takes the image with it at equal specificity. The screen keeps its color and loses the thing that said the table was cut off |
| **The shade stops at the header row and the hovered row** | Both carry an opaque background — the header for its sticky cells, the hovered row for its fill — so the box's own background does not show through them. The note above the table is what says the table scrolls; the shade is a second signal and is absent on two rows of it |
| **What only a browser shows** | Six screens passed the type check, the lint and their tests, and every one was wrong on screen. A chip styled by a block-level class stood a row of pills on end. A holder's name was drawn in placeholder grey. A component's name came out empty, read off a chain that was not there. A form refused to submit and never said what was missing. A comment box offered no mentions. A superseded upload reported a clean scan. None of these is a screen disagreeing with the server, which is the only kind of wrong the checks can see |

## File organization

The finding screen was three thousand lines and the stylesheet four thousand two
hundred: every addition is small and beside something related, and none of them is
the one that made it too long.

| | |
|---|---|
| **The finding screen splits into four, by question** | What the record says about this finding and how it came to say it; what is known about the flaw as against what anybody claimed; who is involved and what hangs off it; and the screen that arranges them |
| **The list screen gives up the parts that take rows and draw them** | Expanded in place, by component, by bump, the pager, and the table itself. What is left holds the filters, the page and the question being asked — the table takes what it draws and holds none of it, which is what stops the path's product being read on the list that spans every product, where there is none |
| **What is selected is a hook, not several pieces of state in a render function** | The rule that a changed question clears the selection was written at some call sites and missing at others, and it held only by a property of another file: every chip either drops its key or puts the wider default back, so removing one only ever widens. Inside the hook there is no call site left that could bypass it |
| **What an address means lives beside the list rather than inside the screen** | Setting one filter, setting several values of one, and hiding a component are pure functions of the parameters. Two screens spelled the build prefix by hand and the finding address twice, and the copies dropped the parameter the finding reads to walk the list it came from |
| **The queue screen splits by which queue** | Five lists lived there. What became of what you proposed is a whole tab with its own endpoint, sharing nothing with the claims but the offset in the address; a disclosure-date movement and a severity rating are two things waiting for a second person that are not claims, and share neither the card nor the selection nor the batch. What is left is the claim queue, which is one thing |
| **The dependency tree gives up the panel** | Walking the graph and asking what is known about one node are two questions, and the second took a third of the page while the first was on screen |
| **The finding screen gives up the one form among its readings** | Rating the issue is a claim about the issue in this product, made from a screen that is otherwise four readings of what the record already says |
| **The notes thread is on the screen whether or not a claim exists** | It is the one somebody can write in before anybody has decided anything, which is what it is for; the claim's own thread stays gated on a claim. It says in words that it is about this issue in this product, because it is read beside a row that may be one of eleven the same issue sits on — not about this component, and not about other products |
| **A thread is one component, and the endpoint is what a caller keeps** | The comments on a claim and the notes on an issue are the same conversation: the avatar, the timestamp, the edited mark, the earlier versions behind it, the editor in place and the draft. Written twice they had already begun to diverge, and the timestamp was formatted separately in each copy — so a fix to it would land in whichever file the author had open. What one piece is called and what adding one does not do stay each caller's, so the two are worded apart deliberately rather than together by accident |
| **The stylesheet splits by position, not by theme** | Order is the mechanism — the last rule wins — so grouping rules by what they are about would silently reorder the cascade. The files are the sections in the order they were already in, with one deliberate exception: the tokens, the frame, what every screen is built from, the charts, what sits over the page, the shapes belonging to one screen, what a narrow screen changes, and what prints |
| **What prints moves to the end, and that is a change** | It sat in the middle of the component file, so a per-screen rule of equal specificity written later won over it. Imported last it wins, which is what a print rule is for and what the file's own name now says. Everything else keeps the position it had, checked selector by selector; this one is the exception and is stated rather than folded into "same order" |
| **What sits over the page is one file** | The sheet, the floating action, the drawer and the two scrims. It is where every stacking decision in the interface is, and reading them against one scale is the only way to keep them in order |
| **What prints is imported last** | It wins by being last rather than only by being marked important, so it has a position in the cascade rather than a name that happens to sort |
| **The two rules that are the page's rather than a screen's move to the frame** | A reduced-motion block over everything, and how a key named on a control is drawn. The per-screen file's own first line says what it holds, and neither of those is one screen's |
| **A shape many screens draw belongs to the parts, whatever it was written beside** | Four sections — the charts, the report sheet, the drawer, the covering panel — styled components in `ui/` from the file that says it holds "shapes that belong to one screen". Moving one earlier in the cascade is a behavior change only where a per-screen rule of equal specificity was relying on losing to it, so it is checked selector by selector rather than assumed; for these four the two files shared none |
| **What the parts file costs is the size of the parts file** | It is the shared vocabulary every screen is built from, so it grows with that vocabulary, and the only split available is per-component — which the cascade rule makes hazardous for no gain. Around nineteen hundred lines is the honest price of this split axis, recorded here rather than paid by cutting the file into pieces that have to be kept in order |

## Limits

| | |
|---|---|
| Color and the brand mark resolve through tokens in one place | How an operator overrides them is deliberately unsettled — that gets decided against real screens — but keeping the whole palette in one stylesheet means the answer will be a stylesheet rather than a hunt through components |
| Dependencies are pinned exactly, not by range | A range resolves at build time and CI stops being reproducible; a caret in a manifest does exactly that. `npm ci` installs the lockfile |
| A failure shows what the server said | Inventing a friendlier sentence hides the one the server wrote, which names the line to fix or which part of a declaration is missing — and is the more useful of the two |
