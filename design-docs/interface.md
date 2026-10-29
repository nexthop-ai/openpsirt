# Interface

The web interface: how it is built, served and routed, how it reaches the
server, and the rules every screen follows for failure, dates and copy.

Satisfies REQ-41, REQ-42, REQ-43, REQ-54, REQ-59, REQ-60, REQ-61.

Each screen family has an `interface-` document of its own, listed in `DESIGN.md`.
The markdown rules are in `design-docs/text.md`.

## Contents

- [One artifact](#one-artifact)
- [Path routing](#path-routing)
- [The generated client](#the-generated-client)
- [Capabilities before drawing](#capabilities-before-drawing)
- [Families a reader holds](#families-a-reader-holds)
- [A read that failed](#a-read-that-failed)
- [A render that threw](#a-render-that-threw)
- [An expired session](#an-expired-session)
- [Units, dates and copy](#units-dates-and-copy)
- [Screen copy](#screen-copy)
- [The initial load](#the-initial-load)
- [Local development](#local-development)
- [Test coverage](#test-coverage)
- [Gaps the checks left](#gaps-the-checks-left)
- [Not built](#not-built)
- [Limits](#limits)

## One artifact

The built interface is embedded in the binary and served from it, so a
deployment is one container and the interface is never a version behind its API.

| Rule | Reason |
|---|---|
| Nothing is fetched at run time: no font, script or stylesheet | An air-gapped install is an ordinary install |
| The embedded directory always exists, tracked empty, and the frontend build fills it; its placeholder is un-ignored at the top level with its directory | The embed fails to compile on a missing directory; `dist/` is ignored everywhere and git does not descend into an excluded directory |
| A binary built without the interface serves the API alone | A checkout with no node toolchain still builds and runs; a supported build |

## Path routing

| Path | Answered by |
|---|---|
| A route the server has | The server, credential required as always |
| A file in the built output | Itself, cached by its content-hashed name |
| Anything else | The page, which does its own routing |

| Rule | Reason |
|---|---|
| Anything beginning `/v1` is the server's, routed or not | A page handed to a JSON client reports a mistyped endpoint as a parse failure |
| The page answers where the router has no route, asked of the router | The framework registers routes of its own (the API document, its schemas), and a prefix rule hands those out |
| Names the server owns are reserved even where nothing is routed; a test asserts mounting the interface opens nothing | The framework's documentation route is disabled, and unrouted is what marks a path as the page's, so `/docs` would be claimed |
| The page loads without a credential | The sign-in screen is the page; it carries no data |
| An address the page does not know says so and keeps the address | A redirect home discards the evidence a wrongly built link leaves |

### The route table

One table names every address the page answers: the pattern for each screen and
the query parameters a link may set. The router is built from it, every address
the interface builds comes from it, and the server's notification links are
tested against it (`design-docs/notifications.md` § Links).

| Rule | Reason |
|---|---|
| Every route in the table is mounted | An entry with no screen lands on the not-found screen |
| An address built from parts is built in one module, from the table, which alone escapes a part as a path segment; a query added to an address built elsewhere is built there too | A name holding a slash or a question mark otherwise becomes a second segment or a query |
| A builder names the parameters it sets: a product, a build, a version, never a query string | The findings list, the audit log, the dependency tree and the two comparisons take a query, because they write their filters into their own address |
| A component link carries the build it was reached from, and the version where the row has one; a by-upgrade row names binaries under one source version and carries none | The component screen opens on the graph somebody was reading; a name at two versions is two components |
| A build's screen moved to another build keeps the address's own segments, cutting the tail from the address as it stands | The router hands the tail back with escaped slashes restored |
| An address written out whole is matched against the table, path and query | An unknown address lands on not-found; an unread parameter opens the screen on its default |
| Every listed parameter is read by its route's screen, found by reading the router and searching every module the screen reaches | A promised parameter nothing reads is a dead link |
| A screen whose address changed keeps its former address, forwarding with query and fragment; an address another screen now holds forwards nowhere | An unread notice keeps the link it was sent with |
| An API address, under `/v1` or joined onto the API's build prefix, is not an address into the page | The API document describes it |

The check reads source string literals. It has one input it must report and one
it must not per shape, and fails where it read no file, route or screen. An
address assembled from values it cannot see, such as the current address's tail,
is not examined, so the scope picker's same-screen move and a finding renaming
its address for a moved issue both go through the route module.

## The generated client

The API client is generated from the committed OpenAPI document (REQ-61): no path
or response shape is hand-written, and a changed endpoint is a compile error.
`make web-api` regenerates it and fails where the result differs from what is
committed. The interface uses no private endpoint.

| Rule | Reason |
|---|---|
| A table of words over a server word is keyed on the generated union | A word the server adds is a compile error until it has words |
| A lint refuses a literal table in the screens keyed on any string, whole or partial; a table typed by an index signature is not caught. A table over an open set (a package kind, a keyboard key, this interface's own names) says why beside it | |
| A read is declared once and asked through its hook | Two declarations miss each other's invalidations |
| The catalog's products, branches and variants, one release's variants, where an issue sits, a decision's approvals and revisions, what sits around a component, and the outbound destinations each have one definition, keyed so a change reaches every screen showing them | |
| A download or document link is built by one link builder over the generated paths: the path is a key of the document, each placeholder required, named as the path names it and escaped as a segment; a placeholder with no value is refused | The browser fetches these, not the client |

The session is a cookie the application never sees. The application holds the
cross-site request token, readable by script where the session cookie is not;
every unsafe request carries it, attached once as middleware, never per call.

## Capabilities before drawing

`GET /v1/session/me` answers who is asking and what they may do in each product
they reach.

| Rule | Reason |
|---|---|
| Capabilities, never roles | A second copy of the role mapping drifts into offering refused buttons |
| A product somebody cannot reach is absent, and a screen treats it as not there (REQ-42) | The server's answer |
| `GET /v1/sign-in` is answered without a credential, listing the providers an operator configured (REQ-41); a test asserts it says nothing about whether any account exists | It is what somebody sees before they have a credential |
| A 401 from `session/me` is an answer: nobody is signed in | A fresh browser |
| Markdown is rendered and sanitized in the browser; the server returns markdown only | Preview and published text are one renderer, with no round trip per keystroke |

## Families a reader holds

A reader holds each family of finding apart: dependency findings (a scan's
matches and the flaws recorded beside them, disclosed or not) and code findings
(security testing work). A count of a family is drawn only where the reader
reads it, because the server narrows every count to the reader (REQ-43) and a
zero for work they cannot see reads as nothing open.

| Reader, at the screen's scope | Screen shows |
|---|---|
| Holds the family in no product | No entry, section, tile or count for it |
| Holds it in another product, not this one | One line, "You don't read code findings in sonic.", and no count |
| Holds it here, nothing open | A real zero, naming what it counts (REQ-60) |
| Reads only disclosed work here | The counts, with "Counting disclosed findings, the ones you read here." |
| Reads only undisclosed work here | The counts, with "Counting undisclosed findings, the ones you read here." |
| Reads one half alone in some products, across products | The counts, with each half's products named |
| Reads no finding of either family in any product | The deployment's records: the change history, access and settings where the audit permission or administration allows, beside the work they hold |

| Rule | Reason |
|---|---|
| The holding is worked out in the browser from the session's answer (§ Capabilities before drawing): reading disclosed or undisclosed work is the dependency family, reading security testing work the code family | The answer already says what each product lets the reader read; nothing new is asked of the server |
| Either half of the dependency family may be read without the other, and each read alone is said | Reading is granted per visibility (`design-docs/access.md` § Roles) |
| One helper decides it, and every screen counting a family or listing undisclosed work alone asks it, never the session's read flags directly | Decided per screen, the answers drift apart |
| A table spanning products draws a dash, with the line on hover, in a row whose product the reader does not read the family in | A zero in one row reads as that product being clean |
| A screen whose subject is the family (the findings list, release comparison, a report on it) shows "Nothing to list." and the line in place of its body, the line included for a reader holding it in no product | Reached by a kept link, its empty body reads as nothing open |
| A report on decisions (the overview's triage times and dismissals, approval quality, effort) is asked and drawn where the reader reads either family at the report's product; elsewhere it shows "Nothing to list." and "You don't read findings in sonic.", or "in any product" for a reader of neither anywhere | Decisions are on either family and narrowed to the reader; an empty exception report reads as a clean one |
| The line names a product only where the session lists it; a product it does not list, a retired one most often, keeps its figures | A product somebody holds no role on is never named to them (REQ-42), and the server has narrowed a retired product's counts already (REQ-43) |
| Security testing work is never disclosed, so the code family has no halves | |
| A count not drawn is not asked for | A request whose answer is never shown is load for nothing |
| Until the session answers, figures are drawn as for a reader holding the family here | The server has narrowed them already; hiding them first and drawing them after moves the page under the reader |
| A case collaborator's single issue is not a product holding | Their reach is one issue, named on the issue itself |
| A count of the reader's own work, or of decisions they may make or approve, is drawn whatever they read: assigned to them, sent back, their proposals, what they reaffirm, and the review queue's lists | It counts what they hold or may act on, which no family narrows away |
| A record or a scan's metadata stays where its findings are not counted: an upload's receipt, a run's scanner and timing, the response windows | It is not a count of findings |

## A read that failed

A read that did not happen is not an empty list, a zero or a spinner; drawn as
one it is a wrong answer.

| Rule | Reason |
|---|---|
| Every read has an arm for its failure beside the arm for its data | A 500 drawn as zero states something nobody computed |
| A fault, a request that never arrived, a timeout and a rate limit are retried twice; every other refusal is drawn at once | Retrying a 403 or 404 holds the not-yours card back about three seconds |
| A page is asked on a timer only while something on it moves: Uploads' receipts every 15 s while an upload is being read or scanned | A settled answer costs the server the same each time, per open screen |
| A refusal is an answer; a fault is not. 403 and 404 draw a quiet not-yours card; anything else is said | |
| A count from a page is not a count: the server's total is the figure; where it only caps, the list says the cap was reached | |
| A set read under a cap is never written back whole; the affected-build editor refuses to edit rather than editing part | The server closes everything absent from the list sent |
| A printed sheet prints only once every figure has arrived | It stamps the moment it was taken |
| A failed identity read is not "signed out" | With one provider the sign-in screen forwards straight to it |
| What the server said is shown; where it said nothing, the status is | HTTP/2 carries no reason phrase |
| One component draws a read's three arms: waiting, the loading line; failed, what the server said; answered, the screen, its empty state included | A screen drawn through it cannot show "none" for an unanswered read |
| A picker whose options failed says so beside it, and the options it has stay usable | An empty select reads as nothing declared |
| A suggestion list may be quiet about a failure, saying why in the source; the web lint fails a read defaulted to an empty list in a file that never consults its failure, unless such a comment is beside it | A name not suggested can still be typed |

## A render that threw

One boundary around the application and one around the routed screens.

| Rule | Reason |
|---|---|
| The inner boundary is inside the frame | The rail, the scope bar and the way to another screen stay |
| It is keyed on the address | Walking away clears it |
| Try again loads again a screen whose code failed to arrive, and only then | A failed lazy load is otherwise held until reload, and code that cannot arrive is not asked for without end |
| It logs as well as drawing | The stack is what a developer needs |
| A number from the address is checked where it is read: a report's window is a whole number of days inside the range the sheets offer, or the sheet's default | A non-number throws in date arithmetic on the render path |
| A cookie is decoded where it can be and passed on where it cannot | The decode runs in the middleware every write goes through |

## An expired session

A write refused for want of a session offers the way back in over the screen,
which stays behind it and comes back on return.

| Rule | Reason |
|---|---|
| It is noticed once, where the client is built | |
| A refetch of the identity refused for want of a session raises the way back in and keeps who was signed in; a refetch that fails keeps the screen. Only a first read answers "nobody is signed in" or draws a failure in place of the frame | |
| A sign-in carries the address it began at, query and path | A findings list is its filters |
| The page is left for sign-in; a draft is saved first (`design-docs/interface-editor.md` § Drafts) | A provider sign-in is a redirect to another host, which cannot be framed or done silently |
| The server checks the return address (`design-docs/access.md`) | |

## Units, dates and copy

Every count says what it is a count of (REQ-60).

| Word | Means |
|---|---|
| Issue | The vulnerability, one identity across its aliases |
| Occurrence | One way a component enters one build |
| Finding | One issue at one occurrence |
| Group | One issue at one component across its occurrences: the findings list's row |

| Rule | Reason |
|---|---|
| Home's open figure, the trend and the severity ring count issues and say "issues"; the findings list and the rail count groups | The same issue at three versions of one library is three rows |
| "CVE" is not a label | Not every issue has one |
| A row says "N occurrences" and is never called a finding | |
| A rail badge carries its unit on the title and to a screen reader | No room for a noun |

| Date form | Rule |
|---|---|
| Absolute | The UTC day, never localized: the server writes a day from the moment in UTC, and a moment sent with an offset is shown as the UTC day it falls on. Every stored instant on a screen goes through one formatter, a key's or token's last use included |
| To the minute | The UTC day and minute, saying UTC, for a moment correlated with another: a comment, a grant, a scan arriving |
| Typed to the minute | In UTC, labeled so, defaulting to now in UTC; the minute typed is the minute shown |
| Relative | For staleness, one scale in both directions, with the absolute form on the title |

A value that is not a stored moment is drawn as nothing in both forms: the shape
is checked, because a bare number parses as a year, and so is the calendar day,
because a parser rolls a day past month's end into the next.

Waiting is one component everywhere, saying it is waiting and announced politely to a screen reader.

A statement about a trend waits for enough history (REQ-54). Leading empty steps
are dropped and the rest kept, since an empty week inside the history is real.
Four steps of real history come before a direction is claimed. The chart still
draws what there is; only the sentence is held back.

## Screen copy

Screen copy is labels and values. The reasoning behind a screen belongs in its
design document.

| Rule | Detail |
|---|---|
| Cut before rewriting | Most of what a screen explains, it shows |
| Nouns and intents | What a thing is, or what a control does, in a couple of words |
| Clarification only where needed | A note on every panel hides the one that matters |
| Help on hover | A tooltip sits on the thing it is about and appears only where it applies |
| Plain spoken English | As one engineer tells another; no sentence read twice |
| Professional, for technical users | The reader knows a CVE, a VEX document and a version range |
| Contractions are allowed | It is written as spoken; the rule against them covers durable documents |

Screen copy is skimmed, so one fact is written differently on a screen and here.

| On the screen | In a design document |
|---|---|
| Nothing received, under Received VEX | No document saying so has been received here |
| Planned fixes. Cleared by the next scan | A release clears when its next scan stops finding the issue; nothing is marked done by hand |
| Applies to every build with this component | The same code built several ways is one piece of work |

Before the sweep applying this: 262 standing strings, about 6,700 words, across
65 files, 69 on the screens opened daily.

### The copy gate

`npm run copy`, part of `make web-check`, bounds how much a screen says at once.

| It checks | Rule |
|---|---|
| Every paragraph, element styled as a hint, and `hint` or `detail` given as text | At most 20 words each |
| What a paragraph shows at once | Every text node and string it renders; the longer side of a condition counts; a list it maps over is data |
| A link or button whose whole text names nothing | "Read them", "See more", "View", "Open", "Here" fail |
| A heading or field label beginning with what, where, who, how, when, which or why | Headings and labels are noun phrases (REQ-60) |
| Nothing examined | Fails the run |

| It cannot check | |
|---|---|
| Whether a short line is plain | |
| Whether a line is needed | |
| Text a helper builds and passes in | Counted as nothing |
| Tooltips | A `title` is where clarification belongs |
| A computed label or heading | Only text written out in full is read |
| A description naming nothing without a question word | A person's job |

A paragraph that has to stay longer is named in the gate's allowlist with its
reason.

## The initial load

Screens are split by route. One 820 KB bundle became a 248 KB initial load, with
the chart library (369 KB) and the markdown renderer (146 KB) fetched only by
screens using them.

## Local development

    make demo                    # build the image, start it, seed it, say where to go
    make demo DEMO_HOST=yourbox  # if you browse by something but localhost
    make demo DEMO_BIND=0.0.0.0  # to reach it from another machine

| Target | Does |
|---|---|
| `make demo-status` | Whether the scan has landed and how much it found |
| `make demo-down` | Stops it |
| `make demo-reset` | Discards the database and the seeded inventories and documents, keeping the scanner's database, about a gigabyte |
| `make dev` | The binary and the interface's dev server on this machine, reloading; the API listens on a port no demo cast member holds, reported up once it answers |
| `make dev-down` | Stops what `make dev` started, by its recorded process groups, and nothing else |

| Rule | Reason |
|---|---|
| Docker is the one prerequisite | |
| The image is built from the working tree, the interface and binary built inside it | What comes up is the change; the embedded directory is git-ignored |
| Everything it writes is in a git-ignored directory in the tree | Deleting the checkout deletes the state |
| Seeding is idempotent | |
| The demo and the dev loop seed through one definition; a test holds the export columns and queue field they read by name to their spelling | |
| It runs the image behind a small proxy adding the trusted header; no mode in the application trusts anybody | A development identity switch is a hole that ships |
| The demo's doors and the dev server listen on this machine alone by default; the first door is an administrator | Every request through them is signed in |
| It is a demonstration deployment: plain HTTP, administration to whoever the proxy names | |

## Test coverage

| Layer | What pins it |
|---|---|
| Shape | `make check` type-checks every screen against the generated client |
| Computation | What a screen computes sits in a function beside it, tested alone; the sign-out sequence is one |
| Writes and gates | A screen that sends or shapes a write is drawn inside its own router and query client, and the test reads the request |
| Invalidation | Each mutation hook runs through a real query client, and the test reads the keys it invalidates |
| Look | A person |

The gate measures statement coverage per file and fails a file no test reaches.
The entry point and the test harness are outside the measure.

## Gaps the checks left

| Gap | Detail |
|---|---|
| An operation the API offers that no screen reaches | The client checks what a screen sends; an endpoint or field nothing calls is invisible to it, to the unreachable-code check and to the decision gate. Walking the API document against the client's call sites would catch it |
| A background shorthand later in the cascade resets a clipped table's shade | The shade is a background image, and a same-specificity shorthand takes it |
| The shade stops at the header row and the hovered row | Both carry an opaque background; the note above the table still says it scrolls |
| What only a browser shows | The checks see a screen disagreeing with the server, never a wrong layout, a wrong tone or an empty name |

Checked: a token referenced and never defined, every reference put to the
definitions, a token set per element in a style object counting as defined; and
a text file that reads as binary, which every text tool skips silently.

## Not built

| Item | Detail |
|---|---|
| A decision scoped to a consumer subtree | Rejected by the owner: one sentence answering a thousand findings is unreadable afterwards |

## Limits

| Limit | Detail |
|---|---|
| Code findings are counted on no shared screen | The code family's rule reaches the rail and the product page's link alone; home, the component screen, the tree and the product figures count dependency findings |
| No component library | Built from the mockup's tokens and components written here; a packaged data grid owning its markup cannot become cards on a phone (REQ-55) |
| Dependencies are pinned exactly | A range resolves at build time; `npm ci` installs the lockfile |
