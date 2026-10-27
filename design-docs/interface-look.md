# Interface look

How the interface is drawn: tokens and the two looks, state colors, layout and
control shapes, keyboard reach, how severity and exploitation are marked, and
where it differs from the mockup.

Satisfies REQ-32, REQ-55, REQ-57, REQ-60.

## Contents

- [The look](#the-look)
- [State chips](#state-chips)
- [Interface-wide rules](#interface-wide-rules)
- [Reachable from a keyboard](#reachable-from-a-keyboard)
- [The ordering signals](#the-ordering-signals)
- [Divergence from the mockup](#divergence-from-the-mockup)
- [Limits](#limits)

## The look

The shell (the rail, the top bar, the scope picker) is the restyled mockup's,
settled (REQ-60). The work surface is quieter than the mockup drew it
(§ Divergence from the mockup). The mockup's frame is the page: its tokens sit
on the root element and its grid on the application container.

A look is a token set (colors, the two typefaces, radii, shadows) over one
markup. Light mode is a dark rail over a light surface; dark mode is dark
throughout. There are two, named light and dark, as every other application
names them.

### The work surface

| Rule | Reason |
|---|---|
| One plane: canvas and surface are one color, and a card, table or figure is set off by a hairline | A shadow says two planes; it is kept for what floats: suggestions, the picker, a drawer |
| Corners are 6 px on a control, 8 on a card, 4 on a tag | |
| A label is sentence case, muted, at the small step: block labels, column heads, field names, captions. Uppercase is kept for the known-exploited and bulk-decision marks | They are read as marks |
| The primary button is ink: black on the light canvas, white on the dark. A secondary button is the outline in two weights of text | The accent is for what opens something |
| A pressed filter chip or segment is ink; a filter in force above the list sits on the raised tone, its label quieter than its value | A state and a link must not read alike on one toolbar |
| Every state is ink or the raised tone: picked, pressed, checked, selected, the current page, the component a path leads to, a set setting. The accent is links, focus rings, hover on what opens, and the row or option the keys are on. A web test fails a state rule using the accent | |
| Severity is a dot and a word colored by the band, with no fill | Fifty tinted pills compete with the column read first |
| A count beside a tab is a number, quieter than its word, the same selected or not | |
| A warning and an all-clear each have three tokens: a panel on the surface, a wash over anything, the line around either. A different strength is a raw mix that says why beside it | Two screens' warnings are one shade |
| A shape many rules share is one rule listing every selector: the sentence-case label, the small uppercase group heading, a chip's tint arms, the editor column's reserved height | A change lands everywhere it is drawn |

### Choosing a look

| Rule | Reason |
|---|---|
| Nothing chosen follows the operating system, and keeps following it | |
| Picking one pins it; picking "system" hands it back | Choosing once must not be one-way |
| Stamped on the root element before the first paint | Otherwise every fresh page flashes the wrong look |
| The page's stamp holds its own copy of the key and the looks; a web test holds the two copies together. A look the stamp does not know is replaced by the system's on load | It cannot import them |
| Kept in the browser, changing nothing anybody else sees | |
| Each look has its own accent beside the same severity scale, exploited above critical; severity never borrows the accent | "Critical" in the brand color leaves nothing meaning "act on this" |

## State chips

A state is a word on a tint of its color.

| Class | Means | Color | Examples |
|---|---|---|---|
| `closed` | Asked for and done | Good | Scanned, met |
| `agreed` | Agreed to | Good | Decided, approved, in force |
| `waiting` | Under way, or waiting on somebody | Amber | Pending, scanning |
| `warn` | Not wrong yet, and close | Amber | A queue at its limit |
| `lapsed` | Ended without standing | Orange | Lapsed, withdrawn, sent back |
| `open` | A state read, not acted on | Muted | A branch, undecided, identifier cannot be read |
| `bad` | Wrong; somebody should look | Red | Failing, failed, stopped |
| none | A fact, neither good nor bad | Muted | Left, held back |

| Rule | Reason |
|---|---|
| A problem is never drawn in the done color; a web test fails a done chip whose words say something is wrong | Green reads as good news |
| A decision is drawn in the color of what it does: warm where it hides risk (every outcome but affected), green where not. An outcome with no color draws as the neutral base; a web test fails an outcome the client names that the stylesheet does not color | |
| A decision's card carries a stripe for where it stands, one mapping on the decision page and the finding screen | |

| Decision | Chip | Stripe |
|---|---|---|
| Waiting for a second person, or still argued | Waiting | Pending |
| Agreed, or proposed where nothing waits on a second person | Agreed | In force |
| Sent back | Lapsed | Pending |
| Withdrawn | Lapsed | None: its proposer ended it |
| Stopped applying | Lapsed | Lapsed |

The chip says whether a decision is finished; the stripe says whether it is in
force.

## Interface-wide rules

Every screen works on a phone (REQ-55).

| Rule | Reason |
|---|---|
| A small screen is shaped for review and respond: read a finding, agree or send back, see what is assigned. Wide-only screens stay wide and say so | Nobody triages three hundred findings on a phone |
| Narrow screens get cards, never a table that scrolls sideways | |
| A table wider than its box says so at every width, in a note above it pinned while it scrolls, with the clipped edge shaded; only tables that are wider, measured by the table itself | A stylesheet cannot ask, and a note over a table that fits teaches people to skip notes |
| A table that scrolls takes a tab stop while there is somewhere to scroll | Arrow keys move a box only once it has focus |
| Headings and field labels are noun phrases (REQ-60); the explanation sits under them; a card always has a name of its own | Somebody scanning reads thirty names, never thirty sentences |
| Labels use the conventional word (REQ-60): Reject, Trend, Assignments, Unassigned, Justification, Path, EPSS, Occurrences, Access, Lapsed decisions, Submit. A caption is a sentence at most | |
| Every text and number box says it is not a credential in the four attributes password managers read | `autocomplete` alone is ignored for saved logins; this deployment holds no password |
| A control carries no prose and is named for what it holds; its explanation sits on the label | A manager reads any text it can reach through a control |
| Two rows are ambiguous only when both ends match (REQ-57): one subproject reaching one component by two routes; expanding the row or the tree resolves it | Nothing is invented for a case the reader can see |
| Panel order and what is left out are decided, never accumulated | |
| What sits over the page is positioned against the viewport | The frame grows with content, so a drawer would be the whole document tall |
| Stacking is one named scale, and every overlay (the sheet, the floating action, the drawer, the two scrims) is styled in one file read against it | Two overlays on one step resolve on document order |
| The way back in after a session ends is the top step | Under an open sheet or the phone rail, its controls are covered |
| The stylesheet's order is the cascade; print rules are imported last and win by position | |
| A closed vocabulary the server owns is rendered from the generated client | A hand table has members it cannot label |
| An outcome's class is what the server publishes in the caller's description, read once at start: hides risk, carries a date, states a reason, is a dismissal. The dismissal reports, the audit log's filter and labels, every form asking for a reason, and the decision form's second-person hint read it. The hint tells a deferral from a promise by name, since their dates are measured against different things. Nothing is classed before the answer arrives | An outcome the server moves moves here |
| A count is never shown before it is known: a faint placeholder in flight, a dash with the reason on hover on failure, the figure once answered. An empty state is drawn once every read it depends on has answered. One renderer does all three, held by a web test | A zero while loading answers a question not yet asked |
| A word the table does not know is shown as it arrived | Unfamiliar beats blank |
| A choice with a consequence is a card per option carrying what picking it does: where a flaw came from, filing or recording, a recorded flaw's disclosure, a ruling's disposition. An option somebody may not pick is left out and said below. A radio group to the keyboard | |
| A switch between values is a segmented control: buttons, the picked one filled, the frame dashed while nothing is picked, keeping its own width in a panel | |
| A row that looks openable opens: pointer and hover fill only where a click anywhere opens its one target | |
| That target stays a real link. Other controls and a second link keep their clicks; a cell holding a form field is the field's; a modified click and a click ending a text selection open nothing; a row with several targets or none is flat | |
| An identifier that opens something is drawn as a link: accent, underlined on hover | The base stylesheet gives a link the surrounding text's color |
| A file is picked in a drop zone: click or drop, a button look at its end, picked files listed as removable chips | The browser's input varies and takes no drop |
| A control is drawn with what the bundle carries: a character a bundled font has, or an icon from the rail's set; never an emoji | No emoji font ships; it is a missing glyph on machines without one |
| One reduced-motion rule covers the page | |

## Reachable from a keyboard

| Rule | Reason |
|---|---|
| The findings list is worked from the keyboard: `j` and `k` move a cursor, `Enter` opens the row in place, `Escape` closes it, `o` opens the finding | It is the screen a triager spends the day on |
| No key acts while focus takes typing; a modified key is the browser's; a key a control already answered is the control's | `j` in a justification is a letter |
| The cursor is drawn, and goes when the question changes | A cursor on row nine of a re-read list points at another finding |
| The focus ring is added to, never replaced: an accent border and a wash around the global ring | A checkbox or radio is browser-painted; a border reaches nothing and a tenth-strength wash is 1.16:1, under 3:1 |
| Where a control has no border, the ring goes on the box around it | The search boxes draw their own frame |
| Nothing a person operates is `display: none`; a drop zone's input is out of sight and focusable, and the zone draws the ring | It leaves the tab order |
| Text on a severity color reads the token that flips with the look | Dark-look severity tokens are light tints; white on one is 2.54:1 |
| A focused control keeps Enter: on the review sheet Enter confirms only where no button, link or field has focus | |
| One contrast ratio for one meaning: a disabled chip and a disabled button match | |

## The ordering signals

The findings list is ordered by urgency (REQ-32): known exploited, then whether
the build reaches customers, then severity, then likelihood. Every signal is on
the row, because an order on something unshown reads as unsorted.

| Rule | Reason |
|---|---|
| Every weakness is shown and named from what the server sends beside the identifier: the short name for a common weakness, the catalog's name otherwise, whole, the catalog's on hover | A bare "CWE-401" names nothing |
| Named alike on the finding, the filter's chips and panel, and the record-a-flaw picker; on the finding each links to its write-up, built from the identifier | |
| The weakness filter takes identifiers only; other words search, and a word that is not an identifier is dropped | A filter matching nothing |
| A feed's two words for "no classification" are stated, never drawn as one | |
| The band a row is drawn in and the word it says are two answers: the two words a scanner reports below low rank and color as low, and the row says what was rated | "Rated negligible" must not read "Unrated" |
| Known exploited is its own badge beside the severity word | An exploited medium is still a medium |
| The feed's flag reads "Known exploited" on the badge and every caption, column and tile counting it | A bare "Exploited" reads as an attack on this product |
| An incident is a filled badge; the feed's flag an outline of the same color, saying on hover it is not on its own a sign this product was attacked (`design-docs/incidents.md` § Three conflated facts) | The record is the rarer, attested fact |
| Where both apply the incident's badge comes first | |
| Every row the server marks with an incident draws its badge, and every caption counting the feed's flag counts incidents beside it where there are any | |
| The score sits beside the word | A 10.0 reads high under CVSS v2 and critical under v3; real disagreement is 3 of 2,645 |
| The word compares down a column (`design-docs/findings-severity.md` § One ladder for every scheme) | Two schemes weigh differently |
| Where a product rated an issue itself, that orders and filters its list, and both ratings are shown; across products each row reads its own product's rating (REQ-29) | The world's beside ours keeps ours from reading as the world's |

## Divergence from the mockup

Each screen was compared with the restyled mockup control for control.

| Mockup | Here |
|---|---|
| A known-exploited tile at every scope | It needs a product to narrow inside |
| Builds past the fix shown and not offered on the reach sheet | Every build at another version is offered; the reach read does not order versions |
| Reaffirms a lapsed occurrence inline on the queue card | On the finding; whole decisions from the To reaffirm tab |
| Variants and branches screens carry their own product select | The scope picker |
| The queue card separates "matching automatically" from "ticked deliberately" | The record does not keep which; an approval keeps one number |
| The users table lists user, identity, last sign-in, roles and assigned | User, identity, roles and a grant control; sign-in and assigned work are on the person's own screen |
| Administration in the grant grid | A control of its own beside the grid: it is global |
| A pipeline key created elsewhere | Created where keys are listed |
| A personal token's reach chosen after it is made | Fixed at creation and asked there; the list shows each token's reach |
| A withdrawn credential leaves the list | It stays, dimmed, the button replaced by the word |
| The sign-in screen drawn where there is one way in | Forwarded straight to the provider, except: over live work after a session ended, straight after sign-out (the provider's session would sign somebody back in), and a second arrival in a tab that already forwarded |
| Uploads' SBOM table carries product, branch and variant columns | The scope bar; it adds when the producer says the build was made |
| Settings write "3 days" in the field | The field holds the server's duration syntax, with the reading beside it |
| A gray canvas with raised white cards | One white plane with hairlines (§ The work surface) |
| Uppercase letter-spaced labels | Sentence case, small, muted |
| The accent on the primary button, a pressed chip and a selected tab | Ink on all three |
| A tinted pill for severity | A dot and the word |

The trend is drawn by hand: open as an area in its own band, new against
resolved as paired bars beneath on their own scale, one x axis. On the chart
library's one scale, open in thousands flattens weekly tens to the baseline. The
severity split and the ring use the library.

## Limits

| Limit | Detail |
|---|---|
| Color and the brand mark resolve through tokens in one stylesheet | How an operator overrides them is not built |
