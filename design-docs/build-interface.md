# Interface checks

The tools `make web-check` runs over the interface source, and the class-name
and whole-interface checks the web tests hold.

Satisfies REQ-75.

## Contents

- [Interface tools](#interface-tools)
- [Web test runs](#web-test-runs)
- [Class-name checks](#class-name-checks)
- [Whole-interface checks](#whole-interface-checks)
- [Limits](#limits)

## Interface tools

| Tool | Covers |
|---|---|
| `tsc` | Strict, with unused locals and parameters, unchecked indexed access, verbatim module syntax |
| ESLint | The rules of hooks, a reason on every disable directive, and little else `tsc` misses |
| Prettier | TypeScript and CSS formatting |
| Stylelint | CSS correctness: unknown properties, duplicate selectors, notation; no whitespace rules |
| `npm run classes` | The class-name checks |
| `npm run lint`, after ESLint | A query's data defaulted to an empty list in a file never consulting the read's failure: its error, `known`, a count, a failure line beside a picker, or the component drawing a read's three arms. `silent-read:` and a reason exempt a read. `design-docs/interface.md` § A read that failed |
| `npm run copy` | More than 20 words of paragraph, hint or empty-state detail on a screen at once. `design-docs/interface.md` § Screen copy |

| Rule | Reason |
|---|---|
| Prettier alone formats | |
| ESLint carries the hook rules: an impure read in render, an effect running every time, a value assigned and unused | A style rule firing on working code teaches people to ignore output |
| ESLint fails on a warning as on an error, writing state from an effect included | A warning a run passes is read by nobody, and the next one hides among those before it |
| A disable directive gives its reason after `--`, on the directive itself | It marks a line a rule would otherwise catch, so the exception is deliberate or a defect |
| A disable directive switching off nothing is an error | The rule it named moved or was fixed, and the directive would silence the next real report |
| The type check is `tsc -p` with `--incremental`, never `tsc -b` | One project with no references; build mode with `--noEmit` reused nothing, 10.7 s each run, against 1.2 s with the build information |
| ESLint and Prettier cache per file by content | ESLint here is not type-aware, so a file's result depends on that file and the configuration alone: 14.6 s against 0.7 s, and 4.6 s against 0.6 s |
| The three caches live in `web/.cache`, outside `node_modules`, and are emptied whenever the lockfile differs from the one they were made under | `npm ci` deletes `node_modules` every run; ESLint's results outlive a plugin moving under an unchanged configuration |

## Web test runs

| Rule | Reason |
|---|---|
| Each test file runs in its own VM context and DOM, inside a child process running file after file | A process per file was 29 s against 9 s on four cores |
| Processes, never threads | Node applies a time zone change only on a main thread, and a zone test passes vacuously under UTC; such a test asserts the zone took effect |
| Whole-interface tests, addresses, query keys, screen copy and control names, share one file and one parse | 0.66 s against 1.19 s |
| A test writing to `console.error` or `console.warn`, or meeting something jsdom does not implement, fails | React reports an update outside `act`, a repeated key and a render that threw there, and a passing run prints them where nobody reads |
| A test expecting such output replaces the method with a spy that prints nothing, and asserts on the spy | A bare spy calls through to the recorder; each test starts with the recorder back |
| The fake server answers a read in the shape the API document gives it, unless the test is about an answer missing a field, and a screen drawn alone sits beside a route answering every other address | A list body for a one-object read crashes the screen landed on, and a forward to an unrouted address warns |
| A test scheduling an animation frame waits for it, and a screen cancels its pending frames as it goes | A frame outliving its test fires inside a later one: jsdom has no `scrollIntoView`, and a findings-list frame failed 2 runs of 8 on four cores |

## Class-name checks

| Check | Rule |
|---|---|
| A class this project defines that Tailwind also defines | Tailwind, imported wholesale, emits a utility for any recognized name, and wins for the properties it sets: `class="col fixed"` takes `position: fixed`. Every class the stylesheet defines is put to Tailwind's compiler, so a new utility is caught |
| A rule that styles nothing | Matched against the whole source, since `col ${kind}` builds a modifier; it reports a name mentioned nowhere. Charting library names and the `language-` prefix are excluded |
| A class on an element nothing styles | A label with no fill is invisible on a dark canvas. Names Tailwind emits are excluded by asking its compiler |
| A rule nested inside another rule | Refused, wherever in its parent it sits: the reader takes innermost blocks, so the outer rule would go unread by every check here. A rule inside an at-rule's block is read |
| A modifier whose bare rule draws a box | A modifier such as `.state.warn` whose own rule sets display, margin, padding, border or background, longhands included, styles every element carrying it, so a table chip draws as a callout. A web test reads every stylesheet |

## Whole-interface checks

| Check | Rule |
|---|---|
| An export nothing else names | Fails, the interface's half of `make unreachable`; a test counts as a caller |
| An address no route answers, or one built outside the route module | Fails, and every query parameter the route table lists is held to a read on its screen. A Go test holds server links to the same table. `design-docs/interface.md` § The route table |
| An invalidation whose key no read's key starts with | Fails: the cache matches by prefix, so it refreshes nothing. Compared as far as each key is literal; a key opening on a name is read through the constant or the literal list the name is bound to, one key per word |
| An invalidation or read whose key opens on something unreadable | Fails: an invalidation nobody can check passes unseen, and such a read would reach every invalidation |

## Limits

| Limit | Detail |
|---|---|
| Only literal class names are read | A class built wholly from an interpolation is unseen |
| A name that is also a Tailwind utility passes the collision and unstyled checks | Both ask the same compiler |
| The unused-export check matches names, never imports | A name that is an ordinary word elsewhere passes |
| A bare `eslint-disable` switches off the reason rule with the rest | A disable naming no rule switches every rule off, and the reason rule is one of them |
| The route-parameter check reads names, never types | A `.get`, `.has` or `.getAll` on any value sharing a query-parameter name in the same file counts as reading the parameter, and so does one on a property of a name any file sets from the query parameters |
